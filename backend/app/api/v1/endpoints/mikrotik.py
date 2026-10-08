"""MikroTik RouterOS 整合 endpoints（admin only；唯讀檢視走全域讀取）。

`/test` 的診斷比其他整合多回**每支端點的列數與耗時**：客戶的 MikroTik 是主力路由器，
「要不要開 ARP 這一段」應該由看得到數字的人決定，而不是由我們預設替他決定。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin, require_global_read
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import detail_of
from app.models.mikrotik import MikroTikAddressList, MikroTikRouter, MikroTikRule
from app.schemas.base import Paginated
from app.schemas.mikrotik import (
    MikroTikAddressListRead,
    MikroTikCreate,
    MikroTikRead,
    MikroTikRuleRead,
    MikroTikUpdate,
)
from app.services import mikrotik as svc
from app.services.background_tasks import spawn_task

router = APIRouter(prefix="/mikrotik", tags=["mikrotik"],
                   dependencies=[Depends(require_admin)])
# 規則 / address-list 屬「全域基礎設施資料」→ 唯讀檢視給具全域讀取權者
view_router = APIRouter(prefix="/mikrotik", tags=["mikrotik"],
                        dependencies=[Depends(require_global_read)])


async def _check_device(session: AsyncSession, device_id: uuid.UUID | None) -> None:
    """指定的對應裝置要存在：不檢查的話外鍵違反會變成 500，畫面上看不出原因。"""
    if device_id is None:
        return
    from app.models.device import Device
    if await session.get(Device, device_id) is None:
        from app.core.ui_error import ui_detail
        raise HTTPException(422, detail=ui_detail("ros_device_not_found", "指定的裝置不存在"))


async def _get_or_404(session: AsyncSession, router_id: uuid.UUID) -> MikroTikRouter:
    obj = await session.get(MikroTikRouter, router_id)
    if obj is None:
        raise HTTPException(404, detail="Not found")
    return obj


# 清單掛 view_router（唯讀檢視頁要用它列出可選的路由器）。回應不含密碼。
@view_router.get("", response_model=Paginated[MikroTikRead])
async def list_routers(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[MikroTikRead]:
    stmt = (select(MikroTikRouter).order_by(MikroTikRouter.name)
            .offset((page - 1) * page_size).limit(page_size))
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(MikroTikRouter)) or 0)
    return Paginated[MikroTikRead](
        items=[MikroTikRead.model_validate(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )


@router.post("", response_model=MikroTikRead, status_code=status.HTTP_201_CREATED)
async def create_router(
    payload: MikroTikCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MikroTikRead:
    data = payload.model_dump(exclude={"api_password"})
    data["api_url"] = str(data["api_url"]).rstrip("/")
    await _check_device(session, data.get("device_id"))
    obj = MikroTikRouter(**data, api_password_enc=b"placeholder",
                         api_password_nonce=b"placeholder")
    session.add(obj)
    try:
        await session.flush()      # 先拿到 id：AAD 綁 id，加密要在 flush 之後
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    obj.api_password_enc, obj.api_password_nonce = svc.encrypt_api_password(
        obj.id, payload.api_password)
    await session.flush()
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="mikrotik_router", object_id=str(obj.id), action="create",
        diff={"name": obj.name, "api_url": obj.api_url},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return MikroTikRead.model_validate(obj)


@router.patch("/{router_id}", response_model=MikroTikRead)
async def update_router(
    router_id: uuid.UUID, payload: MikroTikUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MikroTikRead:
    obj = await _get_or_404(session, router_id)
    data = payload.model_dump(exclude_unset=True)
    password = data.pop("api_password", None)
    await _check_device(session, data.get("device_id"))
    for k, v in data.items():
        if k == "api_url" and v is not None:
            v = str(v).rstrip("/")
        setattr(obj, k, v)
    if password:
        obj.api_password_enc, obj.api_password_nonce = svc.encrypt_api_password(
            obj.id, password)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="mikrotik_router", object_id=str(obj.id), action="update",
        diff={k: str(v) for k, v in data.items()},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return MikroTikRead.model_validate(obj)


async def cleanup_shared_rows(session: AsyncSession, router_id: uuid.UUID) -> None:
    """清掉這台路由器寫進**共用表**的列（不 commit，由呼叫端決定交易邊界）。

    `mikrotik_rules` / `mikrotik_address_lists` 有 cascade 可依靠；
    `dhcp_pool_ranges` 與 `nat_translations` 是多來源共用、沒有 cascade，
    必須自己清且**只能清自己的列** —— 條件一定要帶 `source_type` / `source_origin`。
    """
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="mikrotik", source_id=router_id)


@router.delete("/{router_id}", status_code=204)
async def delete_router(
    router_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    obj = await _get_or_404(session, router_id)
    await cleanup_shared_rows(session, router_id)
    await session.delete(obj)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="mikrotik_router", object_id=str(router_id), action="delete", diff={},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.post("/{router_id}/test")
async def test_router(
    router_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """連線診斷：版本／型號＋逐端點的可讀性、**列數與耗時**、前後 CPU 負載。"""
    obj = await _get_or_404(session, router_id)
    try:
        return await svc.diagnose(obj)
    except svc.RouterOSError as exc:
        raise HTTPException(502, detail=detail_of(exc, "ros_error")) from exc


@router.post("/{router_id}/sync")
async def trigger_sync(
    router_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """非同步 —— 立刻回 task_id，同步在背景跑。"""
    obj = await _get_or_404(session, router_id)
    actor_user_id, label = user.id, obj.name
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)

    async def _runner(sess: AsyncSession, _task: Any) -> dict[str, Any]:
        target = await sess.get(MikroTikRouter, router_id)
        if target is None:
            raise RuntimeError("MikroTik router disappeared")
        summary = await svc.sync_instance(sess, target)
        await append_audit(
            sess, actor_user_id=str(actor_user_id), actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="mikrotik_router", object_id=str(router_id), action="sync",
            diff={k: str(v) for k, v in summary.items()}, request_id=request_id,
        )
        await sess.commit()
        return summary

    task = await spawn_task(
        session=session, kind="mikrotik.sync", target_type="mikrotik_router",
        target_id=router_id, target_label=label, actor_user_id=actor_user_id, runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status,
            "queued_at": task.queued_at.isoformat()}


# ─────────────────── 唯讀檢視 ───────────────────
@view_router.get("/{router_id}/rules")
async def list_rules(
    router_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    table: str | None = Query(None, pattern="^(filter|nat|mangle)$"),
) -> dict[str, Any]:
    """規則清單。**依 position 排序** —— RouterOS 由上而下比對，順序就是語意。"""
    stmt = select(MikroTikRule).where(MikroTikRule.router_id == router_id)
    if table:
        stmt = stmt.where(MikroTikRule.table_name == table)
    rows = (await session.execute(stmt.order_by(
        MikroTikRule.table_name, MikroTikRule.position))).scalars().all()
    return {"items": [MikroTikRuleRead.model_validate(r).model_dump(mode="json") for r in rows]}


@view_router.get("/{router_id}/address-lists")
async def list_address_lists(
    router_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    list_name: str | None = Query(None, max_length=128),
) -> dict[str, Any]:
    stmt = select(MikroTikAddressList).where(MikroTikAddressList.router_id == router_id)
    if list_name:
        stmt = stmt.where(MikroTikAddressList.list_name == list_name)
    rows = (await session.execute(stmt.order_by(
        MikroTikAddressList.list_name, MikroTikAddressList.address))).scalars().all()
    return {"items": [MikroTikAddressListRead.model_validate(r).model_dump(mode="json")
                      for r in rows]}


@view_router.get("/{router_id}/neighbors")
async def list_neighbors(
    router_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """`/ip/neighbor` 鏡像（第二階段）。`device_id`／`device_name`：依鄰居宣告的位址或 MAC 對到的裝置
    （對到多台就不填 —— 重疊網段下同一個位址可能有好幾筆）。"""
    from app.models.mikrotik import MikroTikNeighbor
    from app.services.mikrotik import match_neighbor_devices
    rows = (await session.execute(select(MikroTikNeighbor).where(MikroTikNeighbor.router_id == router_id)
                                  .order_by(MikroTikNeighbor.interface))).scalars().all()
    matched = await match_neighbor_devices(session, rows)
    return {"items": [{
        "interface": r.interface, "address": r.address, "mac": r.mac, "identity": r.identity,
        "platform": r.platform, "board": r.board, "version": r.version,
        "remote_interface": r.remote_interface, "discovered_by": r.discovered_by,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        **(matched.get(r.id) or {"device_id": None, "device_name": None}),
    } for r in rows]}
