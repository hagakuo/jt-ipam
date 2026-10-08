"""OCS Inventory NG 整合 endpoints（admin only；唯讀檢視走全域讀取）。

`/test` 的診斷比其他整合多一件事：**主動測「沒帶憑證連不連得上」**。OCS 的 REST 預設無驗證，
連得上就代表這套 OCS 對任何能到達它的人都是開放的 —— 那是站台該知道的資安狀態，不是我們
默默用掉就好。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin, require_global_read
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import detail_of
from app.models.address import IPAddress
from app.models.ocs import OcsServer
from app.schemas.base import Paginated
from app.schemas.ocs import OcsCreate, OcsRead, OcsUpdate
from app.services import ocs as svc
from app.services.background_tasks import spawn_task

router = APIRouter(prefix="/ocs", tags=["ocs"], dependencies=[Depends(require_admin)])
view_router = APIRouter(prefix="/ocs", tags=["ocs"],
                        dependencies=[Depends(require_global_read)])


async def _get_or_404(session: AsyncSession, server_id: uuid.UUID) -> OcsServer:
    obj = await session.get(OcsServer, server_id)
    if obj is None:
        raise HTTPException(404, detail="Not found")
    return obj


@view_router.get("", response_model=Paginated[OcsRead])
async def list_servers(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[OcsRead]:
    stmt = (select(OcsServer).order_by(OcsServer.name)
            .offset((page - 1) * page_size).limit(page_size))
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(OcsServer)) or 0)
    return Paginated[OcsRead](
        items=[OcsRead.from_row(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )


@router.post("", response_model=OcsRead, status_code=status.HTTP_201_CREATED)
async def create_server(
    payload: OcsCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OcsRead:
    data = payload.model_dump(exclude={"api_password"})
    data["base_url"] = str(data["base_url"]).rstrip("/")
    obj = OcsServer(source_type="rest", **data)
    session.add(obj)
    try:
        await session.flush()      # 先拿到 id：AAD 綁 id，加密要在 flush 之後
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    svc.set_api_password(obj, payload.api_password)
    await session.flush()
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ocs_server", object_id=str(obj.id), action="create",
        diff={"name": obj.name, "base_url": obj.base_url},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return OcsRead.from_row(obj)


@router.patch("/{server_id}", response_model=OcsRead)
async def update_server(
    server_id: uuid.UUID, payload: OcsUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OcsRead:
    obj = await _get_or_404(session, server_id)
    data = payload.model_dump(exclude_unset=True)
    password = data.pop("api_password", None)
    clear = data.pop("clear_credentials", False)
    for k, v in data.items():
        if k == "base_url" and v is not None:
            v = str(v).rstrip("/")
        setattr(obj, k, v)
    if clear:
        obj.api_username = None
        svc.set_api_password(obj, None)
    elif password:
        svc.set_api_password(obj, password)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ocs_server", object_id=str(obj.id), action="update",
        diff={k: str(v) for k, v in data.items()},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return OcsRead.from_row(obj)


@router.delete("/{server_id}", status_code=204)
async def delete_server(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    obj = await _get_or_404(session, server_id)
    # 它寫進共用表的主機名稱／租約／固定分配／NAT／VPN 通道一併收回（沒有外鍵會跟著刪）
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="ocs", source_id=obj.id)
    await session.delete(obj)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ocs_server", object_id=str(server_id), action="delete", diff={},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.post("/{server_id}/test")
async def test_server(
    server_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """連線診斷：可達性、要不要驗證、**是不是無認證就讀得到**、能不能增量、抓得到幾台。"""
    obj = await _get_or_404(session, server_id)
    try:
        return await svc.diagnose(obj)
    except svc.OcsError as exc:
        raise HTTPException(502, detail=detail_of(exc, "ocs_error")) from exc


@router.post("/{server_id}/sync")
async def trigger_sync(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """非同步 —— 立刻回 task_id，同步在背景跑。"""
    obj = await _get_or_404(session, server_id)
    actor_user_id, label = user.id, obj.name
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)

    async def _runner(sess: AsyncSession, _task: Any) -> dict[str, Any]:
        target = await sess.get(OcsServer, server_id)
        if target is None:
            raise RuntimeError("OCS server disappeared")
        summary = await svc.sync_instance(sess, target)
        await append_audit(
            sess, actor_user_id=str(actor_user_id), actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="ocs_server", object_id=str(server_id), action="sync",
            diff={k: str(v) for k, v in summary.items()}, request_id=request_id,
        )
        await sess.commit()
        return summary

    task = await spawn_task(
        session=session, kind="ocs.sync", target_type="ocs_server",
        target_id=server_id, target_label=label, actor_user_id=actor_user_id, runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status,
            "queued_at": task.queued_at.isoformat()}


# ─────────────────── 代理數／未裝 Agent 的 IP（比照 Wazuh 整合頁，管理員限定） ───────────────────


@router.get("/agents")
async def list_ocs_agents(session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    """OCS 盤點到的電腦，一台一筆（一台電腦的多個 IP 彙整在一起）。"""
    items = await svc.list_agents(session)
    return {"items": items, "total": len(items)}


@router.get("/missing-agents")
async def list_ocs_missing_agents(
    session: Annotated[AsyncSession, Depends(get_session)],
    hostnamed_only: bool = True,
    page: Annotated[int | None, Query(ge=1)] = None,
    page_size: Annotated[int, Query(ge=1, le=100_000)] = 100,
    section_id: uuid.UUID | None = None,
    subnet_id: uuid.UUID | None = None,
    customer_id: uuid.UUID | None = None,
    status_filter: Annotated[str | None, Query(alias="status", max_length=16)] = None,
    q: Annotated[str | None, Query(max_length=128)] = None,
    sort: Annotated[Literal["ip", "hostname", "subnet", "section", "customer", "status", "device_kind"],
                    Query()] = "ip",
    order: Annotated[Literal["asc", "desc"], Query()] = "asc",
) -> Any:
    """有主機名稱、卻從來沒被 OCS 盤點過的 IP（帶所屬子網路／區段／單位，畫面據此篩選）。

    OCS 設了「限定子網路範圍」就只列範圍內的（見 agent_scope.expected_subnets）。
    """
    from app.services.agent_scope import annotate_scope, expected_subnets
    servers = list((await session.execute(
        select(OcsServer).where(OcsServer.enabled.is_(True)))).scalars().all())
    if page is not None:
        # 伺服器端分頁與篩選（與 Wazuh 頁同一套：agent_scope.missing_page）
        from app.services.agent_scope import missing_page
        return await missing_page(
            session, missing=IPAddress.ocs_id.is_(None) & IPAddress.last_seen_ocs.is_(None),
            subnet_ids=expected_subnets(servers), hostnamed_only=hostnamed_only, page=page,
            page_size=page_size, section_id=section_id, subnet_id=subnet_id, customer_id=customer_id,
            status=status_filter, q=q, sort=sort, order=order, cache_key=("ocs",))
    return await annotate_scope(session, await svc.find_missing_agents(
        session, hostnamed_only=hostnamed_only, subnet_ids=expected_subnets(servers)))
