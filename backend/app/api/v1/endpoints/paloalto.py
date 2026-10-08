"""Palo Alto（PAN-OS）整合 endpoints（admin only）。

與 OPNsense / pfSense / FortiGate 各自獨立 —— 不做跨廠牌抽象，因為每家的 API
形狀差太多（PAN-OS 甚至同時有 REST 與 XML 兩套）。

`/test` 回「連線診斷」：**逐端點**回報通不通與筆數，並顯示偵測到的 REST 版本段。
沒有實機的情況下，那是唯一能對齊欄位的辦法。
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
from app.models.paloalto import PaloAltoAddressObject, PaloAltoFirewall, PaloAltoPolicy
from app.schemas.base import Paginated
from app.schemas.paloalto import PaloAltoCreate, PaloAltoRead, PaloAltoUpdate
from app.services import paloalto as svc
from app.services.background_tasks import spawn_task

router = APIRouter(prefix="/paloalto", tags=["paloalto"],
                   dependencies=[Depends(require_admin)])
# 政策 / 位址物件屬「全域基礎設施資料」→ 唯讀檢視給具全域讀取權者
view_router = APIRouter(prefix="/paloalto", tags=["paloalto"],
                        dependencies=[Depends(require_global_read)])


async def _get_or_404(session: AsyncSession, fw_id: uuid.UUID) -> PaloAltoFirewall:
    fw = await session.get(PaloAltoFirewall, fw_id)
    if fw is None:
        raise HTTPException(404, detail="Not found")
    return fw


# 實例清單掛 view_router（全域讀取）：唯讀檢視頁要用它列出可選的防火牆。
# 回應不含 API 金鑰（PaloAltoRead 沒有該欄位）。
@view_router.get("", response_model=Paginated[PaloAltoRead])
async def list_firewalls(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[PaloAltoRead]:
    stmt = (select(PaloAltoFirewall).order_by(PaloAltoFirewall.name)
            .offset((page - 1) * page_size).limit(page_size))
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(PaloAltoFirewall)) or 0)
    return Paginated[PaloAltoRead](
        items=[PaloAltoRead.model_validate(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )


@router.post("", response_model=PaloAltoRead, status_code=status.HTTP_201_CREATED)
async def create_firewall(
    payload: PaloAltoCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PaloAltoRead:
    data = payload.model_dump(exclude={"api_key"})
    data["api_url"] = str(data["api_url"]).rstrip("/")
    fw = PaloAltoFirewall(**data, api_key_enc=b"placeholder", api_key_nonce=b"placeholder")
    session.add(fw)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    # 金鑰的 AAD 綁這一列的 id → 必須先 flush 拿到 id 才能加密
    fw.api_key_enc, fw.api_key_nonce = svc.encrypt_api_key(fw.id, payload.api_key)
    await session.flush()
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="paloalto_firewall", object_id=str(fw.id), action="create",
        diff={"name": fw.name, "api_url": fw.api_url},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(fw)
    return PaloAltoRead.model_validate(fw)


@router.patch("/{fw_id}", response_model=PaloAltoRead)
async def update_firewall(
    fw_id: uuid.UUID, payload: PaloAltoUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PaloAltoRead:
    fw = await _get_or_404(session, fw_id)
    data = payload.model_dump(exclude_unset=True)
    key = data.pop("api_key", None)
    # PATCH 的 None 是「不修改」，所以「改回自動偵測」需要自己的旗標
    if data.pop("clear_api_version", False):
        fw.api_version = None
        data.pop("api_version", None)
    for k, v in data.items():
        if k == "api_url" and v is not None:
            v = str(v).rstrip("/")
        setattr(fw, k, v)
    if key:
        fw.api_key_enc, fw.api_key_nonce = svc.encrypt_api_key(fw.id, key)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="paloalto_firewall", object_id=str(fw.id), action="update",
        diff={k: str(v) for k, v in data.items()},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(fw)
    return PaloAltoRead.model_validate(fw)


async def cleanup_shared_rows(session: AsyncSession, fw_id: uuid.UUID) -> None:
    """清掉這台寫進**共用表**的列（不 commit，交易邊界由呼叫端決定）。

    政策／位址物件有外鍵 cascade 可以依靠；`nat_translations` 是多來源共用表、
    沒有 cascade，必須自己清 —— 而且**只能清自己的列**，所以條件要帶 `source_origin`。
    """
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="paloalto", source_id=fw_id)


@router.delete("/{fw_id}", status_code=204)
async def delete_firewall(
    fw_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    fw = await _get_or_404(session, fw_id)
    await cleanup_shared_rows(session, fw_id)
    await session.delete(fw)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="paloalto_firewall", object_id=str(fw_id), action="delete", diff={},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.post("/{fw_id}/test")
async def test_firewall(
    fw_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """連線診斷：偵測 REST 版本段、列出 vsys，並逐端點回報是否可讀與筆數。"""
    fw = await _get_or_404(session, fw_id)
    try:
        return await svc.diagnose(fw)
    except svc.PaloAltoError as exc:
        raise HTTPException(502, detail=detail_of(exc, "paloalto_error")) from exc


@router.post("/{fw_id}/sync")
async def trigger_sync(
    fw_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """非同步 —— 立刻回 task_id，同步在背景跑。"""
    fw = await _get_or_404(session, fw_id)
    actor_user_id, fw_name = user.id, fw.name
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)

    async def _runner(sess: AsyncSession, _task: Any) -> dict[str, Any]:
        obj = await sess.get(PaloAltoFirewall, fw_id)
        if obj is None:
            raise RuntimeError("Palo Alto firewall disappeared")
        summary = await svc.sync_instance(sess, obj)
        await append_audit(
            sess, actor_user_id=str(actor_user_id), actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="paloalto_firewall", object_id=str(fw_id), action="sync",
            diff={k: str(v) for k, v in summary.items()}, request_id=request_id,
        )
        await sess.commit()
        return summary

    task = await spawn_task(
        session=session, kind="paloalto.sync", target_type="paloalto_firewall",
        target_id=fw_id, target_label=fw_name, actor_user_id=actor_user_id, runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status,
            "queued_at": task.queued_at.isoformat()}


# ─────────────────── 唯讀檢視（政策 / 位址物件）───────────────────
@view_router.get("/{fw_id}/policies")
async def list_policies(
    fw_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    vsys: str | None = Query(None),
) -> dict[str, Any]:
    stmt = select(PaloAltoPolicy).where(PaloAltoPolicy.firewall_id == fw_id)
    if vsys:
        stmt = stmt.where(PaloAltoPolicy.vsys == vsys)
    # 依 position 排序：PAN-OS 由上而下比對，順序本身就是語意，按名稱排會看不出優先權
    rows = (await session.execute(stmt.order_by(
        PaloAltoPolicy.vsys, PaloAltoPolicy.position))).scalars().all()
    return {"items": [{
        "id": str(r.id), "vsys": r.vsys, "name": r.name, "position": r.position,
        "action": r.action, "disabled": r.disabled,
        "from_zone": r.from_zone, "to_zone": r.to_zone,
        "source": r.source, "destination": r.destination,
        "application": r.application, "service": r.service, "description": r.description,
    } for r in rows]}


@view_router.get("/{fw_id}/addresses")
async def list_addresses(
    fw_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    vsys: str | None = Query(None),
) -> dict[str, Any]:
    stmt = select(PaloAltoAddressObject).where(PaloAltoAddressObject.firewall_id == fw_id)
    if vsys:
        stmt = stmt.where(PaloAltoAddressObject.vsys == vsys)
    rows = (await session.execute(stmt.order_by(
        PaloAltoAddressObject.vsys, PaloAltoAddressObject.name))).scalars().all()
    return {"items": [{
        "id": str(r.id), "vsys": r.vsys, "name": r.name, "kind": r.kind,
        "obj_type": r.obj_type, "value": r.value, "members": r.members,
        "description": r.description,
    } for r in rows]}
