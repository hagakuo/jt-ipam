"""FortiGate 整合 endpoints（Beta，admin only）。

與 OPNsense / pfSense 各自獨立：這裡只管 FortiGate 自己的設定與同步。
`/test` 回「連線診斷」—— 逐端點回報通不通與筆數，方便無實機開發後上線時快速對齊。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin, require_global_read
from app.core.audit import append_audit
from app.core.db import get_session
from app.models.fortigate import (
    FortiGateAddressObject,
    FortiGateFirewall,
    FortiGatePolicy,
)
from app.schemas.base import Paginated
from app.schemas.fortigate import FortiGateCreate, FortiGateRead, FortiGateUpdate
from app.services import fortigate as svc
from app.services.background_tasks import spawn_task

router = APIRouter(prefix="/fortigate", tags=["fortigate"],
                   dependencies=[Depends(require_admin)])
# 政策 / 位址物件屬「全域基礎設施資料」→ 唯讀檢視給具全域讀取權者
view_router = APIRouter(prefix="/fortigate", tags=["fortigate"],
                        dependencies=[Depends(require_global_read)])


async def _get_or_404(session: AsyncSession, fw_id: uuid.UUID) -> FortiGateFirewall:
    fw = await session.get(FortiGateFirewall, fw_id)
    if fw is None:
        raise HTTPException(404, detail="Not found")
    return fw


# 實例清單掛 view_router（全域讀取）而不是 admin —— 唯讀檢視頁「防火牆 (FortiGate)」
# 要用它列出可選的防火牆。回應不含 API token（FortiGateRead 沒有該欄位）。
@view_router.get("", response_model=Paginated[FortiGateRead])
async def list_firewalls(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[FortiGateRead]:
    stmt = (select(FortiGateFirewall).order_by(FortiGateFirewall.name)
            .offset((page - 1) * page_size).limit(page_size))
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(FortiGateFirewall)) or 0)
    return Paginated[FortiGateRead](
        items=[FortiGateRead.model_validate(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )


@router.post("", response_model=FortiGateRead, status_code=status.HTTP_201_CREATED)
async def create_firewall(
    payload: FortiGateCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FortiGateRead:
    data = payload.model_dump(exclude={"api_token"})
    data["api_url"] = str(data["api_url"]).rstrip("/")
    fw = FortiGateFirewall(**data, api_token_enc=b"placeholder", api_token_nonce=b"placeholder")
    session.add(fw)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    fw.api_token_enc, fw.api_token_nonce = svc.encrypt_api_token(fw.id, payload.api_token)
    await session.flush()
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="fortigate_firewall", object_id=str(fw.id), action="create",
        diff={"name": fw.name, "api_url": fw.api_url},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(fw)
    return FortiGateRead.model_validate(fw)


@router.patch("/{fw_id}", response_model=FortiGateRead)
async def update_firewall(
    fw_id: uuid.UUID, payload: FortiGateUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FortiGateRead:
    fw = await _get_or_404(session, fw_id)
    data = payload.model_dump(exclude_unset=True)
    token = data.pop("api_token", None)
    for k, v in data.items():
        if k == "api_url" and v is not None:
            v = str(v).rstrip("/")
        setattr(fw, k, v)
    if token:
        fw.api_token_enc, fw.api_token_nonce = svc.encrypt_api_token(fw.id, token)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="fortigate_firewall", object_id=str(fw.id), action="update",
        diff={k: str(v) for k, v in data.items()},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(fw)
    return FortiGateRead.model_validate(fw)


async def cleanup_shared_rows(session: AsyncSession, fw_id: uuid.UUID) -> None:
    """清掉這台 FortiGate 寫進共用表的列（不 commit，由呼叫端決定交易邊界）。

    政策／位址物件有外鍵 cascade 可依靠；但 `dhcp_pool_ranges` 與 `nat_translations`
    是多來源共用表、沒有 cascade，必須自己清、且只能清自己的列 ——
    所以兩個條件都要帶 `source_type`／`source_origin` 限定，不可只用 id。
    抽成函式是為了讓測試能直接驗這段真正的邏輯，而不是在測試裡重寫一份。
    """
    from app.models.dhcp import DHCPPoolRange
    from app.models.nat import NATTranslation
    await session.execute(delete(DHCPPoolRange).where(
        DHCPPoolRange.source_type == "fortigate", DHCPPoolRange.source_id == fw_id,
    ))
    await session.execute(delete(NATTranslation).where(
        NATTranslation.source_origin == f"fortigate:{fw_id}",
    ))


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
        object_type="fortigate_firewall", object_id=str(fw_id), action="delete", diff={},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.post("/{fw_id}/test")
async def test_firewall(
    fw_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """連線診斷：列出 VDOM，並逐端點回報是否可讀與筆數。"""
    fw = await _get_or_404(session, fw_id)
    try:
        return await svc.diagnose(fw)
    except svc.FortiGateError as exc:
        raise HTTPException(502, detail=str(exc)) from exc


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
        obj = await sess.get(FortiGateFirewall, fw_id)
        if obj is None:
            raise RuntimeError("FortiGate firewall disappeared")
        summary = await svc.sync_instance(sess, obj)
        await append_audit(
            sess, actor_user_id=str(actor_user_id), actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="fortigate_firewall", object_id=str(fw_id), action="sync",
            diff={k: str(v) for k, v in summary.items()}, request_id=request_id,
        )
        await sess.commit()
        return summary

    task = await spawn_task(
        session=session, kind="fortigate.sync", target_type="fortigate_firewall",
        target_id=fw_id, target_label=fw_name, actor_user_id=actor_user_id, runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status,
            "queued_at": task.queued_at.isoformat()}


# ─────────────────── 唯讀檢視（政策 / 位址物件）───────────────────
@view_router.get("/{fw_id}/policies")
async def list_policies(
    fw_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    vdom: str | None = Query(None),
) -> dict[str, Any]:
    stmt = select(FortiGatePolicy).where(FortiGatePolicy.firewall_id == fw_id)
    if vdom:
        stmt = stmt.where(FortiGatePolicy.vdom == vdom)
    rows = (await session.execute(stmt.order_by(
        FortiGatePolicy.vdom, FortiGatePolicy.policyid))).scalars().all()
    return {"items": [{
        "id": str(r.id), "vdom": r.vdom, "policyid": r.policyid, "name": r.name,
        "status": r.status, "action": r.action, "srcintf": r.srcintf, "dstintf": r.dstintf,
        "srcaddr": r.srcaddr, "dstaddr": r.dstaddr, "service": r.service,
        "nat": r.nat, "comments": r.comments,
    } for r in rows]}


@view_router.get("/{fw_id}/addresses")
async def list_addresses(
    fw_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    vdom: str | None = Query(None),
) -> dict[str, Any]:
    stmt = select(FortiGateAddressObject).where(FortiGateAddressObject.firewall_id == fw_id)
    if vdom:
        stmt = stmt.where(FortiGateAddressObject.vdom == vdom)
    rows = (await session.execute(stmt.order_by(
        FortiGateAddressObject.vdom, FortiGateAddressObject.name))).scalars().all()
    return {"items": [{
        "id": str(r.id), "vdom": r.vdom, "name": r.name, "kind": r.kind,
        "obj_type": r.obj_type, "value": r.value, "members": r.members, "comment": r.comment,
    } for r in rows]}
