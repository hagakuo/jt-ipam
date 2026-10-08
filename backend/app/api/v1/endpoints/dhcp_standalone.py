"""獨立 DHCP 伺服器 endpoints（issue #45，admin only）：Kea 與 ISC DHCP。

- Kea（/kea-dhcp）：比照 Windows DHCP —— 設定、測試連線、手動拉取（背景作業）、排程同步
- ISC DHCP（/isc-dhcp）：沒有連線可測、也不由 jt-ipam 拉；指定一台裝在 DHCP 主機上的掃描代理，
  代理照回報間隔讀檔送回（見 scan_agents 的 dhcpd-report）。這裡只管設定與顯示回報狀態
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import detail_of, ui_detail
from app.models.dhcp_standalone import IscDhcpServer, KeaDhcpServer
from app.models.scan_agent import ScanAgent
from app.schemas.base import Paginated
from app.schemas.dhcp_standalone import (
    IscDhcpCreate,
    IscDhcpRead,
    IscDhcpUpdate,
    KeaDhcpCreate,
    KeaDhcpRead,
    KeaDhcpUpdate,
)
from app.services import kea_dhcp as kea
from app.services.background_tasks import spawn_task

kea_router = APIRouter(prefix="/kea-dhcp", tags=["kea-dhcp"], dependencies=[Depends(require_admin)])
isc_router = APIRouter(prefix="/isc-dhcp", tags=["isc-dhcp"], dependencies=[Depends(require_admin)])


def _meta(request: Request) -> dict[str, Any]:
    return {"actor_ip": request.client.host if request.client else None,
            "actor_user_agent": request.headers.get("user-agent"),
            "request_id": getattr(request.state, "request_id", None)}


# ── Kea ──────────────────────────────────────────────────────────────────────

def _kea_read(inst: KeaDhcpServer) -> KeaDhcpRead:
    out = KeaDhcpRead.model_validate(inst)
    out.has_password = bool(inst.password_enc)
    return out


async def _kea_or_404(session: AsyncSession, sid: uuid.UUID) -> KeaDhcpServer:
    inst = await session.get(KeaDhcpServer, sid)
    if inst is None:
        raise HTTPException(404, detail="Not found")
    return inst


@kea_router.get("/servers", response_model=Paginated[KeaDhcpRead])
async def list_kea(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[KeaDhcpRead]:
    rows = list((await session.execute(select(KeaDhcpServer).order_by(KeaDhcpServer.name)
                                       .offset((page - 1) * page_size).limit(page_size))).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(KeaDhcpServer)) or 0)
    return Paginated[KeaDhcpRead](items=[_kea_read(r) for r in rows], total=total, page=page,
                                  page_size=page_size)


@kea_router.post("/servers", response_model=KeaDhcpRead, status_code=status.HTTP_201_CREATED)
async def create_kea(
    payload: KeaDhcpCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> KeaDhcpRead:
    inst = KeaDhcpServer(**payload.model_dump(exclude={"password"}))
    session.add(inst)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    if payload.password:
        inst.password_enc, inst.password_nonce = kea.encrypt_password(inst.id, payload.password)
    await append_audit(session, actor_user_id=str(user.id), object_type="kea_dhcp_server",
                       object_id=str(inst.id), action="create",
                       diff={"name": inst.name, "api_url": inst.api_url}, **_meta(request))
    await session.commit()
    await session.refresh(inst)
    return _kea_read(inst)


@kea_router.patch("/servers/{server_id}", response_model=KeaDhcpRead)
async def update_kea(
    server_id: uuid.UUID, payload: KeaDhcpUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> KeaDhcpRead:
    inst = await _kea_or_404(session, server_id)
    data = payload.model_dump(exclude_unset=True)
    new_password = data.pop("password", None)
    for k, v in data.items():
        setattr(inst, k, v)
    if new_password:
        inst.password_enc, inst.password_nonce = kea.encrypt_password(inst.id, new_password)
    if "username" in data and not data["username"]:
        # 拿掉帳號＝不用 HTTP 認證，密碼一起清掉（留著也不會被送出，但不該留在資料庫）
        inst.password_enc = inst.password_nonce = None
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    await append_audit(session, actor_user_id=str(user.id), object_type="kea_dhcp_server",
                       object_id=str(inst.id), action="update",
                       diff={**data, **({"password": "changed"} if new_password else {})}, **_meta(request))
    await session.commit()
    await session.refresh(inst)
    return _kea_read(inst)


@kea_router.delete("/servers/{server_id}", status_code=204)
async def delete_kea(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    inst = await _kea_or_404(session, server_id)
    # 它寫進共用表的範圍／保留／租約／主機名稱一併收回（沒有外鍵會跟著刪）
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="kea_dhcp", source_id=inst.id)
    await session.delete(inst)
    await append_audit(session, actor_user_id=str(user.id), object_type="kea_dhcp_server",
                       object_id=str(server_id), action="delete", diff={}, **_meta(request))
    await session.commit()


@kea_router.post("/servers/{server_id}/test")
async def test_kea(
    server_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    inst = await _kea_or_404(session, server_id)
    try:
        return await kea.healthcheck(inst)
    except kea.KeaError as exc:
        raise HTTPException(502, detail=detail_of(exc, "kea_dhcp_error")) from exc


@kea_router.post("/servers/{server_id}/sync")
async def sync_kea(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """非同步 —— 立刻回 task_id，同步在背景跑（作業頁看得到）。"""
    inst = await _kea_or_404(session, server_id)
    actor_user_id, inst_name, meta = user.id, inst.name, _meta(request)

    async def _runner(sess: AsyncSession, _task: Any) -> dict[str, Any]:
        obj = await sess.get(KeaDhcpServer, server_id)
        if obj is None:
            raise RuntimeError("Kea DHCP server disappeared")
        summary = await kea.sync_instance(sess, obj)
        await append_audit(sess, actor_user_id=str(actor_user_id), object_type="kea_dhcp_server",
                           object_id=str(server_id), action="sync", diff=summary, **meta)
        await sess.commit()
        return summary

    task = await spawn_task(session=session, kind="kea_dhcp.sync", target_type="kea_dhcp_server",
                            target_id=server_id, target_label=inst_name, actor_user_id=actor_user_id,
                            runner=_runner)
    return {"task_id": str(task.id), "status": task.status, "queued_at": task.queued_at.isoformat()}


# ── ISC DHCP ─────────────────────────────────────────────────────────────────

async def _isc_read(session: AsyncSession, inst: IscDhcpServer) -> IscDhcpRead:
    out = IscDhcpRead.model_validate(inst)
    if inst.agent_id:
        agent = await session.get(ScanAgent, inst.agent_id)
        if agent is not None:
            out.agent_name, out.agent_version = agent.name, agent.agent_version
            out.agent_last_seen_at = agent.last_seen_at
    return out


async def _isc_or_404(session: AsyncSession, sid: uuid.UUID) -> IscDhcpServer:
    inst = await session.get(IscDhcpServer, sid)
    if inst is None:
        raise HTTPException(404, detail="Not found")
    return inst


async def _check_agent(session: AsyncSession, agent_id: uuid.UUID | None, self_id: uuid.UUID | None) -> None:
    if agent_id is None:
        return
    if await session.get(ScanAgent, agent_id) is None:
        raise HTTPException(422, detail=ui_detail("isc_dhcp_agent_missing", "找不到這台掃描代理"))
    stmt = select(IscDhcpServer.name).where(IscDhcpServer.agent_id == agent_id)
    if self_id is not None:
        stmt = stmt.where(IscDhcpServer.id != self_id)
    taken = (await session.execute(stmt)).scalar()
    if taken:
        raise HTTPException(409, detail=ui_detail(
            "isc_dhcp_agent_taken", "這台掃描代理已經指派給另一個 ISC DHCP 來源", name=taken))


@isc_router.get("/servers", response_model=Paginated[IscDhcpRead])
async def list_isc(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[IscDhcpRead]:
    rows = list((await session.execute(select(IscDhcpServer).order_by(IscDhcpServer.name)
                                       .offset((page - 1) * page_size).limit(page_size))).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(IscDhcpServer)) or 0)
    return Paginated[IscDhcpRead](items=[await _isc_read(session, r) for r in rows], total=total,
                                  page=page, page_size=page_size)


@isc_router.post("/servers", response_model=IscDhcpRead, status_code=status.HTTP_201_CREATED)
async def create_isc(
    payload: IscDhcpCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IscDhcpRead:
    await _check_agent(session, payload.agent_id, None)
    inst = IscDhcpServer(**payload.model_dump())
    session.add(inst)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    await append_audit(session, actor_user_id=str(user.id), object_type="isc_dhcp_server",
                       object_id=str(inst.id), action="create",
                       diff={"name": inst.name, "agent_id": str(inst.agent_id) if inst.agent_id else None},
                       **_meta(request))
    await session.commit()
    await session.refresh(inst)
    return await _isc_read(session, inst)


@isc_router.patch("/servers/{server_id}", response_model=IscDhcpRead)
async def update_isc(
    server_id: uuid.UUID, payload: IscDhcpUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IscDhcpRead:
    inst = await _isc_or_404(session, server_id)
    data = payload.model_dump(exclude_unset=True)
    if "agent_id" in data:
        await _check_agent(session, data["agent_id"], inst.id)
    for k, v in data.items():
        setattr(inst, k, v)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    await append_audit(session, actor_user_id=str(user.id), object_type="isc_dhcp_server",
                       object_id=str(inst.id), action="update",
                       diff={k: (str(v) if isinstance(v, uuid.UUID) else v) for k, v in data.items()},
                       **_meta(request))
    await session.commit()
    await session.refresh(inst)
    return await _isc_read(session, inst)


@isc_router.delete("/servers/{server_id}", status_code=204)
async def delete_isc(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    inst = await _isc_or_404(session, server_id)
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="isc_dhcp", source_id=inst.id)
    await session.delete(inst)
    await append_audit(session, actor_user_id=str(user.id), object_type="isc_dhcp_server",
                       object_id=str(server_id), action="delete", diff={}, **_meta(request))
    await session.commit()
