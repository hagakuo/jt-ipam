"""RustDesk Server（開源版）endpoints（admin only）。

jt-ipam 不連過去：RustDesk 主機上裝專用的 RustDesk 代理（agent/jt_ipam_rustdesk_agent.py），代理用這台伺服器
自己的金鑰每幾秒輪詢一次，照回報間隔讀 hbbs 的資料庫、查線上狀態送回，並收客戶端回報（見 rustdesk_agent.py）。
這裡管設定與代理金鑰、「立即同步」「測試」（設旗標，代理下次輪詢取走）、顯示回報狀態、裝置清單與連線稽核，
以及「刪除舊註冊」（排入請求，代理下次輪詢取走、在 RustDesk 主機上刪；網頁與主機兩邊都要允許）。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.sqlin import in_values
from app.core.ui_error import ui_detail
from app.models.address import IPAddress
from app.models.rustdesk import RustDeskAuditEvent, RustDeskPeer, RustDeskPeerDelete, RustDeskServer
from app.models.user import User
from app.schemas.base import Paginated
from app.schemas.rustdesk import (
    RustDeskAuditRead,
    RustDeskPeerDeleteIn,
    RustDeskPeerDeleteQueued,
    RustDeskPeerDeleteRead,
    RustDeskPeerRead,
    RustDeskServerCreate,
    RustDeskServerCreated,
    RustDeskServerRead,
    RustDeskServerUpdate,
    RustDeskTestState,
)
from app.services import rustdesk as rustdesk_svc

router = APIRouter(prefix="/rustdesk", tags=["rustdesk"], dependencies=[Depends(require_admin)])


def _meta(request: Request) -> dict[str, Any]:
    return {"actor_ip": request.client.host if request.client else None,
            "actor_user_agent": request.headers.get("user-agent"),
            "request_id": getattr(request.state, "request_id", None)}


def _read(inst: RustDeskServer) -> RustDeskServerRead:
    out = RustDeskServerRead.model_validate(inst)
    out.has_agent_key = bool(inst.agent_key_hash)
    out.agent_latest_version = rustdesk_svc.agent_latest_version()
    out.agent_poll_seconds = rustdesk_svc.AGENT_POLL_SECONDS
    out.agent_online = _agent_online(inst)
    return out


async def _or_404(session: AsyncSession, sid: uuid.UUID) -> RustDeskServer:
    inst = await session.get(RustDeskServer, sid)
    if inst is None:
        raise HTTPException(404, detail="Not found")
    return inst


async def _audit(session: AsyncSession, user: Any, request: Request, inst: RustDeskServer, action: str,
                 diff: dict[str, Any] | None = None) -> None:
    await append_audit(session, actor_user_id=str(user.id), object_type="rustdesk_server",
                       object_id=str(inst.id), action=action, diff={"name": inst.name, **(diff or {})},
                       **_meta(request))


@router.get("/servers", response_model=Paginated[RustDeskServerRead])
async def list_servers(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[RustDeskServerRead]:
    rows = list((await session.execute(select(RustDeskServer).order_by(RustDeskServer.name)
                                       .offset((page - 1) * page_size).limit(page_size))).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(RustDeskServer)) or 0)
    items = [_read(r) for r in rows]
    if items:
        bad = dict((await session.execute(
            select(RustDeskPeer.server_id, func.count()).where(
                in_values(RustDeskPeer.server_id, [r.id for r in rows]), rustdesk_svc.key_problem_clause())
            .group_by(RustDeskPeer.server_id))).all())
        for it in items:
            it.key_problems = int(bad.get(it.id, 0))
    return Paginated[RustDeskServerRead](items=items, total=total, page=page, page_size=page_size)


@router.post("/servers", response_model=RustDeskServerCreated, status_code=status.HTTP_201_CREATED)
async def create_server(
    payload: RustDeskServerCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RustDeskServerCreated:
    """新增時順便產生這台伺服器專用代理的金鑰，只在這個回應裡出現一次明文（之後要看走 agent-key）。"""
    inst = RustDeskServer(**payload.model_dump())
    session.add(inst)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    raw = rustdesk_svc.new_agent_key()
    await rustdesk_svc.save_agent_key(session, inst, raw)
    await _audit(session, user, request, inst, "create", {"client_address": inst.client_address})
    await session.commit()
    await session.refresh(inst)
    return RustDeskServerCreated(**_read(inst).model_dump(), agent_key=raw)


@router.patch("/servers/{server_id}", response_model=RustDeskServerRead)
async def update_server(
    server_id: uuid.UUID, payload: RustDeskServerUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RustDeskServerRead:
    inst = await _or_404(session, server_id)
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(inst, k, v)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    if data.get("allow_peer_delete") is False:
        # 關掉「刪除舊註冊」：還在等的請求一併取消，不可以等之後重新打開時才被執行
        n = await rustdesk_svc.cancel_pending_deletes(session, inst.id, "cancelled: delete was turned off for this server")
        if n:
            data = {**data, "cancelled_peer_deletes": n}
    await _audit(session, user, request, inst, "update", data)
    await session.commit()
    await session.refresh(inst)
    return _read(inst)


@router.delete("/servers/{server_id}", status_code=204)
async def delete_server(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    inst = await _or_404(session, server_id)
    # 裝置清單、對應與連線稽核（rustdesk_peers／rustdesk_audit_events）隨 ON DELETE CASCADE 一起刪；
    # 代理金鑰一起刪 → 那台主機上的代理之後每次輪詢都會被拒（401）
    await _audit(session, user, request, inst, "delete")
    await rustdesk_svc.delete_agent_key(session, server_id)
    # 它回報給 IP 記錄的主機名稱一併收回（主機名稱多來源機制）
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="rustdesk", source_id=inst.id)
    await session.delete(inst)
    await session.commit()


@router.post("/servers/{server_id}/rotate-agent-key", response_model=RustDeskServerCreated)
async def rotate_agent_key(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RustDeskServerCreated:
    """換一把新金鑰：舊金鑰立刻失效，裝著舊金鑰的代理要用新的安裝指令重裝。"""
    inst = await _or_404(session, server_id)
    raw = rustdesk_svc.new_agent_key()
    await rustdesk_svc.save_agent_key(session, inst, raw)
    await _audit(session, user, request, inst, "rotate_agent_key")
    await session.commit()
    await session.refresh(inst)
    return RustDeskServerCreated(**_read(inst).model_dump(), agent_key=raw)


@router.get("/servers/{server_id}/agent-key")
async def get_agent_key(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """再看一次代理金鑰（組安裝指令用）。看到金鑰的人就能冒充這台代理送資料，所以每次都留稽核。"""
    inst = await _or_404(session, server_id)
    raw = await rustdesk_svc.load_agent_key(session, server_id)
    if raw is None:
        raise HTTPException(404, detail=ui_detail("rustdesk_no_agent_key", "這台伺服器沒有保存代理金鑰，請換一把新的"))
    await _audit(session, user, request, inst, "view_agent_key")
    await session.commit()
    return {"agent_key": raw}


@router.post("/servers/{server_id}/sync-now", status_code=202)
async def sync_now(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """立即同步：設旗標，代理下次輪詢（最多 AGENT_POLL_SECONDS 秒）取走後馬上讀一次資料庫回報。"""
    inst = await _or_404(session, server_id)
    if not inst.enabled:
        raise HTTPException(409, detail=ui_detail("rustdesk_server_disabled", "這台 RustDesk 伺服器已停用"))
    inst.force_report_at = datetime.now(UTC)
    await _audit(session, user, request, inst, "sync_now")
    await session.commit()
    return {"queued": True, "eta_seconds": rustdesk_svc.AGENT_POLL_SECONDS,
            "agent_online": _agent_online(inst)}


def _agent_online(inst: RustDeskServer) -> bool:
    return (inst.agent_last_seen_at is not None
            and datetime.now(UTC) - inst.agent_last_seen_at <= rustdesk_svc.AGENT_OFFLINE_AFTER)


def _test_state(inst: RustDeskServer) -> RustDeskTestState:
    res = inst.test_result or {}
    return RustDeskTestState(
        test_id=inst.test_id, requested_at=inst.test_requested_at, result_at=inst.test_result_at,
        checks=res.get("checks") or [] if inst.test_result_at else [],
        agent_last_seen_at=inst.agent_last_seen_at)


@router.post("/servers/{server_id}/test", response_model=RustDeskTestState, status_code=202)
async def start_test(
    server_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RustDeskTestState:
    """測試：請代理在 RustDesk 主機上逐項檢查（資料庫、公鑰、線上狀態查詢、客戶端回報接收端）。
    結果由代理下次輪詢後送回，畫面用 GET 同一個網址等結果。"""
    inst = await _or_404(session, server_id)
    inst.test_id = str(uuid.uuid4())
    inst.test_requested_at = datetime.now(UTC)
    inst.test_result_at = None
    inst.test_result = None
    await _audit(session, user, request, inst, "test")
    await session.commit()
    await session.refresh(inst)
    return _test_state(inst)


@router.get("/servers/{server_id}/test", response_model=RustDeskTestState)
async def get_test(
    server_id: uuid.UUID, session: Annotated[AsyncSession, Depends(get_session)],
) -> RustDeskTestState:
    return _test_state(await _or_404(session, server_id))


@router.get("/servers/{server_id}/peers", response_model=Paginated[RustDeskPeerRead])
async def list_peers(
    server_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    q: Annotated[str | None, Query(max_length=100)] = None,
    online: bool | None = None,
    never_online: bool | None = None,
    match_status: Annotated[str | None, Query(max_length=16)] = None,
    key_problem: bool | None = None,
    sort: Annotated[str | None, Query(pattern=_PEER_SORT_PATTERN)] = None,
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "asc",
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[RustDeskPeerRead]:
    """伺服器端分頁、搜尋與排序（裝置可能上萬台；只排畫面上這一頁沒有意義）。"""
    await _or_404(session, server_id)
    cand = aliased(IPAddress)
    conds: list[Any] = [RustDeskPeer.server_id == server_id]
    if online is not None:
        conds.append(RustDeskPeer.online.is_(online))
    if never_online:
        # jt-ipam 從沒看過它上線（「刪除舊註冊」最常挑的那一群：重灌、換電腦、測試機留下的 ID）
        conds.extend([RustDeskPeer.online.is_(False), RustDeskPeer.last_online_at.is_(None)])
    if match_status:
        conds.append(RustDeskPeer.match_status == match_status)
    if key_problem is not None:
        clause = rustdesk_svc.key_problem_clause()
        conds.append(clause if key_problem else ~clause)
    if q and q.strip():
        like = f"%{q.strip()}%"
        conds.append(or_(RustDeskPeer.rustdesk_id.ilike(like),
                         func.host(RustDeskPeer.registered_ip).ilike(like),
                         func.host(RustDeskPeer.report_ip).ilike(like),
                         RustDeskPeer.hostname.ilike(like),
                         RustDeskPeer.username.ilike(like),
                         IPAddress.hostname.ilike(like)))
    base = (select(RustDeskPeer, IPAddress.ip, IPAddress.hostname, IPAddress.subnet_id, cand.ip, cand.hostname,
                   IPAddress.device_kind, IPAddress.device_model)
            .outerjoin(IPAddress, IPAddress.id == RustDeskPeer.address_id)
            .outerjoin(cand, cand.id == RustDeskPeer.candidate_address_id).where(*conds))
    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    if sort:
        ordering = [*_sorted(_peer_sort_cols(sort), order), *_natural(RustDeskPeer.rustdesk_id)]
    else:
        ordering = [RustDeskPeer.online.desc(), RustDeskPeer.last_online_at.desc().nulls_last(),
                    *_natural(RustDeskPeer.rustdesk_id)]
    rows = (await session.execute(
        base.order_by(*ordering).offset((page - 1) * page_size).limit(page_size))).all()
    items = [RustDeskPeerRead(
        id=p.id, rustdesk_id=p.rustdesk_id,
        registered_ip=_ip(p.registered_ip), first_registered_at=p.first_registered_at, online=p.online,
        last_online_at=p.last_online_at, match_status=p.match_status, address_id=p.address_id,
        address_ip=_ip(ip), address_hostname=hostname, subnet_id=subnet_id,
        address_device_kind=dkind, address_device_model=dmodel,
        match_evidence=p.match_evidence, candidate_address_id=p.candidate_address_id,
        candidate_ip=_ip(cip), candidate_hostname=chost,
        hostname=p.hostname, os_name=p.os_name, username=p.username, client_version=p.client_version,
        last_heartbeat_at=p.last_heartbeat_at, active_conns=p.active_conns, report_ip=_ip(p.report_ip),
        key_problem=rustdesk_svc.key_problem(p),
    ) for p, ip, hostname, subnet_id, cip, chost, dkind, dmodel in rows]
    return Paginated[RustDeskPeerRead](items=items, total=total, page=page, page_size=page_size)


def _ip(v: Any) -> str | None:
    return str(v).split("/")[0] if v else None


# ── 欄位排序（只收允許清單；沒有值的一律排最後，升冪降冪都一樣）──

def _natural(col: Any) -> list[Any]:
    """RustDesk ID 多半是數字：先比長度再比字串＝照數字大小排（999999999 在 1000000001 前面）。"""
    return [func.length(col), col]


def _sorted(cols: list[Any], order: str) -> list[Any]:
    return [c.desc().nulls_last() if order == "desc" else c.asc().nulls_last() for c in cols]


_PEER_SORT_KEYS = ("rustdesk_id", "online", "last_online_at", "last_heartbeat_at", "first_registered_at", "hostname",
                   "username", "os_name", "client_version", "registered_ip", "report_ip", "address_ip",
                   "address_hostname", "address_device_kind", "match_status")
_PEER_SORT_PATTERN = "^(" + "|".join(_PEER_SORT_KEYS) + ")$"


def _peer_sort_cols(key: str) -> list[Any]:
    if key == "rustdesk_id":
        return _natural(RustDeskPeer.rustdesk_id)
    if key == "address_ip":
        return [IPAddress.ip]
    if key == "address_hostname":
        return [func.lower(IPAddress.hostname)]
    if key == "address_device_kind":
        return [IPAddress.device_kind]
    col = getattr(RustDeskPeer, key)
    return [func.lower(col)] if key in ("hostname", "username", "os_name") else [col]


_AUDIT_SORT_KEYS = ("occurred_at", "kind", "rustdesk_id", "device_hostname", "device_ip", "peer_id", "peer_name",
                    "ip", "verified")
_AUDIT_SORT_PATTERN = "^(" + "|".join(_AUDIT_SORT_KEYS) + ")$"


def _audit_sort_cols(key: str) -> list[Any]:
    E = RustDeskAuditEvent
    if key in ("rustdesk_id", "peer_id"):
        return _natural(getattr(E, key))
    if key == "device_hostname":
        return [func.lower(func.coalesce(RustDeskPeer.hostname, IPAddress.hostname))]
    if key == "device_ip":
        return [IPAddress.ip]
    if key == "peer_name":
        return [func.lower(E.peer_name)]
    return [getattr(E, key)]


@router.get("/servers/{server_id}/audit", response_model=Paginated[RustDeskAuditRead])
async def list_audit(
    server_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    q: Annotated[str | None, Query(max_length=100)] = None,
    kind: Annotated[str | None, Query(pattern="^(conn|file|alarm|note)$")] = None,
    rustdesk_id: Annotated[str | None, Query(max_length=100)] = None,
    since: datetime | None = None,
    sort: Annotated[str | None, Query(pattern=_AUDIT_SORT_PATTERN)] = None,
    order: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[RustDeskAuditRead]:
    """客戶端回報的連線／檔案傳輸／告警／備註，新的在前。受控端對應到的 IP 一起帶。"""
    await _or_404(session, server_id)
    E = RustDeskAuditEvent
    conds: list[Any] = [E.server_id == server_id]
    if kind:
        conds.append(E.kind == kind)
    if rustdesk_id:
        conds.append(E.rustdesk_id == rustdesk_id)
    if since:
        conds.append(E.occurred_at >= since)
    if q and q.strip():
        like = f"%{q.strip()}%"
        conds.append(or_(E.rustdesk_id.ilike(like), E.peer_id.ilike(like), E.peer_name.ilike(like),
                         func.host(E.ip).ilike(like), RustDeskPeer.hostname.ilike(like),
                         IPAddress.hostname.ilike(like)))
    base = (select(E, RustDeskPeer.address_id, IPAddress.ip, IPAddress.hostname, RustDeskPeer.hostname)
            .outerjoin(RustDeskPeer, and_(RustDeskPeer.server_id == E.server_id,
                                          RustDeskPeer.rustdesk_id == E.rustdesk_id))
            .outerjoin(IPAddress, IPAddress.id == RustDeskPeer.address_id).where(*conds))
    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    ordering = [*_sorted(_audit_sort_cols(sort), order)] if sort else []
    rows = (await session.execute(base.order_by(*ordering, E.occurred_at.desc(), E.created_at.desc())
                                  .offset((page - 1) * page_size).limit(page_size))).all()
    items = [RustDeskAuditRead(
        id=e.id, kind=e.kind, action=e.action, rustdesk_id=e.rustdesk_id, peer_id=e.peer_id, peer_name=e.peer_name,
        ip=_ip(e.ip), conn_type=e.conn_type, conn_id=e.conn_id, session_id=e.session_id, alarm_type=e.alarm_type,
        nonce=e.nonce, verified=e.verified, detail=e.detail, src_ip=_ip(e.src_ip), occurred_at=e.occurred_at,
        device_address_id=addr_id, device_ip=_ip(dip), device_hostname=dhost, device_reported_hostname=rhost,
    ) for e, addr_id, dip, dhost, rhost in rows]
    return Paginated[RustDeskAuditRead](items=items, total=total, page=page, page_size=page_size)



# ── 刪除舊註冊（0182）──────────────────────────────────────────────────────────

@router.post("/servers/{server_id}/peers/delete", response_model=RustDeskPeerDeleteQueued, status_code=202)
async def request_peer_delete(
    server_id: uuid.UUID, payload: RustDeskPeerDeleteIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RustDeskPeerDeleteQueued:
    """要求代理從 hbbs 刪掉這些舊註冊。只收這台伺服器的、jt-ipam 看來離線的 ID；整批檢查，有一個不合就整批不收。
    代理下次輪詢取走，刪之前在 RustDesk 主機上再查一次線上狀態（上線中的不刪）。"""
    inst = await _or_404(session, server_id)
    if not inst.enabled:
        raise HTTPException(409, detail=ui_detail("rustdesk_server_disabled", "這台 RustDesk 伺服器已停用"))
    if not inst.allow_peer_delete:
        raise HTTPException(409, detail=ui_detail(
            "rustdesk_peer_delete_off", "這台 RustDesk 伺服器沒有開啟「允許刪除舊註冊」"))
    can, why = rustdesk_svc.delete_capability(inst)
    if not can:
        reason = why or "the agent does not report write access (agent older than 1.2.0, or not connected yet)"
        raise HTTPException(409, detail=ui_detail(
            "rustdesk_peer_delete_agent", f"RustDesk 主機上的代理沒有寫入權限：{reason}", reason=reason))
    ids = list(dict.fromkeys(payload.rustdesk_ids))
    known = dict((await session.execute(select(RustDeskPeer.rustdesk_id, RustDeskPeer.online).where(
        RustDeskPeer.server_id == inst.id, in_values(RustDeskPeer.rustdesk_id, ids)))).all())
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise HTTPException(422, detail=ui_detail(
            "rustdesk_peer_delete_unknown", f"這些 ID 不在這台伺服器的裝置清單裡：{', '.join(unknown[:10])}",
            ids=", ".join(unknown[:10]), count=len(unknown)))
    online = [i for i in ids if known[i]]
    if online:
        raise HTTPException(409, detail=ui_detail(
            "rustdesk_peer_delete_online", f"這些裝置目前上線中，不能刪除：{', '.join(online[:10])}",
            ids=", ".join(online[:10]), count=len(online)))
    await rustdesk_svc.expire_peer_deletes(session, inst.id)
    now = datetime.now(UTC)
    # 已經在等的不重複排：同一個 ID 只會有一筆等待中的（部分唯一索引）；同時按兩次也不會變成 500
    res = await session.execute(
        pg_insert(RustDeskPeerDelete)
        .values([{"id": uuid.uuid4(), "server_id": inst.id, "rustdesk_id": i, "status": "pending",
                  "requested_by": user.id, "requested_at": now} for i in ids])
        .on_conflict_do_nothing(index_elements=["server_id", "rustdesk_id"], index_where=text("status = 'pending'"))
        .returning(RustDeskPeerDelete.rustdesk_id))
    added = set(res.scalars().all())
    todo = [i for i in ids if i in added]
    already = len(ids) - len(todo)
    await _audit(session, user, request, inst, "rustdesk.peer_delete_requested",
                 {"ids": todo, "count": len(todo), "already_pending": already})
    await session.commit()
    return RustDeskPeerDeleteQueued(queued=len(todo), already_pending=already, requested_at=now,
                                    eta_seconds=rustdesk_svc.AGENT_POLL_SECONDS, agent_online=_agent_online(inst))


@router.get("/servers/{server_id}/peer-deletes", response_model=Paginated[RustDeskPeerDeleteRead])
async def list_peer_deletes(
    server_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    status_: Annotated[str | None, Query(alias="status", pattern="^(pending|deleted|skipped_online|not_found|failed|cancelled)$")] = None,
    since: datetime | None = None,
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[RustDeskPeerDeleteRead]:
    """最近的刪除請求與結果，新的在前（畫面用 since＝送出請求的時間等這一批的結果）。"""
    await _or_404(session, server_id)
    if await rustdesk_svc.expire_peer_deletes(session, server_id):
        await session.commit()
    D = RustDeskPeerDelete
    conds: list[Any] = [D.server_id == server_id]
    if status_:
        conds.append(D.status == status_)
    if since:
        conds.append(D.requested_at >= since)
    total = int(await session.scalar(select(func.count()).select_from(D).where(*conds)) or 0)
    rows = (await session.execute(
        select(D, User.username).outerjoin(User, User.id == D.requested_by).where(*conds)
        .order_by(D.requested_at.desc(), *_natural(D.rustdesk_id))
        .offset((page - 1) * page_size).limit(page_size))).all()
    items = [RustDeskPeerDeleteRead(
        id=d.id, rustdesk_id=d.rustdesk_id, status=d.status, detail=d.detail, requested_by=d.requested_by,
        requested_by_name=uname, requested_at=d.requested_at, finished_at=d.finished_at) for d, uname in rows]
    return Paginated[RustDeskPeerDeleteRead](items=items, total=total, page=page, page_size=page_size)
