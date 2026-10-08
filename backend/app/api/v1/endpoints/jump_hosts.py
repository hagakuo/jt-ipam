"""跳板主機 endpoints（issue #24 階段一，admin only）。

主控台**使用**跳板不另設權限：沿用主控台既有的 deny-by-default 可見性判定 ——
看不到那筆 IP 的人本來就連不了它，經不經跳板都一樣。這裡管的是「誰能設定跳板」。

`/test` 是有意義的第一步：未釘選主機金鑰前，它**只取指紋、不送帳密**。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import ui_detail
from app.models.address import IPAddress
from app.models.jump_host import JumpHost
from app.models.subnet import Subnet
from app.schemas.base import Paginated
from app.schemas.jump_host import JumpHostCreate, JumpHostRead, JumpHostUpdate
from app.services import console_route

router = APIRouter(prefix="/jump-hosts", tags=["jump-hosts"],
                   dependencies=[Depends(require_admin)])


def _read(obj: JumpHost) -> JumpHostRead:
    m = JumpHostRead.model_validate(obj)
    m.has_secret = bool(obj.private_key_enc if obj.auth_kind == "key" else obj.password_enc)
    return m


async def _get_or_404(session: AsyncSession, jump_id: uuid.UUID) -> JumpHost:
    obj = await session.get(JumpHost, jump_id)
    if obj is None:
        raise HTTPException(404, detail="Not found")
    return obj


def _store_secret(obj: JumpHost, *, private_key: str | None, password: str | None) -> None:
    """把機密寫進去。**只覆寫這次真的有給的那一種**，避免編輯時把另一種清成空的。"""
    if private_key:
        obj.private_key_enc, obj.private_key_nonce = console_route.encrypt_secret_for(
            obj.id, "private_key", private_key)
    if password:
        obj.password_enc, obj.password_nonce = console_route.encrypt_secret_for(
            obj.id, "password", password)


@router.get("", response_model=Paginated[JumpHostRead])
async def list_jump_hosts(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[JumpHostRead]:
    stmt = (select(JumpHost).order_by(JumpHost.name)
            .offset((page - 1) * page_size).limit(page_size))
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(JumpHost)) or 0)
    return Paginated[JumpHostRead](items=[_read(r) for r in rows], total=total,
                                   page=page, page_size=page_size)


@router.post("", response_model=JumpHostRead, status_code=status.HTTP_201_CREATED)
async def create_jump_host(
    payload: JumpHostCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JumpHostRead:
    data = payload.model_dump(exclude={"private_key", "password"})
    obj = JumpHost(**data)
    session.add(obj)
    try:
        await session.flush()      # 先拿 id：機密的 AAD 綁 id
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    _store_secret(obj, private_key=payload.private_key, password=payload.password)
    await session.flush()
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="jump_host", object_id=str(obj.id), action="create",
        diff={"name": obj.name, "host": obj.host, "port": str(obj.port),
              "username": obj.username, "auth_kind": obj.auth_kind},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return _read(obj)


@router.patch("/{jump_id}", response_model=JumpHostRead)
async def update_jump_host(
    jump_id: uuid.UUID, payload: JumpHostUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JumpHostRead:
    obj = await _get_or_404(session, jump_id)
    data = payload.model_dump(exclude_unset=True)
    private_key = data.pop("private_key", None)
    password = data.pop("password", None)
    for k, v in data.items():
        setattr(obj, k, v)
    _store_secret(obj, private_key=private_key, password=password)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="jump_host", object_id=str(obj.id), action="update",
        # 機密不入稽核；只記「這次有沒有換過」
        diff={**{k: str(v) for k, v in data.items()},
              "private_key_changed": str(bool(private_key)),
              "password_changed": str(bool(password))},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return _read(obj)


@router.delete("/{jump_id}", status_code=204)
async def delete_jump_host(
    jump_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    obj = await _get_or_404(session, jump_id)
    # 資料庫的 FK 是 ON DELETE SET NULL，但那會**安靜地**把一批子網路改回直連 ——
    # 而「直連」在網段重疊的站台等於連到別人。所以先數出來、寫進稽核。
    used_subnets = int(await session.scalar(
        select(func.count()).select_from(Subnet).where(Subnet.jump_host_id == jump_id)) or 0)
    used_ips = int(await session.scalar(
        select(func.count()).select_from(IPAddress).where(IPAddress.jump_host_id == jump_id)) or 0)
    await session.execute(update(Subnet).where(Subnet.jump_host_id == jump_id)
                          .values(jump_host_id=None))
    await session.execute(update(IPAddress).where(IPAddress.jump_host_id == jump_id)
                          .values(jump_host_id=None))
    await session.delete(obj)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="jump_host", object_id=str(jump_id), action="delete",
        diff={"name": obj.name, "detached_subnets": str(used_subnets),
              "detached_ips": str(used_ips)},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.get("/{jump_id}/usage")
async def jump_host_usage(
    jump_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """哪些子網路／IP 正指向這台跳板（刪除前的確認用）。"""
    await _get_or_404(session, jump_id)
    subnets = (await session.execute(
        select(Subnet.id, Subnet.cidr).where(Subnet.jump_host_id == jump_id).limit(200))).all()
    ips = (await session.execute(
        select(IPAddress.id, IPAddress.ip).where(
            IPAddress.jump_host_id == jump_id).limit(200))).all()
    return {
        "subnets": [{"id": str(r[0]), "cidr": str(r[1])} for r in subnets],
        "ips": [{"id": str(r[0]), "ip": str(r[1])} for r in ips],
    }


@router.post("/{jump_id}/test")
async def test_jump_host(
    jump_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """測試連線：回報可達性與主機金鑰指紋；已釘選時才會實際登入。"""
    obj = await _get_or_404(session, jump_id)
    try:
        out = await console_route.probe(obj)
    except console_route.JumpHostError as exc:
        obj.last_error = str(exc)[:500]
        await session.commit()
        raise HTTPException(502, detail=ui_detail(
            getattr(exc, "code", None) or "jump_host_unreachable", str(exc),
            **(getattr(exc, "params", {}) or {}))) from exc
    if out.get("authenticated"):
        obj.last_ok_at = func.now()
        obj.last_error = None
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="jump_host", object_id=str(jump_id), action="test",
        diff={"fingerprint": str(out.get("fingerprint")),
              "authenticated": str(out.get("authenticated"))},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return out
