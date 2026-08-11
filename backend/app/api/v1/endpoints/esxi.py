"""ESXi / vCenter 整合 endpoints（Beta，僅管理員）。

`/test` 走「連線診斷」—— 逐步回報 RetrieveServiceContent / Login / RetrievePropertiesEx
通不通與筆數。沒有實機時這是唯一能看出卡在哪一步的方式，接上真機後也是對齊欄位的起點。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.models.esxi import ESXiInstance
from app.schemas.esxi import ESXiCreate, ESXiRead, ESXiUpdate
from app.services import esxi as svc

router = APIRouter(prefix="/esxi", tags=["esxi"], dependencies=[Depends(require_admin)])


async def _get_or_404(session: AsyncSession, iid: uuid.UUID) -> ESXiInstance:
    inst = await session.get(ESXiInstance, iid)
    if inst is None:
        raise HTTPException(404, detail="Not found")
    return inst


@router.get("", response_model=list[ESXiRead])
async def list_instances(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    return (await session.execute(
        select(ESXiInstance).order_by(ESXiInstance.name)
    )).scalars().all()


@router.post("", response_model=ESXiRead, status_code=201)
async def create_instance(
    payload: ESXiCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    inst = ESXiInstance(
        name=payload.name, api_url=str(payload.api_url).rstrip("/"),
        extra_api_urls=payload.extra_api_urls or None,
        username=payload.username, enabled=payload.enabled,
        verify_tls=payload.verify_tls,
        sync_interval_seconds=payload.sync_interval_seconds,
        scope_subnet_ids=payload.scope_subnet_ids,
        description=payload.description,
        password_enc=b"placeholder", password_nonce=b"placeholder",
    )
    session.add(inst)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="name already exists") from exc
    enc, nonce = svc.encrypt_password(inst.id, payload.password)
    inst.password_enc, inst.password_nonce = enc, nonce
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="esxi_instance", object_id=str(inst.id), action="create",
        diff={"name": inst.name}, request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(inst)
    return inst


@router.patch("/{instance_id}", response_model=ESXiRead)
async def update_instance(
    instance_id: uuid.UUID, payload: ESXiUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    inst = await _get_or_404(session, instance_id)
    data = payload.model_dump(exclude_unset=True)
    new_pwd = data.pop("password", None)
    for k, v in data.items():
        if k == "api_url" and v is not None:
            v = str(v).rstrip("/")
        # 清空備援位址存 NULL，與建立時的 `or None` 一致 —— 存成空字串會讓
        # 「有沒有設過」在資料層變得模稜兩可
        if k == "extra_api_urls":
            v = v or None
        setattr(inst, k, v)
    if new_pwd:
        enc, nonce = svc.encrypt_password(inst.id, new_pwd)
        inst.password_enc, inst.password_nonce = enc, nonce
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="esxi_instance", object_id=str(inst.id), action="update",
        diff={k: str(v)[:120] for k, v in data.items()},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(inst)
    return inst


@router.delete("/{instance_id}", status_code=204)
async def delete_instance(
    instance_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    inst = await _get_or_404(session, instance_id)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="esxi_instance", object_id=str(inst.id), action="delete",
        diff={"name": inst.name}, request_id=getattr(request.state, "request_id", None),
    )
    await session.delete(inst)
    await session.commit()


@router.post("/{instance_id}/test")
# 函式名不用 test_ 開頭：ruff 的 pytest 規則會把它誤認成測試（路由路徑仍是 /test）
async def check_connection(
    instance_id: uuid.UUID, _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """逐步診斷，而不是只回「成功／失敗」—— 卡在哪一步才是使用者要知道的。"""
    inst = await _get_or_404(session, instance_id)
    steps = await svc.diagnose(inst)
    return {"ok": all(s["ok"] for s in steps), "steps": steps}


@router.post("/{instance_id}/sync")
async def sync_now(
    instance_id: uuid.UUID, _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    inst = await _get_or_404(session, instance_id)
    try:
        out = await svc.sync_instance(session, inst)
    except svc.ESXiError as exc:
        await session.rollback()
        inst = await _get_or_404(session, instance_id)
        inst.last_error = str(exc)[:2000]
        await session.commit()
        raise HTTPException(502, detail=str(exc)) from exc
    await session.commit()
    return out
