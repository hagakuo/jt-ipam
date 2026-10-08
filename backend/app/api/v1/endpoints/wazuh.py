"""Wazuh 整合 endpoints。

CRUD WazuhInstance + 同步 + agents 列表 + missing-agent 偵測（A09 提供
給 SOC：「應該裝 agent 卻沒裝」的清單）。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import detail_of
from app.models.address import IPAddress
from app.models.wazuh import WazuhAgent, WazuhInstance
from app.schemas.base import Paginated
from app.schemas.wazuh import (
    MissingAgentPage,
    MissingAgentRow,
    WazuhAgentRead,
    WazuhInstanceCreate,
    WazuhInstanceRead,
    WazuhInstanceUpdate,
)
from app.services import wazuh as wazuh_service

router = APIRouter(
    prefix="/wazuh",
    tags=["wazuh"],
    dependencies=[Depends(require_admin)],
)


# ─────────────────── Instance CRUD ───────────────────


@router.get("/instances", response_model=Paginated[WazuhInstanceRead])
async def list_instances(
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    total = (
        await session.execute(select(func.count()).select_from(WazuhInstance))
    ).scalar_one()
    rows = (
        await session.execute(
            select(WazuhInstance).order_by(WazuhInstance.created_at.desc())
            .offset(offset).limit(limit)
        )
    ).scalars().all()
    return {"items": rows, "total": total, "page": offset // limit + 1, "page_size": limit}


@router.post("/instances", response_model=WazuhInstanceRead,
             status_code=status.HTTP_201_CREATED)
async def create_instance(
    payload: WazuhInstanceCreate,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    inst = WazuhInstance(
        name=payload.name,
        api_url=str(payload.api_url).rstrip("/"),
        api_user=payload.api_user,
        enabled=payload.enabled,
        verify_tls=payload.verify_tls,
        sync_interval_seconds=payload.sync_interval_seconds,
        description=payload.description,
        scope_subnet_ids=payload.scope_subnet_ids,
        api_password_enc=b"placeholder", api_password_nonce=b"placeholder",
    )
    session.add(inst)
    await session.flush()
    enc, nonce = wazuh_service.encrypt_password(inst.id, payload.api_password)
    inst.api_password_enc = enc
    inst.api_password_nonce = nonce
    await append_audit(
        session,
        actor_user_id=str(getattr(request.state, "user_id", "")) or None,
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="wazuh_instance", object_id=str(inst.id),
        action="create",
        diff={"name": inst.name, "api_url": inst.api_url, "api_user": inst.api_user},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(inst)
    return inst


@router.patch("/instances/{instance_id}", response_model=WazuhInstanceRead)
async def update_instance(
    instance_id: uuid.UUID,
    payload: WazuhInstanceUpdate,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    inst = (
        await session.execute(
            select(WazuhInstance).where(WazuhInstance.id == instance_id)
        )
    ).scalar_one_or_none()
    if inst is None:
        raise HTTPException(404, detail="instance not found")
    data = payload.model_dump(exclude_unset=True)
    new_pwd = data.pop("api_password", None)
    for k, v in data.items():
        if k == "api_url" and v is not None:
            v = str(v).rstrip("/")
        setattr(inst, k, v)
    if new_pwd is not None:
        enc, nonce = wazuh_service.encrypt_password(inst.id, new_pwd)
        inst.api_password_enc = enc
        inst.api_password_nonce = nonce
    await append_audit(
        session,
        actor_user_id=str(getattr(request.state, "user_id", "")) or None,
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="wazuh_instance", object_id=str(inst.id),
        action="update", diff=data,
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(inst)
    return inst


@router.delete("/instances/{instance_id}", status_code=204)
async def delete_instance(
    instance_id: uuid.UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    inst = (
        await session.execute(
            select(WazuhInstance).where(WazuhInstance.id == instance_id)
        )
    ).scalar_one_or_none()
    if inst is None:
        raise HTTPException(404, detail="instance not found")
    # 它寫進共用表的主機名稱／租約／固定分配／NAT／VPN 通道一併收回（沒有外鍵會跟著刪）
    from app.services.integration_cleanup import forget_instance
    await forget_instance(session, source="wazuh", source_id=inst.id)
    await session.delete(inst)
    await append_audit(
        session,
        actor_user_id=str(getattr(request.state, "user_id", "")) or None,
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="wazuh_instance", object_id=str(instance_id),
        action="delete", diff={"name": inst.name},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.post("/instances/{instance_id}/test")
async def test_instance(
    instance_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    inst = (
        await session.execute(
            select(WazuhInstance).where(WazuhInstance.id == instance_id)
        )
    ).scalar_one_or_none()
    if inst is None:
        raise HTTPException(404, detail="instance not found")
    try:
        info = await wazuh_service.healthcheck(inst)
    except wazuh_service.WazuhError as exc:
        raise HTTPException(502, detail=detail_of(exc, "wazuh_error")) from exc
    return {"ok": True, "info": info}


@router.post("/instances/{instance_id}/sync")
async def sync_instance(
    instance_id: uuid.UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """非同步：立刻回 task_id，sync 在背景跑。"""
    from app.services.background_tasks import spawn_task

    inst = (
        await session.execute(
            select(WazuhInstance).where(WazuhInstance.id == instance_id)
        )
    ).scalar_one_or_none()
    if inst is None:
        raise HTTPException(404, detail="instance not found")

    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)
    inst_name = inst.name
    inst_id = inst.id

    async def _runner(sess: AsyncSession, _task) -> dict[str, Any]:  # type: ignore[no-untyped-def]
        ag = await sess.get(WazuhInstance, inst_id)
        if ag is None:
            raise RuntimeError("Wazuh instance disappeared")
        try:
            summary = await wazuh_service.sync_agents(sess, ag)
        except wazuh_service.WazuhError as exc:
            ag.last_error = str(exc)
            await sess.commit()
            raise
        await append_audit(
            sess,
            actor_user_id=str(getattr(request.state, "user_id", "")) or None,
            actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="wazuh_instance", object_id=str(ag.id),
            action="sync", diff=summary,
            request_id=request_id,
        )
        await sess.commit()
        return summary

    task = await spawn_task(
        session=session, kind="wazuh.sync",
        target_type="wazuh_instance", target_id=inst_id, target_label=inst_name,
        runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status,
            "queued_at": task.queued_at.isoformat()}


# ─────────────────── Agents read ───────────────────


@router.get("/agents", response_model=Paginated[WazuhAgentRead])
async def list_agents(
    session: Annotated[AsyncSession, Depends(get_session)],
    instance_id: uuid.UUID | None = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Any:
    base = select(WazuhAgent)
    if instance_id is not None:
        base = base.where(WazuhAgent.instance_id == instance_id)
    if status_filter:
        base = base.where(WazuhAgent.status == status_filter)
    total = (
        await session.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()
    rows = (
        await session.execute(
            base.order_by(WazuhAgent.last_keep_alive.desc().nullslast())
            .offset(offset).limit(limit)
        )
    ).scalars().all()
    return {"items": rows, "total": total, "page": offset // limit + 1, "page_size": limit}


@router.get("/missing-agents", response_model=list[MissingAgentRow] | MissingAgentPage)
async def missing_agents(
    session: Annotated[AsyncSession, Depends(get_session)],
    instance_id: uuid.UUID | None = None,
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
    """應裝 Wazuh agent 卻沒有 active 對映的 IP 清單（hostnamed_only=True 預設只看有設 hostname 的）。

    每筆帶所屬子網路／區段／單位，畫面據此篩選（與 OCS 整合頁共用 annotate_scope）。
    整合設了「限定子網路範圍」就只列範圍內的（見 agent_scope.expected_subnets）。
    """
    from app.services.agent_scope import annotate_scope, expected_subnets
    if instance_id is not None:
        one = await session.get(WazuhInstance, instance_id)
        insts = [one] if one is not None else []
    else:
        insts = list((await session.execute(
            select(WazuhInstance).where(WazuhInstance.enabled.is_(True)))).scalars().all())
    if page is not None:
        # 伺服器端分頁與篩選（大站台 5 萬筆缺口時，整份一次回傳要幾十 MB）
        from app.services.agent_scope import missing_page
        active = select(WazuhAgent.jt_ipam_address_id).where(
            WazuhAgent.status == "active", WazuhAgent.jt_ipam_address_id.is_not(None))
        if instance_id is not None:
            active = active.where(WazuhAgent.instance_id == instance_id)
        return await missing_page(
            session, missing=IPAddress.id.not_in(active), subnet_ids=expected_subnets(insts),
            hostnamed_only=hostnamed_only, page=page, page_size=page_size, section_id=section_id,
            subnet_id=subnet_id, customer_id=customer_id, status=status_filter, q=q, sort=sort, order=order,
            cache_key=("wazuh", instance_id), version_tables=(WazuhAgent,))
    return await annotate_scope(session, await wazuh_service.find_missing_agents(
        session, instance_id=instance_id, hostnamed_only=hostnamed_only,
        subnet_ids=expected_subnets(insts),
    ))
