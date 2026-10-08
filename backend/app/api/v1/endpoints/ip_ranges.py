"""子網路內的位址範圍（集區）—— GitHub issue #40。

路由掛在子網路底下，權限直接沿用子網路的（讀得到子網路才看得到範圍、改得了子網路才改得了範圍）：
範圍只是子網路裡的一段，沒有自己獨立的權限。每一次新增／修改／刪除都寫稽核。
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_object_perm
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import UiError, detail_of, ui_detail
from app.models.ip_range import IPRange
from app.models.subnet import Subnet
from app.schemas.ip_range import IPRangeCreate, IPRangeRead, IPRangeUpdate
from app.services.ip_ranges import ranges_with_usage, validate_range

router = APIRouter(prefix="/subnets", tags=["ip-ranges"])

_READ = [Depends(require_object_perm("subnet", "read", path_param="subnet_id"))]
_WRITE = [Depends(require_object_perm("subnet", "write", path_param="subnet_id"))]


async def _subnet(session: AsyncSession, subnet_id: uuid.UUID) -> Subnet:
    sn = await session.get(Subnet, subnet_id)
    if sn is None:
        raise HTTPException(status_code=404, detail="Subnet not found")
    return sn


async def _range(session: AsyncSession, subnet_id: uuid.UUID, range_id: uuid.UUID) -> IPRange:
    r = await session.get(IPRange, range_id)
    # 範圍要真的屬於網址上的那個子網路 —— 否則拿著別的子網路的寫入權限就能改到這一筆
    if r is None or r.subnet_id != subnet_id:
        raise HTTPException(status_code=404, detail="Range not found")
    return r


def _status_of(exc: UiError) -> int:
    return status.HTTP_409_CONFLICT if exc.code == "range_overlap" else status.HTTP_400_BAD_REQUEST


async def _one(session: AsyncSession, sn: Subnet, range_id: uuid.UUID) -> IPRangeRead:
    row = next(x for x in await ranges_with_usage(session, sn) if x["id"] == range_id)
    return IPRangeRead.model_validate(row)


async def _audit(session: AsyncSession, user: Any, request: Request, r: IPRange, action: str,
                 diff: dict[str, Any]) -> None:
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ip_range", object_id=str(r.id), action=action, diff=diff,
        request_id=getattr(request.state, "request_id", None),
    )


def _refuse_auto(r: IPRange) -> None:
    """自動建立的範圍由同步管理：改了下一輪會被蓋回去、刪了會再建 —— 直接擋，講清楚要改上游。"""
    if r.source_origin:
        raise HTTPException(status_code=409, detail=ui_detail(
            "range_auto_managed",
            f"這段範圍是依「{r.name or r.source_origin}」偵測到的 DHCP 發放範圍自動建立的，"
            "會跟著上游同步；要改請改 DHCP 伺服器上的設定",
            source=r.name or r.source_origin))


@router.get("/{subnet_id}/ranges", response_model=list[IPRangeRead], dependencies=_READ)
async def list_ranges(
    subnet_id: uuid.UUID, session: Annotated[AsyncSession, Depends(get_session)],
) -> list[IPRangeRead]:
    sn = await _subnet(session, subnet_id)
    return [IPRangeRead.model_validate(x) for x in await ranges_with_usage(session, sn)]


@router.post("/{subnet_id}/ranges", response_model=IPRangeRead,
             status_code=status.HTTP_201_CREATED, dependencies=_WRITE)
async def create_range(
    subnet_id: uuid.UUID, payload: IPRangeCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IPRangeRead:
    sn = await _subnet(session, subnet_id)
    try:
        start, end = await validate_range(session, sn, payload.start_ip, payload.end_ip)
    except UiError as exc:
        raise HTTPException(status_code=_status_of(exc), detail=detail_of(exc, "range_invalid")) from exc
    r = IPRange(subnet_id=sn.id, start_ip=start, end_ip=end, purpose=payload.purpose,
                name=payload.name, description=payload.description)
    session.add(r)
    await session.flush()
    await _audit(session, user, request, r, "create",
                 {"after": {**payload.model_dump(), "start_ip": start, "end_ip": end,
                            "subnet_id": str(sn.id)}})
    await session.commit()
    return await _one(session, sn, r.id)


@router.patch("/{subnet_id}/ranges/{range_id}", response_model=IPRangeRead, dependencies=_WRITE)
async def update_range(
    subnet_id: uuid.UUID, range_id: uuid.UUID, payload: IPRangeUpdate, user: CurrentUser,
    request: Request, session: Annotated[AsyncSession, Depends(get_session)],
) -> IPRangeRead:
    sn = await _subnet(session, subnet_id)
    r = await _range(session, subnet_id, range_id)
    _refuse_auto(r)
    changes = payload.model_dump(exclude_unset=True)
    before = {"start_ip": str(r.start_ip).split("/")[0], "end_ip": str(r.end_ip).split("/")[0],
              "purpose": r.purpose, "name": r.name, "description": r.description}
    try:
        start, end = await validate_range(
            session, sn, changes.get("start_ip") or before["start_ip"],
            changes.get("end_ip") or before["end_ip"], exclude_id=r.id)
    except UiError as exc:
        raise HTTPException(status_code=_status_of(exc), detail=detail_of(exc, "range_invalid")) from exc
    r.start_ip, r.end_ip = start, end
    for k in ("purpose", "name", "description"):
        if k in changes:
            setattr(r, k, changes[k])
    await _audit(session, user, request, r, "update", {"before": before, "changes": changes})
    await session.commit()
    return await _one(session, sn, r.id)


@router.delete("/{subnet_id}/ranges/{range_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=_WRITE)
async def delete_range(
    subnet_id: uuid.UUID, range_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    r = await _range(session, subnet_id, range_id)
    _refuse_auto(r)
    await _audit(session, user, request, r, "delete", {"before": {
        "start_ip": str(r.start_ip).split("/")[0], "end_ip": str(r.end_ip).split("/")[0],
        "purpose": r.purpose, "name": r.name}})
    await session.delete(r)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
