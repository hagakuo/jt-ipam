"""事件規則 endpoints（admin only）。

規則決定「發生什麼事、在什麼條件下、要做什麼」，屬純管理資料 → `require_admin`。
`/test` 讓使用者拿一份範例內容先試，不必真的去觸發一次事件才知道規則寫對沒有。
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import ui_detail
from app.models.event_rule import EventRule
from app.schemas.base import Paginated, StrictModel
from app.services import event_rules as svc

router = APIRouter(prefix="/event-rules", tags=["event-rules"],
                   dependencies=[Depends(require_admin)])


class EventRuleBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    description: Annotated[str | None, Field(max_length=2048)] = None
    enabled: bool = True
    #: ["*"] = 所有事件
    events: list[Annotated[str, Field(min_length=1, max_length=64)]] = []
    conditions: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []


class EventRuleCreate(EventRuleBase):
    pass


class EventRuleUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    enabled: bool | None = None
    events: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = None
    conditions: list[dict[str, Any]] | None = None
    actions: list[dict[str, Any]] | None = None


class EventRuleRead(EventRuleBase):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    match_count: int = 0
    last_matched_at: Any = None
    last_error: str | None = None


class RuleTestIn(StrictModel):
    event: Annotated[str, Field(min_length=1, max_length=64)]
    payload: dict[str, Any] = {}


def _validate(conditions: list[dict[str, Any]], actions: list[dict[str, Any]]) -> None:
    """在寫進資料庫前擋掉寫不通的規則 —— 讓錯誤出現在儲存當下，而不是事件發生時。"""
    for c in conditions:
        op = str(c.get("op") or "")
        if op not in svc.OPS:
            raise HTTPException(422, detail=ui_detail("evr_bad_operator",
                                f"不支援的運算子：{op}（可用：{', '.join(svc.OPS)}）",
                                value=op, allowed=", ".join(svc.OPS)))
        if not str(c.get("field") or "").strip():
            raise HTTPException(422, detail=ui_detail("evr_condition_needs_field", "條件必須指定欄位"))
    for a in actions:
        kind = str(a.get("type") or "")
        if kind not in svc.ACTIONS:
            raise HTTPException(422, detail=ui_detail("evr_bad_action",
                                f"不支援的動作：{kind}（可用：{', '.join(svc.ACTIONS)}）",
                                value=kind, allowed=", ".join(svc.ACTIONS)))
        if kind == svc.ACTION_WEBHOOK and not a.get("subscription_id"):
            raise HTTPException(422, detail=ui_detail("evr_webhook_needs_subscription", "webhook 動作必須指定目標訂閱"))


@router.get("", response_model=Paginated[EventRuleRead])
async def list_rules(
    session: Annotated[AsyncSession, Depends(get_session)],
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[EventRuleRead]:
    stmt = (select(EventRule).order_by(EventRule.name)
            .offset((page - 1) * page_size).limit(page_size))
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(select(func.count()).select_from(EventRule)) or 0)
    return Paginated[EventRuleRead](
        items=[EventRuleRead.model_validate(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )


@router.post("", response_model=EventRuleRead, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: EventRuleCreate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EventRuleRead:
    _validate(payload.conditions, payload.actions)
    rule = EventRule(**payload.model_dump())
    session.add(rule)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise HTTPException(409, detail="Name already exists") from exc
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="event_rule", object_id=str(rule.id), action="create",
        diff={"name": rule.name, "events": ",".join(rule.events or [])},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(rule)
    return EventRuleRead.model_validate(rule)


@router.patch("/{rule_id}", response_model=EventRuleRead)
async def update_rule(
    rule_id: uuid.UUID, payload: EventRuleUpdate, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EventRuleRead:
    rule = await session.get(EventRule, rule_id)
    if rule is None:
        raise HTTPException(404, detail="Not found")
    data = payload.model_dump(exclude_unset=True)
    _validate(data.get("conditions", rule.conditions) or [],
              data.get("actions", rule.actions) or [])
    for k, v in data.items():
        setattr(rule, k, v)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="event_rule", object_id=str(rule.id), action="update",
        diff={k: str(v) for k, v in data.items()},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(rule)
    return EventRuleRead.model_validate(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: uuid.UUID, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    rule = await session.get(EventRule, rule_id)
    if rule is None:
        raise HTTPException(404, detail="Not found")
    await session.delete(rule)
    await append_audit(
        session, actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="event_rule", object_id=str(rule_id), action="delete", diff={},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: uuid.UUID, payload: RuleTestIn,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """拿一份範例內容試跑：只回「會不會命中」與逐條條件的結果，**不執行動作**。

    不執行動作是刻意的：測試按鈕不該真的送出 webhook 或通知所有管理員。
    """
    rule = await session.get(EventRule, rule_id)
    if rule is None:
        raise HTTPException(404, detail="Not found")
    envelope = {"event": payload.event, "payload": payload.payload,
                "data": payload.payload}
    events = set(rule.events or [])
    event_ok = "*" in events or payload.event in events
    details = [{
        "field": c.get("field"), "op": c.get("op"), "value": c.get("value"),
        "actual": svc.get_field(envelope, str(c.get("field") or "")),
        "passed": svc.check_condition(envelope, c),
    } for c in (rule.conditions or []) if isinstance(c, dict)]
    return {
        "event_matched": event_ok,
        "conditions": details,
        "matched": event_ok and all(d["passed"] for d in details),
    }
