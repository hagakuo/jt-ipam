"""事件規則：事件 → 條件 → 動作。

## 為什麼條件不是運算式

規則由使用者輸入。如果條件是一段可執行的東西（Python 運算式、jq、樣板語言），
那就是一條注入路徑，而且是**帶著資料庫 session 的**注入路徑。所以條件是結構化資料：
`{field, op, value}`，由這裡的程式碼解讀，沒有任何東西被執行。

同理不提供正規表示式：使用者輸入的 regex 會給出 ReDoS 的機會（一條規則就能讓每次
事件分派卡住）。要比對就用 `contains` / `startswith` 這類有界的運算子。

## 失敗處理

規則出錯**不可以影響事件本身**。壞掉的規則把錯誤寫回自己的 `last_error`，
其他規則與原本的 webhook 分派照常進行 —— 一條規則寫壞不該讓所有通知停擺。
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event_rule import EventRule

log = logging.getLogger("jt_ipam.event_rules")

#: 支援的運算子。刻意不含正規表示式（ReDoS）與任何形式的運算式求值。
OPS = ("eq", "ne", "contains", "not_contains", "startswith", "endswith",
       "in", "not_in", "gt", "lt", "gte", "lte", "exists", "missing")

#: 動作型別
ACTION_NOTIFY = "notify_admins"
ACTION_WEBHOOK = "webhook"
ACTIONS = (ACTION_NOTIFY, ACTION_WEBHOOK)

#: 防呆上限：欄位路徑深度與字串長度都設界，避免規則本身變成負擔
_MAX_DEPTH = 8
_MAX_TEXT = 4096


def get_field(envelope: dict[str, Any], path: str) -> Any:
    """用點號路徑取值（`data.subnet.cidr`）；取不到回 None。

    只走 dict 與 list 索引，不呼叫任何屬性 —— 事件內容是資料，不是物件。
    """
    cur: Any = envelope
    for i, part in enumerate(str(path or "").split(".")):
        if i >= _MAX_DEPTH or cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if 0 <= idx < len(cur) else None
        else:
            return None
    return cur


def _as_text(v: Any) -> str:
    return str(v)[:_MAX_TEXT] if v is not None else ""


def _as_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def check_condition(envelope: dict[str, Any], cond: dict[str, Any]) -> bool:
    """單一條件。認不得的運算子一律回 False（不放行）。"""
    op = str(cond.get("op") or "").strip().lower()
    if op not in OPS:
        return False
    actual = get_field(envelope, str(cond.get("field") or ""))
    expected = cond.get("value")

    if op == "exists":
        return actual is not None
    if op == "missing":
        return actual is None
    if op in ("in", "not_in"):
        seq = expected if isinstance(expected, list) else [expected]
        hit = any(_as_text(actual) == _as_text(x) for x in seq)
        return hit if op == "in" else not hit
    if op in ("gt", "lt", "gte", "lte"):
        a, b = _as_number(actual), _as_number(expected)
        if a is None or b is None:
            return False
        return {"gt": a > b, "lt": a < b, "gte": a >= b, "lte": a <= b}[op]

    a_text, b_text = _as_text(actual), _as_text(expected)
    if op == "eq":
        return a_text == b_text
    if op == "ne":
        return a_text != b_text
    if op == "contains":
        return bool(b_text) and b_text in a_text
    if op == "not_contains":
        return not (bool(b_text) and b_text in a_text)
    if op == "startswith":
        return bool(b_text) and a_text.startswith(b_text)
    if op == "endswith":
        return bool(b_text) and a_text.endswith(b_text)
    return False


def rule_matches(rule: EventRule, event: str, payload: dict[str, Any]) -> bool:
    """事件名稱符合，且**所有**條件都成立（AND）。沒有條件＝只看事件名稱。"""
    events = set(rule.events or [])
    if "*" not in events and event not in events:
        return False
    envelope = {"event": event, "data": payload}
    conds = rule.conditions or []
    if not isinstance(conds, list):
        return False
    return all(isinstance(c, dict) and check_condition(envelope, c) for c in conds)


async def _run_action(
    session: AsyncSession, action: dict[str, Any], *, rule: EventRule,
    event: str, payload: dict[str, Any],
) -> None:
    kind = str(action.get("type") or "").strip().lower()
    if kind == ACTION_NOTIFY:
        from app.models.user import User
        from app.services.notification import push_notification

        admins = (await session.execute(
            select(User).where(User.is_admin.is_(True), User.is_active.is_(True))
        )).scalars().all()
        # 標題與內文由規則作者自己寫；只有**沒寫**的時候才用我們的退路句 ——
        # 那一句要跟著讀的人的語言，作者寫的當然照原樣顯示。
        custom_title = _as_text(action.get("title") or "")[:200]
        custom_body = _as_text(action.get("body") or "")[:2000]
        title = custom_title or f"事件規則：{rule.name}"
        body = custom_body or f"{event}"
        title_key = None if custom_title else "notif.event_rule"
        body_key = None if custom_body else "notif.event_rule_body"
        notif_params = None if (custom_title and custom_body) else {
            "rule": rule.name, "event": event}
        severity = str(action.get("severity") or "info")
        if severity not in ("info", "warning", "error"):
            severity = "info"
        for admin in admins:
            await push_notification(
                session, user_id=admin.id, severity=severity,
                title=title, body=body, object_type="event_rule", object_id=None,
                title_key=title_key, body_key=body_key, params=notif_params,
                # 帶去規則本身那一頁。事件是使用者自己定的，我們無從得知「該看哪一筆資料」，
                # 但至少要能一鍵回到「是哪條規則發的」—— 通知點下去沒反應本身就是缺陷。
                link="/event-rules",
            )
    elif kind == ACTION_WEBHOOK:
        # 指定送到某個既有的 webhook 訂閱（沿用它的簽章金鑰與 SSRF 檢查）
        from app.services.notification import deliver_event_to
        sub_id = action.get("subscription_id")
        if sub_id:
            await deliver_event_to(session, subscription_id=str(sub_id),
                                   event=event, payload=payload)


async def run_rules(
    session: AsyncSession, *, event: str, payload: dict[str, Any],
) -> list[str]:
    """跑一遍所有啟用的規則；回傳命中的規則名稱。

    **絕不讓規則的錯誤外溢**：單一規則出錯就把訊息寫回它自己的 `last_error`，
    其餘規則與原本的事件分派照常。
    """
    try:
        rules = (await session.execute(
            select(EventRule).where(EventRule.enabled.is_(True))
        )).scalars().all()
    except Exception as exc:            # 規則表讀不到不該讓事件消失
        log.error("event rules unreadable: %s", exc)
        return []

    matched: list[str] = []
    for rule in rules:
        try:
            # 形狀不對的規則要**看得見**，不能安靜地什麼都不做：
            # 迴圈跑一個 dict 只會拿到鍵、一條都不執行，畫面上卻顯示規則啟用中。
            if not isinstance(rule.conditions, list):
                rule.last_error = "conditions 必須是清單"
                continue
            if not isinstance(rule.actions, list):
                rule.last_error = "actions 必須是清單"
                continue
            if not rule_matches(rule, event, payload):
                continue
            matched.append(rule.name)
            rule.match_count = (rule.match_count or 0) + 1
            rule.last_matched_at = datetime.now(UTC)
            rule.last_error = None
            for action in (rule.actions or []):
                if isinstance(action, dict):
                    await _run_action(session, action, rule=rule,
                                      event=event, payload=payload)
        except Exception as exc:
            rule.last_error = f"{type(exc).__name__}: {exc}"[:500]
            log.error("event rule %s failed: %s", rule.name, exc)
    return matched
