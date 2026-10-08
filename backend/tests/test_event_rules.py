"""事件規則：事件 → 條件 → 動作。

守三件事：
1. 條件是**資料**不是運算式 —— 不支援 regex／不求值，認不得的運算子一律不放行
2. 一條規則寫壞不可以讓事件分派停擺
3. 規則指定的 webhook 走的是同一條發送路徑（簽章與 SSRF 檢查不可被繞過）
"""
from __future__ import annotations

import uuid

import pytest

from app.models.event_rule import EventRule
from app.services import event_rules as er


def _rule(**kw) -> EventRule:
    base = {"name": f"r-{uuid.uuid4().hex[:6]}", "enabled": True,
            "events": ["subnet.created"], "conditions": [], "actions": []}
    base.update(kw)
    return EventRule(**base)


ENVELOPE = {"event": "subnet.created", "data": {
    "subnet": {"cidr": "10.20.0.0/24", "description": "Production DB"},
    "count": 5, "tags": ["prod", "db"],
}}


def test_get_field_walks_dot_paths() -> None:
    assert er.get_field(ENVELOPE, "data.subnet.cidr") == "10.20.0.0/24"
    assert er.get_field(ENVELOPE, "data.tags.0") == "prod"
    assert er.get_field(ENVELOPE, "data.nope") is None
    assert er.get_field(ENVELOPE, "data.subnet.cidr.deeper") is None


def test_get_field_never_touches_attributes() -> None:
    """事件內容是資料 —— 路徑不可以變成屬性存取（那是注入面）。"""
    class Sneaky:
        secret = "should-not-be-reachable"

    env = {"data": Sneaky()}
    assert er.get_field(env, "data.secret") is None


@pytest.mark.parametrize(("op", "value", "expected"), [
    ("eq", "10.20.0.0/24", True),
    ("eq", "10.20.0.0/25", False),
    ("ne", "x", True),
    ("contains", "10.20.", True),
    ("not_contains", "203.0.113.", True),
    ("startswith", "10.", True),
    ("endswith", "/24", True),
    ("in", ["10.20.0.0/24", "10.30.0.0/24"], True),
    ("not_in", ["10.30.0.0/24"], True),
    ("exists", None, True),
])
def test_condition_operators(op: str, value: object, expected: bool) -> None:
    cond = {"field": "data.subnet.cidr", "op": op, "value": value}
    assert er.check_condition(ENVELOPE, cond) is expected


def test_numeric_operators() -> None:
    assert er.check_condition(ENVELOPE, {"field": "data.count", "op": "gt", "value": 3})
    assert not er.check_condition(ENVELOPE, {"field": "data.count", "op": "gt", "value": 50})
    # 比不出數字就是不成立，不可以拿字串比大小裝作成功
    assert not er.check_condition(
        ENVELOPE, {"field": "data.subnet.cidr", "op": "gt", "value": 3})


def test_unknown_operator_never_passes() -> None:
    """認不得的運算子＝不放行。放行才是危險的預設。"""
    assert er.check_condition(ENVELOPE, {"field": "data.count", "op": "regex", "value": ".*"}) is False
    assert er.check_condition(ENVELOPE, {"field": "data.count", "op": "", "value": 1}) is False
    assert er.check_condition(ENVELOPE, {}) is False


def test_rule_requires_all_conditions() -> None:
    rule = _rule(conditions=[
        {"field": "data.subnet.cidr", "op": "startswith", "value": "10."},
        {"field": "data.subnet.description", "op": "contains", "value": "Production"},
    ])
    assert er.rule_matches(rule, "subnet.created", ENVELOPE["data"]) is True

    rule.conditions.append({"field": "data.count", "op": "gt", "value": 99})
    assert er.rule_matches(rule, "subnet.created", ENVELOPE["data"]) is False


def test_rule_event_matching() -> None:
    rule = _rule(events=["subnet.created"])
    assert er.rule_matches(rule, "subnet.created", {}) is True
    assert er.rule_matches(rule, "ip.allocated", {}) is False
    assert er.rule_matches(_rule(events=["*"]), "anything.at.all", {}) is True


@pytest.mark.anyio
async def test_broken_rule_does_not_stop_the_others(db_session) -> None:
    """一條規則寫壞，其餘規則與事件分派要照常。"""
    good = _rule(name=f"good-{uuid.uuid4().hex[:6]}", events=["*"],
                 actions=[{"type": "notify_admins", "title": "ok"}])
    # actions 形狀不對 → 必須被標記出來，而不是安靜地什麼都不做
    bad = _rule(name=f"bad-{uuid.uuid4().hex[:6]}", events=["*"], actions={"type": "boom"})
    db_session.add_all([good, bad])
    await db_session.flush()

    matched = await er.run_rules(db_session, event="subnet.created", payload={"x": 1})
    assert good.name in matched
    assert bad.last_error is not None, "形狀壞掉的規則要留下錯誤訊息（不可以安靜失效）"
    assert bad.name not in matched


@pytest.mark.anyio
async def test_disabled_rules_are_skipped(db_session) -> None:
    off = _rule(name=f"off-{uuid.uuid4().hex[:6]}", events=["*"], enabled=False)
    db_session.add(off)
    await db_session.flush()
    assert await er.run_rules(db_session, event="whatever", payload={}) == []


@pytest.mark.anyio
async def test_match_updates_counters(db_session) -> None:
    r = _rule(name=f"cnt-{uuid.uuid4().hex[:6]}", events=["ip.allocated"])
    db_session.add(r)
    await db_session.flush()
    await er.run_rules(db_session, event="ip.allocated", payload={})
    assert r.match_count == 1
    assert r.last_matched_at is not None
