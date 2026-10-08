"""變更影響預演的 MCP 工具（規格 §10.6、T25）。

- 唯讀 MCP 金鑰看不到、也呼叫不了建案／開始分析／存待辦；讀取類照常
- 建案一定要帶 impact_prepare_scenario 簽發的草稿憑證；內容被改過（換了新位址）就拒絕
- 功能關閉時工具清單裡沒有 impact_*（少佔小模型的提示詞）
- 非管理員不能經由工具建案（異動工具一律只給管理員，維持原本的權限邊界）
"""
from __future__ import annotations

import json
import uuid

import pytest
from app.mcp.server import process_message
from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.change_impact import jobs


@pytest.fixture(autouse=True)
def _inline(monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(jobs, "SPAWN_IN_BACKGROUND", False)


async def _setup(db, enabled: bool = True) -> IPAddress:  # type: ignore[no-untyped-def]
    from app.services.change_impact.config import set_config
    await set_config(db, {"enabled": enabled}, updated_by=None)
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.10", state="active")
    db.add(ip)
    await db.commit()
    return ip


async def _call(user, name, args, readonly=False):  # type: ignore[no-untyped-def]
    r = await process_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": args}}, user, readonly=readonly)
    res = r.get("result") or {}
    if not res:
        return {"isError": True}, {"error": "protocol", "raw": r}
    text = (res.get("content") or [{}])[0].get("text", "{}")
    try:
        body = json.loads(text)
    except ValueError:
        body = {"_text": text}
    return res, body


async def _names(user, readonly=False):  # type: ignore[no-untyped-def]
    r = await process_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, user, readonly=readonly)
    return {t["name"] for t in r["result"]["tools"]}


async def test_t25_read_only_key_cannot_create_but_can_read(db_session, admin_user) -> None:
    ip = await _setup(db_session)
    names = await _names(admin_user, readonly=True)
    assert "impact_list_plans" in names and "impact_prepare_scenario" in names
    assert not {"impact_create_plan", "impact_start_run", "impact_accept_task_draft"} & names
    _res, draft = await _call(admin_user, "impact_prepare_scenario",
                              {"target_ip": "198.51.100.10", "new_ip": "198.51.100.80"}, readonly=True)
    assert "draft" in draft, draft
    assert draft["draft"]["target_id"] == str(ip.id) and draft["draft_token"]
    res, body = await _call(admin_user, "impact_create_plan", {**draft["draft"], "draft_token": draft["draft_token"]},
                            readonly=True)
    assert res.get("isError") is True or "error" in body
    from app.models.change_impact import ChangePlan
    from sqlalchemy import select
    assert not (await db_session.execute(select(ChangePlan))).scalars().all()


async def test_create_needs_an_untampered_draft_token(db_session, admin_user) -> None:
    await _setup(db_session)
    _r, draft = await _call(admin_user, "impact_prepare_scenario",
                            {"target_ip": "198.51.100.10", "new_ip": "198.51.100.80"})
    tampered = {**draft["draft"], "parameters": {"new_ip": "198.51.100.99"}, "draft_token": draft["draft_token"]}
    _r, body = await _call(admin_user, "impact_create_plan", tampered)
    assert body.get("error") == "impact_draft_invalid"
    _r, body = await _call(admin_user, "impact_create_plan", {**draft["draft"], "draft_token": "123.forged"})
    assert body.get("error") == "impact_draft_invalid"
    _r, made = await _call(admin_user, "impact_create_plan", {**draft["draft"], "draft_token": draft["draft_token"]})
    assert made.get("plan_id"), made
    _r, run = await _call(admin_user, "impact_start_run", {"plan_id": made["plan_id"]})
    _r, got = await _call(admin_user, "impact_get_run", {"run_id": run["run_id"]})
    assert got["status"] in ("completed", "partial") and "尚未執行任何變更" in got["notice"]


async def test_tools_are_hidden_when_the_feature_is_off(db_session, admin_user) -> None:
    await _setup(db_session, enabled=False)
    assert not any(n.startswith("impact_") for n in await _names(admin_user))


async def test_non_admins_cannot_create_plans_through_tools(db_session) -> None:
    from app.core.security import hash_password
    from app.models.permission import Permission
    from app.models.user import User
    ip = await _setup(db_session)
    u = User(username=f"u-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@t.local", display_name="U",
             password_hash=hash_password("TestPassword2026!"), auth_provider="local", is_active=True)
    db_session.add(u)
    await db_session.flush()
    sub_id = (await db_session.get(IPAddress, ip.id)).subnet_id
    db_session.add(Permission(object_type="subnet", object_id=sub_id, principal_type="user", principal_id=u.id,
                              level="write"))
    await db_session.commit()
    names = await _names(u)
    assert "impact_prepare_scenario" in names and "impact_create_plan" not in names
