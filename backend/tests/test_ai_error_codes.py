"""AI 對話與 IP 調查的錯誤：一般帳號只拿到代碼，管理員才看得到原因（CodeQL #11／#15／#16，2026-10-01）。

以前把例外原文直接給任何登入帳號：內部 LLM 主機名稱、出站防護規則（「Private IP 10.x 不允許」）、
上游 401 回應的前 200 字（有的閘道會回遮罩過的金鑰）、工具執行失敗時資料庫錯誤的 SQL 片段。
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import httpx
from app.services import ai as ai_mod
from app.services.system_config import LLMConfig

INTERNAL = "llm-internal.corp.example"


def _cfg() -> LLMConfig:
    return LLMConfig(enabled=True, url=f"http://{INTERNAL}:11434", embedding_model="e",
                     chat_model="m", timeout=30.0)


async def _plain_user(db):
    from app.core.security import hash_password
    from app.models.user import User
    u = User(username=f"u-{uuid.uuid4().hex[:6]}", email=f"u-{uuid.uuid4().hex[:6]}@test.local",
             display_name="U", password_hash=hash_password("TestPassword2026!"), auth_provider="local",
             is_active=True, is_admin=False)
    db.add(u)
    await db.commit()
    return u


def _unreachable(monkeypatch):
    async def _get(_s):
        return _cfg()
    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", _get)

    @asynccontextmanager
    async def _stream(*a, **kw):
        raise httpx.ConnectError(f"[Errno -2] Name or service not known: {INTERNAL}")
        yield  # pragma: no cover
    monkeypatch.setattr(ai_mod, "safe_stream", _stream)


async def _events(db, user):
    return [e async for e in ai_mod.chat_stream(db, user=user, messages=[{"role": "user", "content": "hi"}])]


async def test_chat_stream_error_is_a_code_for_ordinary_accounts(db_session, monkeypatch) -> None:
    _unreachable(monkeypatch)
    user = await _plain_user(db_session)
    (err,) = [e for e in await _events(db_session, user) if e["type"] == "error"]
    assert err["code"] == "ai_unreachable"
    assert err["params"] == {}
    assert INTERNAL not in str(err)


async def test_admins_still_see_the_reason(db_session, admin_user, monkeypatch) -> None:
    _unreachable(monkeypatch)
    (err,) = [e for e in await _events(db_session, admin_user) if e["type"] == "error"]
    assert err["code"] == "ai_unreachable"
    assert INTERNAL in err["params"]["reason"]


def test_error_classes_map_to_codes() -> None:
    assert ai_mod.ai_error_code(ai_mod.AIBlocked("SSRF guard: Private IP 10.0.0.5")) == "ai_ssrf_blocked"
    assert ai_mod.ai_error_code(ai_mod.AIUpstream("OpenAI chat 401: sk-...abcd")) == "ai_upstream_error"
    assert ai_mod.ai_error_code(ai_mod.AITimeout("slow")) == "ai_timeout"
    assert ai_mod.ai_error_code(TimeoutError()) == "ai_timeout"
    assert ai_mod.ai_error_code(RuntimeError("boom")) == "ai_failed"
    ev = ai_mod.ai_error_event(ai_mod.AIBlocked("SSRF guard: Private IP 10.0.0.5"), admin=False)
    assert "10.0.0.5" not in str(ev)


async def test_tool_failure_text_does_not_reach_ordinary_accounts(db_session, admin_user, monkeypatch) -> None:
    """工具結果會隨 trace_messages 回到畫面：一般帳號只看到類別名稱；管理員看得到第一行，
    但 SQLAlchemy 附在後面幾行的 SQL 與參數不會出現。"""
    from app.mcp import tools as tools_mod

    async def boom(session, *, user, **kw):
        raise RuntimeError("detector exploded\n[SQL: SELECT password_hash FROM users WHERE id = $1]")
    monkeypatch.setitem(tools_mod.TOOLS, "explode", {"fn": boom, "description": "x", "parameters": {}})

    async def allow(session, user, name):
        return None
    monkeypatch.setattr(tools_mod, "authorize_tool", allow)
    call = [{"function": {"name": "explode", "arguments": {}}}]
    plain = (await ai_mod._run_tool_calls(db_session, await _plain_user(db_session), call))[0]["content"]
    assert "RuntimeError" in plain
    assert "detector exploded" not in plain
    admin = (await ai_mod._run_tool_calls(db_session, admin_user, call))[0]["content"]
    assert "detector exploded" in admin
    assert "password_hash" not in admin


async def test_investigate_narrative_hides_the_reason_from_ordinary_accounts(client, db_session,
                                                                           monkeypatch) -> None:
    from app.models.address import IPAddress
    from app.models.permission import Permission
    from app.models.section import Section
    from app.models.subnet import Subnet
    from app.services.auth import issue_access_token

    sec = Section(name=f"inv-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    db_session.add(IPAddress(subnet_id=sub.id, ip="198.51.100.9"))
    user = await _plain_user(db_session)
    db_session.add(Permission(object_type="subnet", object_id=sub.id, principal_type="user",
                              principal_id=user.id, level="read"))
    await db_session.commit()

    async def blocked(*a, **kw):
        raise ai_mod.AIBlocked(f"SSRF guard: Private IP 10.0.0.5 not allowed ({INTERNAL})")
    monkeypatch.setattr(ai_mod, "interpret_chat", blocked)
    r = await client.post("/api/v1/investigate/narrative/stream?ip=198.51.100.9",
                          headers={"Authorization": f"Bearer {issue_access_token(user)}"})
    assert r.status_code == 200, r.text
    assert '"code": "ai_ssrf_blocked"' in r.text
    assert INTERNAL not in r.text
    assert "10.0.0.5" not in r.text
