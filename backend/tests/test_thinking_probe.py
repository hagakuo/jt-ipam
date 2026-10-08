"""思考檢查：模型照不照「關閉思考」的參數做（2026-10-01；參考 jt-doc-tools 的 thinking_probe）。

AI 巡檢與判讀一律送關閉思考的參數，但伺服器或閘道可能根本沒照做（LiteLLM 沒轉送、舊版
llama.cpp 忽略 reasoning_effort……）。症狀只是「很慢」或「答案被切掉」，不會報錯。設定頁要能
當場問一次：用同一套參數送一句極短的話，回報模型有沒有先思考、伺服器拒收了哪些參數、花了幾秒。

回答是空的也算在思考：有些閘道**不把思考內容轉出來**（jt-doc-tools 實測 LiteLLM 的 `ollama/`：
思考開著時花了 54 秒，回來的思考字數卻是 0），額度被思考用光、正文是空的。
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from app.services import ai as ai_mod
from app.services.system_config import set_llm_config


class _R:
    def __init__(self, status: int = 200, payload: Any = None, text: str = ""):
        self.status_code, self._p, self.text = status, payload, text

    def json(self):
        return self._p


@pytest.fixture(autouse=True)
def _forget_rejections():
    ai_mod._REJECTED_CONTROLS.clear()
    yield
    ai_mod._REJECTED_CONTROLS.clear()


def _script(monkeypatch, *responses):
    sent: list[dict[str, Any]] = []
    it = iter(responses)

    async def _fake(method, url, **kw):
        sent.append({"url": url, **dict(kw["json"])})
        nxt = next(it)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt
    monkeypatch.setattr(ai_mod, "safe_request", _fake)
    return sent


async def _llm(db, **kw) -> None:
    base = {"enabled": True, "url": "http://192.0.2.30:11434", "chat_model": "gemma4:26b"}
    await set_llm_config(db, **{**base, **kw})
    await db.commit()


async def test_ollama_still_thinking_is_reported(db_session, monkeypatch) -> None:
    await _llm(db_session)
    sent = _script(monkeypatch, _R(payload={"message": {"content": "OK", "thinking": "Let me think." * 20},
                                            "done_reason": "stop"}))
    r = await ai_mod.probe_thinking(db_session, "gemma4:26b")
    assert r["ok"] is True
    assert r["thinking"] is True
    assert r["reasoning_chars"] > 100
    assert r["answer"] == "OK"
    # 與 AI 巡檢／判讀同一套：think:false＋產出上限（不會為了一次檢查讓模型想好幾分鐘）
    assert sent[0]["think"] is False
    assert sent[0]["options"]["num_predict"] <= 128
    assert sent[0]["stream"] is False


async def test_litellm_rejects_one_control_and_thinking_is_off(db_session, monkeypatch) -> None:
    await _llm(db_session, provider="openai", url="http://192.0.2.31:4000/v1")
    sent = _script(
        monkeypatch,
        _R(400, text="litellm.UnsupportedParamsError: does not support parameters: ['thinking_budget_tokens']"),
        _R(payload={"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}),
    )
    r = await ai_mod.probe_thinking(db_session, "gemma4:26b")
    assert r["ok"] is True
    assert r["thinking"] is False
    assert r["rejected_params"] == ["thinking_budget_tokens"]
    assert sent[1]["reasoning_effort"] == "none"            # 認得的那個照送
    assert sent[0]["max_tokens"] <= 128


async def test_empty_answer_counts_as_thinking(db_session, monkeypatch) -> None:
    """閘道不轉出思考內容：額度被思考用光、正文空白、finish_reason=length。不可以丟錯誤，要報「在思考」。"""
    await _llm(db_session, provider="openai", url="http://192.0.2.31:4000/v1")
    _script(monkeypatch, _R(payload={"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}))
    r = await ai_mod.probe_thinking(db_session, "gemma4:26b")
    assert r["ok"] is True
    assert r["thinking"] is True
    assert r["empty_answer"] is True
    assert r["reasoning_chars"] == 0


async def test_think_tags_in_the_answer_count(db_session, monkeypatch) -> None:
    await _llm(db_session, provider="openai", url="http://192.0.2.32:8081/v1")
    _script(monkeypatch, _R(payload={"choices": [{"message": {"content": "<think>hmm</think>OK"},
                                                   "finish_reason": "stop"}]}))
    r = await ai_mod.probe_thinking(db_session, "qwen3:8b")
    assert r["thinking"] is True
    assert r["think_tag"] is True
    assert r["answer"] == "OK"


async def test_unreachable_server_is_an_error_not_a_crash(db_session, monkeypatch) -> None:
    await _llm(db_session)
    _script(monkeypatch, httpx.ConnectError("Connection refused"))
    r = await ai_mod.probe_thinking(db_session, "gemma4:26b")
    assert r["ok"] is False
    assert "Connection refused" in r["error"]
    assert r["thinking"] is None


async def test_endpoint_checks_chat_and_interpret_models(client, auth_headers, db_session, monkeypatch) -> None:
    await _llm(db_session, ai_interpret_model="judge:32b")
    sent = _script(monkeypatch,
                   _R(payload={"message": {"content": "OK"}, "done_reason": "stop"}),
                   _R(payload={"message": {"content": "OK", "thinking": "x" * 50}, "done_reason": "stop"}))
    r = await client.get("/api/v1/ai/thinking-check", headers=auth_headers)
    assert r.status_code == 200, r.text
    rows = r.json()["results"]
    assert [(x["role"], x["model"], x["thinking"]) for x in rows] == [
        ("chat", "gemma4:26b", False), ("interpret", "judge:32b", True)]
    assert [s["model"] for s in sent] == ["gemma4:26b", "judge:32b"]


async def test_endpoint_checks_the_audit_model_too(client, auth_headers, db_session, monkeypatch) -> None:
    await _llm(db_session, ai_audit_model="audit:14b", ai_interpret_model="audit:14b")
    sent = _script(monkeypatch, *[_R(payload={"message": {"content": "OK"}, "done_reason": "stop"})] * 2)
    rows = (await client.get("/api/v1/ai/thinking-check", headers=auth_headers)).json()["results"]
    assert [(x["role"], x["model"]) for x in rows] == [("chat", "gemma4:26b"), ("audit", "audit:14b")]
    assert len(sent) == 2                                     # 同一個模型只問一次


async def test_endpoint_skips_interpret_when_it_is_the_chat_model(client, auth_headers, db_session,
                                                                 monkeypatch) -> None:
    await _llm(db_session)
    _script(monkeypatch, _R(payload={"message": {"content": "OK"}, "done_reason": "stop"}))
    rows = (await client.get("/api/v1/ai/thinking-check", headers=auth_headers)).json()["results"]
    assert [x["role"] for x in rows] == ["chat"]


async def test_endpoint_requires_admin(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"na-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local",
             display_name="NA", password_hash=hash_password("TestPassword2026!"),
             auth_provider="local", is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.commit()
    r = await client.get("/api/v1/ai/thinking-check",
                          headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 403
