"""AI 對話可以設定「關閉思考」（2026-10-01 使用者決定：「可設定」）。

巡檢與判讀一律送關閉思考的參數；互動式 AI 對話以前一個都不送。接會思考的模型（尤其經過
LiteLLM 這類閘道）時，每一輪對話都先寫一大段思考，回答慢很多。預設維持允許思考（畫面會顯示
「思考中」），可在「管理 → LLM / AI」關掉。關掉時伺服器若拒絕某個參數，只拿掉被點名的那個、
並記住這台伺服器不收（與判讀同一套：services/ai._strip_rejected_controls）。
"""
from __future__ import annotations

import pytest
from app.services import ai as ai_mod
from app.services.system_config import get_llm_config, set_llm_config

from tests.test_llm_reasoning_control import _fake, _Resp, _sse


@pytest.fixture(autouse=True)
def _forget_rejections():
    ai_mod._REJECTED_CONTROLS.clear()
    yield
    ai_mod._REJECTED_CONTROLS.clear()


def _cfg(**kw):
    from app.services.system_config import LLMConfig
    base = dict(enabled=True, url="http://192.0.2.20:11434", embedding_model="e", chat_model="gemma4:26b",
                timeout=30.0)
    base.update(kw)
    return LLMConfig(**base)


async def test_setting_round_trip(db_session, client, auth_headers) -> None:
    cfg = await get_llm_config(db_session)
    assert cfg.chat_thinking is True                       # 預設維持以前的行為
    await set_llm_config(db_session, chat_thinking=False)
    await db_session.commit()
    assert (await get_llm_config(db_session)).chat_thinking is False
    r = await client.patch("/api/v1/system/llm", headers=auth_headers, json={"chat_thinking": True})
    assert r.status_code == 200, r.text
    assert r.json()["chat_thinking"] is True


def test_chat_body_carries_the_controls_only_when_thinking_is_off() -> None:
    msgs = [{"role": "user", "content": "hi"}]
    assert "think" not in ai_mod.chat_body(_cfg(), "ollama", messages=msgs, tools=[])
    assert ai_mod.chat_body(_cfg(chat_thinking=False), "ollama", messages=msgs, tools=[])["think"] is False
    oa = ai_mod.chat_body(_cfg(chat_thinking=False, url="http://192.0.2.21:4000/v1", provider="openai"),
                          "openai", messages=msgs, tools=[])
    assert oa["reasoning_effort"] == "none"                # LiteLLM 會轉成 Ollama 的 think:false
    assert "think" not in oa
    official = ai_mod.chat_body(_cfg(chat_thinking=False, url="https://api.openai.com/v1", provider="openai"),
                                "openai", messages=msgs, tools=[])
    assert "reasoning_effort" not in official             # 官方 OpenAI 對不認得的欄位回 400


async def test_streamed_chat_drops_only_the_rejected_control(db_session, admin_user, monkeypatch) -> None:
    cfg = _cfg(chat_thinking=False, url="http://192.0.2.21:4000/v1", provider="openai")

    async def _get(_s):
        return cfg
    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", _get)
    ok = _sse({"choices": [{"delta": {"content": "你好"}}]},
              {"choices": [{"delta": {}, "finish_reason": "stop"}]})
    rejected = _Resp([], status=400, text="litellm.UnsupportedParamsError: does not support parameters: "
                                          "['thinking_budget_tokens']")
    seen: list[dict] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([rejected, _Resp(ok)], seen))
    events = [e async for e in ai_mod.chat_stream(db_session, user=admin_user,
                                                    messages=[{"role": "user", "content": "hi"}])]
    assert not [e for e in events if e["type"] == "error"], events
    assert "".join(e["text"] for e in events if e["type"] == "token") == "你好"
    assert "thinking_budget_tokens" in seen[0]
    assert "thinking_budget_tokens" not in seen[1]
    assert seen[1]["reasoning_effort"] == "none"
    # 記住了：下一個請求一開始就不送
    again = ai_mod.chat_body(cfg, "openai", messages=[], tools=[])
    assert "thinking_budget_tokens" not in again


async def test_old_ollama_that_rejects_think_still_chats(db_session, admin_user, monkeypatch) -> None:
    cfg = _cfg(chat_thinking=False)

    async def _get(_s):
        return cfg
    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", _get)
    import json as _json
    ok = [_json.dumps({"message": {"content": "ok"}, "done": False}),
          _json.dumps({"message": {"content": ""}, "done": True})]
    rejected = _Resp([], status=400, text='{"error":"json: unknown field \\"think\\""}')
    seen: list[dict] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([rejected, _Resp(ok)], seen))
    events = [e async for e in ai_mod.chat_stream(db_session, user=admin_user,
                                                    messages=[{"role": "user", "content": "hi"}])]
    assert not [e for e in events if e["type"] == "error"], events
    assert seen[0]["think"] is False
    assert "think" not in seen[1]
