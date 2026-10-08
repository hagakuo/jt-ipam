"""OpenAI 相容端點上的「不要思考」（GitHub issue #36 的第二個問題）。

回報者用 llama.cpp b9882＋gemma 4：AI 巡檢要求 `no_thinking`，但 OpenAI 相容路徑完全忽略它，
模型把 6000 token 的產出額度全部寫成 reasoning_content，以 `finish_reason: length` 結束，
答案 0 字 —— 我們再把它報成籠統的「（空回應）」，看起來像模型壞了。

llama.cpp（b9882 原始碼確認）每個請求認兩個欄位：
- `chat_template_kwargs: {"enable_thinking": false}`：交給聊天樣板（樣板有沒有理它看模型）
- `thinking_budget_tokens: 0`：取樣層強制結束思考，任何有思考標記的模型都適用
官方 OpenAI API 對不認得的欄位回 400，所以只送給自架的端點；自架服務若拒絕，拿掉重送一次。
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import pytest
from app.services import ai as ai_mod


def _cfg(**kw):
    from app.services.system_config import LLMConfig
    base = dict(enabled=True, url="http://192.0.2.10:8081/v1", embedding_model="e",
                chat_model="c", timeout=30.0)
    base.update(kw)
    return LLMConfig(**base)


def _body(cfg, no_thinking=True):
    return ai_mod.json_chat_body(cfg, "openai", prompt="hi", stream=True, force_json=True,
                                 max_output_tokens=6000, num_ctx=None, no_thinking=no_thinking)


def test_self_hosted_endpoint_gets_both_reasoning_controls() -> None:
    b = _body(_cfg())
    assert b["chat_template_kwargs"] == {"enable_thinking": False}
    assert b["thinking_budget_tokens"] == 0
    # OpenAI 標準欄位；llama.cpp 自 b10434 起照做（回報者升級後單送它就解決）
    assert b["reasoning_effort"] == "none"
    assert "think" not in b, "think 是 Ollama 專屬"


def test_official_openai_gets_neither_because_it_rejects_unknown_fields() -> None:
    for url in ("https://api.openai.com/v1", "https://myres.openai.azure.com/openai"):
        b = _body(_cfg(url=url))
        assert not {"chat_template_kwargs", "thinking_budget_tokens", "reasoning_effort"} & set(b), url


def test_nothing_is_sent_when_thinking_is_allowed() -> None:
    b = _body(_cfg(), no_thinking=False)
    assert "chat_template_kwargs" not in b and "thinking_budget_tokens" not in b


# ── 串流 ─────────────────────────────────────────────────────────────────

def _sse(*chunks: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for c in chunks:
        lines += [f"data: {json.dumps(c, ensure_ascii=False)}", ""]
    return [*lines, "data: [DONE]", ""]


class _Resp:
    def __init__(self, lines: list[str], status: int = 200, text: str = ""):
        self.status_code = status
        self._lines = lines
        self._text = text

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def aread(self):
        return self._text.encode()


def _fake(script: list[_Resp], seen: list[dict[str, Any]]):
    calls = iter(script)

    @asynccontextmanager
    async def _stream(method, url, *, headers=None, json=None, timeout=None):
        seen.append(dict(json or {}))
        yield next(calls)
    return _stream


async def _noop(piece: str, kind: str) -> None:
    return None


@pytest.mark.anyio
async def test_thinking_until_the_limit_is_reported_as_such(monkeypatch) -> None:
    """只有思考、沒有答案、以 length 結束 —— 要講清楚是額度被思考用完，不是「空回應」。"""
    lines = _sse(*[{"choices": [{"delta": {"reasoning_content": "想" * 50}}]} for _ in range(3)],
                 {"choices": [{"delta": {}, "finish_reason": "length"}]})
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([_Resp(lines)], seen))
    with pytest.raises(ai_mod.AIError) as ei:
        await ai_mod._stream_once("http://llm/v1/chat/completions", {"max_tokens": 6000}, 5.0,
                                  _noop, provider="openai")
    msg = str(ei.value)
    assert "思考" in msg and "length" in msg
    assert "150" in msg, "思考了幾個字要講出來"
    assert "6000" in msg, "額度多少要講出來"


@pytest.mark.anyio
async def test_a_normal_answer_after_thinking_is_still_returned(monkeypatch) -> None:
    lines = _sse({"choices": [{"delta": {"reasoning_content": "hmm"}}]},
                 {"choices": [{"delta": {"content": '{"findings": []}'}}]},
                 {"choices": [{"delta": {}, "finish_reason": "stop"}]})
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([_Resp(lines)], seen))
    out = await ai_mod._stream_once("http://llm/v1/chat/completions", {}, 5.0, _noop,
                                    provider="openai")
    assert out == '{"findings": []}'


@pytest.fixture(autouse=True)
def _forget_rejections():
    ai_mod._REJECTED_CONTROLS.clear()
    yield
    ai_mod._REJECTED_CONTROLS.clear()


URL = "http://192.0.2.10:8081/v1/chat/completions"


@pytest.mark.anyio
async def test_only_the_control_the_server_names_is_dropped(monkeypatch) -> None:
    """LiteLLM 這類閘道預設拒絕它不認得的欄位（2026-09-30，jt-doc-tools 同一天踩到）。以前只要一個被拒，
    三個一起拿掉 —— 連 LiteLLM 認得、會轉成 Ollama `think:false` 的 reasoning_effort 也拿掉了，
    重送的請求完全沒關思考，gemma4 每次先寫上萬字。現在只拿掉被點名的，可以連續拿好幾個。"""
    ok = _sse({"choices": [{"delta": {"content": "{}"}}]},
              {"choices": [{"delta": {}, "finish_reason": "stop"}]})
    r1 = _Resp([], status=400, text='{"error":{"message":"Unrecognized request argument supplied: '
                                    'chat_template_kwargs"}}')
    r2 = _Resp([], status=400, text="litellm.UnsupportedParamsError: ollama_chat does not support "
                                    "parameters: ['thinking_budget_tokens'], for model=gemma4:26b")
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([r1, r2, _Resp(ok)], seen))
    out = await ai_mod._raw_chat_streamed(URL, _body(_cfg()), 5.0, _noop, provider="openai")
    assert out == "{}"
    assert "chat_template_kwargs" not in seen[1]
    assert "thinking_budget_tokens" in seen[1]
    assert seen[2].get("reasoning_effort") == "none"                 # 閘道認得的那個一直都在
    assert not {"chat_template_kwargs", "thinking_budget_tokens"} & set(seen[2])


@pytest.mark.anyio
async def test_a_rejection_is_remembered_for_that_server_and_model(monkeypatch) -> None:
    """記住這台伺服器、這個模型不收哪些欄位：以後的請求一開始就不送，不必每次先失敗一次（延遲加倍）。"""
    ok = _sse({"choices": [{"delta": {"content": "{}"}}]},
              {"choices": [{"delta": {}, "finish_reason": "stop"}]})
    rejected = _Resp([], status=400, text="does not support parameters: ['thinking_budget_tokens']")
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([rejected, _Resp(ok)], seen))
    await ai_mod._raw_chat_streamed(URL, _body(_cfg()), 5.0, _noop, provider="openai")
    again = _body(_cfg())
    assert "thinking_budget_tokens" not in again
    assert again["reasoning_effort"] == "none"
    assert again["chat_template_kwargs"] == {"enable_thinking": False}
    other_model = _body(_cfg(chat_model="another"))
    assert other_model["thinking_budget_tokens"] == 0                # 別的模型不受影響


@pytest.mark.anyio
async def test_non_streamed_path_drops_only_the_named_control(monkeypatch) -> None:
    sent: list[dict[str, Any]] = []

    class _R:
        def __init__(self, status: int, text: str = "", payload: Any = None):
            self.status_code, self.text, self._p = status, text, payload

        def json(self):
            return self._p
    script = iter([_R(422, "Extra inputs are not permitted: thinking_budget_tokens"),
                   _R(200, payload={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})])

    async def _fake_request(method, url, **kw):
        sent.append(dict(kw["json"]))
        return next(script)
    monkeypatch.setattr(ai_mod, "safe_request", _fake_request)

    async def _get_cfg(_s):
        return _cfg(provider="openai")
    from app.services import system_config
    monkeypatch.setattr(system_config, "get_llm_config", _get_cfg)
    assert await ai_mod.raw_chat(None, "hi", no_thinking=True) == "ok"
    assert "thinking_budget_tokens" in sent[0]
    assert "thinking_budget_tokens" not in sent[1]
    assert sent[1]["reasoning_effort"] == "none"


@pytest.mark.anyio
async def test_other_400s_are_not_retried(monkeypatch) -> None:
    rejected = _Resp([], status=400, text='{"error":{"message":"context length exceeded"}}')
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake([rejected], seen))
    with pytest.raises(ai_mod.AIError, match="context length"):
        await ai_mod._raw_chat_streamed("http://llm/v1/chat/completions", _body(_cfg()), 5.0,
                                        _noop, provider="openai")
    assert len(seen) == 1


def test_non_streamed_reply_cut_off_while_thinking_is_reported() -> None:
    data = {"choices": [{"message": {"content": "", "reasoning_content": "想" * 200},
                         "finish_reason": "length"}]}
    with pytest.raises(ai_mod.AIError, match="思考"):
        ai_mod._answer_or_explain(data, max_tokens=6000)
    ok = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}
    assert ai_mod._answer_or_explain(ok, max_tokens=6000) == "{}"
    ollama = {"message": {"content": "x"}, "done_reason": "stop"}
    assert ai_mod._answer_or_explain(ollama, max_tokens=None) == "x"
