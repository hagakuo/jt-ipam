"""串流回應的兩種格式：Ollama 的逐行 JSON 與 OpenAI 相容的 SSE。

GitHub issue #36：接 OpenAI 相容服務時，手動執行 AI 巡檢一律「6/6 批分析失敗：
（空回應）」，排程執行卻正常。差別在手動執行走串流 —— 而串流解析直接把每一行丟給
`json.loads`。SSE 的每一行長這樣：`data: {...}`，加了前綴就不是 JSON，全部被
`except ValueError: continue` 靜靜跳過，最後回傳空字串。模型其實有回答，是我們丟掉的。

同一個問題也在 AI 對話裡：`chat_stream` 解析不到任何內容與工具呼叫，於是走「強制作答」
的後援 —— 畫面上有回答，但**模型從頭到尾沒有呼叫工具查資料**。這比報錯更糟：
看起來正常，內容卻沒有根據。
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import pytest
from app.services import ai as ai_mod


def _sse(*chunks: dict[str, Any], done: bool = True) -> list[str]:
    lines: list[str] = [": keep-alive comment", ""]
    for c in chunks:
        lines += [f"data: {json.dumps(c, ensure_ascii=False)}", ""]
    if done:
        lines += ["data: [DONE]", ""]
    return lines


def _ndjson(*chunks: dict[str, Any]) -> list[str]:
    return [json.dumps(c, ensure_ascii=False) for c in chunks]


class _StreamResp:
    def __init__(self, lines: list[str], status: int = 200):
        self.status_code = status
        self._lines = lines

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def aread(self):
        return b""


def _fake_stream(script: list[list[str]], seen: list[dict[str, Any]]):
    """每呼叫一次回下一組行；把送出的 body 記下來。"""
    calls = iter(script)

    @asynccontextmanager
    async def _stream(method, url, *, headers=None, json=None, timeout=None):
        seen.append({"url": url, "body": json})
        yield _StreamResp(next(calls))
    return _stream


# ── 逐行解析 ──────────────────────────────────────────────────────────────

def test_sse_lines_are_unwrapped_and_markers_ignored():
    assert ai_mod._stream_payload('data: {"a": 1}') == {"a": 1}
    assert ai_mod._stream_payload('data:{"a": 1}') == {"a": 1}           # 冒號後可以沒有空白
    assert ai_mod._stream_payload("data: [DONE]") == {"done": True}
    for ignored in ("", "   ", ": comment", "event: message", "id: 7", "retry: 3000", "not json"):
        assert ai_mod._stream_payload(ignored) is None, ignored


def test_ollama_lines_still_parse():
    assert ai_mod._stream_payload('{"message": {"content": "hi"}, "done": false}') == {
        "message": {"content": "hi"}, "done": False}


def test_deltas_are_normalised_for_both_formats():
    o = ai_mod._stream_delta({"choices": [{"delta": {"content": "x", "reasoning_content": "t"}}]})
    assert (o.content, o.thinking, o.done) == ("x", "t", False)
    fin = ai_mod._stream_delta({"choices": [{"delta": {}, "finish_reason": "stop"}]})
    assert fin.done and fin.done_reason == "stop"
    ol = ai_mod._stream_delta({"message": {"content": "y", "thinking": "u"}, "done": True,
                               "done_reason": "length"})
    assert (ol.content, ol.thinking, ol.done, ol.done_reason) == ("y", "u", True, "length")
    assert ai_mod._stream_delta({"done": True}).done            # [DONE] 的哨兵
    err = ai_mod._stream_delta({"error": {"message": "context length exceeded"}})
    assert "context length exceeded" in err.error


def test_openai_tool_call_fragments_are_joined_by_index():
    buf = ai_mod._ToolCallBuffer()
    buf.add([{"index": 0, "id": "call_a", "type": "function",
              "function": {"name": "search_ip", "arguments": '{"q": "19'}}])
    buf.add([{"index": 0, "function": {"arguments": '2.0.2.10"}'}},
             {"index": 1, "id": "call_b", "function": {"name": "list_racks", "arguments": "{}"}}])
    calls = buf.calls()
    assert [c["id"] for c in calls] == ["call_a", "call_b"]
    assert calls[0]["function"] == {"name": "search_ip", "arguments": '{"q": "192.0.2.10"}'}
    assert calls[0]["type"] == "function"


def test_ollama_tool_calls_arrive_whole_and_are_kept():
    buf = ai_mod._ToolCallBuffer()
    buf.add([{"function": {"name": "search_ip", "arguments": {"q": "192.0.2.10"}}}])
    assert buf.calls() == [{"function": {"name": "search_ip", "arguments": {"q": "192.0.2.10"}}}]


# ── 巡檢用的 _stream_once（#36 的重現）────────────────────────────────────

@pytest.mark.anyio
async def test_stream_once_reads_sse_content(monkeypatch):
    seen: list[dict[str, Any]] = []
    lines = _sse({"choices": [{"delta": {"role": "assistant"}}]},
                 {"choices": [{"delta": {"content": '{"findings"'}}]},
                 {"choices": [{"delta": {"content": ": []}"}}]},
                 {"choices": [{"delta": {}, "finish_reason": "stop"}]})
    monkeypatch.setattr(ai_mod, "safe_stream", _fake_stream([lines], seen))
    got: list[tuple[str, str]] = []

    async def on_chunk(piece: str, kind: str) -> None:
        got.append((kind, piece))

    out = await ai_mod._stream_once("http://llm/v1/chat/completions", {}, 5.0, on_chunk, provider="openai")
    assert out == '{"findings": []}', "SSE 內容被丟掉了（#36）"
    assert ("content", '{"findings"') in got


@pytest.mark.anyio
async def test_stream_once_still_reads_ollama(monkeypatch):
    seen: list[dict[str, Any]] = []
    lines = _ndjson({"message": {"content": "a"}, "done": False},
                    {"message": {"content": "b"}, "done": True})
    monkeypatch.setattr(ai_mod, "safe_stream", _fake_stream([lines], seen))

    async def on_chunk(piece: str, kind: str) -> None:
        return None

    assert await ai_mod._stream_once("http://llm/api/chat", {}, 5.0, on_chunk) == "ab"


@pytest.mark.anyio
async def test_stream_once_surfaces_an_sse_error_event(monkeypatch):
    seen: list[dict[str, Any]] = []
    lines = _sse({"error": {"message": "model not found"}}, done=False)
    monkeypatch.setattr(ai_mod, "safe_stream", _fake_stream([lines], seen))

    async def on_chunk(piece: str, kind: str) -> None:
        return None

    with pytest.raises(ai_mod.AIError, match="model not found"):
        await ai_mod._stream_once("http://llm/v1/chat/completions", {}, 5.0, on_chunk, provider="openai")


# ── 對話：在 OpenAI 相容服務上真的會呼叫工具 ───────────────────────────────

@pytest.mark.anyio
async def test_chat_stream_uses_tools_on_an_openai_endpoint(monkeypatch, db_session, admin_user):
    from app.services.system_config import LLMConfig

    cfg = LLMConfig(enabled=True, url="http://llm:8000", embedding_model="e",
                    chat_model="m", timeout=30.0, provider="openai")

    async def _cfg(_s):
        return cfg
    monkeypatch.setattr("app.services.system_config.get_llm_config", _cfg)

    ran: list[dict[str, Any]] = []

    async def _fake_run(session, user, tool_calls):
        ran.extend(tool_calls)
        return [{"role": "tool", "name": "list_racks", "tool_call_id": tool_calls[0]["id"],
                 "content": '{"items": []}'}]
    monkeypatch.setattr(ai_mod, "_run_tool_calls", _fake_run)

    round1 = _sse({"choices": [{"delta": {"tool_calls": [
                      {"index": 0, "id": "call_1", "type": "function",
                       "function": {"name": "list_racks", "arguments": '{"lim'}}]}}]},
                  {"choices": [{"delta": {"tool_calls": [
                      {"index": 0, "function": {"arguments": 'it": 5}'}}]}}]},
                  {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]})
    round2 = _sse({"choices": [{"delta": {"content": "目前沒有機櫃。"}}]},
                  {"choices": [{"delta": {}, "finish_reason": "stop"}]})
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(ai_mod, "safe_stream", _fake_stream([round1, round2], seen))

    events = [ev async for ev in ai_mod.chat_stream(
        db_session, user=admin_user, messages=[{"role": "user", "content": "有幾個機櫃？"}],
        locale="zh-TW")]

    assert ran and ran[0]["function"]["name"] == "list_racks", "OpenAI 串流裡的工具呼叫沒有被執行"
    assert json.loads(ran[0]["function"]["arguments"]) == {"limit": 5}
    done = [e for e in events if e.get("type") == "done"]
    assert done and "目前沒有機櫃" in done[0]["answer"]
    for call in seen:
        assert "options" not in call["body"], "Ollama 專屬的 options 被送到 OpenAI 端點"
    # 第二輪送回去的對話：assistant 的 tool_calls 要有 id，tool 訊息要對得上
    convo = seen[1]["body"]["messages"]
    asst = next(m for m in convo if m.get("role") == "assistant" and m.get("tool_calls"))
    assert asst["tool_calls"][0]["id"] == "call_1"
    tool_msg = next(m for m in convo if m.get("role") == "tool")
    assert tool_msg["tool_call_id"] == "call_1"


@pytest.mark.anyio
async def test_tool_results_carry_the_call_id(db_session, admin_user):
    out = await ai_mod._run_tool_calls(db_session, admin_user, [
        {"id": "call_x", "type": "function", "function": {"name": "no_such_tool", "arguments": "{}"}},
        {"function": {"name": "no_such_tool", "arguments": {}}},
    ])
    assert out[0]["tool_call_id"] == "call_x"
    assert "tool_call_id" not in out[1], "Ollama 格式沒有 id，就不要憑空生一個"


def test_inline_tool_calls_get_ids_only_for_openai():
    calls = [{"function": {"name": "search_ip", "arguments": {"q": "192.0.2.10"}}}]
    oa = ai_mod._with_call_ids(calls, "openai")
    assert oa[0]["id"] and oa[0]["type"] == "function"
    assert json.loads(oa[0]["function"]["arguments"]) == {"q": "192.0.2.10"}
    assert ai_mod._with_call_ids(calls, "ollama") == calls


# ── #37：對話泡泡的服務標籤 ─────────────────────────────────────────────

@pytest.mark.anyio
@pytest.mark.parametrize("provider", ["openai", "ollama"])
async def test_model_info_reports_the_provider(monkeypatch, db_session, admin_user, provider):
    """泡泡上寫死「本地 Ollama」，接 OpenAI 相容服務也一樣（GitHub issue #37）。
    前端要知道實際的服務類型；OpenAI 相容服務沒有 Ollama 的 /api/show，別去打它。"""
    from app.api.v1.endpoints import ai as ai_ep
    from app.services.system_config import LLMConfig

    cfg = LLMConfig(enabled=True, url="http://llm:8000", embedding_model="e",
                    chat_model="m", timeout=30.0, provider=provider)

    async def _cfg(_s):
        return cfg
    monkeypatch.setattr("app.services.system_config.get_llm_config", _cfg)
    called: list[str] = []

    class _R:
        status_code = 200

        def json(self):
            return {"details": {"family": "gemma", "parameter_size": "27B"}, "model_info": {}}

    async def _req(method, url, **kw):
        called.append(url)
        return _R()
    monkeypatch.setattr("app.core.safe_http.safe_request", _req)

    out = await ai_ep.model_info(admin_user, db_session, None)
    assert out["provider"] == provider
    if provider == "openai":
        assert called == [], "OpenAI 相容服務沒有 /api/show"
    else:
        assert out.get("parameter_size") == "27B"
