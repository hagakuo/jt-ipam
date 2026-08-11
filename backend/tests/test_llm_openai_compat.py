"""OpenAI 相容端點。

為什麼加：原本只支援 Ollama，而且路徑是寫死的（`/api/chat`、`/api/embeddings`）。
改成可選 OpenAI 相容格式之後，同一份設定可以接 ChatGPT、vLLM、LM Studio、OpenRouter
等一大票服務 —— Ollama 自己也提供 `/v1` 相容層。

**預設仍是 Ollama。** 這個專案的賣點是「自架 LLM，資料不外流」，接雲端等於把網段、
主機名稱、拓樸送到外部服務 —— 那是使用者要明確選擇的事，不是升版就自動改變的行為。
"""
from __future__ import annotations

import pytest
from app.services import ai as ai_mod


class _Resp:
    def __init__(self, status: int, payload: dict | None = None, text: str = ""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


OPENAI_CHAT = {
    "choices": [{"message": {"role": "assistant", "content": "你好"}, "finish_reason": "stop"}],
    "model": "gpt-4o-mini",
}
OLLAMA_CHAT = {"message": {"role": "assistant", "content": "你好"}, "done": True}


def test_default_provider_is_ollama():
    """沒設定就維持 Ollama —— 升版不該把資料改送到外部。"""
    from app.services.system_config import LLMConfig
    cfg = LLMConfig(enabled=True, url="http://x:11434", embedding_model="e",
                    chat_model="c", timeout=30.0)
    assert getattr(cfg, "provider", "ollama") == "ollama"


def test_chat_url_differs_by_provider():
    assert ai_mod.chat_url("http://x:11434", "ollama").endswith("/api/chat")
    assert ai_mod.chat_url("https://api.openai.com/v1", "openai").endswith("/chat/completions")


def test_openai_base_url_keeps_an_existing_v1():
    """使用者填 https://api.openai.com/v1 時不可以變成 /v1/v1/chat/completions。"""
    u = ai_mod.chat_url("https://api.openai.com/v1", "openai")
    assert u.count("/v1") == 1


def test_openai_base_url_without_v1_gets_one():
    u = ai_mod.chat_url("https://llm.example.test", "openai")
    assert u == "https://llm.example.test/v1/chat/completions"


def test_reply_parsing_handles_both_shapes():
    """兩家的回應結構不同：Ollama 是 message、OpenAI 是 choices[0].message。"""
    assert ai_mod.extract_reply(OLLAMA_CHAT, "ollama")["content"] == "你好"
    assert ai_mod.extract_reply(OPENAI_CHAT, "openai")["content"] == "你好"


def test_openai_reply_without_choices_is_not_a_crash():
    """服務回了非預期結構時要給可讀錯誤，不是 IndexError 五百。"""
    assert ai_mod.extract_reply({}, "openai") == {}


def test_api_key_header_only_for_openai():
    assert ai_mod.auth_headers("openai", "sk-abc")["Authorization"] == "Bearer sk-abc"
    assert "Authorization" not in ai_mod.auth_headers("ollama", "sk-abc")


def test_no_key_means_no_header():
    """本地 vLLM／LM Studio 多半不需要金鑰 —— 沒填就不要送空的 Bearer。"""
    assert "Authorization" not in ai_mod.auth_headers("openai", None)
    assert "Authorization" not in ai_mod.auth_headers("openai", "")


def test_embedding_url_differs_by_provider():
    assert ai_mod.embedding_url("http://x:11434", "ollama").endswith("/api/embeddings")
    assert ai_mod.embedding_url("https://api.openai.com/v1", "openai").endswith("/embeddings")


@pytest.mark.parametrize("provider", ["ollama", "openai"])
def test_options_are_provider_appropriate(provider):
    """Ollama 的 num_ctx 等參數走 options；OpenAI 沒有這個欄位，送過去會被拒絕。"""
    from app.services.system_config import LLMConfig
    cfg = LLMConfig(enabled=True, url="http://x", embedding_model="e", chat_model="c",
                    timeout=30.0, num_ctx=8192)
    body = ai_mod.chat_body(cfg, provider, messages=[{"role": "user", "content": "hi"}],
                            tools=[])
    if provider == "ollama":
        assert body["options"]["num_ctx"] == 8192
    else:
        assert "options" not in body


def test_models_url_differs_by_provider():
    """設定頁的模型下拉是靠這支端點填的。

    路徑寫死 `/api/tags` 的話，接 OpenAI 相容端點時下拉會是空的 —— 而且不會報錯，
    使用者只會看到「沒有模型」，完全猜不到原因。
    """
    assert ai_mod.models_url("http://x:11434", "ollama").endswith("/api/tags")
    assert ai_mod.models_url("https://api.openai.com/v1", "openai") == \
        "https://api.openai.com/v1/models"


def test_model_list_parsing_handles_both_shapes():
    """Ollama 回 {"models":[{"name":...}]}，OpenAI 回 {"data":[{"id":...}]}。"""
    ollama = {"models": [{"name": "gemma3:27b",
                          "details": {"family": "gemma3", "parameter_size": "27B"}}]}
    openai = {"data": [{"id": "gpt-4o-mini", "owned_by": "openai"},
                       {"id": "text-embedding-3-small", "owned_by": "openai"}]}
    assert [m["name"] for m in ai_mod.parse_models(ollama, "ollama")] == ["gemma3:27b"]
    assert ai_mod.parse_models(ollama, "ollama")[0]["parameter_size"] == "27B"
    names = [m["name"] for m in ai_mod.parse_models(openai, "openai")]
    assert names == ["gpt-4o-mini", "text-embedding-3-small"]


def test_model_list_of_an_unexpected_shape_is_empty_not_a_crash():
    assert ai_mod.parse_models({}, "openai") == []
    assert ai_mod.parse_models({"data": "nope"}, "openai") == []


@pytest.mark.anyio
async def test_api_key_is_not_stored_in_clear_text(db_session):
    """金鑰不能明文躺在 system_settings。

    這個專案其他所有機密（MCP 金鑰、Zulip、防火牆 token、憑證私鑰）都是 AES-GCM
    加密後才進 DB；LLM 金鑰是雲端服務的付費憑證，同一個標準。DB 備份、跨機搬移、
    誤開的 psql 都看得到明文的話，加密其他欄位就沒有意義。
    """
    from app.models.system_setting import SystemSetting
    from app.services.system_config import LLM_KEY, get_llm_config, set_llm_config

    await set_llm_config(db_session, provider="openai", api_key="sk-super-secret-123")
    await db_session.flush()
    row = await db_session.get(SystemSetting, LLM_KEY)
    assert "sk-super-secret-123" not in str(row.value)
    assert "api_key" not in row.value          # 明文欄位名也不該存在

    cfg = await get_llm_config(db_session)     # 讀回來仍要是可用的明文
    assert cfg.api_key == "sk-super-secret-123"
    assert cfg.provider == "openai"


@pytest.mark.anyio
async def test_clearing_the_api_key_removes_the_stored_secret(db_session):
    from app.models.system_setting import SystemSetting
    from app.services.system_config import LLM_KEY, get_llm_config, set_llm_config

    await set_llm_config(db_session, provider="openai", api_key="sk-abc")
    await set_llm_config(db_session, api_key="")
    await db_session.flush()
    row = await db_session.get(SystemSetting, LLM_KEY)
    assert "sk-abc" not in str(row.value)
    assert not (await get_llm_config(db_session)).api_key


def _cfg(**kw):
    from app.services.system_config import LLMConfig
    base = dict(enabled=True, url="http://x", embedding_model="e", chat_model="c", timeout=30.0)
    base.update(kw)
    return LLMConfig(**base)


def test_json_mode_body_is_provider_appropriate():
    """AI 巡檢用的 JSON 模式：四個欄位全是 Ollama 專屬。

    `options` / `format` / `think` / `num_predict` 送給 OpenAI 相容端點會被打回
    400（未知參數），而巡檢是背景批次 —— 失敗只會留在 last_error 裡，沒有人在看畫面。
    """
    cfg = _cfg(num_ctx=8192)
    o = ai_mod.json_chat_body(cfg, "ollama", prompt="hi", stream=False, force_json=True,
                              max_output_tokens=2000, num_ctx=16384, no_thinking=True)
    assert o["format"] == "json"
    assert o["think"] is False
    assert o["options"]["num_predict"] == 2000
    assert o["options"]["num_ctx"] == 16384

    a = ai_mod.json_chat_body(cfg, "openai", prompt="hi", stream=False, force_json=True,
                              max_output_tokens=2000, num_ctx=16384, no_thinking=True)
    assert "options" not in a and "format" not in a and "think" not in a
    assert a["response_format"] == {"type": "json_object"}
    assert a["max_tokens"] == 2000


def test_json_mode_without_a_limit_sends_no_limit():
    a = ai_mod.json_chat_body(_cfg(), "openai", prompt="hi", stream=False, force_json=False,
                              max_output_tokens=None, num_ctx=None, no_thinking=False)
    assert "max_tokens" not in a and "response_format" not in a


def test_error_messages_name_the_provider_actually_called():
    """回「Ollama chat 401」但其實打的是 OpenAI，只會把人送去查錯的地方。"""
    assert ai_mod.provider_label("openai") != ai_mod.provider_label("ollama")
    assert "Ollama" not in ai_mod.provider_label("openai")


def test_embedding_request_and_response_shapes_differ():
    """Ollama 收 `prompt` 回 `embedding`；OpenAI 收 `input` 回 `data[0].embedding`。

    這條路徑是語意搜尋在用的，兩邊都不對就等於整個功能靜靜地不能用。
    """
    cfg = _cfg(embedding_model="m")
    assert ai_mod.embedding_body(cfg, "ollama", "hello")["prompt"] == "hello"
    a = ai_mod.embedding_body(cfg, "openai", "hello")
    assert a["input"] == "hello" and "prompt" not in a

    assert ai_mod.extract_embedding({"embedding": [0.1, 0.2]}, "ollama") == [0.1, 0.2]
    assert ai_mod.extract_embedding({"data": [{"embedding": [0.3]}]}, "openai") == [0.3]


def test_embedding_of_an_unexpected_shape_is_empty_not_a_crash():
    assert ai_mod.extract_embedding({}, "openai") == []
    assert ai_mod.extract_embedding({"data": []}, "openai") == []


@pytest.mark.anyio
async def test_upgrading_an_existing_install_stays_on_ollama(db_session):
    """升級既有站台：設定裡沒有 provider 這個欄位。

    這種欄位「不存在」的舊資料，如果被判成空值再套上某個預設，行為就會在升版當下
    悄悄改變 —— 而這個專案改變的會是「資料送去哪裡」。舊設定必須原封不動留在 Ollama。
    """
    from app.models.system_setting import SystemSetting
    from app.services.system_config import LLM_KEY, _bust, get_llm_config

    # 模擬升級前的資料列：只有舊版寫得出來的欄位
    row = await db_session.get(SystemSetting, LLM_KEY)
    if row is None:
        row = SystemSetting(key=LLM_KEY, value={})
        db_session.add(row)
    row.value = {"enabled": True, "url": "http://192.0.2.10:11434",
                 "chat_model": "gemma3:27b", "embedding_model": "qwen3-embedding",
                 "timeout": 120.0, "num_ctx": 8192}
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(row, "value")
    await db_session.flush()
    _bust()

    cfg = await get_llm_config(db_session)
    assert cfg.provider == "ollama"          # 沒有欄位＝維持自架，不是換供應商
    assert cfg.api_key is None
    # 原本的設定一項都不能掉
    assert cfg.url == "http://192.0.2.10:11434"
    assert cfg.chat_model == "gemma3:27b"
    assert cfg.embedding_model == "qwen3-embedding"
    assert cfg.timeout == 120.0 and cfg.num_ctx == 8192
    # 而且照舊打 Ollama 的路徑
    from app.services import ai as _ai
    assert _ai.chat_url(cfg.url, cfg.provider) == "http://192.0.2.10:11434/api/chat"


@pytest.mark.anyio
async def test_changing_another_setting_does_not_touch_the_provider(db_session):
    """改別的設定（例如逾時）不可以順手把供應商或金鑰洗掉。"""
    from app.services.system_config import get_llm_config, set_llm_config

    await set_llm_config(db_session, provider="openai", api_key="sk-keepme",
                         url="https://api.openai.com/v1")
    await set_llm_config(db_session, timeout=90.0)
    cfg = await get_llm_config(db_session)
    assert cfg.provider == "openai" and cfg.api_key == "sk-keepme" and cfg.timeout == 90.0
