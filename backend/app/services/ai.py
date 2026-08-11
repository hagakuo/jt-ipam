"""語意搜尋與對話：預設走自架 Ollama，本地推論不外送（規格 §11.1 / §11.3）。

設計：
- 透過 LLM HTTP API 取得 embedding（Ollama `/api/embeddings`、OpenAI 相容 `/v1/embeddings`）
- 寫入時 / 排程時對 Subnet / IPAddress / Device 的 description 計算向量
- /api/v1/search/semantic?q=... 走 cosine 相似度（pgvector ivfflat）

供應商：`ollama`（預設）或 `openai`（OpenAI 相容端點）。**預設不變是刻意的** ——
接外部服務等於把網段、主機名稱、拓樸送出去，那要使用者明確選擇。路徑、回應結構、
可送的參數三處都不同，各自在 `chat_url` / `extract_reply` / `chat_body` 處理。

OWASP A04 / A06：LLM URL 走 safe_request（私網允許）；任何回到該端點之外的呼叫都會被擋住。
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.safe_http import UnsafeOutboundURL, safe_request, safe_stream


class AINotConfigured(RuntimeError):
    pass


class AIError(RuntimeError):
    pass


# 單一工具結果回填上下文的字元上限（避免超大清單拖慢/逾時模型）
_TOOL_RESULT_CAP = 12000


def _chat_options(cfg: Any) -> dict[str, Any]:
    """Ollama 對話請求的 options：低溫度減少亂插字；num_ctx 有設才帶（None＝用模型/Ollama 預設）。"""
    opts: dict[str, Any] = {"temperature": 0.2}
    n = getattr(cfg, "num_ctx", None)
    if n:
        opts["num_ctx"] = int(n)
    return opts

# ── 供應商抽象（Ollama 原生 vs OpenAI 相容）────────────────────────────
#
# 預設 ollama。改成可選 OpenAI 相容之後，同一份設定能接 ChatGPT、vLLM、LM Studio、
# OpenRouter 等 —— Ollama 自己也提供 /v1 相容層。
#
# **這是資料出境的決定**：本專案的賣點是「自架 LLM、資料不外流」，接雲端等於把網段、
# 主機名稱、拓樸送給外部服務。所以預設不變，要使用者明確選擇。

def _openai_base(url: str) -> str:
    """OpenAI 相容的 base。使用者填 `.../v1` 或不填都要正確 —— 直接接字串會變成
    `/v1/v1/chat/completions`，那種錯誤只會在實際呼叫時才炸。"""
    u = url.rstrip("/")
    return u if u.endswith("/v1") else f"{u}/v1"


def chat_url(url: str, provider: str) -> str:
    if provider == "openai":
        return f"{_openai_base(url)}/chat/completions"
    return f"{url.rstrip('/')}/api/chat"


def embedding_url(url: str, provider: str) -> str:
    if provider == "openai":
        return f"{_openai_base(url)}/embeddings"
    return f"{url.rstrip('/')}/api/embeddings"


def models_url(url: str, provider: str) -> str:
    if provider == "openai":
        return f"{_openai_base(url)}/models"
    return f"{url.rstrip('/')}/api/tags"


def parse_models(data: dict[str, Any], provider: str) -> list[dict[str, Any]]:
    """把模型清單正規化成設定頁下拉要的形狀。

    Ollama 回 `{"models":[{"name":..., "details":{...}}]}`，
    OpenAI 相容回 `{"data":[{"id":...}]}`（沒有大小／參數量這些資訊）。
    結構不如預期時回空清單，不要讓設定頁整頁掛掉。
    """
    if provider == "openai":
        rows = data.get("data")
        if not isinstance(rows, list):
            return []
        return [
            {"name": m.get("id"), "size": None, "modified_at": None,
             "family": m.get("owned_by"), "parameter_size": None}
            for m in rows if isinstance(m, dict) and m.get("id")
        ]
    rows = data.get("models")
    if not isinstance(rows, list):
        return []
    return [
        {"name": m.get("name"), "size": m.get("size"), "modified_at": m.get("modified_at"),
         "family": (m.get("details") or {}).get("family"),
         "parameter_size": (m.get("details") or {}).get("parameter_size")}
        for m in rows if isinstance(m, dict)
    ]


def auth_headers(provider: str, api_key: str | None) -> dict[str, str]:
    """OpenAI 相容用 Bearer；Ollama 不需要。

    沒填金鑰就不要送空的 Bearer —— 本地 vLLM／LM Studio 多半不需要金鑰，
    送一個空的反而會被判成認證失敗。
    """
    h = {"Content-Type": "application/json"}
    if provider == "openai" and api_key:
        h["Authorization"] = f"Bearer {api_key}"
    return h


def extract_reply(data: dict[str, Any], provider: str) -> dict[str, Any]:
    """把回應正規化成 `{"role":..., "content":..., "tool_calls":[...]}`。

    兩家結構不同：Ollama 是 `message`，OpenAI 是 `choices[0].message`。
    結構不如預期時回空 dict，不要讓 IndexError 變成 500。
    """
    if provider == "openai":
        choices = data.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return {}
        return choices[0].get("message") or {}
    return data.get("message") or {}


def chat_body(cfg: Any, provider: str, *, messages: list[Any], tools: list[Any]) -> dict[str, Any]:
    """組請求主體。`options`（num_ctx 等）是 Ollama 專屬 —— 送給 OpenAI 端點會被拒絕。"""
    body: dict[str, Any] = {
        "model": cfg.chat_model,
        "messages": messages,
        "stream": False,
    }
    if tools:
        body["tools"] = tools
    if provider == "ollama":
        body["options"] = _chat_options(cfg)
    return body


def provider_label(provider: str) -> str:
    """錯誤訊息裡的供應商名稱。

    回「Ollama chat 401」但實際打的是 OpenAI 端點，只會把人送去查錯的地方。
    """
    return "OpenAI-compatible" if provider == "openai" else "Ollama"


def json_chat_body(
    cfg: Any,
    provider: str,
    *,
    prompt: str,
    stream: bool,
    force_json: bool,
    max_output_tokens: int | None,
    num_ctx: int | None,
    no_thinking: bool,
    model: str | None = None,
) -> dict[str, Any]:
    """JSON 模式（AI 巡檢用）的請求主體。

    四個控制欄位在兩家的名字完全不同，而且送錯會被打回 400：
    `options` / `format` / `think` / `num_predict` 是 Ollama 專屬，OpenAI 相容端點
    對應的是 `response_format` 與 `max_tokens`（`think`、上下文長度則沒有對應，
    只能省略）。巡檢是背景批次，失敗只會留在紀錄裡沒有人在看畫面 —— 更不能靠運氣。
    """
    body: dict[str, Any] = {
        "model": model or cfg.chat_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": stream,
    }
    if provider == "openai":
        if force_json:
            body["response_format"] = {"type": "json_object"}
        if max_output_tokens:
            body["max_tokens"] = int(max_output_tokens)
        return body
    options = _chat_options(cfg)
    if max_output_tokens:
        options = {**options, "num_predict": int(max_output_tokens)}
    if num_ctx:
        options = {**options, "num_ctx": int(num_ctx)}
    body["options"] = options
    if force_json:
        body["format"] = "json"
    if no_thinking:
        body["think"] = False
    return body




def embedding_body(cfg: Any, provider: str, text_in: str) -> dict[str, Any]:
    """Ollama 收 `prompt`，OpenAI 相容收 `input`。"""
    if provider == "openai":
        return {"model": cfg.embedding_model, "input": text_in}
    return {"model": cfg.embedding_model, "prompt": text_in}


def extract_embedding(data: dict[str, Any], provider: str) -> list[float]:
    """Ollama 回 `embedding`，OpenAI 相容回 `data[0].embedding`。

    取不到就回空清單，讓呼叫端統一報「沒有拿到向量」，而不是 KeyError／IndexError。
    """
    vec: Any
    if provider == "openai":
        rows = data.get("data")
        vec = rows[0].get("embedding") if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
    else:
        vec = data.get("embedding")
    return vec if isinstance(vec, list) else []



async def embed(session: AsyncSession, text_in: str) -> list[float]:
    """呼叫 Ollama 的 embedding endpoint。設定取自 system_settings (DB)，fallback 到 env。"""
    from app.services.system_config import get_llm_config
    cfg = await get_llm_config(session)
    if not cfg.enabled:
        raise AINotConfigured("LLM is disabled")
    url = embedding_url(cfg.url, cfg.provider)
    body = embedding_body(cfg, cfg.provider, text_in)
    try:
        resp = await safe_request(
            "POST", url,
            headers=auth_headers(cfg.provider, cfg.api_key),
            json=body, timeout=cfg.timeout,
        )
    except UnsafeOutboundURL as exc:
        raise AIError(f"SSRF guard: {exc}") from exc
    except httpx.HTTPError as exc:
        raise AIError(f"transport: {exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise AIError(f"{provider_label(cfg.provider)} {resp.status_code}: {resp.text[:200]}")
    vec = extract_embedding(resp.json(), cfg.provider)
    if not vec:
        raise AIError(f"{provider_label(cfg.provider)} returned no embedding")
    expected_dim = get_settings().embedding_dim
    if len(vec) != expected_dim:
        raise AIError(
            f"Embedding dim mismatch: got {len(vec)}, expected {expected_dim} "
            f"(adjust EMBEDDING_DIM or migration vector(N))"
        )
    return [float(x) for x in vec]


def _vector_literal(vec: list[float]) -> str:
    """pgvector 的字串字面值：'[0.1,0.2,...]'。"""
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


# ─────────────────── 寫入：對單一物件描述產生向量 ───────────────────


async def index_subnet(session: AsyncSession, subnet_id: str, description: str | None,
                       *, raise_on_error: bool = False) -> bool:
    """為一個 subnet 產 embedding 並寫入 vector 欄位；description 為空則清空。"""
    if not description:
        await session.execute(
            text("UPDATE subnets SET description_embedding = NULL WHERE id = :id"),
            {"id": subnet_id},
        )
        return True
    try:
        vec = await embed(session, description)
    except (AIError, AINotConfigured):
        # 單筆寫入路徑（存檔時順手索引）不因為 LLM 不通就讓存檔失敗；
        # 批次 reindex 則要知道原因，否則「全失敗」會被當成「沒事可做」。
        if raise_on_error:
            raise
        return False
    await session.execute(
        text("UPDATE subnets SET description_embedding = (:v)::vector WHERE id = :id"),
        {"v": _vector_literal(vec), "id": subnet_id},
    )
    return True


async def index_ip(session: AsyncSession, ip_id: str, description: str | None,
                   *, raise_on_error: bool = False) -> bool:
    if not description:
        await session.execute(
            text("UPDATE ip_addresses SET description_embedding = NULL WHERE id = :id"),
            {"id": ip_id},
        )
        return True
    try:
        vec = await embed(session, description)
    except (AIError, AINotConfigured):
        # 單筆寫入路徑（存檔時順手索引）不因為 LLM 不通就讓存檔失敗；
        # 批次 reindex 則要知道原因，否則「全失敗」會被當成「沒事可做」。
        if raise_on_error:
            raise
        return False
    await session.execute(
        text("UPDATE ip_addresses SET description_embedding = (:v)::vector WHERE id = :id"),
        {"v": _vector_literal(vec), "id": ip_id},
    )
    return True


async def index_device(session: AsyncSession, device_id: str, description: str | None,
                       *, raise_on_error: bool = False) -> bool:
    if not description:
        await session.execute(
            text("UPDATE devices SET description_embedding = NULL WHERE id = :id"),
            {"id": device_id},
        )
        return True
    try:
        vec = await embed(session, description)
    except (AIError, AINotConfigured):
        # 單筆寫入路徑（存檔時順手索引）不因為 LLM 不通就讓存檔失敗；
        # 批次 reindex 則要知道原因，否則「全失敗」會被當成「沒事可做」。
        if raise_on_error:
            raise
        return False
    await session.execute(
        text("UPDATE devices SET description_embedding = (:v)::vector WHERE id = :id"),
        {"v": _vector_literal(vec), "id": device_id},
    )
    return True


# ─────────────────── 查詢：跨表 cosine 最相近 ───────────────────


async def probe_embedding(session: AsyncSession) -> dict[str, Any]:
    """實際取一次向量，回報維度是否與資料庫欄位相符。

    設定頁上，嵌入模型選錯的唯一症狀是「語意搜尋永遠沒有結果」—— 沒有任何訊息會說
    是維度不合。這支就是把那件事講出來：模型回幾維、資料庫要幾維、通不通。
    """
    expected = get_settings().embedding_dim
    try:
        vec = await embed(session, "jt-ipam embedding dimension probe")
    except (AIError, AINotConfigured) as exc:
        return {"ok": False, "dim": None, "expected": expected, "error": str(exc)[:300]}
    return {"ok": len(vec) == expected, "dim": len(vec), "expected": expected, "error": None}


async def semantic_search(
    session: AsyncSession,
    *,
    user: Any,
    query: str,
    limit: int = 20,
) -> dict[str, Any]:
    """跨 subnets / ip_addresses / devices 的語意搜尋（cosine 距離，越小越像）。"""
    vec = await embed(session, query)
    vlit = _vector_literal(vec)

    sub_rows = (
        await session.execute(
            text(
                """
                SELECT id::text AS id, cidr::text AS label, description,
                       (description_embedding <=> (:v)::vector) AS distance
                  FROM subnets
                 WHERE description_embedding IS NOT NULL
                 ORDER BY description_embedding <=> (:v)::vector
                 LIMIT :limit
                """
            ),
            {"v": vlit, "limit": limit},
        )
    ).all()

    ip_rows = (
        await session.execute(
            text(
                """
                SELECT id::text AS id, host(ip)::text AS label,
                       hostname, description,
                       (description_embedding <=> (:v)::vector) AS distance
                  FROM ip_addresses
                 WHERE description_embedding IS NOT NULL
                 ORDER BY description_embedding <=> (:v)::vector
                 LIMIT :limit
                """
            ),
            {"v": vlit, "limit": limit},
        )
    ).all()

    dev_rows = (
        await session.execute(
            text(
                """
                SELECT id::text AS id, name AS label, description,
                       (description_embedding <=> (:v)::vector) AS distance
                  FROM devices
                 WHERE description_embedding IS NOT NULL
                 ORDER BY description_embedding <=> (:v)::vector
                 LIMIT :limit
                """
            ),
            {"v": vlit, "limit": limit},
        )
    ).all()

    from app.services.permission import filter_visible

    subnet_ids = [uuid.UUID(r.id) for r in sub_rows]
    ip_ids = [uuid.UUID(r.id) for r in ip_rows]
    device_ids = [uuid.UUID(r.id) for r in dev_rows]
    visible_subnet_ids = set(await filter_visible(
        session, user=user, object_type="subnet",
        object_ids=subnet_ids, required="read",
    ))
    visible_ip_ids = set(await filter_visible(
        session, user=user, object_type="ip",
        object_ids=ip_ids, required="read",
    ))
    visible_device_ids = set(await filter_visible(
        session, user=user, object_type="device",
        object_ids=device_ids, required="read",
    ))

    return {
        "query": query,
        "subnets": [
            {"id": r.id, "label": r.label, "description": r.description,
             "score": round(1 - float(r.distance), 4)}
            for r in sub_rows
            if uuid.UUID(r.id) in visible_subnet_ids
        ],
        "ip_addresses": [
            {"id": r.id, "label": r.label, "hostname": r.hostname,
             "description": r.description, "score": round(1 - float(r.distance), 4)}
            for r in ip_rows
            if uuid.UUID(r.id) in visible_ip_ids
        ],
        "devices": [
            {"id": r.id, "label": r.label, "description": r.description,
             "score": round(1 - float(r.distance), 4)}
            for r in dev_rows
            if uuid.UUID(r.id) in visible_device_ids
        ],
    }


# ─────────────────── Chat：自然語言 + tool use（Phase 4）───────────────────


_LANG_MAP = {
    "zh-TW": "Traditional Chinese (繁體中文，使用台灣用語)",
    "zh-CN": "Simplified Chinese (简体中文)",
    "en-US": "English",
    "en": "English",
    "ja": "Japanese (日本語)",
}


def _lang_instruction(locale: str | None) -> str:
    """根據使用者 UI locale 給出要求 LLM 用何語言回應的指令。"""
    name = _LANG_MAP.get(locale or "", None)
    if not name:
        # 未知 locale → 不強制；讓 LLM 跟著使用者輸入的語言
        return "Respond in the same language as the user's most recent message."
    return f"Always respond to the user in {name}, regardless of the language of tool outputs."


# 模型偶爾會把工具呼叫當成「文字」吐出來（而非結構化 tool_calls）——即使是支援工具呼叫的
# 模型也會偶發如此。常見痕跡：<tool_call>…</tool_call> 標記 / call:name(args) / JSON {"name":…,"arguments":…}
_TOOL_LEAK_RE = re.compile(
    r"</?tool_?call>"
    r"|\bcall\s*:\s*[A-Za-z_]\w*\s*\("
    r'|\{[^{}]*"name"\s*:\s*"[^"]+"[^{}]*"(?:arguments|parameters)"',
    re.I | re.S,
)


def _norm_tool(n: str) -> str:
    return re.sub(r"[^a-z0-9]", "", n.lower())


def _looks_like_tool_leak(content: str) -> bool:
    """內容看起來是「被當成文字吐出來的工具呼叫」而非正常答案。"""
    return bool(content and _TOOL_LEAK_RE.search(content))


def _parse_inline_args(raw: str) -> dict[str, Any]:
    """解析 gemma 式參數字串 `arg:</~/>value</~/>, n:3`（值內可能含冒號，如 MAC）。"""
    raw = raw.replace("</~/>", '"').replace("<~>", '"').strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
        except (ValueError, TypeError):
            pass
    args: dict[str, Any] = {}
    for part in re.split(r",(?![^{\[]*[}\]])", raw):
        part = part.strip()
        if not part:
            continue
        seps = [i for i in (part.find(":"), part.find("=")) if i >= 0]
        if not seps:
            continue
        cut = min(seps)
        key = part[:cut].strip().strip("\"'")
        val = part[cut + 1:].strip().strip("\"'")
        if not key:
            continue
        if re.fullmatch(r"-?\d+", val):
            args[key] = int(val)
        elif val.lower() in ("true", "false"):
            args[key] = val.lower() == "true"
        else:
            args[key] = val
    return args


def _inline_tool_calls(content: str, allowed: set[str] | None) -> list[dict[str, Any]]:
    """後援：模型偶發把工具呼叫寫成文字時，盡量還原成 Ollama 結構化 tool_calls。
    僅在偵測到 tool-call 痕跡、且名稱對得上已知（且該使用者可用）的工具時才接受，
    避免把一般文句誤判成呼叫。"""
    from app.mcp.tools import TOOLS
    if not _looks_like_tool_leak(content):
        return []
    known = {_norm_tool(n): n for n in TOOLS if allowed is None or n in allowed}
    found: list[tuple[str, dict[str, Any]]] = []
    # (a) JSON 物件 {"name": "...", "arguments"/"parameters": {...}}
    for m in re.finditer(
        r'\{[^{}]*?"name"\s*:\s*"([^"]+)"'
        r'(?:[^{}]*?"(?:arguments|parameters)"\s*:\s*(\{[^{}]*\}))?[^{}]*\}',
        content, re.S,
    ):
        real = known.get(_norm_tool(m.group(1)))
        if not real:
            continue
        args: dict[str, Any] = {}
        if m.group(2):
            try:
                args = json.loads(m.group(2))
            except (ValueError, TypeError):
                args = {}
        found.append((real, args))
    # (b) 函式式 `[call:]name(args)`（含 gemma 的 <toolcall> 標記）
    if not found:
        for m in re.finditer(r"(?:call\s*:\s*)?([A-Za-z_]\w*)\s*\(([^()]*)\)", content):
            real = known.get(_norm_tool(m.group(1)))
            if not real:
                continue
            found.append((real, _parse_inline_args(m.group(2))))
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, args in found:
        key = name + "|" + json.dumps(args, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append({"function": {"name": name, "arguments": args}})
        if len(out) >= 4:
            break
    return out


def _tool_leak_message(locale: str | None) -> str:
    """偵測到工具呼叫外洩、但無法還原執行時，給使用者的友善說明（取代原始亂碼）。

    注意：模型本身支援工具呼叫，只是這次偶發地把呼叫寫成了無法解析的文字 → 請使用者重試即可，
    不要誤導成「模型不支援」或叫他換模型。
    """
    if (locale or "").lower().startswith("en"):
        return (
            "This reply contained a tool call I couldn't parse, so no data was fetched. "
            "Please try again or rephrase your question."
        )
    return (
        "這次的回應裡有一段工具呼叫無法解析，因此沒有取得資料。請再試一次，或換個說法重新詢問。"
    )


async def chat(
    session: AsyncSession,
    *,
    user: Any,
    messages: list[dict[str, Any]],
    locale: str | None = None,
    max_iterations: int = 4,
    page_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """以 Ollama chat 模型 + jt-ipam tools 處理自然語言。

    流程：
      1. 把 IPAM tools 註冊表轉成 Ollama tools schema
      2. 用 system prompt 框定身份（jt-ipam 助手）
      3. 呼叫 Ollama；若回 tool_calls，執行對應 jt-ipam 工具
      4. 把 tool 結果 append 回 messages，再呼叫一次（最多 max_iterations 輪）

    OWASP A04 / A06：
      - chat 對外 URL 走 safe_request
      - tool 執行時的 user 與 session 都從本端拿，不從 LLM 輸入信任
    """
    from app.services.system_config import get_llm_config
    cfg = await get_llm_config(session)
    if not cfg.enabled:
        raise AINotConfigured("LLM is disabled")

    from app.mcp.tools import allowed_tool_names
    _allowed = await allowed_tool_names(session, user)
    ollama_tools, convo = _build_chat_context(messages, locale, page_context, _allowed)
    url = chat_url(cfg.url, cfg.provider)
    started = time.monotonic()

    def _meta() -> dict[str, Any]:
        return {"model": cfg.chat_model, "elapsed_ms": int((time.monotonic() - started) * 1000)}

    for _ in range(max_iterations):
        body = {
            "model": cfg.chat_model,
            "messages": convo,
            "tools": ollama_tools,
            "stream": False,
            # 低溫度：減少模型亂插字（如把 192.168 寫成「19 kiếm 168」之類的跨語言錯字）
            "options": _chat_options(cfg),
        }
        try:
            resp = await safe_request(
                "POST", url,
                headers=auth_headers(cfg.provider, cfg.api_key),
                json=body, timeout=cfg.timeout,
            )
        except UnsafeOutboundURL as exc:
            raise AIError(f"SSRF guard: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AIError(f"transport: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            raise AIError(f"{provider_label(cfg.provider)} chat {resp.status_code}: {resp.text[:200]}")
        data = resp.json()

        msg = extract_reply(data, cfg.provider)
        convo.append(msg)

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            # 後援：模型偶發把工具呼叫寫成文字（而非結構化 tool_calls）→ 還原執行
            inline = _inline_tool_calls(msg.get("content") or "", _allowed)
            if inline:
                msg["tool_calls"] = inline
                msg["content"] = ""
                tool_calls = inline
            elif _looks_like_tool_leak(msg.get("content") or ""):
                return {"answer": _tool_leak_message(locale), "messages": convo, **_meta()}
            else:
                return {"answer": msg.get("content") or "", "messages": convo, **_meta()}

        # 異動類工具不直接執行 → 回傳待確認動作，等使用者按「確認」
        pending = _pending_mutations(tool_calls)
        if pending:
            return {"answer": msg.get("content") or _pending_prompt_text(pending),
                    "messages": convo, "pending_actions": pending, **_meta()}

        convo.extend(await _run_tool_calls(session, user, tool_calls))

    # 用完 max_iterations 還在叫工具 → 最後不給工具再叫一次，逼它用現有資訊作答
    answer = await _force_final_answer(cfg, convo)
    return {"answer": answer, "messages": convo, **_meta()}


async def _force_final_answer(cfg: Any, convo: list[dict[str, Any]]) -> str:
    """max_iterations 用完時的收尾：不帶 tools 再呼叫一次，要 LLM 直接作答。"""
    url = chat_url(cfg.url, cfg.provider)
    # 明確指示：根據已取得的工具結果立刻作答，別再呼叫工具（否則模型常回空字串 → 落到 fallback）
    nudge = {
        "role": "user",
        "content": (
            "Based on the tool results already gathered above, give your best final "
            "answer to my question now, in my language. Do NOT call any more tools. "
            "If the data is incomplete, answer with what you have and say what is missing."
        ),
    }
    body = {"model": cfg.chat_model, "messages": [*convo, nudge],
            "stream": False, "options": _chat_options(cfg)}
    try:
        resp = await safe_request(
            "POST", url, headers=auth_headers(cfg.provider, cfg.api_key),
            json=body, timeout=cfg.timeout,
        )
        if resp.status_code == 200:
            msg = extract_reply(resp.json(), cfg.provider)
            content = msg.get("content")
            if content:
                convo.append({"role": "assistant", "content": content})
                return content  # type: ignore[no-any-return]
    except (UnsafeOutboundURL, httpx.HTTPError):
        pass
    return "（查詢步驟過多仍未完成，請把問題拆小一點再試一次）"


def _page_context_line(context: dict[str, Any] | None) -> str:
    """把前端帶來的「目前所在頁面」資訊轉成 system prompt 提示。"""
    if not context:
        return ""
    parts: list[str] = []
    cidr = context.get("subnet_cidr")
    sid = context.get("subnet_id")
    if sid or cidr:
        ref = cidr or sid
        parts.append(
            f" The user is currently viewing subnet {ref}"
            + (f" (subnet_id={sid})" if sid else "")
            + ". If they ask for free IPs, usage, or allocation without naming a "
            "subnet, default to THIS subnet."
        )
    if context.get("device_id"):
        parts.append(f" They are viewing device_id={context['device_id']}.")
    if context.get("section_id"):
        parts.append(f" They are viewing section_id={context['section_id']}.")
    return "".join(parts)


def _build_chat_context(
    messages: list[dict[str, Any]], locale: str | None,
    page_context: dict[str, Any] | None = None,
    allowed_tools: set[str] | None = None,
) -> Any:
    """共用：把 IPAM tools 轉 Ollama schema + 組 system prompt + 接上對話。

    回傳 (ollama_tools, convo)。chat / chat_stream 共用，避免兩份 prompt 不一致。
    allowed_tools 給定時依 RBAC 過濾掉使用者不可呼叫的工具（避免 LLM 浪費回合）。
    """
    from app.mcp.tools import TOOLS

    ollama_tools = [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": meta["description"],
                "parameters": meta["parameters"],
            },
        }
        for name, meta in TOOLS.items()
        if allowed_tools is None or name in allowed_tools
    ]
    convo: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are jt-ipam's network operations assistant. Use the provided "
                "tools to answer questions about subnets, IPs (get_ip_detail / "
                "get_subnet_detail for full records), devices, DNS (servers/zones/"
                "consistency), VPN tunnels (WireGuard / IPsec / OpenVPN, incl. site-to-"
                "site), NAT, VLANs, VRFs, racks, sections, firewalls and their rules/"
                "aliases, network topology (get_topology), ARP/FDB, IP-allocation "
                "requests, scan agents, virtual machines, wireless links, customers, "
                "Wazuh security-coverage gaps (wazuh_missing_agents), TLS certificates and "
                "their distribution to hosts (list_certificates / list_cert_distribution — "
                "metadata only, private keys are never exposed), DHCP pool ranges "
                "(list_dhcp_ranges), anomaly detection results (list_anomalies — IP "
                "conflicts, MAC drifts, ghost IPs, unauthorised IPs, rogue DHCP servers; "
                "these are measured facts and can be stated plainly), and AI review "
                "findings (list_ai_findings — these are model inferences, not verified "
                "facts; say so when you repeat them). Both are admin-only. "
                "list_firewalls covers OPNsense, pfSense and FortiGate together; FortiGate "
                "policies and address objects have their own tools. Before saying you "
                "cannot determine something, check whether a relevant tool exists and "
                "call it (e.g. list_vpn_tunnels for site-to-site VPN, get_topology for "
                "how things connect, list_firewall_rules for firewall policy). "
                "When the user asks how many IPs are used / free / available / usable in a "
                "subnet or CIDR (e.g. '192.168.1.0/24 有多少可用 IP'), you MUST call "
                "get_subnet_detail (subnet_cidr=...) or get_subnet_usage to report jt-ipam's "
                "ACTUAL allocated/used/free counts and usage %. Do NOT answer with generic "
                "CIDR arithmetic (total addresses, usable-hosts = 2^n − 2, network/broadcast) "
                "— the user wants this IPAM's real data, not subnet math. Only say the subnet "
                "is not in IPAM if the tool reports no such subnet. "
                "Tools whose description says 'ADMIN ONLY' only work for admin users; "
                "do not attempt writes unless the user clearly asks to change data. "
                "Always cite the IPs / CIDRs / device names returned by tools, and copy "
                "every IP, CIDR, MAC, hostname and identifier VERBATIM, character for "
                "character — never translate, localise, reformat or alter a single digit. "
                "If a tool errors, explain it briefly. "
                "Stay strictly on-topic: only answer questions about THIS jt-ipam system, "
                "its data (network / IPAM / devices / firewalls / DNS …) or how to use it. "
                "For unrelated questions (general coding, world knowledge, chit-chat), "
                "politely decline and suggest a dedicated general-purpose LLM platform "
                "such as Open WebUI or opencode instead. "
                "NEVER invent, guess, or extend IP data — only report exactly what "
                "tools return. When the user wants several or consecutive free IPs, "
                "call find_free_ips with the right count/consecutive ONCE; report only "
                "the IPs it returns, and if it returns fewer than requested, say so "
                "instead of making up more. "
                "Some list tools return has_more/next_offset; if a result is truncated "
                "or the user asks for more, tell them there are more and, when they ask "
                "for the next batch, call the SAME tool again with offset=next_offset. "
                + _lang_instruction(locale)
                + _page_context_line(page_context)
            ),
        }
    ]
    convo.extend(messages)
    return ollama_tools, convo


def _pending_mutations(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """挑出 tool_calls 中會異動資料的，回傳 {tool,args,title} 清單給前端確認。"""
    from app.mcp.tools import MUTATING_TOOLS, summarize_action

    pending: list[dict[str, Any]] = []
    for call in tool_calls:
        fn = call.get("function") or {}
        name = fn.get("name")
        if name not in MUTATING_TOOLS:
            continue
        args = fn.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        pending.append({"tool": name, "args": args, "title": summarize_action(name, args)})
    return pending


def _pending_prompt_text(pending: list[dict[str, Any]]) -> str:
    """模型回傳待確認動作卻沒給文字時，用動作標題組一句提示，避免空白回應。"""
    titles = [str(p.get("title") or p.get("tool") or "") for p in pending if p]
    titles = [t for t in titles if t]
    if not titles:
        return ""
    return "我準備執行以下動作，請確認後再進行：\n" + "\n".join(f"• {t}" for t in titles)


async def _run_tool_calls(session: AsyncSession, user: Any, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """執行 LLM 要求的 tool_calls，回傳要 append 進 convo 的 tool 訊息（含 name）。"""
    from app.mcp.tools import TOOLS, IPAMToolError, authorize_tool

    out: list[dict[str, Any]] = []
    for call in tool_calls:
        fn = call.get("function") or {}
        name = fn.get("name")
        args = fn.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        denied = await authorize_tool(session, user, name) if name in TOOLS else None
        if name not in TOOLS:
            tool_result: Any = {"error": f"unknown tool {name!r}"}
        elif denied is not None:
            tool_result = {"error": denied}
        else:
            try:
                tool_result = await TOOLS[name]["fn"](session, user=user, **args)
            except IPAMToolError as exc:
                tool_result = {"error": str(exc)}
            except Exception as exc:
                tool_result = {"error": f"tool failed: {exc.__class__.__name__}"}
        blob = json.dumps(tool_result, ensure_ascii=False, default=str)
        # 防止單一工具回傳過大撐爆上下文 → 模型變慢甚至 ReadTimeout
        if len(blob) > _TOOL_RESULT_CAP:
            blob = blob[:_TOOL_RESULT_CAP] + " …[truncated; 結果過多，請縮小範圍或加篩選條件]"
        out.append({"role": "tool", "name": name, "content": blob})
    return out


async def chat_stream(
    session: AsyncSession,
    *,
    user: Any,
    messages: list[dict[str, Any]],
    locale: str | None = None,
    max_iterations: int = 4,
    page_context: dict[str, Any] | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """chat 的 streaming 版：逐 token 把最終回答吐出來（規格 §11.1，本地推論不外送）。

    yield 的事件（給 SSE endpoint 包成 data: ...）：
      {"type": "token",      "text": ...}    最終回答的增量片段
      {"type": "tool",       "name": ...}    正在執行某個工具
      {"type": "tool_round"}                 該輪是 tool round，前端應清掉已收到的暫存 token
      {"type": "done",       "answer": ..., "trace_messages": convo}
      {"type": "error",      "detail": ...}

    串流時無法在中途改 HTTP status，故所有錯誤都以 error 事件回報；config 未開的
    503 由 endpoint 在開串流前先擋掉。
    """
    from app.services.system_config import get_llm_config
    cfg = await get_llm_config(session)
    if not cfg.enabled:
        yield {"type": "error", "detail": "LLM is disabled"}
        return

    from app.mcp.tools import allowed_tool_names
    _allowed = await allowed_tool_names(session, user)
    ollama_tools, convo = _build_chat_context(messages, locale, page_context, _allowed)
    url = chat_url(cfg.url, cfg.provider)
    started = time.monotonic()

    def _meta() -> dict[str, Any]:
        return {"model": cfg.chat_model, "elapsed_ms": int((time.monotonic() - started) * 1000)}

    for _ in range(max_iterations):
        body = {
            "model": cfg.chat_model,
            "messages": convo,
            "tools": ollama_tools,
            "stream": True,
            "options": _chat_options(cfg),
        }
        content_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        try:
            async with safe_stream(
                "POST", url,
                headers=auth_headers(cfg.provider, cfg.api_key),
                json=body, timeout=cfg.timeout,
            ) as resp:
                if resp.status_code != 200:
                    detail = (await resp.aread()).decode("utf-8", "replace")[:200]
                    yield {"type": "error", "detail": f"{provider_label(cfg.provider)} chat {resp.status_code}: {detail}"}
                    return
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    m = chunk.get("message") or {}
                    piece = m.get("content")
                    if piece:
                        content_parts.append(piece)
                        yield {"type": "token", "text": piece}
                    tcs = m.get("tool_calls")
                    if tcs:
                        tool_calls.extend(tcs)
                    if chunk.get("done"):
                        break
        except UnsafeOutboundURL as exc:
            yield {"type": "error", "detail": f"SSRF guard: {exc}"}
            return
        except httpx.HTTPError as exc:
            yield {"type": "error", "detail": f"transport: {exc.__class__.__name__}"}
            return

        full_content = "".join(content_parts)
        assistant_msg: dict[str, Any] = {"role": "assistant", "content": full_content}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        convo.append(assistant_msg)

        if not tool_calls:
            # 後援：模型偶發把工具呼叫寫成文字（而非結構化 tool_calls）→ 還原；
            # 後面的 tool_round 事件會叫前端清掉剛串流出去的呼叫文字。
            inline = _inline_tool_calls(full_content, _allowed)
            if inline:
                assistant_msg["tool_calls"] = inline
                assistant_msg["content"] = ""
                tool_calls = inline
            elif _looks_like_tool_leak(full_content):
                yield {"type": "tool_round"}
                yield {"type": "done", "answer": _tool_leak_message(locale),
                       "trace_messages": convo, **_meta()}
                return
            else:
                yield {"type": "done", "answer": full_content, "trace_messages": convo, **_meta()}
                return

        # 異動類工具：不直接執行，回傳待確認動作給前端，等使用者按「確認」
        pending = _pending_mutations(tool_calls)
        if pending:
            yield {"type": "pending_action", "actions": pending}
            return

        # 這輪是 tool round：剛吐的 token（若有，多半是 thinking）不是最終答案，叫前端清掉
        yield {"type": "tool_round"}
        for call in tool_calls:
            yield {"type": "tool", "name": (call.get("function") or {}).get("name")}
        convo.extend(await _run_tool_calls(session, user, tool_calls))

    # max_iterations 用完 → 不給工具，串流最後一次強制作答
    yield {"type": "tool_round"}
    final_parts: list[str] = []
    body = {"model": cfg.chat_model, "messages": convo, "stream": True, "options": _chat_options(cfg)}
    try:
        async with safe_stream(
            "POST", url, headers=auth_headers(cfg.provider, cfg.api_key),
            json=body, timeout=cfg.timeout,
        ) as resp:
            if resp.status_code == 200:
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    piece = (chunk.get("message") or {}).get("content")
                    if piece:
                        final_parts.append(piece)
                        yield {"type": "token", "text": piece}
                    if chunk.get("done"):
                        break
    except (UnsafeOutboundURL, httpx.HTTPError):
        pass
    answer = "".join(final_parts) or "（查詢步驟過多仍未完成，請把問題拆小一點再試一次）"
    if final_parts:
        convo.append({"role": "assistant", "content": answer})
    yield {"type": "done", "answer": answer, "trace_messages": convo, **_meta()}


# ─────────────────── 全表 reindex（admin 一次性） ───────────────────


async def reindex_all(session: AsyncSession) -> dict[str, Any]:
    """重新計算所有有 description 的物件的 embedding。慢；只在初始化或換 model 時跑。

    **失敗筆數與原因要一起回報。** 只回成功數的話，「全部失敗」看起來會跟「沒有東西
    要索引」一模一樣 —— 實機上就是這樣：嵌入模型回 4096 維、欄位是 vector(768)，
    每一筆都丟例外被吞掉，reindex 回 0/0/0，語意搜尋從頭到尾沒有真的運作過。
    """
    from app.models.address import IPAddress
    from app.models.device import Device
    from app.models.subnet import Subnet

    stats: dict[str, Any] = {"subnets": 0, "ip_addresses": 0, "devices": 0,
                             "failed": 0, "error": None}

    def _note(exc: Exception) -> None:
        stats["failed"] = int(stats["failed"]) + 1
        if not stats["error"]:
            stats["error"] = str(exc)[:300]

    # 分批 commit：整表放在同一個交易裡，會跟同時在跑的整合同步（jt-ipam-sync 每 ~5 分鐘
    # 更新同一批 ip_addresses）互鎖 —— 實機第一次真的跑得動 reindex 就撞到 deadlock，
    # 整批因此中止。每 N 筆放掉一次鎖，衝突視窗就只剩下這 N 筆。
    _BATCH = 25

    sub_rows = (
        await session.execute(
            select(Subnet.id, Subnet.description).where(Subnet.description.isnot(None))
        )
    ).all()
    for sid, desc in sub_rows:
        try:
            if await index_subnet(session, str(sid), desc, raise_on_error=True):
                stats["subnets"] += 1
        except (AIError, AINotConfigured) as exc:
            _note(exc)
        if (stats["subnets"] + stats["failed"]) % _BATCH == 0:
            await session.commit()
    await session.commit()

    ip_rows = (
        await session.execute(
            select(IPAddress.id, IPAddress.description).where(
                IPAddress.description.isnot(None)
            )
        )
    ).all()
    for iid, desc in ip_rows:
        try:
            if await index_ip(session, str(iid), desc, raise_on_error=True):
                stats["ip_addresses"] += 1
        except (AIError, AINotConfigured) as exc:
            _note(exc)
        if (stats["ip_addresses"] + stats["failed"]) % _BATCH == 0:
            await session.commit()
    await session.commit()

    dev_rows = (
        await session.execute(
            select(Device.id, Device.description).where(Device.description.isnot(None))
        )
    ).all()
    for did, desc in dev_rows:
        try:
            if await index_device(session, str(did), desc, raise_on_error=True):
                stats["devices"] += 1
        except (AIError, AINotConfigured) as exc:
            _note(exc)
        if (stats["devices"] + stats["failed"]) % _BATCH == 0:
            await session.commit()
    await session.commit()

    return stats


async def raw_chat(session: AsyncSession, prompt: str, timeout: float | None = None,
                   model: str | None = None, force_json: bool = False,
                   max_output_tokens: int | None = None, no_thinking: bool = False,
                   num_ctx: int | None = None,
                   on_chunk: Callable[[str, str], Awaitable[None]] | None = None) -> str:
    """單次、不帶工具的對話 —— 給 AI 巡檢這類「送一段提示詞、要一段結構化輸出」的用途。

    刻意**不掛 IPAM 工具**：巡檢的資料已經由呼叫端依可見範圍取好並放進提示詞裡，
    再讓模型去呼叫工具只會多一條繞過權限的路。

    `timeout` 留空＝用 LLM 設定裡的值（那個是為互動對話調的）。背景批次要自己給一個
    夠長的值 —— 幾百筆資料的提示詞用互動逾時去跑，幾乎每次都會逾時。
    `model` 留空＝用設定的對話模型。
    `force_json=True` 會要求 Ollama 只輸出 JSON —— 光靠提示詞說「只回 JSON」不夠，
    模型（尤其提示詞很長時）常常改寫一段散文回來。
    `max_output_tokens` 限制產出長度。沒有上限的話，模型有機會卡在重複輸出的迴圈裡，
    把整個逾時燒完才失敗（實測看過一批產出 34,000 字還沒停）。
    `no_thinking=True` 關掉思考模式。**思考過程也算在產出額度裡** —— 實測 gemma4 一批
    寫了 10,401 字的思考，結果真正的答案被額度切斷。舊版 Ollama 不認這個欄位，
    被拒絕時會自動退回不帶它重送。
    `on_chunk(片段, 種類)` 有給就改走串流：一批要跑好幾分鐘，沒有中途訊號的話畫面上
    完全看不出模型是在算還是已經卡死。種類是 "thinking"（思考過程）或 "content"
    （最終輸出）—— 會思考的模型前幾分鐘只吐 thinking，兩者要分開才講得清楚現況。
    """
    from app.services.system_config import get_llm_config
    cfg = await get_llm_config(session)
    if not cfg.enabled:
        raise AINotConfigured("LLM is disabled")
    url = chat_url(cfg.url, cfg.provider)
    body = json_chat_body(
        cfg, cfg.provider, prompt=prompt, stream=on_chunk is not None,
        force_json=force_json, max_output_tokens=max_output_tokens, num_ctx=num_ctx,
        no_thinking=no_thinking, model=model,
    )
    wait = timeout or cfg.timeout
    try:
        if on_chunk is not None:
            return await _raw_chat_streamed(url, body, wait, on_chunk,
                                            auth_headers(cfg.provider, cfg.api_key),
                                            cfg.provider)
        resp = await safe_request("POST", url, headers=auth_headers(cfg.provider, cfg.api_key),
                                  json=body, timeout=wait)
        if _rejected_think(resp):
            body.pop("think", None)
            resp = await safe_request("POST", url, headers=auth_headers(cfg.provider, cfg.api_key),
                                      json=body, timeout=wait)
    except UnsafeOutboundURL as exc:
        raise AIError(f"SSRF guard: {exc}") from exc
    except httpx.ReadTimeout as exc:
        raise AIError(
            f"LLM 伺服器在 {int(wait)} 秒內沒有回覆完（模型太慢或資料量太大）"
        ) from exc
    except httpx.HTTPError as exc:
        raise AIError(f"transport: {exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise AIError(f"{provider_label(cfg.provider)} chat {resp.status_code}: {resp.text[:200]}")
    # 兩家結構不同：Ollama 是 message、OpenAI 是 choices[0].message
    data = resp.json()
    msg = data.get("message") or {}
    if not msg:
        msg = ((data.get("choices") or [{}])[0]).get("message") or {}
    return str(msg.get("content") or "")


def _rejected_think(resp: Any) -> bool:
    """舊版 Ollama 不認 `think` 欄位 —— 認出這種錯誤，好退回不帶它重送。"""
    if resp.status_code == 200 or "think" not in (resp.text or "").lower():
        return False
    return True


async def _raw_chat_streamed(
    url: str, body: dict[str, Any], wait: float,
    on_chunk: Callable[[str, str], Awaitable[None]],
    headers: dict[str, str] | None = None,
    provider: str = "ollama",
) -> str:
    """串流版：邊收邊回報，最後把整段內容拼回來給呼叫端解析。"""
    try:
        return await _stream_once(url, body, wait, on_chunk, headers, provider)
    except AIError as exc:
        # 舊版 Ollama 不認 `think`：拿掉重來一次，而不是整批失敗
        if "think" not in str(exc).lower() or "think" not in body:
            raise
        body.pop("think", None)
        return await _stream_once(url, body, wait, on_chunk, headers, provider)


async def _stream_once(
    url: str, body: dict[str, Any], wait: float,
    on_chunk: Callable[[str, str], Awaitable[None]],
    headers: dict[str, str] | None = None,
    provider: str = "ollama",
) -> str:
    parts: list[str] = []
    async with safe_stream("POST", url,
                           headers=headers or {"Content-Type": "application/json"},
                           json=body, timeout=wait) as resp:
        if resp.status_code != 200:
            detail = (await resp.aread()).decode("utf-8", "replace")[:200]
            raise AIError(f"{provider_label(provider)} chat {resp.status_code}: {detail}")
        async for line in resp.aiter_lines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except ValueError:
                continue          # Ollama 偶爾夾非 JSON 行；跳過即可
            # 串流每一行的結構兩家不同（Ollama: message；OpenAI: choices[0].delta）。
            # 這支輔助函式拿不到 cfg，也不需要 —— 兩種都試，取到就用。
            msg = data.get("message") or {}
            if not msg:
                ch = (data.get("choices") or [{}])[0]
                msg = ch.get("delta") or ch.get("message") or {}
            # 會思考的模型（gemma4 等）先吐一大段 thinking，content 要等到最後才出現。
            # 只看 content 的話，畫面會停住好幾分鐘完全沒有動靜 —— 實際上模型正在想。
            thinking = str(msg.get("thinking") or "")
            if thinking:
                await on_chunk(thinking, "thinking")
            piece = str(msg.get("content") or "")
            if piece:
                parts.append(piece)
                await on_chunk(piece, "content")
            if data.get("error"):
                raise AIError(f"LLM: {str(data['error'])[:200]}")
    return "".join(parts)
