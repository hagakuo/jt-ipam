"""模型清單端點：連不到或被擋下，都要回可讀訊息，不是 500。

由來（2026-09-05，e2e 逐頁巡檢抓到）：LLM 設定頁一開就有四次
`GET /api/v1/system/llm/models` 回 **500 Internal Server Error**，畫面上只有
「伺服器發生錯誤」。真正的原因是 SSRF 防護把設定的位址擋下了 ——
**而預設的 Ollama 位址正是 `http://127.0.0.1:11434`，loopback 在
`safe_http._BLOCKED_CIDRS` 裡是一律封鎖的**（要放行得自己設 `OUTBOUND_ALLOW_CIDRS`）。

端點本來就有處理連線失敗（`httpx.HTTPError` → 回 `{"models": [], "error": …}`），
只是漏了「被自己的防護擋下」這一種。同一類錯誤在 `services/ai.py` 是有接的，
所以這是單點遺漏，不是設計如此。使用者看得到的差別很大：
一個是「這個位址被擋下，要放行請設 X」，另一個是什麼線索都沒有的 500。
"""
from __future__ import annotations


async def test_blocked_url_returns_readable_error(client, db_session, auth_headers):
    """LLM 位址被 SSRF 防護擋下時：200 + 可讀 error，而且訊息要講得出怎麼放行。"""
    from app.services.system_config import set_llm_config

    # 產品預設的 Ollama 位址就是 loopback，而 loopback 在 SSRF 防護裡一律被擋
    await set_llm_config(db_session, enabled=True, url="http://127.0.0.1:11434",
                         chat_model="c", embedding_model="e")
    await db_session.commit()

    resp = await client.get("/api/v1/system/llm/models", headers=auth_headers)
    assert resp.status_code == 200, f"被擋下不是伺服器錯誤，不該回 {resp.status_code}"
    body = resp.json()
    assert body["models"] == []
    detail = body.get("error_detail")
    assert detail, "沒有 error_detail＝畫面上是一個空下拉，看不出為什麼"
    # 代碼要能翻成使用者的語言；`message` 是沒有翻譯時的退路
    assert detail["code"] == "llm_models_ssrf_blocked"
    # 訊息要能讓人採取行動：講出是被擋下的，以及放行的設定鍵
    assert "OUTBOUND_ALLOW_CIDRS" in detail["message"]
    # 底層原文要留著 —— 少了它就看不出被擋的是哪個位址
    assert "127.0.0.1" in detail["params"]["reason"]
