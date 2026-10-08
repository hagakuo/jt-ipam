"""direct（uvicorn 直出 TLS）模式的 SPA 供應：後端要能自己出前端。

客戶實例（2026-08-17）：direct 模式 doctor 全綠、/healthz 通，但瀏覽器開 https://host:8443/
只得到 {"detail":"Not Found"} —— nginx 被跳過（正確），後端卻沒掛 dist，UI 無人供應。

規格：
- 有 frontend/dist/index.html → 掛 SPA fallback（掛在最後，API route 永遠優先）。
- `/` 與任意前端路由（/attack-surface 這類）都回 index.html（SPA 客端路由）。
- API 的 404 仍是 JSON（不可被 fallback 吃掉變成回 HTML）。
- index.html／version.json 要帶 no-cache（版本自動偵測靠它）；hash 過的 assets 可長快取。
"""
from __future__ import annotations

from pathlib import Path

import pytest

DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

pytestmark = pytest.mark.skipif(
    not (DIST / "index.html").is_file(),
    reason="frontend/dist 未建置（客戶機必有；CI 無前端時跳過）",
)


@pytest.mark.anyio
async def test_root_serves_spa(client) -> None:
    r = await client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "<!doctype html" in r.text.lower()


@pytest.mark.anyio
async def test_spa_route_falls_back_to_index(client) -> None:
    """前端 client-side 路由直接輸入網址（或重新整理）也要回 index.html。"""
    r = await client.get("/attack-surface")
    assert r.status_code == 200
    assert "<!doctype html" in r.text.lower()


@pytest.mark.anyio
async def test_api_404_stays_json(client) -> None:
    """API 底下的 404 不可被 SPA fallback 吃掉 —— 客戶端要靠 JSON 錯誤判斷。"""
    r = await client.get("/api/v1/definitely-not-a-route")
    assert r.status_code == 404
    assert r.headers.get("content-type", "").startswith("application/json")


@pytest.mark.anyio
async def test_healthz_untouched(client) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_index_no_cache(client) -> None:
    """index.html 被瀏覽器長快取的話，發新版後長壽分頁永遠跑舊 bundle。"""
    for path in ("/", "/version.json"):
        r = await client.get(path)
        assert r.status_code == 200
        assert "no-cache" in r.headers.get("cache-control", ""), path
