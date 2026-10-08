"""錯誤回應要保留 HTTPException 帶的標頭（2026-09-30 改寫 API 手冊時發現）。

main.py 的錯誤處理只回 status 與 detail，把 `exc.headers` 丟掉了：401 沒有 `WWW-Authenticate`
（RFC 7235 要求）、限流的 429 沒有 `Retry-After` —— 客戶端不知道要等多久，只能瞎重試。
"""
from __future__ import annotations


async def test_401_carries_www_authenticate(client) -> None:
    r = await client.get("/api/v1/subnets")
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Bearer"


async def test_429_carries_retry_after() -> None:
    """限流丟的 HTTPException 帶 Retry-After（core/rate_limit.py）—— 經過錯誤處理後要還在。"""
    from starlette.exceptions import HTTPException
    from starlette.requests import Request

    from app.main import app
    handler = app.exception_handlers[HTTPException]
    resp = await handler(Request({"type": "http", "method": "GET", "path": "/", "headers": []}),
                         HTTPException(status_code=429, detail="Too Many Requests", headers={"Retry-After": "60"}))
    assert resp.status_code == 429
    assert resp.headers.get("retry-after") == "60"
