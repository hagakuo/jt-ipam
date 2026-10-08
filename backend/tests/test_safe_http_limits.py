"""出站請求的兩道保護：共用連線與回應大小上限。

由來（2026-09-04，MikroTik 整合的前置修正）：客戶的 MikroTik 是**主力路由器**
（CCR2004／CCR1072），拉資料不可以把它拖慢，而我們自己有兩個問題：

1. `safe_request()` 每呼叫一次就新建一個 client → **每支端點各做一次 TLS 握手**。
   CCR1072 是 Tile 架構（核多但單核弱，握手跑在單核上），一輪十個區段就白費十次。
2. 完全**沒有回應大小上限**。RouterOS 的 REST 沒有分頁也沒有 limit，一支 `/ip/route`
   在跑 BGP 的路由器上可能是上百萬列 —— 讀完再判斷就已經 OOM 了。
"""

from __future__ import annotations

import httpx
import pytest
from app.core.safe_http import ResponseTooLarge, safe_request


class _Transport(httpx.AsyncBaseTransport):
    """回固定內容的假傳輸層；記錄被建立幾個連線（以請求次數代替）。"""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(self.status, content=self.body,
                              headers={"content-type": "application/json"})


@pytest.mark.anyio
async def test_oversized_response_is_aborted_with_a_readable_error() -> None:
    """超過上限要中止並說清楚，而不是把記憶體吃光。"""
    transport = _Transport(b"x" * 5000)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ResponseTooLarge) as exc:
            await safe_request("GET", "https://example.com/big",
                               client=client, max_bytes=1000)
    assert "1000" in str(exc.value), "訊息要講出上限是多少，否則使用者不知道要調什麼"


@pytest.mark.anyio
async def test_response_within_the_limit_is_returned_intact() -> None:
    """沒超過就要跟平常一模一樣（含 .json()）——不能為了設限而改變行為。"""
    transport = _Transport(b'{"ok": true, "rows": [1, 2, 3]}')
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await safe_request("GET", "https://example.com/small",
                                  client=client, max_bytes=1_000_000)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "rows": [1, 2, 3]}


@pytest.mark.anyio
async def test_no_limit_means_no_streaming_path() -> None:
    """沒給上限時維持原本的行為（既有整合不受影響）。"""
    transport = _Transport(b'{"ok": true}')
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await safe_request("GET", "https://example.com/x", client=client)
    assert resp.json() == {"ok": True}


@pytest.mark.anyio
async def test_a_shared_client_is_reused_across_requests() -> None:
    """共用連線：多支端點只用同一個 client（TLS 握手因此只做一次）。

    這裡驗的是「傳進去的 client 真的被用到」——沒有被忽略、也沒有偷偷另建一個。
    """
    transport = _Transport(b"{}")
    async with httpx.AsyncClient(transport=transport) as client:
        for path in ("/a", "/b", "/c"):
            await safe_request("GET", f"https://example.com{path}", client=client)
    assert transport.calls == 3, "三次請求都應該走同一個 client"


class _GzipTransport(httpx.AsyncBaseTransport):
    """回 gzip 壓縮的內容（GitHub API 一律這樣回）。"""

    def __init__(self, body: bytes) -> None:
        import gzip
        self.raw = gzip.compress(body)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.raw,
                              headers={"content-type": "application/json", "content-encoding": "gzip",
                                       "content-length": str(len(self.raw))})


@pytest.mark.anyio
async def test_gzip_response_within_the_limit_is_decoded_once() -> None:
    """串流時收到的已經是解壓後的內容；重建回應若還留著 content-encoding: gzip，
    讀取時會再解一次而失敗（2026-09-29：檢查 Recog 新版時 GitHub API 一律回 DecodingError）。"""
    async with httpx.AsyncClient(transport=_GzipTransport(b'{"tag_name": "v3.2.0"}')) as client:
        resp = await safe_request("GET", "https://example.com/api", client=client, max_bytes=1_000_000)
    assert resp.json() == {"tag_name": "v3.2.0"}


@pytest.mark.anyio
async def test_gzip_limit_counts_the_decompressed_size() -> None:
    """上限算解壓後的大小：一小包壓縮炸彈不可以因為「傳輸量很小」就放行。"""
    async with httpx.AsyncClient(transport=_GzipTransport(b"0" * 200_000)) as client:
        with pytest.raises(ResponseTooLarge):
            await safe_request("GET", "https://example.com/bomb", client=client, max_bytes=10_000)


class _RedirectTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/latest":
            return httpx.Response(302, headers={"location": "https://example.com/tag/v3.2.0"})
        return httpx.Response(200, content=b"ok")


@pytest.mark.anyio
async def test_redirects_are_followed_when_a_limit_is_set() -> None:
    """設了大小上限也要跟轉址（以前重建的回應沒有 next_request，會直接回 302）。"""
    async with httpx.AsyncClient(transport=_RedirectTransport()) as client:
        resp = await safe_request("GET", "https://example.com/latest", client=client, max_bytes=1000)
    assert resp.status_code == 200
    assert str(resp.url) == "https://example.com/tag/v3.2.0"
