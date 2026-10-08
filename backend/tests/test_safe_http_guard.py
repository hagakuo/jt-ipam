"""出站請求的 SSRF 防護（CodeQL #1／#2 判讀，2026-10-01）。

判讀抓到三個實際可繞過的洞：

1. **IPv4 對映的 IPv6 位址**（`::ffff:127.0.0.1`）：比對只看同版本的網段，這種寫法既不算本機也不算
   私網；Linux 雙堆疊卻會把它連到 127.0.0.1。工具頁的 HTTP 檢查（任何登入帳號）因此打得到本機與
   雲端中繼資料 169.254.169.254。
2. **檢查與連線之間 DNS 換了答案**（DNS rebinding）：先解析檢查、httpx 連線時再解析一次。現在改在
   **建立 TCP 連線的當下**才解析、檢查、連到檢查過的那個位址（網址、SNI、憑證檢查都不變）。
3. **轉址把認證標頭帶到別的主機**：手動處理轉址時沿用原本的標頭（LibreNMS 的 X-Auth-Token、
   Proxmox 的 Authorization、LLM 金鑰），302 到別的網域就整包送過去；查詢參數每一跳還會再疊一次。
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from app.core import safe_http
from app.core.config import get_settings
from app.core.safe_http import UnsafeOutboundURL, assert_url_safe, safe_client, safe_request


@pytest.fixture
def env(monkeypatch):
    """設定是快取的：改環境變數後要清快取，測完再清一次（不影響其他測試）。"""
    def _set(name: str, value: str) -> None:
        monkeypatch.setenv(name, value)
        get_settings.cache_clear()
    yield _set
    get_settings.cache_clear()


@pytest.mark.parametrize("url", [
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[::ffff:7f00:1]:8000/",
    "http://[fd00:ec2::254]/",                  # AWS 的 IPv6 中繼資料位址
])
def test_mapped_and_metadata_addresses_are_blocked(url) -> None:
    with pytest.raises(UnsafeOutboundURL):
        assert_url_safe(url)


def test_mapped_private_needs_the_same_permission_as_plain_private(env) -> None:
    env("OUTBOUND_ALLOW_PRIVATE", "false")
    with pytest.raises(UnsafeOutboundURL):
        assert_url_safe("http://[::ffff:10.0.0.5]/")


# ── 本機測試伺服器：記錄每個請求的路徑與標頭 ──

class _Srv:
    def __init__(self) -> None:
        seen: list[dict] = []
        self.seen = seen

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _rec(self, body: bytes = b""):
                seen.append({"method": self.command, "path": self.path,
                             "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})

            def do_GET(self):
                self._rec()
                if self.path.startswith("/hop-cross"):
                    port = self.server.server_address[1]
                    self.send_response(302)
                    self.send_header("Location", f"http://other.test:{port}/landed")
                    self.end_headers()
                    return
                if self.path.startswith("/hop-same"):
                    self.send_response(302)
                    self.send_header("Location", "/landed")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())

            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                self._rec(self.rfile.read(n))
                self.send_response(303)
                self.send_header("Location", "/after-post")
                self.end_headers()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()


@pytest.fixture
def srv(monkeypatch, env):
    """兩個「主機名稱」都解析到本機測試伺服器；本機加進允許清單（否則本來就會被擋）。"""
    s = _Srv()
    env("OUTBOUND_ALLOW_CIDRS", "127.0.0.1/32")
    names = {"api.test", "other.test"}
    lo = [ipaddress.ip_address("127.0.0.1")]
    monkeypatch.setattr(safe_http, "_resolve", lambda h: lo if h in names else (_ for _ in ()).throw(
        UnsafeOutboundURL(f"no such host {h}")))

    async def aresolve(host, port):
        return lo if host in names else []
    monkeypatch.setattr(safe_http, "_aresolve", aresolve)
    yield s
    s.close()


@pytest.mark.anyio
async def test_dns_answer_changing_after_the_check_is_caught_at_connect_time(monkeypatch) -> None:
    """檢查時解析到公網位址、連線時變成 127.0.0.1：要在連線當下擋下，不可以真的連過去。"""
    monkeypatch.setattr(safe_http, "_resolve", lambda h: [ipaddress.ip_address("192.0.2.10")])

    async def rebound(host, port):
        return [ipaddress.ip_address("127.0.0.1")]
    monkeypatch.setattr(safe_http, "_aresolve", rebound)
    with pytest.raises(UnsafeOutboundURL):
        await safe_request("GET", "http://rebind.test:9/x", timeout=3)


@pytest.mark.anyio
async def test_the_connection_goes_to_the_checked_address_with_the_name_kept(srv) -> None:
    resp = await safe_request("GET", f"http://api.test:{srv.port}/x", timeout=5)
    assert resp.status_code == 200
    assert srv.seen[-1]["headers"]["host"] == f"api.test:{srv.port}"      # Host 仍是主機名稱


@pytest.mark.anyio
async def test_shared_clients_are_guarded_too(monkeypatch) -> None:
    """safe_client（各整合共用連線）也要在連線當下檢查。"""
    monkeypatch.setattr(safe_http, "_resolve", lambda h: [ipaddress.ip_address("192.0.2.10")])

    async def rebound(host, port):
        return [ipaddress.ip_address("169.254.169.254")]
    monkeypatch.setattr(safe_http, "_aresolve", rebound)
    async with safe_client(timeout=3) as client:
        with pytest.raises(UnsafeOutboundURL):
            await safe_request("GET", "http://meta.test/latest", client=client)


@pytest.mark.anyio
async def test_credentials_are_not_carried_to_another_host(srv) -> None:
    secret = {"X-Auth-Token": "tok-123", "Authorization": "Bearer abc", "Accept": "application/json"}
    resp = await safe_request("GET", f"http://api.test:{srv.port}/hop-cross", headers=secret,
                              params={"q": "1"}, timeout=5)
    assert resp.status_code == 200
    first, landed = srv.seen[-2], srv.seen[-1]
    assert first["headers"]["x-auth-token"] == "tok-123"
    assert landed["path"] == "/landed"                                 # 查詢參數不再疊上去
    assert "x-auth-token" not in landed["headers"]
    assert "authorization" not in landed["headers"]
    assert landed["headers"]["accept"] == "application/json"


@pytest.mark.anyio
async def test_same_host_redirect_keeps_credentials(srv) -> None:
    resp = await safe_request("GET", f"http://api.test:{srv.port}/hop-same", headers={"X-Auth-Token": "tok-123"},
                              timeout=5)
    assert resp.status_code == 200
    assert srv.seen[-1]["path"] == "/landed"
    assert srv.seen[-1]["headers"]["x-auth-token"] == "tok-123"


@pytest.mark.anyio
async def test_303_after_post_becomes_a_get_without_the_body(srv) -> None:
    resp = await safe_request("POST", f"http://api.test:{srv.port}/submit", json={"a": 1}, timeout=5)
    assert resp.status_code == 200
    last = srv.seen[-1]
    assert (last["method"], last["path"], last["body"]) == ("GET", "/after-post", b"")


@pytest.mark.anyio
async def test_netdiag_http_check_is_guarded_at_connect_time(monkeypatch) -> None:
    """工具頁的 HTTP 檢查（任何登入帳號）：DNS 換答案到 127.0.0.1 也要擋。"""
    from app.services import netdiag

    async def ok(url):
        return None
    monkeypatch.setattr(netdiag, "_assert_diag_http_target", ok)      # 模擬「檢查時是好的」

    async def rebound(host, port):
        return [ipaddress.ip_address("127.0.0.1")]
    monkeypatch.setattr(safe_http, "_aresolve", rebound)
    res = await netdiag.http_check("http://rebind.test:9/", timeout=3)
    assert res.ok is False
    assert res.status is None


@pytest.mark.anyio
async def test_netdiag_refuses_mapped_loopback() -> None:
    from app.services import netdiag
    res = await netdiag.http_check("http://[::ffff:127.0.0.1]:9/", timeout=3)
    assert res.ok is False
    assert "not a diagnostic target" in (res.error or "")


def test_the_guard_is_wired_into_httpcore() -> None:
    """守門靠的是 httpcore 的 network backend；httpx／httpcore 升級改了內部結構時要大聲失敗，
    不可以安靜地變回沒有防護。"""
    t = safe_http.GuardedTransport(check=lambda host, addrs: None)
    assert isinstance(t._pool._network_backend, safe_http._GuardedBackend)
    asyncio.run(t.aclose())
