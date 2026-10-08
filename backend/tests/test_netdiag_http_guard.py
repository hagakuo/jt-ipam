"""CodeQL 標出的 SSRF（2026-09-29）：工具頁的 HTTP 檢查讓任何登入的人叫伺服器去連任意網址。

內網是這個診斷工具本來的用途（不擋）；本機、link-local（雲端中繼資料 169.254.169.254）、多播不是診斷對象。
轉址後的每一跳都要檢查 —— 對外的網址可以 302 到 127.0.0.1。
"""
from __future__ import annotations

import pytest
from app.services import netdiag


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000/api/v1/system/version",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://0.0.0.0/",
])
async def test_loopback_and_metadata_are_refused(url) -> None:
    res = await netdiag.http_check(url)
    assert res.ok is False
    assert res.status is None
    assert "not a diagnostic target" in (res.error or "")


async def test_a_redirect_into_loopback_is_refused(monkeypatch) -> None:
    """對外的網址 302 到本機：第二跳要被擋，不可以真的去連。"""
    import httpx
    hits: list[str] = []

    async def fake_get(self, url, **kw):
        hits.append(str(url))
        req = httpx.Request("GET", url)
        return httpx.Response(302, headers={"location": "http://127.0.0.1:6379/"}, request=req)

    from urllib.parse import urlsplit

    async def ok_target(url):
        if urlsplit(url).hostname == "127.0.0.1":
            raise netdiag.DiagTargetBlocked("127.0.0.1 is loopback / link-local / multicast — not a diagnostic target")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(netdiag, "_assert_diag_http_target", ok_target)
    res = await netdiag.http_check("http://203.0.113.10/")
    assert hits == ["http://203.0.113.10/"], "轉址到本機的那一跳不可以送出"
    assert "not a diagnostic target" in (res.error or "")


async def test_private_addresses_are_still_allowed(monkeypatch) -> None:
    """內網主機是這個工具的正常用途。"""
    await netdiag._assert_diag_http_target("http://198.51.100.20/")
    await netdiag._assert_diag_http_target("http://10.20.0.12:8080/")


# ── TCP／UDP／TLS 檢查也是任何登入帳號都能用（CodeQL 判讀附帶發現，2026-10-01）──
# 以前只有 HTTP 檢查擋本機與 link-local：TCP 檢查可以拿來掃 jt-ipam 主機自己的本機埠（Redis、
# PostgreSQL…），TLS 檢查可以讀本機服務的憑證。規則跟 HTTP 檢查一樣；私網照常可測。

@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "localhost"])
async def test_tcp_udp_tls_refuse_loopback_and_metadata(target) -> None:
    (tcp,) = await netdiag.tcp_check([target], [6379], timeout=0.5)
    assert tcp.open is False
    assert "not a diagnostic target" in (tcp.error or "")
    (udp,) = await netdiag.udp_check([target], [53], timeout=0.5)
    assert udp.state != "open"
    assert "not a diagnostic target" in (udp.detail or "")
    (tls,) = await netdiag.tls_check([target], 443, timeout=1.0)
    assert tls.ok is False
    assert "not a diagnostic target" in (tls.error or "")


async def test_private_targets_are_still_diagnosable() -> None:
    """私網是這個工具本來的用途：被擋的只有本機／link-local／多播（TEST-NET 位址沒人回，會逾時而不是被擋）。"""
    (tcp,) = await netdiag.tcp_check(["192.0.2.55"], [22], timeout=0.3)
    assert "not a diagnostic target" not in (tcp.error or "")


async def test_the_servers_own_addresses_are_refused(monkeypatch) -> None:
    """jt-ipam 主機自己的區網位址（不是 127.0.0.1）也不是診斷對象：打得到就能讀本機上只綁區網介面的服務。"""
    monkeypatch.setattr(netdiag, "_local_addresses", lambda: {"192.0.2.10"})
    res = await netdiag.http_check("http://192.0.2.10:8000/api/v1/system/version")
    assert res.ok is False and res.status is None
    assert "this server" in (res.error or "")


def test_local_addresses_reads_the_kernel_table() -> None:
    addrs = netdiag._local_addresses()
    assert isinstance(addrs, (set, frozenset))
    assert not any(a.startswith("127.") for a in addrs), "迴路位址另外擋，不需要在這裡"


async def test_accounts_without_any_visibility_cannot_use_the_http_check(client, db_session) -> None:
    """完全沒有任何檢視權限的帳號不能叫伺服器替它去連內網（比照 AI 對話的總閘）。"""
    from tests.test_rbac_enforcement import _nonadmin_token
    _u, token = await _nonadmin_token(db_session)
    await db_session.commit()
    r = await client.post("/api/v1/tools/net/http", headers={"Authorization": f"Bearer {token}"},
                          json={"url": "http://192.0.2.1/"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "nd_no_visibility"
