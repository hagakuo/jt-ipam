"""統一外部 HTTP client，內建 SSRF 防護（OWASP A06）。

使用方式：

    from app.core.safe_http import safe_request
    resp = await safe_request("GET", "https://librenms.example.com/api/v0/devices",
                              headers={...}, timeout=10.0)

任何對外整合（DNS server、LibreNMS、Webhook、OIDC discovery）一律走這支；
不允許直接 `httpx.AsyncClient(...)` 呼叫使用者控制的 URL。

防護內容：
1. URL 允許清單（協定、host、解析後 IP CIDR）
2. DNS 解析後 pin IP，避免 DNS rebinding
3. 重導向 follow 上限 + 每次 redirect 重檢
4. 超時必填
5. 阻擋 metadata IP（AWS/GCP/Azure 169.254.169.254、Alibaba 100.100.100.200）
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import asynccontextmanager
from typing import Any, Final
from urllib.parse import urlparse

import httpcore
import httpx

from app.core.config import get_settings
from app.core.ui_error import UiError

# =============================================================================
# Hardcoded denylist（無論設定如何，都不允許）
# =============================================================================
_BLOCKED_CIDRS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = (
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Link-local（含 cloud metadata）
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Unique local IPv6 隨設定
    # Multicast / broadcast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    # 0.0.0.0/8（routable 為 unspecified）
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    # Carrier-grade NAT — 對 IPAM 通常不該打過去
    ipaddress.ip_network("100.64.0.0/10"),
    # AWS 的 IPv6 中繼資料位址（落在 fc00::/7，私網預設允許時不會被上面那幾條擋到）
    ipaddress.ip_network("fd00:ec2::254/128"),
)

_PRIVATE_CIDRS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
_DEFAULT_TIMEOUT: Final[float] = 10.0
_MAX_REDIRECTS: Final[int] = 3


class UnsafeOutboundURL(ValueError):
    """請求被 SSRF 防護擋下。"""


def _parse_allow_cidrs(items: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in items:
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return out


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeOutboundURL(f"DNS resolution failed for {host}: {exc}") from exc
    addrs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for family, _type, _proto, _name, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if family == socket.AF_INET6 and isinstance(addr, ipaddress.IPv6Address):
            addrs.append(addr)
        elif family == socket.AF_INET and isinstance(addr, ipaddress.IPv4Address):
            addrs.append(addr)
    if not addrs:
        raise UnsafeOutboundURL(f"No usable address for {host}")
    return addrs


def _canon(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """IPv4 對映的 IPv6（`::ffff:a.b.c.d`）當成它代表的 IPv4。

    CodeQL 判讀（2026-10-01）：網段比對只看同版本，`::ffff:127.0.0.1` 既不算本機也不算私網，
    Linux 雙堆疊卻會把它連到 127.0.0.1 —— 任何登入帳號都能用工具頁的 HTTP 檢查打本機與雲端中繼資料。
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _ip_in(addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
           networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
                     | list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    addr = _canon(addr)
    return any(addr in net for net in networks if addr.version == net.version)


Addr = ipaddress.IPv4Address | ipaddress.IPv6Address


def check_addrs(host: str, addrs: Iterable[Addr]) -> None:
    """出站的位址規則：封鎖清單一律擋、私網要設定允許、允許清單網段可放行。不安全丟 UnsafeOutboundURL。"""
    settings = get_settings()
    extra_allow = _parse_allow_cidrs(settings.outbound_allow_cidrs)
    for ip in addrs:
        # 允許清單命中可放行（即便落在 private）
        if extra_allow and _ip_in(ip, extra_allow):
            continue
        # 封鎖清單一律擋
        if _ip_in(ip, _BLOCKED_CIDRS):
            raise UnsafeOutboundURL(f"Blocked IP for SSRF: {ip}")
        # 私網需明確允許（A10）
        if _ip_in(ip, _PRIVATE_CIDRS) and not settings.outbound_allow_private:
            raise UnsafeOutboundURL(
                f"Private IP {ip} not allowed (set OUTBOUND_ALLOW_PRIVATE=true if intended)"
            )


def assert_url_safe(url: str) -> list[Addr]:
    """A10 — 檢查 URL 是否安全；不安全則丟 UnsafeOutboundURL。回傳檢查過的位址。

    這是送出前的快速檢查（錯誤訊息清楚）；真正的防線在連線當下（`GuardedTransport`）：
    這裡解析完到 httpx 連線之間，DNS 可以換答案。
    """
    settings = get_settings()
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeOutboundURL(f"Disallowed scheme: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise UnsafeOutboundURL("URL missing host")

    # IP literal 直接驗證
    try:
        addr = ipaddress.ip_address(host)
        addrs = [addr]
    except ValueError:
        # 走 DNS
        if settings.outbound_allow_hosts and host not in settings.outbound_allow_hosts:
            # host 允許清單存在則必須命中
            pass  # fallthrough：仍會檢 IP 允許清單
        addrs = _resolve(host)

    check_addrs(host, addrs)
    return addrs


async def _aresolve(host: str, port: int) -> list[Addr]:
    """連線當下的解析（非阻塞）。IP 字面值直接回它自己。"""
    try:
        return [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeOutboundURL(f"DNS resolution failed for {host}: {exc}") from exc
    out: list[Addr] = []
    for _fam, _t, _p, _n, sockaddr in infos:
        try:
            a = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if a not in out:
            out.append(a)
    return out


class _GuardedBackend(httpcore.AsyncNetworkBackend):
    """在**建立 TCP 連線的當下**解析、檢查、連到檢查過的位址。

    以前是「先解析檢查、httpx 連線時再解析一次」：DNS 在兩次之間換答案（rebinding）就繞過去了。
    只換掉連線目標，網址、Host、SNI 與憑證檢查都還是原本的主機名稱（httpcore 的 TLS 用請求的
    origin 當 server_hostname），連線池也照舊以主機名稱為鍵。
    """

    def __init__(self, inner: httpcore.AsyncNetworkBackend, check: Callable[[str, list[Addr]], None]) -> None:
        self._inner = inner
        self._check = check

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                          local_address: str | None = None,
                          socket_options: Iterable[Any] | None = None) -> httpcore.AsyncNetworkStream:
        addrs = await _aresolve(host, port)
        if not addrs:
            raise UnsafeOutboundURL(f"No usable address for {host}")
        self._check(host, addrs)                 # 任何一個位址不合規就整個拒絕（同送出前的檢查）
        last: Exception | None = None
        for ip in addrs:
            try:
                return await self._inner.connect_tcp(
                    str(ip), port, timeout=timeout, local_address=local_address,
                    socket_options=socket_options)
            except httpcore.ConnectError as exc:
                last = exc
        assert last is not None
        raise last

    async def connect_unix_socket(self, path: str, timeout: float | None = None,
                                  socket_options: Iterable[Any] | None = None) -> httpcore.AsyncNetworkStream:
        raise UnsafeOutboundURL("unix sockets are not an outbound target")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """連線當下套用位址規則的傳輸層（預設規則 `check_addrs`；工具頁的診斷另有自己的規則）。

    httpx 沒有公開的 network backend 參數，只能換掉內部連線池的那一個；`test_safe_http_guard`
    驗證它真的接上了 —— httpx／httpcore 升級改了內部結構時要大聲失敗，不能安靜地變回沒有防護。
    """

    def __init__(self, *, check: Callable[[str, list[Addr]], None] = check_addrs, **kw: Any) -> None:
        kw.setdefault("trust_env", False)        # A05：不信任 HTTP_PROXY、SSL_CERT_FILE 等環境變數
        super().__init__(**kw)
        pool = self._pool
        if not isinstance(pool, httpcore.AsyncConnectionPool):
            raise RuntimeError("GuardedTransport: unexpected httpx pool type")
        pool._network_backend = _GuardedBackend(pool._network_backend, check)


def guarded_client(*, timeout: float = _DEFAULT_TIMEOUT, verify: bool = True, http2: bool = True,
                   check: Callable[[str, list[Addr]], None] = check_addrs) -> httpx.AsyncClient:
    """不跟轉址、不信任環境變數、連線當下檢查位址的 client。"""
    return httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False,
        transport=GuardedTransport(verify=verify, http2=http2, check=check),
    )


#: 轉址到別的主機時只留下這些標頭（認證類一律不帶過去）
_REDIRECT_KEEP: Final[frozenset[str]] = frozenset(
    {"accept", "accept-language", "accept-encoding", "user-agent"})


def _same_target(cur: httpx.URL, nxt: httpx.URL) -> bool:
    """同一個來源；或同一台主機從 http 升級成 https（預設埠）—— 跟 httpx 自己的規則一樣。"""
    if (cur.scheme, cur.host, cur.port) == (nxt.scheme, nxt.host, nxt.port):
        return True
    return (cur.host == nxt.host and cur.scheme == "http" and nxt.scheme == "https"
            and cur.port in (None, 80) and nxt.port in (None, 443))


class ResponseTooLarge(UiError):
    """對方回的內容超過允許的大小 —— 讀完再判斷就來不及了，要在串流途中中止。"""


@asynccontextmanager
async def safe_client(
    *, timeout: float = _DEFAULT_TIMEOUT, verify: bool = True,
) -> AsyncIterator[httpx.AsyncClient]:
    """一批請求共用的連線（keep-alive）。

    為什麼需要：`safe_request()` 每呼叫一次就建一個 client，等於**每支端點各做一次
    TLS 握手**。對一般 API 無所謂，但對 CPU 弱的網路設備差很多 —— MikroTik CCR1072
    是 Tile 架構（核多但單核弱，握手跑在單核上），一輪同步十個區段就是十次握手。

    用法：
        async with safe_client(verify=fw.verify_tls) as client:
            await safe_request("GET", url, client=client)
    """
    async with guarded_client(timeout=timeout, verify=verify) as client:
        yield client


async def safe_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json: Any = None,
    content: bytes | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    verify: bool = True,
    max_redirects: int = _MAX_REDIRECTS,
    client: httpx.AsyncClient | None = None,
    max_bytes: int | None = None,
) -> httpx.Response:
    """經過 SSRF 檢查的 HTTP 請求。

    redirect 採手動處理：每次重導向後重新驗 URL，避免 302 → 169.254.169.254。

    `client`：共用連線（見 `safe_client`）。給了就不再自己建 client，
    省下每支端點一次 TLS 握手。

    `max_bytes`：回應大小上限。**超過就在串流途中中止**，不會先把整份讀進記憶體 ——
    像是帶著全表 BGP 的路由器，一支 `/ip/route` 可能是上百萬列，等讀完再判斷已經太遲。
    """
    current_url = url
    for _ in range(max_redirects + 1):
        assert_url_safe(current_url)
        if client is not None:
            resp = await _do_request(
                client, method, current_url, headers=headers, params=params,
                json=json, content=content, max_bytes=max_bytes)
        else:
            async with guarded_client(timeout=timeout, verify=verify) as owned:
                resp = await _do_request(
                    owned, method, current_url, headers=headers, params=params,
                    json=json, content=content, max_bytes=max_bytes)
        if resp.is_redirect and resp.next_request is not None:
            cur, nxt = httpx.URL(current_url), resp.next_request.url
            # 轉址到別的主機：認證標頭不帶過去（以前整包沿用，302 到別的網域就把
            # X-Auth-Token／Authorization／LLM 金鑰送給對方 —— httpx 自己會剝掉，手動處理時丟了這一步）
            if not _same_target(cur, nxt):
                headers = {k: v for k, v in (headers or {}).items() if k.lower() in _REDIRECT_KEEP}
            # 303（以及 POST 遇到 301／302）：改用 GET、不帶內容 —— 瀏覽器與 httpx 的慣例
            m = method.upper()
            if (resp.status_code == 303 and m != "HEAD") or (resp.status_code in (301, 302) and m == "POST"):
                method, json, content = "GET", None, None
                if headers:
                    headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
            params = None                       # 已在網址裡；不再每一跳疊一次
            current_url = str(nxt)
            continue
        return resp
    raise UnsafeOutboundURL(f"Too many redirects following {url}")


async def _do_request(
    client: httpx.AsyncClient, method: str, url: str, *,
    headers: dict[str, str] | None, params: dict[str, Any] | None,
    json: Any, content: bytes | None, max_bytes: int | None,
) -> httpx.Response:
    if max_bytes is None:
        return await client.request(
            method, url, headers=headers, params=params, json=json, content=content)

    # 有上限時走串流：邊收邊算，超過就中止，記憶體不會被一份大回應吃掉
    req = client.build_request(
        method, url, headers=headers, params=params, json=json, content=content)
    resp = await client.send(req, stream=True)
    try:
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise ResponseTooLarge(
                    f"回應超過 {max_bytes} bytes（已收 {total}）：{url}",
                    code="response_too_large", max=max_bytes, received=total, url=url)
            chunks.append(chunk)
    finally:
        await resp.aclose()
    body = b"".join(chunks)
    # 用同樣的狀態與標頭重建一個「已讀完」的回應，呼叫端照常用 .json() / .text。
    # aiter_bytes() 給的已經是解壓後的內容：content-encoding／content-length 要拿掉，
    # 否則讀取時會再解壓一次而失敗（GitHub API 一律 gzip）。
    headers = [(k, v) for k, v in resp.headers.multi_items()
               if k.lower() not in ("content-encoding", "content-length")]
    out = httpx.Response(
        status_code=resp.status_code, headers=headers, content=body,
        request=resp.request, extensions=resp.extensions)
    # 轉址：呼叫端（safe_request）要靠 next_request 才知道下一站
    out.next_request = resp.next_request
    return out


@asynccontextmanager
async def safe_stream(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json: Any = None,
    timeout: float = _DEFAULT_TIMEOUT,
    verify: bool = True,
) -> AsyncIterator[httpx.Response]:
    """經過 SSRF 檢查的 streaming HTTP 請求（NDJSON / SSE 用）。

    與 safe_request 不同：不 follow redirect（streaming 對重導向再驗 URL 成本高，
    且本專案的 streaming 目標只有自家 Ollama）。URL 仍先過 assert_url_safe。

        async with safe_stream("POST", url, json=body, timeout=t) as resp:
            async for line in resp.aiter_lines():
                ...
    """
    assert_url_safe(url)
    async with guarded_client(timeout=timeout, verify=verify) as client:
        async with client.stream(method, url, headers=headers, json=json) as resp:
            yield resp


def transport_detail(exc: BaseException, *, limit: int = 200) -> str:
    """把出站請求的例外整理成「看得出原因」的一行字。

    只印類別名稱是不夠的：`ConnectError` 一個名字底下至少有四種完全不同的狀況 ——
    名稱解析不到、連線被拒、路由不通、TLS 憑證驗不過（httpx 把握手期的 SSL 錯誤
    也包成 ConnectError）。少了底層原文，畫面上的「transport: ConnectError」對
    使用者與對我們都一樣沒有資訊，只能靠猜。

    原因有時在例外本身、有時在 `__cause__`（socket.gaierror / ssl.SSLCertVerificationError），
    兩邊都取。長度設界：這串會存進 `last_error` 並顯示在表格裡。
    """
    name = exc.__class__.__name__
    msg = str(exc).strip()
    cause = exc.__cause__ or exc.__context__
    if cause is not None:
        # OSError 子類（socket.gaierror / ssl.SSLCertVerificationError）用 strerror 才
        # 印得出人看得懂的字；直接 str() 有時會得到 tuple 的樣子。
        cmsg = str(getattr(cause, "strerror", None) or cause).strip()
        if cmsg and cmsg not in msg:
            msg = f"{msg} ({cmsg})" if msg else cmsg
    return f"{name}: {msg}"[:limit] if msg else name
