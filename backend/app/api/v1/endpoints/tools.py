"""IP / CIDR 計算機與工具端點（純運算，無 DB 寫入）。

實際運算邏輯在 `app/services/nettools.py`，同一套同時供 MCP / AI chat 工具使用。
此處只負責：HTTP 參數驗證、把 `NetToolError` 翻成 400、套 response_model。

OWASP A05：所有輸入透過 stdlib `ipaddress` 解析（service 層），拒絕不合法 input。
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.rate_limit import check_rate_limit
from app.schemas.base import StrictModel
from app.services import netdiag, nettools
from app.services.nettools import NetToolError

router = APIRouter(prefix="/tools", tags=["tools"])


# ─────────────────── Schemas ───────────────────
class IPInfo(StrictModel):
    ip: str
    version: int
    is_private: bool
    is_global: bool
    is_reserved: bool
    is_multicast: bool
    is_loopback: bool
    is_link_local: bool
    decimal: str  # int as string（避免 JS 大整數精度）
    hex: str
    reverse_pointer: str
    binary: str | None  # IPv4 32-bit binary；IPv6 因長度太長 → None


class CIDRInfo(StrictModel):
    cidr: str
    version: int
    network_address: str
    broadcast_address: str | None  # IPv6 沒有 broadcast 概念
    netmask: str
    hostmask: str
    prefixlen: int
    num_addresses: str  # int as string
    host_count: str
    first_host: str | None
    last_host: str | None
    is_private: bool


class CIDRSplit(StrictModel):
    cidr: str
    new_prefix: int
    subnets: list[str]
    count: int


class EUI64Result(StrictModel):
    mac: str
    prefix: str
    address: str


def _bad(exc: NetToolError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


# ─────────────────── Endpoints ───────────────────
@router.get("/ip-info", response_model=IPInfo)
async def ip_info(
    _user: CurrentUser,
    ip: Annotated[str, Query(min_length=2, max_length=64)],
) -> IPInfo:
    try:
        return IPInfo(**nettools.ip_info(ip))
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/cidr-info", response_model=CIDRInfo)
async def cidr_info(
    _user: CurrentUser,
    cidr: Annotated[str, Query(min_length=3, max_length=64)],
) -> CIDRInfo:
    try:
        return CIDRInfo(**nettools.cidr_info(cidr))
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/cidr-split", response_model=CIDRSplit)
async def cidr_split(
    _user: CurrentUser,
    cidr: Annotated[str, Query(min_length=3, max_length=64)],
    new_prefix: Annotated[int, Query(ge=0, le=128)],
) -> CIDRSplit:
    try:
        return CIDRSplit(**nettools.cidr_split(cidr, new_prefix))
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/eui64", response_model=EUI64Result)
async def eui64(
    _user: CurrentUser,
    mac: Annotated[str, Query(min_length=12, max_length=17)],
    prefix: Annotated[str, Query(min_length=3, max_length=64)],
) -> EUI64Result:
    """從 MAC 與 IPv6 prefix 產生 EUI-64 位址（RFC 4291）。prefix 應為 /64 或更短。"""
    try:
        return EUI64Result(**nettools.eui64(mac, prefix))
    except NetToolError as exc:
        raise _bad(exc) from exc


# ─────────────────── 更多 IP / CIDR / FQDN / DNS 工具 ───────────────────
@router.get("/ip-in-cidr")
async def ip_in_cidr(
    _user: CurrentUser,
    ip: Annotated[str, Query(min_length=2, max_length=64)],
    cidr: Annotated[str, Query(min_length=3, max_length=64)],
) -> dict[str, Any]:
    """判斷某 IP 是否落在某 CIDR 內。"""
    try:
        return nettools.ip_in_cidr(ip, cidr)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/cidr-relation")
async def cidr_relation(
    _user: CurrentUser,
    a: Annotated[str, Query(min_length=3, max_length=64)],
    b: Annotated[str, Query(min_length=3, max_length=64)],
) -> dict[str, Any]:
    """兩個 CIDR 的關係：相等 / 包含 / 被包含 / 重疊 / 不相交。"""
    try:
        return nettools.cidr_relation(a, b)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/range-to-cidr")
async def range_to_cidr(
    _user: CurrentUser,
    start: Annotated[str, Query(min_length=2, max_length=64)],
    end: Annotated[str, Query(min_length=2, max_length=64)],
) -> dict[str, Any]:
    """把起訖 IP 範圍轉成最少數量的 CIDR 區塊。"""
    try:
        return nettools.range_to_cidr(start, end)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/cidr-to-range")
async def cidr_to_range(
    _user: CurrentUser,
    cidr: Annotated[str, Query(min_length=3, max_length=64)],
) -> dict[str, Any]:
    """CIDR → 起訖位址與總數。"""
    try:
        return nettools.cidr_to_range(cidr)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/aggregate")
async def aggregate(
    _user: CurrentUser,
    cidrs: Annotated[str, Query(min_length=3, max_length=4096)],
) -> dict[str, Any]:
    """把多個 CIDR（逗號或空白分隔）聚合成最少數量的區塊。"""
    try:
        return nettools.aggregate(cidrs)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/netmask")
async def netmask_convert(
    _user: CurrentUser,
    value: Annotated[str, Query(min_length=1, max_length=64)],
) -> dict[str, Any]:
    """首碼長度 (24 或 /24) 或網路遮罩 (255.255.255.0) 互轉，附 wildcard / hostmask。"""
    try:
        return nettools.netmask(value)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/mac-format")
async def mac_format(
    _user: CurrentUser,
    mac: Annotated[str, Query(min_length=12, max_length=23)],
) -> dict[str, Any]:
    """MAC 正規化為各種常見格式。"""
    try:
        return nettools.mac_format(mac)
    except NetToolError as exc:
        raise _bad(exc) from exc


@router.get("/fqdn")
async def fqdn_parse(
    _user: CurrentUser,
    name: Annotated[str, Query(min_length=1, max_length=255)],
) -> dict[str, Any]:
    """解析 / 驗證 FQDN（RFC 1123）：labels、TLD、host、domain。"""
    return nettools.fqdn_parse(name)


@router.get("/dns-lookup")
async def dns_lookup(
    _user: CurrentUser,
    name: Annotated[str, Query(min_length=1, max_length=255)],
    type: Annotated[str, Query(pattern=r"^(A|AAAA|PTR|ANY)$")] = "ANY",
) -> dict[str, Any]:
    """以系統解析器查 A / AAAA / PTR（stdlib，無外部相依）。"""
    try:
        return await nettools.dns_lookup_live(name, type)
    except NetToolError as exc:
        # 逾時翻 504、其餘 400
        if "逾時" in str(exc):
            raise HTTPException(status_code=504, detail=str(exc)) from exc
        raise _bad(exc) from exc


@router.get("/geoip")
async def geoip(
    _user: CurrentUser,
    ip: Annotated[str, Query(min_length=1, max_length=64)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """IP 地理位置查詢（MaxMind GeoLite2 web service；需管理者先在系統設定填憑證）。"""
    try:
        addr = nettools.parse_addr(ip)
    except NetToolError as exc:
        raise _bad(exc) from exc
    from app.services.geoip import geoip_lookup
    return await geoip_lookup(session, str(addr))


@router.get("/dns-mail")
async def dns_mail(
    _user: CurrentUser,
    domain: Annotated[str, Query(min_length=1, max_length=255)],
    dkim_selector: Annotated[str, Query(max_length=128)] = "",
) -> dict[str, Any]:
    """郵件相關 DNS 診斷：MX / SPF / DMARC / DKIM。"""
    try:
        return await nettools.dns_mail(domain, dkim_selector)
    except NetToolError as exc:
        if "逾時" in str(exc):
            raise HTTPException(status_code=504, detail=str(exc)) from exc
        raise _bad(exc) from exc


# ─────────────────── 網路診斷（會實際送封包）───────────────────
#
# 與這個檔案其他工具的差別：上面都是純計算，這幾支會從伺服器對外送封包。
# 因此除了輸入驗證，另外做三件事：
#   1. 每使用者限流 —— 避免有人把它當掃描跳板反覆呼叫（caps 只限單次規模）
#   2. 寫稽核 —— 誰、從哪裡、對哪些目標做了什麼，要留得下來
#   3. 服務層強制上限（目標數 / 併發 / 逾時 / 整體期限），見 services/netdiag.py
#
# 權限沿用 `CurrentUser`（與本頁其他工具一致）。刻意不要求 admin：診斷是網管日常，
# 而零權限帳號也看得到工具頁；限流與稽核才是這裡合適的控制手段。

@router.get("/net/capabilities")
async def net_capabilities(_user: CurrentUser) -> dict[str, Any]:
    """這台伺服器上哪些診斷工具可用（前端據此標示不可用的功能）。"""
    return netdiag.tool_availability()


async def _diag_guard(
    session: AsyncSession, user: Any, request: Request, action: str, detail: dict[str, Any],
) -> None:
    await check_rate_limit(bucket=f"rl:netdiag:user:{user.id}", rate="30/minute")
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="net_diagnostic",
        object_id=None,
        action=action,
        diff=detail,
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()


class _PingIn(StrictModel):
    targets: Annotated[str, Field(min_length=1, max_length=4096)]
    count: Annotated[int, Field(ge=1, le=netdiag.MAX_COUNT)] = 3
    timeout: Annotated[float, Field(ge=0.5, le=10.0)] = 2.0
    concurrency: Annotated[int, Field(ge=1, le=netdiag.MAX_CONCURRENCY)] = 8


@router.post("/net/ping")
async def net_ping(
    payload: _PingIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """對一個或多個目標 ping（可設併發）。目標可用換行/逗號分隔，或直接給 CIDR。"""
    try:
        targets = netdiag.expand_targets(payload.targets)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_ping",
                      {"count": len(targets), "sample": targets[:5]})
    try:
        results = await netdiag.ping_many(
            targets, count=payload.count, timeout=payload.timeout,
            concurrency=payload.concurrency)
    except netdiag.NetDiagUnavailable as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return {"count": len(results), "results": [asdict(r) for r in results]}


class _TraceIn(StrictModel):
    target: Annotated[str, Field(min_length=1, max_length=253)]
    max_hops: Annotated[int, Field(ge=1, le=netdiag.MAX_HOPS)] = 20


@router.post("/net/traceroute")
async def net_traceroute(
    payload: _TraceIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """路徑追蹤（優先用 tracepath，會一併回報路徑 MTU）。"""
    try:
        target = netdiag.normalize_target(payload.target)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_traceroute", {"target": target})
    try:
        res = await netdiag.traceroute(target, max_hops=payload.max_hops)
    except netdiag.NetDiagUnavailable as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"target": res.target, "tool": res.tool, "path_mtu": res.path_mtu,
            "truncated": res.truncated, "hops": [asdict(h) for h in res.hops]}


@router.post("/net/traceroute/stream")
async def net_traceroute_stream(
    payload: _TraceIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> StreamingResponse:
    """路徑追蹤，一跳一列地邊跑邊送（SSE）。

    沒回應的躍點要等滿逾時才能確定，15 跳可能要 30～60 秒。整批做完才回應的話，
    使用者看到的是一個按下去長時間毫無反應的按鈕 —— 分不出是在跑、卡住、還是壞了。
    """
    try:
        target = netdiag.normalize_target(payload.target)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_traceroute", {"target": target})

    async def gen() -> Any:
        try:
            async for ev in netdiag.traceroute_stream(target, max_hops=payload.max_hops):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
        except netdiag.NetDiagUnavailable as exc:
            yield f"data: {json.dumps({'type': 'error', 'detail': str(exc)})}\n\n"
        except netdiag.NetDiagError as exc:
            yield f"data: {json.dumps({'type': 'error', 'detail': str(exc)})}\n\n"

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        # X-Accel-Buffering：nginx 預設會把上游回應緩衝起來，一路憋到結束才送出 ——
        # 那樣後端再怎麼逐行吐，瀏覽器還是最後才一次收到。
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class _TcpIn(StrictModel):
    targets: Annotated[str, Field(min_length=1, max_length=4096)]
    ports: Annotated[list[int], Field(min_length=1, max_length=8)]
    timeout: Annotated[float, Field(ge=0.2, le=10.0)] = 2.0
    concurrency: Annotated[int, Field(ge=1, le=netdiag.MAX_CONCURRENCY)] = 16


@router.post("/net/tcp")
async def net_tcp(
    payload: _TcpIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """TCP 埠連通性。對擋 ICMP 的主機比 ping 有用 —— 測的是實際要用的那個埠。"""
    try:
        targets = netdiag.expand_targets(payload.targets)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_tcp",
                      {"count": len(targets), "ports": payload.ports, "sample": targets[:5]})
    try:
        results = await netdiag.tcp_check(
            targets, payload.ports, timeout=payload.timeout, concurrency=payload.concurrency)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    return {"count": len(results), "results": [asdict(r) for r in results]}


class _UdpIn(StrictModel):
    targets: Annotated[str, Field(min_length=1, max_length=4096)]
    ports: Annotated[list[int], Field(min_length=1, max_length=8)]
    timeout: Annotated[float, Field(ge=0.2, le=10.0)] = 2.0
    concurrency: Annotated[int, Field(ge=1, le=netdiag.MAX_CONCURRENCY)] = 16


@router.post("/net/udp")
async def net_udp(
    payload: _UdpIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """UDP 埠探測。回三種狀態（open / closed / no_reply）——「沒回應」在 UDP 是
    無法判定的，不能當成開啟。對 53 / 123 會送真實協定封包。"""
    try:
        targets = netdiag.expand_targets(payload.targets)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_udp",
                      {"count": len(targets), "ports": payload.ports, "sample": targets[:5]})
    try:
        results = await netdiag.udp_check(
            targets, payload.ports, timeout=payload.timeout, concurrency=payload.concurrency)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    return {"count": len(results), "results": [asdict(r) for r in results]}


class _TlsIn(StrictModel):
    targets: Annotated[str, Field(min_length=1, max_length=4096)]
    port: Annotated[int, Field(ge=1, le=65535)] = 443
    server_name: Annotated[str | None, Field(max_length=253)] = None
    timeout: Annotated[float, Field(ge=1.0, le=15.0)] = 5.0


@router.post("/net/tls")
async def net_tls(
    payload: _TlsIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """看對方實際送出的憑證：主體 / 簽發者 / 效期 / SAN / 是否受信任 / 名稱是否相符。"""
    try:
        targets = netdiag.expand_targets(payload.targets)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_tls",
                      {"count": len(targets), "port": payload.port, "sample": targets[:5]})
    results = await netdiag.tls_check(
        targets, payload.port, server_name=payload.server_name, timeout=payload.timeout)
    return {"count": len(results), "results": [asdict(r) for r in results]}


class _HttpIn(StrictModel):
    url: Annotated[str, Field(min_length=1, max_length=2048)]
    timeout: Annotated[float, Field(ge=1.0, le=30.0)] = 10.0
    max_redirects: Annotated[int, Field(ge=0, le=10)] = 5
    verify_tls: bool = False


@router.post("/net/http")
async def net_http(
    payload: _HttpIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """狀態碼、轉址鏈與關鍵回應標頭。"""
    await _diag_guard(session, user, request, "net_http", {"url": payload.url[:200]})
    res = await netdiag.http_check(
        payload.url, timeout=payload.timeout, max_redirects=payload.max_redirects,
        verify_tls=payload.verify_tls)
    out = asdict(res)
    out["redirects"] = [asdict(h) for h in res.redirects]
    return out


class _RdnsIn(StrictModel):
    targets: Annotated[str, Field(min_length=1, max_length=4096)]
    timeout: Annotated[float, Field(ge=0.5, le=10.0)] = 3.0
    concurrency: Annotated[int, Field(ge=1, le=netdiag.MAX_CONCURRENCY)] = 16


@router.post("/net/rdns")
async def net_rdns(
    payload: _RdnsIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """整批查 PTR —— 用來找出網段裡哪些位址沒有反解。"""
    try:
        targets = netdiag.expand_targets(payload.targets)
    except netdiag.NetDiagError as exc:
        raise _bad(exc) from exc
    await _diag_guard(session, user, request, "net_rdns",
                      {"count": len(targets), "sample": targets[:5]})
    results = await netdiag.rdns_many(
        targets, timeout=payload.timeout, concurrency=payload.concurrency)
    return {"count": len(results),
            "with_ptr": sum(1 for r in results if r.ptr),
            "results": [asdict(r) for r in results]}
