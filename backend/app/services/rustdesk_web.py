"""相容 RustDesk 的網頁連線：後端的網路部分（會合、中繼、限流）。

依據 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md（乾淨室實作，章節編號照規格）：
- 4 會合：連 hbbs 送 PunchHoleRequest，等 relay_response；收到「可以直連」的回覆時開新連線改送 RequestRelay
- 5 中繼：連 hbbr 送 RequestRelay，第一則收到的就是受控端的訊息（沒有配對確認）
- 7.8 限流：受控端以 jt-ipam 後端的 IP 計算錯誤次數，所有使用者共用；後端要自己先擋

**只連設定好的位址**（防 SSRF）：hbbs 用 `hbbs_host`（空白＝代理回報的來源位址），hbbr 用 `relay_host`
（空白＝hbbs 的主機＋中繼預設埠）。hbbs 回的 `relay_server` 只記稽核，不跟著連（5.4：只有設了多台中繼時才需要）。
連線當下解析並套用出站位址規則（check_addrs），與其他整合一致。
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import time
import uuid as uuidlib
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.safe_http import UnsafeOutboundURL, _aresolve, check_addrs, transport_detail
from app.core.ui_error import UiError
from app.services import rustdesk_web_proto as proto

# 預設埠（0 名詞表）
PORTS = {"tcp": (21116, 21117), "ws": (21118, 21119)}

# 4.4 時限與重試（測試時可以縮短）
CONNECT_TIMEOUT = 18.0          # 連 hbbs／hbbr 的連線逾時
PUNCH_ATTEMPTS = 3              # PunchHoleRequest 最多送 3 次（同一條連線）
ATTEMPT_WAIT_UNIT = 3.0         # 第 i 次送出後最多等 i × 3 秒
REQUEST_RELAY_WAIT = 18.0       # 4.3 等 relay_response：規格沒寫，用連線逾時的數值（保守）
MAX_KEY_EXCHANGE_SKIP = 2       # 4.2.3：key_exchange 最多略過 2 則
PAIR_TIMEOUT = 30.0             # 5.2：先到的一方最多等 30 秒
#: 收到 relay_response 之後先等一下再連 hbbr。黑箱實測（hbbr 1.1.16，2026-10-04）：後端與受控端在同一瞬間
#: 送出同一個 uuid 時，hbbr 兩邊都當成「先到」，結果一條被關掉、另一條等到逾時（8 次失敗 2 次）；
#: 等 0.3 秒後再連就 8／8 成功。受控端快的（規格 5.2：Windows 0.1 秒內）會先到、我們一到就配上；
#: 慢的（Linux 約 5 秒）照樣是我們先到等它。
RELAY_CONNECT_DELAY = 0.3
#: 連上 hbbr 後很快就被關掉、而且還沒收到任何訊息＝上面那種競態被擠掉的一方：用同一個 uuid 再試。
#: （金鑰不符也是「立刻關掉」，再試一樣會被關，所以次數要有上限。）
RELAY_RETRY_WITHIN = 1.0
RELAY_RETRIES = 2
#: 附錄 C-3：連上 hbbr 後這麼久還沒有第一則＝競態裡被蓋掉的是對方那條（留下來的我們只會等到逾時），
#: 整個從會合重來一次（新的 uuid），只重來一次。比受控端慢的情況（規格 5.2：Linux 約 5 秒）長。
RESTART_AFTER = 10.0


class RdWebError(UiError):
    """會合／中繼失敗。code 是第 11 節的錯誤代碼；detail 是原文（hbbs 給的拒絕原因、連線錯誤、位址），
    畫面在翻譯後面另外顯示，稽核照存（2.3 的 error 訊息：`{"code", "detail"}`）。"""

    def __init__(self, code: str, message: str, *, detail: str = "", **params: Any) -> None:
        self.detail = (detail or "")[:500]
        params.setdefault("reason", self.detail or message)
        super().__init__(message, code=code, **params)


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    def label(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


def split_host_port(addr: str, default_port: int) -> Endpoint:
    """`主機`、`主機:埠`、`[v6]`、`[v6]:埠`，或不帶括號的 IPv6 字面值（代理回報的來源位址）。"""
    addr = addr.strip()
    try:
        ipaddress.ip_address(addr)
        return Endpoint(addr, default_port)      # 純 IP（含不帶括號的 IPv6）
    except ValueError:
        pass
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return Endpoint(host, port)
    if ":" in addr:
        host, _, port_s = addr.rpartition(":")
        return Endpoint(host, int(port_s))
    return Endpoint(addr, default_port)


def hbbs_endpoint(server: Any) -> Endpoint | None:
    host = (server.hbbs_host or "").strip() or (server.agent_source_ip or "").strip()
    if not host:
        return None
    return split_host_port(host, PORTS[_transport(server)][0])


def relay_endpoint(server: Any) -> Endpoint | None:
    """5.4：預設是「後端連 hbbs 用的主機 + 中繼埠」，可以另外設定。"""
    port = PORTS[_transport(server)][1]
    if (server.relay_host or "").strip():
        return split_host_port(server.relay_host, port)
    hbbs = hbbs_endpoint(server)
    return Endpoint(hbbs.host, port) if hbbs else None


def _transport(server: Any) -> str:
    return server.transport if server.transport in PORTS else "tcp"


# ── 傳輸（2.1 TCP 長度前綴、2.2 WebSocket 一則一則）──────────────────────────────

class ChannelClosed(Exception):
    """對方關閉了連線。"""


class Channel(Protocol):
    label: str

    async def send(self, msg: bytes) -> None: ...

    async def recv(self) -> bytes: ...

    async def close(self) -> None: ...


class TcpChannel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, label: str) -> None:
        self._r = reader
        self._w = writer
        self.label = label

    async def send(self, msg: bytes) -> None:
        if len(msg) > proto.MAX_MESSAGE:
            raise RdWebError("rd_message_too_large", "訊息超過 16 MB 上限", detail=f"> {proto.MAX_MESSAGE} bytes")
        try:
            self._w.write(proto.frame(msg))
            await self._w.drain()              # 背壓：寫不出去就停在這裡
        except (ConnectionError, OSError) as exc:
            raise ChannelClosed(str(exc)) from exc

    async def recv(self) -> bytes:
        try:
            first = await self._r.readexactly(1)
            rest = await self._r.readexactly(proto.header_size(first[0]) - 1)
            n = proto.parse_header(first + rest)
            if n > proto.MAX_MESSAGE:
                raise RdWebError("rd_message_too_large", "訊息超過 16 MB 上限", detail=f"> {proto.MAX_MESSAGE} bytes")
            return await self._r.readexactly(n) if n else b""
        except asyncio.IncompleteReadError as exc:
            raise ChannelClosed("eof") from exc
        except (ConnectionError, OSError) as exc:
            raise ChannelClosed(str(exc)) from exc

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self._w.close()
            await asyncio.wait_for(self._w.wait_closed(), 2)


class WsChannel:
    """hbbs 21118／hbbr 21119：一則 binary 就是一則訊息，沒有長度前綴。text／ping／pong 不是訊息。"""

    def __init__(self, ws: Any, label: str) -> None:
        self._ws = ws
        self.label = label

    async def send(self, msg: bytes) -> None:
        from websockets.exceptions import ConnectionClosed
        if len(msg) > proto.MAX_MESSAGE:
            raise RdWebError("rd_message_too_large", "訊息超過 16 MB 上限", detail=f"> {proto.MAX_MESSAGE} bytes")
        try:
            await self._ws.send(msg)
        except ConnectionClosed as exc:
            raise ChannelClosed(str(exc)) from exc

    async def recv(self) -> bytes:
        from websockets.exceptions import ConnectionClosed, PayloadTooBig
        while True:
            try:
                m = await self._ws.recv()
            except PayloadTooBig as exc:
                raise RdWebError("rd_message_too_large", "訊息超過 16 MB 上限", detail=f"> {proto.MAX_MESSAGE} bytes") from exc
            except ConnectionClosed as exc:
                raise ChannelClosed(str(exc)) from exc
            if isinstance(m, bytes):
                return m

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._ws.close(), 2)


async def open_channel(ep: Endpoint, transport: str, *, what: str) -> Channel:
    """連 hbbs 或 hbbr。連線當下解析、檢查出站位址規則，再連到檢查過的位址（DNS 換答案也繞不過去）。"""
    code = "rd_hbbs_unreachable" if what == "hbbs" else "rd_hbbr_unreachable"
    try:
        addrs = await _aresolve(ep.host, ep.port)
        if not addrs:
            raise UnsafeOutboundURL(f"No usable address for {ep.host}")
        check_addrs(ep.host, addrs)
    except UnsafeOutboundURL as exc:
        raise RdWebError(code, f"{what} {ep.label()}：{exc}", detail=f"{ep.label()}: {exc}") from exc
    last: BaseException | None = None
    for ip in addrs:
        try:
            if transport == "ws":
                return await _open_ws(str(ip), ep)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), ep.port, limit=64 * 1024), CONNECT_TIMEOUT)
            return TcpChannel(reader, writer, ep.label())
        except (TimeoutError, OSError) as exc:
            last = exc
        except Exception as exc:   # websockets 的握手錯誤（InvalidHandshake 等）
            last = exc
    why = transport_detail(last) if last else "no address"
    raise RdWebError(code, f"{what} {ep.label()}：{why}", detail=f"{ep.label()}: {why}")


async def _open_ws(ip: str, ep: Endpoint) -> WsChannel:
    from websockets.asyncio.client import connect
    host = f"[{ip}]" if ":" in ip else ip
    ws = await connect(
        f"ws://{host}:{ep.port}/",
        open_timeout=CONNECT_TIMEOUT, max_size=proto.MAX_MESSAGE, compression=None,
        # hbbs／hbbr 不轉送 ping／pong（2.2），也不知道它們會不會回 pong：不送，免得被自己的逾時斷線
        ping_interval=None, close_timeout=2,
    )
    return WsChannel(ws, ep.label())


# ── 4 會合 ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rendezvous:
    uuid: str
    relay_server: str     # hbbs 回的原文（稽核用；不跟著連）
    pk: bytes             # hbbs 簽章過的受控端身分（6.1）
    peer_version: str
    via_request_relay: bool   # 走了 4.3（hbbs 判定可以直連）


async def _recv_within(ch: Channel, seconds: float) -> bytes | None:
    try:
        return await asyncio.wait_for(ch.recv(), max(seconds, 0.0))
    except TimeoutError:
        return None


async def rendezvous(ep: Endpoint, transport: str, peer_id: str, licence_key: str) -> Rendezvous:
    """4.1～4.4。回傳中繼要用的 uuid 與簽章過的受控端身分；失敗丟 RdWebError（代碼見第 11 節）。"""
    ch = await open_channel(ep, transport, what="hbbs")
    try:
        req = proto.punch_hole_request(peer_id, licence_key)
        skipped = 0
        for attempt in range(1, PUNCH_ATTEMPTS + 1):
            try:
                await ch.send(req)
            except ChannelClosed as exc:
                raise RdWebError("rd_hbbs_unreachable", f"hbbs {ep.label()} 關閉了連線", detail=f"{ep.label()}: closed") from exc
            deadline = time.monotonic() + attempt * ATTEMPT_WAIT_UNIT
            while True:
                try:
                    raw = await _recv_within(ch, deadline - time.monotonic())
                except ChannelClosed as exc:
                    raise RdWebError("rd_hbbs_unreachable", f"hbbs {ep.label()} 關閉了連線",
                                     detail=f"{ep.label()}: closed") from exc
                if raw is None:
                    break                                   # 這一次沒等到 → 重送
                try:
                    kind, sub = proto.parse_rendezvous(raw)
                except proto.ProtoError as exc:
                    raise RdWebError("rd_handshake_failed", f"hbbs 的回覆無法解析：{exc}", detail=str(exc)) from exc
                if kind == "key_exchange":
                    # 開源版不會送（Pro 版的連線加密）；收到就略過，最多 2 則
                    skipped += 1
                    if skipped > MAX_KEY_EXCHANGE_SKIP:
                        raise RdWebError("rd_handshake_failed", "hbbs 一直送 key_exchange", detail="key_exchange")
                    continue
                if kind == "relay_response":
                    rr = proto.RelayResponse.of(sub)
                    if rr.refuse_reason:
                        raise RdWebError("rd_relay_refused", rr.refuse_reason, detail=rr.refuse_reason)
                    return Rendezvous(uuid=rr.uuid, relay_server=rr.relay_server, pk=rr.pk,
                                      peer_version=rr.version, via_request_relay=False)
                if kind == "punch_hole_response":
                    ph = proto.PunchHoleResponse.of(sub)
                    if not ph.socket_addr:
                        if ph.other_failure:
                            raise RdWebError("rd_relay_refused", ph.other_failure, detail=ph.other_failure)
                        code = proto.FAILURE_CODES.get(ph.failure, "rd_relay_refused")
                        raise RdWebError(code, f"hbbs 回覆 failure={ph.failure}", detail=f"failure={ph.failure}")
                    # hbbs 判定可以直連（打洞或同一個內網）。第一階段不直連 → 4.3 改要中繼
                    await ch.close()
                    return await _request_relay(ep, transport, peer_id, ph)
                # 其他種類：不是給我們的，繼續等
        raise RdWebError("rd_rendezvous_timeout", f"hbbs {ep.label()} 送了 {PUNCH_ATTEMPTS} 次都沒有回覆",
                         detail=ep.label())
    finally:
        await ch.close()


async def _request_relay(ep: Endpoint, transport: str, peer_id: str, ph: proto.PunchHoleResponse) -> Rendezvous:
    """4.3：開**新的** hbbs 連線（hbbs 以來源位址區分每次嘗試），送 RequestRelay，用自己產生的 uuid。"""
    my_uuid = str(uuidlib.uuid4())
    ch = await open_channel(ep, transport, what="hbbs")
    try:
        try:
            await ch.send(proto.request_relay_hbbs(peer_id, my_uuid, ph.relay_server))
        except ChannelClosed as exc:
            raise RdWebError("rd_hbbs_unreachable", f"hbbs {ep.label()} 關閉了連線", detail=f"{ep.label()}: closed") from exc
        deadline = time.monotonic() + REQUEST_RELAY_WAIT
        skipped = 0
        while True:
            try:
                raw = await _recv_within(ch, deadline - time.monotonic())
            except ChannelClosed as exc:
                raise RdWebError("rd_hbbs_unreachable", f"hbbs {ep.label()} 關閉了連線",
                                 detail=f"{ep.label()}: closed") from exc
            if raw is None:
                raise RdWebError("rd_rendezvous_timeout", f"hbbs {ep.label()} 沒有回覆中繼請求",
                                 detail=ep.label())
            try:
                kind, sub = proto.parse_rendezvous(raw)
            except proto.ProtoError as exc:
                raise RdWebError("rd_handshake_failed", f"hbbs 的回覆無法解析：{exc}", detail=str(exc)) from exc
            if kind == "key_exchange":
                skipped += 1
                if skipped > MAX_KEY_EXCHANGE_SKIP:
                    raise RdWebError("rd_handshake_failed", "hbbs 一直送 key_exchange", detail="key_exchange")
                continue
            if kind != "relay_response":
                continue
            rr = proto.RelayResponse.of(sub)
            if rr.refuse_reason:
                raise RdWebError("rd_relay_refused", rr.refuse_reason, detail=rr.refuse_reason)
            # 附錄 C-5：簽章過的身分以 4.2 第 2 種回覆裡的 pk 為準；這一則若也帶 pk，兩者必須相同
            if rr.pk and rr.pk != ph.pk:
                raise RdWebError("rd_bad_server_signature", "hbbs 兩次給的受控端身分不一樣",
                                 detail="pk mismatch between punch_hole_response and relay_response")
            return Rendezvous(uuid=my_uuid, relay_server=ph.relay_server or rr.relay_server,
                              pk=ph.pk, peer_version=rr.version, via_request_relay=True)
    finally:
        await ch.close()


# ── 5 中繼 ────────────────────────────────────────────────────────────────────

async def open_relay(ep: Endpoint, transport: str, peer_id: str, uuid: str,
                     licence_key: str, *, wait: float | None = None) -> tuple[Channel, bytes]:
    """連 hbbr、送 RequestRelay，等第一則受控端的訊息（配對沒有確認，第一則到了才知道配上了）。

    回傳 (中繼連線, 第一則訊息)。`wait`（預設 30 秒）內沒有配對 → rd_relay_timeout。
    """
    if RELAY_CONNECT_DELAY:
        await asyncio.sleep(RELAY_CONNECT_DELAY)
    budget = PAIR_TIMEOUT if wait is None else min(wait, PAIR_TIMEOUT)
    deadline = time.monotonic() + budget
    attempt = 0
    while True:
        ch = await open_channel(ep, transport, what="hbbr")
        started = time.monotonic()
        try:
            await ch.send(proto.request_relay_hbbr(peer_id, uuid, licence_key))
            first = await asyncio.wait_for(ch.recv(), max(deadline - time.monotonic(), 0.1))
            return ch, first
        except TimeoutError as exc:
            await ch.close()
            raise RdWebError("rd_relay_timeout", f"{budget:.0f} 秒內沒有配對", detail=ep.label()) from exc
        except ChannelClosed as exc:
            await ch.close()
            took = time.monotonic() - started
            if took < RELAY_RETRY_WITHIN and attempt < RELAY_RETRIES and time.monotonic() < deadline:
                attempt += 1
                await asyncio.sleep(RELAY_CONNECT_DELAY or 0.1)
                continue
            # hbbr 在金鑰不符時直接斷線、不回任何訊息（5.1）；配對逾時也會被關閉（5.1）
            raise RdWebError("rd_hbbr_unreachable",
                             f"中繼 {ep.label()} 在配對前關閉了連線（{took:.1f} 秒；可能是伺服器公鑰不符或配對逾時）",
                             detail=f"{ep.label()}: closed before pairing after {took:.1f}s "
                                    f"({attempt + 1} attempts)") from exc
        except BaseException:
            await ch.close()
            raise


# ── 7.8 錯誤次數限流（每位使用者 × 每台受控端）──────────────────────────────────

#: 瀏覽器回報的登入結果（7.5、7.6）→ 計入哪一組失敗次數。其他字串（等待對方同意、要兩步驟驗證…）不算失敗
_FAIL_KIND = {
    "Wrong Password": "password",
    "Wrong 2FA Code": "2fa",
    # 受控端自己已經在擋了：再試只會讓整台 jt-ipam 被鎖更久
    "Too many wrong attempts": "password",
    "Please try 1 minute later": "password",
    # 附錄 G.7：沒有桌面的 Linux 受控端說 RustDesk 密碼錯（跟作業系統帳號一起送的那次）＝猜錯密碼，跟 Wrong Password
    # 同一組，否則從這條路猜密碼不會被限流。「password empty」不算：那是沒給 RustDesk 密碼時的第一個提示，沒有猜任何
    # 密碼（跟 No Password Access 一樣）；「Desktop session not ready」表示 RustDesk 密碼已經通過，只缺作業系統帳號。
    "Desktop session not ready, password wrong": "password",
}
FAIL_KINDS = ("password", "2fa")


def failure_kind(error: str) -> str | None:
    return _FAIL_KIND.get((error or "").strip())


def _fail_key(kind: str, window: str, user_id: Any, server_id: Any, peer_id: str) -> str:
    return f"rdweb:fail:{kind}:{window}:{user_id}:{server_id}:{peer_id}"


async def failure_counts(redis: Any, user_id: Any, server_id: Any, peer_id: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for kind in FAIL_KINDS:
        out[kind] = {}
        for window in ("m", "d"):
            v = await redis.get(_fail_key(kind, window, user_id, server_id, peer_id))
            out[kind][window] = int(v) if v else 0
    return out


def _over(counts: dict[str, dict[str, int]], per_minute: int, per_day: int) -> bool:
    return any((per_minute and c["m"] >= per_minute) or (per_day and c["d"] >= per_day) for c in counts.values())


async def is_blocked(redis: Any, user_id: Any, server_id: Any, peer_id: str) -> bool:
    from app.core.config import get_settings
    s = get_settings()
    counts = await failure_counts(redis, user_id, server_id, peer_id)
    return _over(counts, s.rustdesk_web_fail_per_minute, s.rustdesk_web_fail_per_day)


async def record_failure(redis: Any, user_id: Any, server_id: Any, peer_id: str, kind: str) -> bool:
    """記一次失敗（固定視窗：一分鐘、一天，從第一次失敗起算）。回傳記完之後是否已達上限。"""
    for window, ttl in (("m", 60), ("d", 86400)):
        key = _fail_key(kind, window, user_id, server_id, peer_id)
        n = await redis.incr(key)
        if int(n) == 1:
            await redis.expire(key, ttl)
    return await is_blocked(redis, user_id, server_id, peer_id)
