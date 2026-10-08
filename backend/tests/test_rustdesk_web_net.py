"""相容 RustDesk 的網頁連線：會合（hbbs）與中繼（hbbr）對假伺服器的行為（規格第 4、5 節）。

假伺服器照規格的線上格式：TCP 每則訊息前面加長度前綴（2.1），WebSocket 一則 binary 就是一則（2.2）。
"""
from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

import pytest

from app.services import rustdesk_web as W
from app.services import rustdesk_web_proto as proto

PEER = "123456789"
KEY = "K" * 43 + "="


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    """縮短時限；假伺服器都在 127.0.0.1，出站規則（迴路一律擋）在這裡放行。"""
    monkeypatch.setattr(W, "ATTEMPT_WAIT_UNIT", 0.15)
    monkeypatch.setattr(W, "REQUEST_RELAY_WAIT", 0.5)
    monkeypatch.setattr(W, "PAIR_TIMEOUT", 0.6)
    monkeypatch.setattr(W, "RELAY_CONNECT_DELAY", 0.0)
    monkeypatch.setattr(W, "CONNECT_TIMEOUT", 1.0)
    monkeypatch.setattr(W, "check_addrs", lambda host, addrs: None)


class Conn:
    """假伺服器那一端看到的一條連線（TCP 或 WS 都包成同一個介面）。"""

    def __init__(self, recv: Callable[[], Awaitable[bytes | None]], send: Callable[[bytes], Awaitable[None]],
                 close: Callable[[], Awaitable[None]]) -> None:
        self.recv = recv
        self.send = send
        self.close = close


class FakeServer:
    """每來一條連線就呼叫 handler(conn, index)；收到的訊息記在 received[index]。"""

    def __init__(self, transport: str, handler: Callable[[Conn, int], Awaitable[None]]) -> None:
        self.transport = transport
        self.handler = handler
        self.received: list[list[bytes]] = []
        self.port = 0
        self._srv = None

    async def __aenter__(self) -> FakeServer:
        if self.transport == "tcp":
            self._srv = await asyncio.start_server(self._tcp, "127.0.0.1", 0)
            self.port = self._srv.sockets[0].getsockname()[1]
        else:
            from websockets.asyncio.server import serve
            self._srv = await serve(self._ws, "127.0.0.1", 0, compression=None)
            self.port = next(iter(self._srv.sockets)).getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._srv.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._srv.wait_closed(), 2)

    @property
    def ep(self) -> W.Endpoint:
        return W.Endpoint("127.0.0.1", self.port)

    async def _tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        idx = len(self.received)
        self.received.append([])

        async def recv() -> bytes | None:
            try:
                first = await reader.readexactly(1)
                rest = await reader.readexactly(proto.header_size(first[0]) - 1)
                body = await reader.readexactly(proto.parse_header(first + rest))
            except asyncio.IncompleteReadError:
                return None
            self.received[idx].append(body)
            return body

        async def send(b: bytes) -> None:
            writer.write(proto.frame(b))
            await writer.drain()

        async def close() -> None:
            writer.close()

        try:
            await self.handler(Conn(recv, send, close), idx)
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _ws(self, ws) -> None:
        idx = len(self.received)
        self.received.append([])

        async def recv() -> bytes | None:
            try:
                while True:
                    m = await ws.recv()
                    if isinstance(m, bytes):
                        self.received[idx].append(m)
                        return m
            except Exception:
                return None

        async def send(b: bytes) -> None:
            await ws.send(b)

        async def close() -> None:
            await ws.close()

        await self.handler(Conn(recv, send, close), idx)


def relay_response(uuid: str = "u" * 36, relay: str = "rd.example.com", pk: bytes = b"p" * 109,
                   refuse: str = "", version: str = "1.4.1") -> bytes:
    body = (proto.f_str(2, uuid) + proto.f_str(3, relay) + proto.f_bytes(5, pk)
            + proto.f_str(6, refuse) + proto.f_str(7, version))
    return proto.f_msg(19, body)


def punch_hole_response(socket_addr: bytes = b"", pk: bytes = b"", failure: int = 0, relay: str = "",
                        other: str = "") -> bytes:
    body = (proto.f_bytes(1, socket_addr) + proto.f_bytes(2, pk) + proto.f_varint(3, failure)
            + proto.f_str(4, relay) + proto.f_str(7, other))
    return proto.f_msg(11, body)


KEY_EXCHANGE = proto.f_msg(25, proto.f_bytes(1, b"k" * 32))


async def _hold(conn: Conn) -> None:
    """讀到對方關閉為止（模擬 hbbs 不回）。"""
    while await conn.recv() is not None:
        pass


# ── 4.1、4.2 正常情況 ──

@pytest.mark.parametrize("transport", ["tcp", "ws"])
async def test_relay_response_on_the_same_connection(transport: str) -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()
        await conn.send(relay_response())
        await _hold(conn)

    async with FakeServer(transport, hbbs) as srv:
        rv = await W.rendezvous(srv.ep, transport, PEER, KEY)
    assert rv.uuid == "u" * 36
    assert rv.relay_server == "rd.example.com"
    assert rv.pk == b"p" * 109
    assert rv.via_request_relay is False
    # 送出的就是 PunchHoleRequest，欄位照 4.1
    kind, sub = proto.parse_rendezvous(srv.received[0][0])
    assert kind == "punch_hole_request"
    assert proto.get_str(sub, 1) == PEER
    assert proto.get_str(sub, 3) == KEY
    assert proto.get_int(sub, 8) == 1


async def test_key_exchange_is_skipped_up_to_two() -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()
        await conn.send(KEY_EXCHANGE)
        await conn.send(KEY_EXCHANGE)
        await conn.send(relay_response())
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        rv = await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert rv.uuid == "u" * 36


async def test_a_third_key_exchange_is_a_handshake_failure() -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()
        for _ in range(3):
            await conn.send(KEY_EXCHANGE)
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == "rd_handshake_failed"


# ── 4.4 重送與逾時 ──

async def test_retries_on_the_same_connection() -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()                  # 第一次不理
        await conn.recv()                  # 第二次才回
        await conn.send(relay_response())
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        rv = await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert rv.uuid == "u" * 36
    assert len(srv.received) == 1, "重送要在同一條連線上（hbbs 以來源位址找回這條連線）"
    assert len(srv.received[0]) == 2


async def test_three_unanswered_attempts_time_out() -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == "rd_rendezvous_timeout"
    assert len(srv.received[0]) == 3


async def test_unreachable_hbbs() -> None:
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()
    with pytest.raises(W.RdWebError) as e:
        await W.rendezvous(W.Endpoint("127.0.0.1", port), "tcp", PEER, KEY)
    assert e.value.code == "rd_hbbs_unreachable"
    assert str(port) in e.value.detail


# ── 4.2 的失敗回覆 ──

@pytest.mark.parametrize(("failure", "code"), [
    (None, "rd_id_not_exist"),            # 欄位不存在＝0＝ID_NOT_EXIST
    (2, "rd_offline"),
    (3, "rd_key_mismatch"),
    (4, "rd_key_overuse"),
])
async def test_punch_hole_failures(failure: int | None, code: str) -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()
        await conn.send(punch_hole_response(failure=failure or 0))
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == code


async def test_other_failure_text_wins() -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()
        await conn.send(punch_hole_response(failure=2, other="something upstream said"))
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == "rd_relay_refused"
    assert e.value.detail == "something upstream said"


async def test_refuse_reason_is_an_error() -> None:
    async def hbbs(conn: Conn, _i: int) -> None:
        await conn.recv()
        await conn.send(relay_response(refuse="peer refused"))
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == "rd_relay_refused"
    assert e.value.detail == "peer refused"


# ── 4.3 hbbs 判定可以直連 → 開新連線改要中繼 ──

@pytest.mark.parametrize("transport", ["tcp", "ws"])
async def test_direct_reply_switches_to_request_relay_on_a_new_connection(transport: str) -> None:
    async def hbbs(conn: Conn, idx: int) -> None:
        msg = await conn.recv()
        kind, _ = proto.parse_rendezvous(msg)
        if idx == 0:
            assert kind == "punch_hole_request"
            await conn.send(punch_hole_response(socket_addr=b"\x01\x02", pk=b"S" * 109,
                                                relay="relay.example.com:21117"))
        else:
            assert kind == "request_relay"
            await conn.send(relay_response(uuid="", relay="", pk=b""))     # 其他欄位可能是空的
        await _hold(conn)

    async with FakeServer(transport, hbbs) as srv:
        rv = await W.rendezvous(srv.ep, transport, PEER, KEY)
    assert len(srv.received) == 2, "4.3 要開一條新的 hbbs 連線"
    kind, sub = proto.parse_rendezvous(srv.received[1][0])
    assert kind == "request_relay"
    assert proto.get_str(sub, 1) == PEER
    assert proto.get_str(sub, 4) == "relay.example.com:21117"
    assert proto.get_int(sub, 5) == 1
    my_uuid = proto.get_str(sub, 2)
    assert len(my_uuid) == 36
    assert rv.uuid == my_uuid, "用自己產生的 uuid 去 hbbr"
    assert rv.pk == b"S" * 109, "簽章過的身分用 4.2 第 2 種回覆裡的 pk"
    assert rv.via_request_relay is True


async def test_request_relay_with_a_different_signed_identity_is_rejected() -> None:
    """附錄 C-5：改走 RequestRelay 後的 relay_response 若也帶 pk，必須和第一次會合回覆的相同。"""
    async def hbbs(conn: Conn, idx: int) -> None:
        await conn.recv()
        if idx == 0:
            await conn.send(punch_hole_response(socket_addr=b"\x01", pk=b"S" * 109))
        else:
            await conn.send(relay_response(uuid="", relay="", pk=b"T" * 109))
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == "rd_bad_server_signature"


async def test_request_relay_uses_only_the_first_signed_identity() -> None:
    """簽章用的 pk 以第一次會合回覆的為準；第一次沒有 pk 就是沒有（之後驗證會拒絕，不拿第二則補）。"""
    async def hbbs(conn: Conn, idx: int) -> None:
        await conn.recv()
        if idx == 0:
            await conn.send(punch_hole_response(socket_addr=b"\x01", pk=b""))
        else:
            await conn.send(relay_response(uuid="", relay="", pk=b""))
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        rv = await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert rv.pk == b""


async def test_request_relay_refused() -> None:
    async def hbbs(conn: Conn, idx: int) -> None:
        await conn.recv()
        if idx == 0:
            await conn.send(punch_hole_response(socket_addr=b"\x01", pk=b"S" * 109))
        else:
            await conn.send(relay_response(refuse="no relay for you"))
        await _hold(conn)

    async with FakeServer("tcp", hbbs) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.rendezvous(srv.ep, "tcp", PEER, KEY)
    assert e.value.code == "rd_relay_refused"


# ── 5 中繼 ──

@pytest.mark.parametrize("transport", ["tcp", "ws"])
async def test_relay_pairs_and_returns_the_first_peer_message(transport: str) -> None:
    async def hbbr(conn: Conn, _i: int) -> None:
        await conn.recv()
        await asyncio.sleep(0.1)                     # 受控端晚一點才到
        await conn.send(b"first-peer-message")
        got = await conn.recv()
        await conn.send(b"echo:" + (got or b""))
        await _hold(conn)

    async with FakeServer(transport, hbbr) as srv:
        ch, first = await W.open_relay(srv.ep, transport, PEER, "u" * 36, KEY)
        try:
            assert first == b"first-peer-message"
            await ch.send(b"hello")
            assert await ch.recv() == b"echo:hello"
        finally:
            await ch.close()
    kind, sub = proto.parse_rendezvous(srv.received[0][0])
    assert kind == "request_relay"
    assert proto.get_str(sub, 2) == "u" * 36
    assert proto.get_str(sub, 6) == KEY
    assert proto.get_int(sub, 7) == 0


async def test_relay_without_peer_times_out() -> None:
    async def hbbr(conn: Conn, _i: int) -> None:
        await _hold(conn)

    async with FakeServer("tcp", hbbr) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.open_relay(srv.ep, "tcp", PEER, "u" * 36, KEY)
    assert e.value.code == "rd_relay_timeout"


async def test_relay_closing_before_pairing() -> None:
    """hbbr 在金鑰不符時直接斷線、不回任何訊息（5.1）。再試幾次一樣被關 → 報錯，不會無限重試。"""
    async def hbbr(conn: Conn, _i: int) -> None:
        await conn.recv()
        await conn.close()

    async with FakeServer("tcp", hbbr) as srv:
        with pytest.raises(W.RdWebError) as e:
            await W.open_relay(srv.ep, "tcp", PEER, "u" * 36, KEY)
    assert e.value.code == "rd_hbbr_unreachable"
    assert len(srv.received) == 1 + W.RELAY_RETRIES


async def test_relay_retries_once_after_losing_the_simultaneous_arrival_race() -> None:
    """黑箱實測的 hbbr 競態：同一瞬間到達時其中一條被立刻關掉。用同一個 uuid 再連一次就配上。"""
    async def hbbr(conn: Conn, idx: int) -> None:
        await conn.recv()
        if idx == 0:
            await conn.close()
            return
        await conn.send(b"first-peer-message")
        await _hold(conn)

    async with FakeServer("tcp", hbbr) as srv:
        ch, first = await W.open_relay(srv.ep, "tcp", PEER, "u" * 36, KEY)
        await ch.close()
    assert first == b"first-peer-message"
    assert len(srv.received) == 2
    assert proto.get_str(proto.parse_rendezvous(srv.received[1][0])[1], 2) == "u" * 36


async def test_relay_waits_a_moment_before_connecting(monkeypatch) -> None:
    import time as _t
    monkeypatch.setattr(W, "RELAY_CONNECT_DELAY", 0.2)
    seen: list[float] = []

    async def hbbr(conn: Conn, _i: int) -> None:
        seen.append(_t.monotonic())
        await conn.recv()
        await conn.send(b"x")
        await _hold(conn)

    async with FakeServer("tcp", hbbr) as srv:
        t0 = _t.monotonic()
        ch, _ = await W.open_relay(srv.ep, "tcp", PEER, "u" * 36, KEY)
        await ch.close()
    assert seen[0] - t0 >= 0.19


async def test_oversized_message_is_refused() -> None:
    """長度標頭宣稱超過 16 MB：不讀、不配置記憶體，直接報錯（2.3 的上限）。"""
    async def raw_hbbr(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        first = await reader.readexactly(1)
        rest = await reader.readexactly(proto.header_size(first[0]) - 1)
        await reader.readexactly(proto.parse_header(first + rest))
        writer.write(proto.frame(b"ok"))                          # 第一則（配對）
        writer.write(proto.length_header(17 * 1024 * 1024))       # 只送標頭
        await writer.drain()
        with contextlib.suppress(Exception):
            await reader.read()

    srv = await asyncio.start_server(raw_hbbr, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        ch, first = await W.open_relay(W.Endpoint("127.0.0.1", port), "tcp", PEER, "u" * 36, KEY)
        try:
            assert first == b"ok"
            with pytest.raises(W.RdWebError) as e:
                await ch.recv()
            assert e.value.code == "rd_message_too_large"
        finally:
            await ch.close()
    finally:
        srv.close()


# ── 位址：只連設定好的、而且套用出站規則 ──

def test_endpoints_default_to_agent_address_and_relay_port() -> None:
    class S:
        hbbs_host = None
        relay_host = None
        agent_source_ip = "192.0.2.10"
        transport = "tcp"

    assert W.hbbs_endpoint(S()) == W.Endpoint("192.0.2.10", 21116)
    assert W.relay_endpoint(S()) == W.Endpoint("192.0.2.10", 21117)
    S.transport = "ws"
    assert W.hbbs_endpoint(S()) == W.Endpoint("192.0.2.10", 21118)
    assert W.relay_endpoint(S()) == W.Endpoint("192.0.2.10", 21119)


def test_endpoints_from_settings() -> None:
    class S:
        hbbs_host = "rd.example.com:31116"
        relay_host = "[2001:db8::5]:31117"
        agent_source_ip = "192.0.2.10"
        transport = "tcp"

    assert W.hbbs_endpoint(S()) == W.Endpoint("rd.example.com", 31116)
    assert W.relay_endpoint(S()) == W.Endpoint("2001:db8::5", 31117)
    S.relay_host = None
    assert W.relay_endpoint(S()) == W.Endpoint("rd.example.com", 21117), "中繼預設是 hbbs 的主機＋21117"
    S.hbbs_host = None
    S.agent_source_ip = "2001:db8::9"
    assert W.hbbs_endpoint(S()) == W.Endpoint("2001:db8::9", 21116)


def test_no_address_at_all() -> None:
    class S:
        hbbs_host = None
        relay_host = None
        agent_source_ip = None
        transport = "tcp"

    assert W.hbbs_endpoint(S()) is None
    assert W.relay_endpoint(S()) is None


async def test_outbound_rules_apply(monkeypatch) -> None:
    from app.core.safe_http import check_addrs
    monkeypatch.setattr(W, "check_addrs", check_addrs)
    with pytest.raises(W.RdWebError) as e:
        await W.rendezvous(W.Endpoint("169.254.169.254", 21116), "tcp", PEER, KEY)
    assert e.value.code == "rd_hbbs_unreachable"
    assert "169.254.169.254" in e.value.detail


# ── 7.8 錯誤次數限流 ──

class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.ttl: dict[str, int] = {}

    async def get(self, key: str):
        v = self.store.get(key)
        return str(v).encode() if v is not None else None

    async def incr(self, key: str) -> int:
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key: str, ttl: int) -> None:
        self.ttl[key] = ttl


def test_failure_kinds() -> None:
    assert W.failure_kind("Wrong Password") == "password"
    assert W.failure_kind("Wrong 2FA Code") == "2fa"
    assert W.failure_kind("Please try 1 minute later") == "password"
    assert W.failure_kind("No Password Access") is None        # 等待對方同意，不是失敗
    assert W.failure_kind("2FA Required") is None
    assert W.failure_kind("") is None


def test_headless_login_failure_kinds() -> None:
    """附錄 G.7：Linux 受控端沒有桌面時的登入回應。

    「password wrong」是 RustDesk 密碼猜錯，跟 Wrong Password 算同一組（否則從這條路猜密碼不會被限流）；
    「password empty」是控制端沒給 RustDesk 密碼時的第一個提示（沒有猜任何密碼，跟等待對方同意一樣）；
    「not ready」表示 RustDesk 密碼已經通過、只缺作業系統帳號密碼。後兩者都不算失敗。
    """
    assert W.failure_kind("Desktop session not ready, password wrong") == "password"
    assert W.failure_kind("Desktop session not ready, password empty") is None
    assert W.failure_kind("Desktop session not ready") is None


async def test_three_failures_a_minute_blocks() -> None:
    r = FakeRedis()
    assert await W.is_blocked(r, "u1", "s1", PEER) is False
    assert await W.record_failure(r, "u1", "s1", PEER, "password") is False
    assert await W.record_failure(r, "u1", "s1", PEER, "password") is False
    assert await W.record_failure(r, "u1", "s1", PEER, "password") is True    # 第 3 次之後就擋（第 4 次試不到）
    assert await W.is_blocked(r, "u1", "s1", PEER) is True
    # 別人、別台不受影響
    assert await W.is_blocked(r, "u2", "s1", PEER) is False
    assert await W.is_blocked(r, "u1", "s1", "987654321") is False
    # 視窗：一分鐘、一天
    assert sorted(r.ttl.values()) == [60, 86400]


async def test_two_factor_failures_are_counted_separately() -> None:
    r = FakeRedis()
    await W.record_failure(r, "u1", "s1", PEER, "password")
    await W.record_failure(r, "u1", "s1", PEER, "password")
    assert await W.record_failure(r, "u1", "s1", PEER, "2fa") is False
    counts = await W.failure_counts(r, "u1", "s1", PEER)
    assert counts["password"]["m"] == 2
    assert counts["2fa"]["m"] == 1


async def test_daily_limit(monkeypatch) -> None:
    from app.core.config import get_settings
    r = FakeRedis()
    monkeypatch.setattr(get_settings(), "rustdesk_web_fail_per_minute", 0)   # 只看每天
    for _ in range(9):
        assert await W.record_failure(r, "u1", "s1", PEER, "password") is False
    assert await W.record_failure(r, "u1", "s1", PEER, "password") is True
