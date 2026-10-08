"""相容 RustDesk 的網頁連線：票證、WebSocket 轉送、權限、限流、稽核（規格第 2.3、7.8、10、14 節）。

後端只轉送：瀏覽器 ↔（WebSocket，一則 binary＝一則訊息）↔ 後端 ↔（TCP 長度前綴）↔ hbbr。
這裡用假的 hbbs／hbbr 與假的瀏覽器 WebSocket 走完整條路。
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import select

from app.models.address import IPAddress
from app.models.permission import Permission
from app.models.rustdesk import RustDeskPeer, RustDeskServer
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.user import User
from app.services import rustdesk_web as W
from app.services import rustdesk_web_proto as proto

PEER = "123456789"


# ── 假 Redis（票證 take_once 走 EVAL；限流用 INCR）──

class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.ttl: dict[str, int] = {}

    async def set(self, key: str, value: Any, ex: int | None = None) -> None:
        self.store[key] = value.encode() if isinstance(value, str) else value
        if ex:
            self.ttl[key] = ex

    async def get(self, key: str):
        v = self.store.get(key)
        if isinstance(v, int):
            return str(v).encode()
        return v

    async def eval(self, _script: str, _numkeys: int, key: str):
        return self.store.pop(key, None)

    async def incr(self, key: str) -> int:
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    async def expire(self, key: str, ttl: int) -> None:
        self.ttl[key] = ttl


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr("app.api.v1.endpoints.rustdesk_console._redis_client", lambda: fake)
    monkeypatch.setattr("app.core.rate_limit._redis_client", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(W, "ATTEMPT_WAIT_UNIT", 0.2)
    monkeypatch.setattr(W, "PAIR_TIMEOUT", 1.0)
    monkeypatch.setattr(W, "RELAY_CONNECT_DELAY", 0.0)
    monkeypatch.setattr(W, "CONNECT_TIMEOUT", 1.0)
    # 假伺服器在 127.0.0.1（出站規則一律擋迴路）
    monkeypatch.setattr(W, "check_addrs", lambda host, addrs: None)
    from app.api.v1.endpoints import rustdesk_console as C
    C._active_total = 0
    C._active_by_user.clear()


# ── 資料 ──

def _server_keys() -> tuple[Ed25519PrivateKey, str]:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, base64.b64encode(pub).decode()


async def _user(db, *, admin: bool = False, can_ssh: bool = False) -> User:
    from app.core.security import hash_password
    u = User(username=f"u-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local", display_name="U",
             password_hash=hash_password("TestPassword2026!"), auth_provider="local", is_active=True,
             is_admin=admin, can_ssh=can_ssh)
    db.add(u)
    await db.flush()
    return u


async def _setup(db, *, rustdesk_enabled: bool = True, web_enabled: bool = True, matched: bool = True,
                 public_key: str | None = None, hbbs_port: int = 1, relay_port: int = 2,
                 transport: str = "tcp") -> tuple[IPAddress, RustDeskServer, RustDeskPeer]:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.20", rustdesk_enabled=rustdesk_enabled)
    db.add(ip)
    await db.flush()
    srv = RustDeskServer(name=f"rd-{uuid.uuid4().hex[:6]}", public_key=public_key or ("K" * 43 + "="),
                         web_enabled=web_enabled, hbbs_host=f"127.0.0.1:{hbbs_port}",
                         relay_host=f"127.0.0.1:{relay_port}", transport=transport)
    db.add(srv)
    await db.flush()
    peer = RustDeskPeer(server_id=srv.id, rustdesk_id=PEER, online=True,
                        address_id=ip.id if matched else None, match_status="matched" if matched else "no_ip")
    db.add(peer)
    await db.commit()
    return ip, srv, peer


# ── 票證 ──

async def test_ticket_is_issued_and_bound(client, auth_headers, db_session, fake_redis) -> None:
    ip, srv, _peer = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ws_path"] == f"/api/v1/addresses/{ip.id}/rustdesk/ws"
    assert body["peer_id"] == PEER
    assert body["ttl"] == 30
    assert body["my_name"].endswith(" (jt-ipam)")
    stored = json.loads(fake_redis.store[f"rdweb:tk:{body['ticket']}"])
    assert stored["ip_id"] == str(ip.id)
    assert stored["server_id"] == str(srv.id)
    assert stored["peer_id"] == PEER
    assert fake_redis.ttl[f"rdweb:tk:{body['ticket']}"] == 30
    # 不帶任何密碼；只有附錄 D.5 的布林旗標（有沒有記住的密碼）
    assert body["has_saved_password"] is False
    rest = {k: v for k, v in body.items() if k != "has_saved_password"}
    assert "password" not in json.dumps(rest).lower()


async def test_ticket_needs_rustdesk_enabled_on_the_ip(client, auth_headers, db_session, fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session, rustdesk_enabled=False)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "rd_not_permitted"


async def test_ticket_needs_web_enabled_on_the_server(client, auth_headers, db_session, fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session, web_enabled=False)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "rd_web_disabled"


async def test_ticket_needs_a_matched_peer(client, auth_headers, db_session, fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session, matched=False)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "rd_no_peer"


async def test_ticket_for_a_user_without_console_rights(client, db_session, fake_redis) -> None:
    from app.services.auth import issue_access_token
    ip, _srv, _peer = await _setup(db_session)
    u = await _user(db_session)
    db_session.add(Permission(object_type="subnet", object_id=ip.subnet_id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket",
                          headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 403


async def test_ticket_refused_while_rate_limited(client, auth_headers, admin_user, db_session, fake_redis) -> None:
    ip, srv, _peer = await _setup(db_session)
    for _ in range(3):
        await W.record_failure(fake_redis, admin_user.id, srv.id, PEER, "password")
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 429
    assert r.json()["detail"]["code"] == "rd_rate_limited"


# ── IP 詳細資料與連線清單 ──

async def test_ip_detail_says_whether_web_is_available(client, auth_headers, db_session, fake_redis) -> None:
    ip, srv, _peer = await _setup(db_session)
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["rustdesk"]["web_available"] is True
    srv.web_enabled = False
    db_session.add(srv)
    await db_session.commit()
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers=auth_headers)
    assert r.json()["rustdesk"]["web_available"] is False


async def test_ip_detail_hides_web_from_users_without_rights(client, db_session, fake_redis) -> None:
    from app.services.auth import issue_access_token
    ip, _srv, _peer = await _setup(db_session)
    u = await _user(db_session)
    db_session.add(Permission(object_type="subnet", object_id=ip.subnet_id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 200
    assert r.json()["rustdesk"]["web_available"] is False
    assert r.json()["rustdesk"]["connect_uri"] is None


async def test_connection_targets_list_web_capable_rustdesk(client, auth_headers, db_session, fake_redis) -> None:
    ip, srv, _peer = await _setup(db_session)
    r = await client.get("/api/v1/addresses/connections/targets", headers=auth_headers)
    assert r.status_code == 200
    rows = {x["id"]: x for x in r.json()}
    assert rows[str(ip.id)]["rustdesk_web_available"] is True
    srv.web_enabled = False
    db_session.add(srv)
    await db_session.commit()
    r = await client.get("/api/v1/addresses/connections/targets", headers=auth_headers)
    assert str(ip.id) not in {x["id"] for x in r.json()}, "沒有任何可用連線的 IP 不列出"


# ── 假瀏覽器 WebSocket ──

class FakeBrowser:
    def __init__(self) -> None:
        self.inbox: asyncio.Queue[dict] = asyncio.Queue()
        self.texts: list[dict] = []
        self.binaries: list[bytes] = []
        self.accepted = False
        self.closed_code: int | None = None
        self.client = type("C", (), {"host": "203.0.113.5"})()
        self.headers = {"user-agent": "pytest"}
        self.got = asyncio.Event()

    async def accept(self) -> None:
        self.accepted = True

    async def receive(self) -> dict:
        return await self.inbox.get()

    async def send_text(self, text: str) -> None:
        self.texts.append(json.loads(text))
        self.got.set()

    async def send_bytes(self, data: bytes) -> None:
        self.binaries.append(data)
        self.got.set()

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        if self.closed_code is None:
            self.closed_code = code
        self.got.set()

    # 瀏覽器那一端的動作
    def send_bin(self, b: bytes) -> None:
        self.inbox.put_nowait({"type": "websocket.receive", "bytes": b})

    def send_json(self, obj: dict) -> None:
        self.inbox.put_nowait({"type": "websocket.receive", "text": json.dumps(obj)})

    def disconnect(self) -> None:
        self.inbox.put_nowait({"type": "websocket.disconnect", "code": 1000})

    async def wait_for(self, pred, timeout: float = 3.0) -> None:
        async def loop() -> None:
            while not pred():
                self.got.clear()
                await self.got.wait()
        await asyncio.wait_for(loop(), timeout)

    def kinds(self) -> list[str]:
        return [t.get("t") for t in self.texts]


class FakeRustDesk:
    """hbbs（回 relay_response）＋ hbbr（配對後扮演受控端：先送第一則，之後照腳本回）。"""

    def __init__(self, server_sk: Ed25519PrivateKey, *, idpk_id: str = PEER) -> None:
        self.sk = server_sk
        self.idpk_id = idpk_id
        self.hbbs_got: list[bytes] = []
        self.hbbr_got: list[bytes] = []
        self.hbbr_connections = 0
        self.silent_hbbr_connections = 0        # 前幾條 hbbr 連線不送第一則（模擬配對失敗）
        self.hbbr_writer: asyncio.StreamWriter | None = None
        self.hbbr_closed = asyncio.Event()
        self._servers: list[asyncio.base_events.Server] = []

    def signed_pk(self) -> bytes:
        idpk = proto.f_str(1, self.idpk_id) + proto.f_bytes(2, b"\x05" * 32)
        return self.sk.sign(idpk) + idpk

    async def start(self) -> tuple[int, int]:
        hbbs = await asyncio.start_server(self._hbbs, "127.0.0.1", 0)
        hbbr = await asyncio.start_server(self._hbbr, "127.0.0.1", 0)
        self._servers = [hbbs, hbbr]
        return hbbs.sockets[0].getsockname()[1], hbbr.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for s in self._servers:
            s.close()

    @staticmethod
    async def _read(reader: asyncio.StreamReader) -> bytes | None:
        try:
            first = await reader.readexactly(1)
            rest = await reader.readexactly(proto.header_size(first[0]) - 1)
            return await reader.readexactly(proto.parse_header(first + rest))
        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    async def _hbbs(self, reader, writer) -> None:
        msg = await self._read(reader)
        self.hbbs_got.append(msg or b"")
        body = (proto.f_str(2, "u" * 36) + proto.f_str(3, "rd.example.com")
                + proto.f_bytes(5, self.signed_pk()) + proto.f_str(7, "1.4.1"))
        writer.write(proto.frame(proto.f_msg(19, body)))
        await writer.drain()
        while await self._read(reader) is not None:
            pass

    async def _hbbr(self, reader, writer) -> None:
        self.hbbr_connections += 1
        msg = await self._read(reader)
        self.hbbr_got.append(msg or b"")
        if self.hbbr_connections <= self.silent_hbbr_connections:
            while await self._read(reader) is not None:
                pass
            return
        self.hbbr_writer = writer
        writer.write(proto.frame(b"SIGNED_ID"))          # 受控端的第一則（瀏覽器會驗）
        await writer.drain()
        while True:
            m = await self._read(reader)
            if m is None:
                break
            self.hbbr_got.append(m)
        self.hbbr_closed.set()

    async def peer_send(self, data: bytes) -> None:
        assert self.hbbr_writer is not None
        self.hbbr_writer.write(proto.frame(data))
        await self.hbbr_writer.drain()

    async def peer_close(self) -> None:
        assert self.hbbr_writer is not None
        self.hbbr_writer.close()


async def _ticket(fake_redis, *, user_id, ip_id, server_id, peer_id=PEER) -> str:
    t = uuid.uuid4().hex
    await fake_redis.set(f"rdweb:tk:{t}", json.dumps(
        {"user_id": str(user_id), "ip_id": str(ip_id), "server_id": str(server_id), "peer_id": peer_id}), ex=30)
    return t


async def _run(ip_id, ticket: str, browser: FakeBrowser) -> asyncio.Task:
    from app.api.v1.endpoints.rustdesk_console import rustdesk_ws
    return asyncio.create_task(rustdesk_ws(browser, ip_id, ticket))


async def _audits(db, ip_id) -> list[tuple[str, dict]]:
    from app.models.audit import AuditLog
    rows = (await db.execute(select(AuditLog).where(AuditLog.object_id == ip_id)
                             .order_by(AuditLog.id))).scalars().all()
    return [(r.action, r.diff or {}) for r in rows]


@contextlib.asynccontextmanager
async def _env(db_session, admin_user, fake_redis, **kw):
    sk, pub = _server_keys()
    rd = FakeRustDesk(sk, **{k: v for k, v in kw.items() if k == "idpk_id"})
    hbbs_port, hbbr_port = await rd.start()
    ip, srv, peer = await _setup(db_session, public_key=pub, hbbs_port=hbbs_port, relay_port=hbbr_port,
                                 **{k: v for k, v in kw.items() if k != "idpk_id"})
    try:
        yield ip, srv, rd
    finally:
        await rd.stop()


# ── WebSocket：票證 ──

async def test_invalid_ticket_is_refused(db_session, fake_redis) -> None:
    b = FakeBrowser()
    task = await _run(uuid.uuid4(), "nope", b)
    await asyncio.wait_for(task, 3)
    assert b.kinds() == ["error"]
    assert b.texts[0]["code"] == "rd_ticket_invalid"
    assert b.closed_code == 4401


async def test_ticket_is_single_use_and_bound_to_the_ip(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=uuid.uuid4(), server_id=srv.id)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 3)
        assert b.texts[0]["code"] == "rd_ticket_invalid", "綁定別的 IP 的票證不能用"
        # 同一張票不能再用（已經被取出）
        b2 = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b2), 3)
        assert b2.texts[0]["code"] == "rd_ticket_invalid"


async def test_ticket_for_a_peer_that_is_no_longer_mapped(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id, peer_id="999999999")
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 3)
        assert b.texts[-1]["code"] == "rd_not_permitted"
        assert b.closed_code == 4403


# ── WebSocket：完整轉送 ──

async def test_full_relay_session(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        stages = [x["stage"] for x in b.texts if x.get("t") == "stage"]
        assert stages == ["rendezvous", "relay", "paired"]
        ready = next(x for x in b.texts if x.get("t") == "ready")
        assert ready["peer_id"] == PEER
        assert ready["transport"] == "tcp"
        assert ready["server_key"] == srv.public_key
        assert base64.b64decode(ready["signed_id_pk"]) == rd.signed_pk()
        assert b.binaries[0] == b"SIGNED_ID", "第一則是受控端的訊息，原封不動"
        # hbbs 收到的是 PunchHoleRequest、hbbr 收到的是帶 uuid 的 RequestRelay
        assert proto.parse_rendezvous(rd.hbbs_got[0])[0] == "punch_hole_request"
        kind, sub = proto.parse_rendezvous(rd.hbbr_got[0])
        assert kind == "request_relay"
        assert proto.get_str(sub, 2) == "u" * 36
        # 兩個方向轉送（一則對一則）
        b.send_bin(b"PUBLIC_KEY" * 10)
        await asyncio.sleep(0.05)
        await rd.peer_send(b"HASH")
        await b.wait_for(lambda: len(b.binaries) >= 2)
        assert b.binaries[1] == b"HASH"
        for _ in range(50):
            if len(rd.hbbr_got) >= 2:
                break
            await asyncio.sleep(0.02)
        assert rd.hbbr_got[1] == b"PUBLIC_KEY" * 10
        b.send_json({"t": "login_result", "ok": True, "error": ""})
        b.send_json({"t": "close", "reason": "user"})
        await asyncio.wait_for(task, 3)
        await asyncio.wait_for(rd.hbbr_closed.wait(), 3)
    audits = await _audits(db_session, ip.id)
    actions = [a for a, _ in audits]
    assert actions == ["rustdesk.web_session_open", "rustdesk.web_session_close"]
    opened, closed = audits[0][1], audits[1][1]
    assert opened["peer_id"] == PEER
    assert opened["transport"] == "tcp"
    assert closed["end_reason"] == "browser_close"
    assert closed["relay_server"] == "rd.example.com"
    assert closed["relay_address"].startswith("127.0.0.1:")
    assert closed["login_results"][0]["ok"] is True
    assert closed["login_results_source"] == "browser"
    assert closed["paired"] is True
    dumped = json.dumps(audits)
    assert srv.public_key not in dumped, "稽核不存金鑰"


async def test_peer_closing_tells_the_browser(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        await rd.peer_close()
        await asyncio.wait_for(task, 3)
    assert b.texts[-1]["t"] == "close"
    assert b.texts[-1]["reason"] == "peer_closed"
    audits = await _audits(db_session, ip.id)
    assert audits[-1][1]["end_reason"] == "peer_closed"


async def test_browser_disconnect_closes_the_relay(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.disconnect()
        await asyncio.wait_for(task, 3)
        await asyncio.wait_for(rd.hbbr_closed.wait(), 3)


async def test_forged_identity_never_reaches_the_relay(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis, idpk_id="555555555") as (ip, srv, rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 3)
        assert b.texts[-1]["t"] == "error"
        assert b.texts[-1]["code"] == "rd_bad_server_signature"
        assert rd.hbbr_connections == 0
    audits = await _audits(db_session, ip.id)
    assert audits[-1][1]["end_reason"] == "rd_bad_server_signature"


async def test_wrong_server_key_in_jt_ipam(db_session, admin_user, fake_redis) -> None:
    """jt-ipam 存的公鑰與簽章的不一樣（6.1）。"""
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        _sk, other_pub = _server_keys()
        srv.public_key = other_pub
        db_session.add(srv)
        await db_session.commit()
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 3)
        assert b.texts[-1]["code"] == "rd_bad_server_signature"


async def test_no_pairing_within_ten_seconds_restarts_once_from_rendezvous(db_session, admin_user, fake_redis,
                                                                          monkeypatch) -> None:
    """附錄 C-3：連上 hbbr 後一直沒有第一則（被同時到達的競態擠掉的是對方）→ 從會合重來一次，新 uuid。"""
    monkeypatch.setattr(W, "RESTART_AFTER", 0.4)
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        rd.silent_hbbr_connections = 1          # 第一次連上的 hbbr 不送任何東西
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries, timeout=5)
        assert len(rd.hbbs_got) == 2, "重來一次＝再送一次 PunchHoleRequest"
        assert rd.hbbr_connections == 2
        b.disconnect()
        await asyncio.wait_for(task, 3)
    audits = await _audits(db_session, ip.id)
    assert audits[-1][1]["restarted"] is True


async def test_restart_happens_only_once(db_session, admin_user, fake_redis, monkeypatch) -> None:
    monkeypatch.setattr(W, "RESTART_AFTER", 0.3)
    monkeypatch.setattr(W, "PAIR_TIMEOUT", 0.6)
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        rd.silent_hbbr_connections = 99
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 5)
        assert b.texts[-1]["code"] == "rd_relay_timeout"
        assert len(rd.hbbs_got) == 2
        assert rd.hbbr_connections == 2


# ── 7.8 限流 ──

async def test_three_reported_failures_close_the_session(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_bin(b"P" * 90)                      # PublicKey
        for _ in range(3):
            b.send_bin(b"L" * 150)                 # LoginRequest（密文）
            b.send_json({"t": "login_result", "ok": False, "error": "Wrong Password"})
        await asyncio.wait_for(task, 3)
    assert b.texts[-1]["t"] == "error"
    assert b.texts[-1]["code"] == "rd_rate_limited"
    assert await W.is_blocked(fake_redis, admin_user.id, srv.id, PEER) is True
    audits = await _audits(db_session, ip.id)
    closed = audits[-1][1]
    assert closed["end_reason"] == "rd_rate_limited"
    assert [r["error"] for r in closed["login_results"]] == ["Wrong Password"] * 3


async def test_headless_wrong_rustdesk_password_shares_the_password_limit(db_session, admin_user, fake_redis) -> None:
    """附錄 G.7：沒有桌面的 Linux 受控端回「password wrong」＝RustDesk 密碼猜錯，跟 Wrong Password 用同一個限額。"""
    reports = ["Wrong Password", "Wrong Password", "Desktop session not ready, password wrong"]
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_bin(b"P" * 90)                      # PublicKey
        for err in reports:
            b.send_bin(b"L" * 150)                 # LoginRequest（密文；第三次帶 os_login）
            b.send_json({"t": "login_result", "ok": False, "error": err})
        await asyncio.wait_for(task, 3)
    assert b.texts[-1]["t"] == "error"
    assert b.texts[-1]["code"] == "rd_rate_limited"
    counts = await W.failure_counts(fake_redis, admin_user.id, srv.id, PEER)
    assert counts["password"]["m"] == 3
    assert await W.is_blocked(fake_redis, admin_user.id, srv.id, PEER) is True


async def test_headless_first_prompt_is_not_a_failure(db_session, admin_user, fake_redis) -> None:
    """附錄 G.7：沒給 RustDesk 密碼時的第一個提示（password empty）與只缺作業系統帳號（not ready）都不算失敗。"""
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_bin(b"P" * 90)
        b.send_bin(b"L" * 150)                     # 空的 RustDesk 密碼
        b.send_json({"t": "login_result", "ok": False, "error": "Desktop session not ready, password empty"})
        b.send_bin(b"L" * 150)                     # 補上 RustDesk 密碼與作業系統帳號密碼
        b.send_json({"t": "login_result", "ok": False, "error": "Desktop session not ready"})
        b.send_bin(b"L" * 150)
        b.send_json({"t": "login_result", "ok": True, "error": ""})
        b.send_json({"t": "close", "reason": "user"})
        await asyncio.wait_for(task, 3)
    assert await W.failure_counts(fake_redis, admin_user.id, srv.id, PEER) == {
        "password": {"m": 0, "d": 0}, "2fa": {"m": 0, "d": 0}}


async def test_waiting_for_approval_is_not_a_failure(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_bin(b"P" * 90)
        b.send_bin(b"L" * 150)
        b.send_json({"t": "login_result", "ok": False, "error": "No Password Access"})
        b.send_json({"t": "login_result", "ok": True, "error": ""})
        b.send_json({"t": "close", "reason": "user"})
        await asyncio.wait_for(task, 3)
    assert await W.failure_counts(fake_redis, admin_user.id, srv.id, PEER) == {
        "password": {"m": 0, "d": 0}, "2fa": {"m": 0, "d": 0}}


async def test_unreported_login_attempts_are_cut_off(db_session, admin_user, fake_redis) -> None:
    """瀏覽器回報的結果不可信（2.3）：不回報、一直送登入請求的連線，後端自己擋下來。"""
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_bin(b"P" * 90)                      # PublicKey
        b.send_bin(b"T" * 30)                      # TestDelay 原封不動送回（小）
        b.send_bin(b"L" * 150)                     # 第一次登入
        b.send_bin(b"L" * 150)                     # 沒有回報結果就又送一次
        await asyncio.wait_for(task, 3)
    assert b.texts[-1]["code"] == "rd_rate_limited"
    counts = await W.failure_counts(fake_redis, admin_user.id, srv.id, PEER)
    assert counts["password"]["m"] == 1


async def test_rate_limited_user_cannot_open_the_websocket(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        for _ in range(3):
            await W.record_failure(fake_redis, admin_user.id, srv.id, PEER, "2fa")
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 3)
        assert b.texts[-1]["code"] == "rd_rate_limited"
        assert rd.hbbs_got == [], "被擋的時候連 hbbs 都不碰"


# ── 資源上限 ──

async def test_per_user_concurrency_cap(db_session, admin_user, fake_redis, monkeypatch) -> None:
    from app.api.v1.endpoints import rustdesk_console as C
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "rustdesk_web_max_sessions_per_user", 1)
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        t1 = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b1 = FakeBrowser()
        task1 = await _run(ip.id, t1, b1)
        await b1.wait_for(lambda: b1.binaries)
        t2 = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b2 = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t2, b2), 3)
        assert b2.texts[-1]["code"] == "rd_too_many"
        b1.disconnect()
        await asyncio.wait_for(task1, 3)
    assert C._active_total == 0
    assert not C._active_by_user


async def test_server_side_settings_round_trip(client, auth_headers, db_session) -> None:
    r = await client.post("/api/v1/rustdesk/servers", headers=auth_headers, json={
        "name": "rd-web", "web_enabled": True, "hbbs_host": "rd.example.com", "relay_host": "10.0.0.5:21117",
        "transport": "ws"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["web_enabled"] is True
    assert body["hbbs_host"] == "rd.example.com"
    assert body["relay_host"] == "10.0.0.5:21117"
    assert body["transport"] == "ws"
    r = await client.patch(f"/api/v1/rustdesk/servers/{body['id']}", headers=auth_headers,
                           json={"transport": "udp"})
    assert r.status_code == 422
    r = await client.patch(f"/api/v1/rustdesk/servers/{body['id']}", headers=auth_headers,
                           json={"hbbs_host": "http://evil/x"})
    assert r.status_code == 422
    r = await client.patch(f"/api/v1/rustdesk/servers/{body['id']}", headers=auth_headers,
                           json={"web_enabled": False, "hbbs_host": ""})
    assert r.status_code == 200
    assert r.json()["web_enabled"] is False
    assert r.json()["hbbs_host"] is None


# ── 受控端 Key 設錯（代理從 hbbr 日誌看到「invalid key」）──

async def _flag_key_failure(db, srv, at: datetime, ok_at: datetime | None = None) -> None:
    peer = (await db.execute(select(RustDeskPeer).where(RustDeskPeer.server_id == srv.id))).scalars().one()
    peer.key_fail_at, peer.key_fail_scope, peer.key_fail_count, peer.key_ok_at = at, "relay", 1, ok_at
    await db.commit()


async def test_relay_refused_for_a_wrong_peer_key_says_so(db_session, admin_user, fake_redis, monkeypatch) -> None:
    """2026-10-05 實機：受控端的 Key 打錯 → hbbr 拒絕它、這邊等到逾時。代理已經從 hbbr 日誌看到，
    就直接說「對方的 Key 跟伺服器不同」，也不用再從會合重來一次。"""
    monkeypatch.setattr(W, "RESTART_AFTER", 0.3)
    monkeypatch.setattr(W, "PAIR_TIMEOUT", 0.6)
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        rd.silent_hbbr_connections = 99
        await _flag_key_failure(db_session, srv, datetime.now(UTC))
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 5)
        assert b.texts[-1]["code"] == "rd_peer_key_mismatch"
        assert b.texts[-1]["params"]["at"]
        assert len(rd.hbbs_got) == 1, "已經知道是 Key 錯，重來也沒用"
    audits = await _audits(db_session, ip.id)
    assert audits[-1][1]["end_reason"] == "rd_peer_key_mismatch"


async def test_old_or_cleared_key_failure_keeps_the_timeout(db_session, admin_user, fake_redis, monkeypatch) -> None:
    """很久以前被拒過、或之後又通過過中繼：這次逾時不能怪到 Key 頭上。"""
    monkeypatch.setattr(W, "RESTART_AFTER", 0.3)
    monkeypatch.setattr(W, "PAIR_TIMEOUT", 0.6)
    now = datetime.now(UTC)
    for at, ok_at in ((now - timedelta(hours=1), None), (now, now + timedelta(seconds=1))):
        async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
            rd.silent_hbbr_connections = 99
            await _flag_key_failure(db_session, srv, at, ok_at)
            t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
            b = FakeBrowser()
            await asyncio.wait_for(await _run(ip.id, t, b), 5)
            assert b.texts[-1]["code"] == "rd_relay_timeout"
