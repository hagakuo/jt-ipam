"""主控台經由掃描代理中繼（issue #24 階段二）。

這組測試守的是兩件事：
1. **不會連錯主機**：出口解析只從資料庫推導、任何一道開關沒開就報錯，**絕不退回直連**；
   代理自己把關目標（只信它被指派的子網路與本機設定，不只信伺服器派的目標）。
2. **通道真的通**：代理自寫的 WebSocket 子集要能跟標準實作互通（這裡用 websockets 套件當伺服器），
   位元組雙向完整、關閉會傳遞、票證只能用一次而且綁定代理。
"""
from __future__ import annotations

import asyncio
import json
import socket
import struct
import threading
import time
import uuid
from typing import Any

import pytest
from app.models.address import IPAddress
from app.models.jump_host import JumpHost
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import console_route

from tests.test_agent_scan_split import _agent_module


# ─────────────────── 假 Redis（CI 沒有 Redis）───────────────────
class _FakeRedis:
    def __init__(self) -> None:
        self.kv: dict[str, bytes] = {}
        self.lists: dict[str, list[bytes]] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.blpop_timeouts: list[float] = []

    async def set(self, key, value, ex=None):
        self.kv[key] = value.encode() if isinstance(value, str) else value

    async def get(self, key):
        return self.kv.get(key)

    async def delete(self, key):
        self.kv.pop(key, None)

    async def eval(self, _script, _n, key):
        return self.kv.pop(key, None)

    async def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value.encode() if isinstance(value, str) else value)

    async def expire(self, key, seconds):
        return True

    async def blpop(self, keys, timeout=0):
        self.blpop_timeouts.append(timeout)
        deadline = time.monotonic() + timeout
        while True:
            for k in keys:
                if self.lists.get(k):
                    return (k.encode(), self.lists[k].pop(0))
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.02)

    async def zremrangebyscore(self, key, lo, hi):
        z = self.zsets.get(key, {})
        for m in [m for m, s in z.items() if lo <= s <= hi]:
            z.pop(m)

    async def zcard(self, key):
        return len(self.zsets.get(key, {}))

    async def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)

    async def zrem(self, key, member):
        self.zsets.get(key, {}).pop(member, None)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("app.services.console_relay._redis_client", lambda: fake)
    return fake


# ─────────────────── 代理端：WebSocket 子集 ───────────────────
def _server_frame(opcode: int, payload: bytes, *, fin: bool = True, masked: bool = False) -> bytes:
    n = len(payload)
    b1 = (0x80 if fin else 0) | opcode
    if n < 126:
        head = struct.pack("!BB", b1, (0x80 if masked else 0) | n)
    elif n < 65536:
        head = struct.pack("!BBH", b1, (0x80 if masked else 0) | 126, n)
    else:
        head = struct.pack("!BBQ", b1, (0x80 if masked else 0) | 127, n)
    return head + (b"\x00\x00\x00\x00" if masked else b"") + payload


def _unmask_client_frame(data: bytes) -> tuple[int, bytes]:
    b1, b2 = data[0], data[1]
    assert b1 & 0x80, "FIN 要設"
    assert b2 & 0x80, "用戶端的框一定要遮罩（RFC 6455）"
    n, i = b2 & 0x7F, 2
    if n == 126:
        n, i = struct.unpack("!H", data[2:4])[0], 4
    elif n == 127:
        n, i = struct.unpack("!Q", data[2:10])[0], 10
    key, body = data[i:i + 4], data[i + 4:i + 4 + n]
    return b1 & 0x0F, bytes(b ^ key[j % 4] for j, b in enumerate(body))


@pytest.mark.parametrize("size", [0, 5, 125, 126, 65535, 65536])
def test_client_frames_are_masked_and_round_trip(size) -> None:
    mod = _agent_module()
    payload = bytes(range(256)) * (size // 256 + 1)
    payload = payload[:size]
    op, body = _unmask_client_frame(mod._ws_encode(0x2, payload))
    assert (op, body) == (0x2, payload)


def test_server_frames_decode_and_wait_for_more_bytes() -> None:
    mod = _agent_module()
    frame = _server_frame(0x2, b"hello") + _server_frame(0x9, b"p")
    buf = bytearray(frame[:3])
    assert mod._ws_decode(buf) is None                 # 不完整：等更多位元組
    buf += frame[3:]
    assert mod._ws_decode(buf) == (0x2, b"hello")
    assert mod._ws_decode(buf) == (0x9, b"p")
    assert buf == bytearray()


@pytest.mark.parametrize("frame,why", [
    (_server_frame(0x2, b"x", masked=True), "masked"),
    (_server_frame(0x2, b"x", fin=False), "fragmented"),
    (_server_frame(0x0, b"x"), "fragmented"),
    (_server_frame(0x3, b"x"), "opcode"),
    (_server_frame(0x2, b"x" * (64 * 1024 + 1)), "too large"),
])
def test_anything_outside_the_subset_closes_the_session(frame, why) -> None:
    mod = _agent_module()
    with pytest.raises(mod._WSError, match=why):
        mod._ws_decode(bytearray(frame))


# ─────────────────── 代理端：自我允許清單 ───────────────────
def _relay_agent(monkeypatch, *, enabled=True, ports="22,3389,5900-5910", local_ports=None, local_max=None,
                 pinned=None, assigned=("192.0.2.0/24",), max_sessions=4):
    """ports／max_sessions／assigned＝伺服器在 poll 裡給的（網頁上的設定）；local_*／pinned＝代理主機的選用限縮。"""
    mod = _agent_module()
    monkeypatch.setattr(mod, "RELAY_ENABLED", enabled)
    monkeypatch.setattr(mod, "RELAY_PORTS_LOCAL", mod._parse_ports(local_ports) if local_ports else None)
    monkeypatch.setattr(mod, "RELAY_MAX_LOCAL", local_max)
    monkeypatch.setattr(mod, "RELAY_PINNED", mod._parse_nets(pinned) if pinned else None)
    monkeypatch.setattr(mod, "_RELAY_ACTIVE", 0)
    mod._relay_set_assigned(list(assigned), sorted(mod._parse_ports(ports)), max_sessions)
    return mod


@pytest.mark.parametrize("value,on", [(None, True), ("", True), ("1", True), ("yes", True),
                                      ("0", False), ("false", False), ("off", False), (" NO ", False)])
def test_relay_follows_the_web_ui_unless_the_agent_host_vetoes(value, on) -> None:
    """要不要中繼由管理員在網頁上決定（系統設定＋掃描代理頁），代理主機不必下任何指令（2026-10-02 使用者要求：
    新功能升級後自動可用）。代理主機的擁有者仍可以用 JT_IPAM_RELAY=0 在本機否決。"""
    assert _agent_module()._relay_env_on(value) is on


def test_a_vetoing_agent_host_refuses_and_says_so(monkeypatch) -> None:
    mod = _relay_agent(monkeypatch, enabled=False)
    assert mod._relay_target_ok("192.0.2.10", 22) == "relay_disabled"
    assert mod._relay_header().startswith("enabled=0;")


def test_nothing_is_relayed_until_the_server_allows_it(monkeypatch) -> None:
    """伺服器只在網頁上兩道開關都開時才給子網路與埠；沒給＝什麼都不中繼（代理不會自己假設任何預設）。"""
    mod = _relay_agent(monkeypatch, assigned=(), ports="")
    assert mod._relay_target_ok("192.0.2.10", 22) in ("relay_target_not_allowed", "relay_port_not_allowed")


def test_target_must_be_in_an_assigned_subnet_and_port_allowed(monkeypatch) -> None:
    mod = _relay_agent(monkeypatch)
    assert mod._relay_target_ok("192.0.2.10", 22) is None
    assert mod._relay_target_ok("192.0.2.10", 5905) is None
    assert mod._relay_target_ok("198.51.100.10", 22) == "relay_target_not_allowed"   # 不在被指派的子網路
    assert mod._relay_target_ok("192.0.2.10", 8080) == "relay_port_not_allowed"
    assert mod._relay_target_ok("not-an-ip", 22) == "relay_target_not_allowed"      # 不收主機名稱


def test_ports_come_from_the_web_ui(monkeypatch) -> None:
    """SSH 不在 22 埠：在掃描代理頁改允許的埠就好，不必到代理主機改環境檔。"""
    mod = _relay_agent(monkeypatch, ports="2222")
    assert mod._relay_target_ok("192.0.2.10", 2222) is None
    assert mod._relay_target_ok("192.0.2.10", 22) == "relay_port_not_allowed"


def test_local_port_pin_still_narrows_what_the_server_allows(monkeypatch) -> None:
    mod = _relay_agent(monkeypatch, ports="22,2222", local_ports="22")
    assert mod._relay_target_ok("192.0.2.10", 22) is None
    assert mod._relay_target_ok("192.0.2.10", 2222) == "relay_port_not_allowed"


def test_session_limit_follows_the_web_ui_and_the_local_cap(monkeypatch) -> None:
    mod = _relay_agent(monkeypatch, max_sessions=2)
    assert mod._relay_acquire() and mod._relay_acquire()
    assert not mod._relay_acquire()
    mod._relay_release()
    assert mod._relay_acquire()
    mod = _relay_agent(monkeypatch, max_sessions=8, local_max=1)
    assert mod._relay_acquire()
    assert not mod._relay_acquire()


def test_loopback_and_link_local_are_refused_even_if_the_server_assigns_them(monkeypatch) -> None:
    """後端被入侵時，代理是最後一道閘：伺服器說 127.0.0.0/8 是你的子網路，也不可以中繼進代理主機自己。"""
    mod = _relay_agent(monkeypatch, assigned=("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"))
    for ip in ("127.0.0.1", "169.254.169.254", "224.0.0.1"):
        assert mod._relay_target_ok(ip, 22) == "relay_target_not_allowed", ip


def test_local_pin_limits_what_the_server_can_ask_for(monkeypatch) -> None:
    mod = _relay_agent(monkeypatch, pinned="192.0.2.0/25", assigned=("192.0.2.0/24",))
    assert mod._relay_target_ok("192.0.2.10", 22) is None
    assert mod._relay_target_ok("192.0.2.200", 22) == "relay_target_not_allowed"
    assert "pinned=1" in mod._relay_header()


def test_relay_header_round_trips_through_the_server_parser(monkeypatch) -> None:
    from app.api.v1.endpoints.scan_agents import parse_relay_header
    mod = _relay_agent(monkeypatch)
    caps = parse_relay_header(mod._relay_header())
    assert caps["enabled"] is True
    assert caps["ports"] == []                  # 代理主機沒有限縮 → 完全照網頁上的設定
    assert caps["max"] == 0
    mod = _relay_agent(monkeypatch, local_ports="22,5900-5901", local_max=2)
    caps = parse_relay_header(mod._relay_header())
    assert caps["ports"] == [22, 5900, 5901]
    assert caps["max"] == 2
    assert parse_relay_header(None) is None
    assert parse_relay_header("enabled=1;ports=1-70000")["ports"] == []     # 範圍不合理就不收


# ─────────────────── 伺服器端：出口解析（絕不退回直連）───────────────────
async def _setup(db, *, relay_on=True, allowed=True, caps=None, ip_level=False):
    from app.services.system_config import set_console_relay_enabled
    await set_console_relay_enabled(db, enabled=relay_on)
    agent = ScanAgent(name=f"ag-{uuid.uuid4().hex[:6]}", relay_allowed=allowed, relay_max_sessions=2,
                      relay_caps=caps if caps is not None else {"enabled": True, "ports": [], "max": 0})
    db.add(agent)
    sec = Section(name=f"rl-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24", scan_agent_id=agent.id,
                 console_agent_id=None if ip_level else agent.id)
    db.add(sub)
    await db.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="192.0.2.50", console_agent_id=agent.id if ip_level else None)
    db.add(ipa)
    await db.commit()
    return agent, sub, ipa


async def test_agent_route_when_both_web_switches_are_on(db_session) -> None:
    agent, _sub, ipa = await _setup(db_session)
    route = await console_route.resolve_route(db_session, ipa)
    assert isinstance(route, console_route.ViaAgent)
    assert (route.id, route.max_sessions) == (agent.id, 2)
    assert route.ports == (22, 3389, *range(5900, 5911))          # 掃描代理頁的預設
    assert console_route.route_kind(route) == "agent"


async def test_route_ports_and_limit_follow_the_agent_page_and_any_local_pin(db_session) -> None:
    agent, _sub, ipa = await _setup(db_session, caps={"enabled": True, "ports": [22, 3389], "max": 1})
    agent.relay_ports = "22,2222"
    await db_session.commit()
    route = await console_route.resolve_route(db_session, ipa)
    assert route.ports == (22,)                                     # 網頁 ∩ 代理主機的限縮
    assert route.max_sessions == 1


@pytest.mark.parametrize("kw,code", [
    ({"relay_on": False}, "relay_disabled_system"),
    ({"allowed": False}, "relay_agent_not_allowed"),
    ({"caps": {}}, "relay_agent_not_capable"),                          # 舊代理沒回報
    ({"caps": {"enabled": False, "ports": []}}, "relay_agent_host_off"),   # 代理主機以 JT_IPAM_RELAY=0 否決
])
async def test_any_switch_off_refuses_instead_of_going_direct(db_session, kw, code) -> None:
    _agent, _sub, ipa = await _setup(db_session, **kw)
    with pytest.raises(console_route.RelayError) as exc:
        await console_route.resolve_route(db_session, ipa)
    assert exc.value.code == code


async def test_disabled_agent_refuses(db_session) -> None:
    agent, _sub, ipa = await _setup(db_session)
    agent.enabled = False
    await db_session.commit()
    with pytest.raises(console_route.RelayError) as exc:
        await console_route.resolve_route(db_session, ipa)
    assert exc.value.code == "relay_agent_disabled"


async def test_ip_level_agent_overrides_a_subnet_jump_host(db_session) -> None:
    agent, sub, ipa = await _setup(db_session, ip_level=True)
    jump = JumpHost(name=f"j-{uuid.uuid4().hex[:6]}", host="198.51.100.9", username="j", auth_kind="key")
    db_session.add(jump)
    await db_session.flush()
    sub.jump_host_id = jump.id
    await db_session.commit()
    route = await console_route.resolve_route(db_session, ipa)
    assert isinstance(route, console_route.ViaAgent)
    assert route.id == agent.id


async def test_bmc_is_never_relayed(db_session) -> None:
    """BMC（IPMI，UDP）走不了 TCP 中繼：主控台看到不是直連就擋下（不是默默直連）。"""
    _agent, _sub, ipa = await _setup(db_session)
    route = await console_route.resolve_route(db_session, ipa)
    assert not isinstance(route, console_route.Direct)


# ─────────────────── 伺服器端：出口設定的驗證 ───────────────────
async def test_egress_settings(db_session, client, auth_headers) -> None:
    agent, sub, _ipa = await _setup(db_session, ip_level=True)
    other = ScanAgent(name=f"other-{uuid.uuid4().hex[:6]}")
    jump = JumpHost(name=f"j-{uuid.uuid4().hex[:6]}", host="198.51.100.9", username="j", auth_kind="key")
    db_session.add_all([other, jump])
    await db_session.commit()

    r = await client.patch(f"/api/v1/subnets/{sub.id}", headers=auth_headers, json={"jump_host_id": str(jump.id)})
    assert r.status_code == 200, r.text
    r = await client.patch(f"/api/v1/subnets/{sub.id}", headers=auth_headers,
                           json={"console_agent_id": str(agent.id)})
    assert r.status_code == 200, r.text
    assert r.json()["console_agent_id"] == str(agent.id)
    assert r.json()["jump_host_id"] is None                         # 選了代理，跳板自動清掉
    r = await client.patch(f"/api/v1/subnets/{sub.id}", headers=auth_headers,
                           json={"console_agent_id": str(other.id)})
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "console_agent_not_assigned"
    r = await client.patch(f"/api/v1/subnets/{sub.id}", headers=auth_headers,
                           json={"console_agent_id": str(agent.id), "jump_host_id": str(jump.id)})
    assert r.json()["detail"]["code"] == "console_egress_both"
    # 換掉掃描代理、出口卻還指著舊的：擋下來，請使用者重新選（不默默清成直連）
    r = await client.patch(f"/api/v1/subnets/{sub.id}", headers=auth_headers, json={"scan_agent_id": str(other.id)})
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "console_agent_not_assigned"


async def test_agent_page_sets_the_relay_ports(db_session, client, auth_headers) -> None:
    agent, _sub, _ipa = await _setup(db_session)
    r = await client.patch(f"/api/v1/scan-agents/{agent.id}", headers=auth_headers,
                           json={"relay_ports": " 22, 2222 ,5900-5902 "})
    assert r.status_code == 200, r.text
    assert r.json()["relay_ports"] == "22,2222,5900-5902"
    for bad in ("", "abc", "1-70000", "0", "22,1-300"):
        r = await client.patch(f"/api/v1/scan-agents/{agent.id}", headers=auth_headers, json={"relay_ports": bad})
        assert r.status_code == 422, bad
        assert r.json()["detail"]["code"] == "relay_ports_invalid", bad


async def test_poll_hands_out_relay_scope_only_when_the_web_ui_allows_it(db_session, client) -> None:
    """代理照網頁上的設定做：兩道開關都開才給子網路、埠與上限；任何一道關掉就給空的（代理什麼都不中繼）。"""
    import hashlib
    from app.services.system_config import set_console_relay_enabled
    agent, _sub, _ipa = await _setup(db_session)
    agent.enroll_key_hash = hashlib.sha256(b"relay-poll-key").hexdigest()
    agent.relay_ports = "22,2222"
    agent.relay_max_sessions = 3
    await db_session.commit()
    h = {"X-Agent-Key": "relay-poll-key", "X-Agent-Relay": "enabled=1;ports=;max=0;pinned=0"}

    body = (await client.get("/api/v1/scan-agents/poll", headers=h)).json()
    assert body["relay_cidrs"] == ["192.0.2.0/24"]
    assert body["relay_ports"] == [22, 2222]
    assert body["relay_max"] == 3

    agent.relay_allowed = False
    await db_session.commit()
    body = (await client.get("/api/v1/scan-agents/poll", headers=h)).json()
    assert (body["relay_cidrs"], body["relay_ports"], body["relay_max"]) == ([], [], 0)

    agent.relay_allowed = True
    await set_console_relay_enabled(db_session, enabled=False)
    await db_session.commit()
    body = (await client.get("/api/v1/scan-agents/poll", headers=h)).json()
    assert (body["relay_cidrs"], body["relay_ports"], body["relay_max"]) == ([], [], 0)


# ─────────────────── 票證與名額 ───────────────────
async def test_ticket_is_single_use_and_bound_to_the_agent(fake_redis) -> None:
    from app.services import console_relay
    a, b = uuid.uuid4(), uuid.uuid4()
    sid = console_relay.new_session_id()
    t = await console_relay.issue_ticket(sid, agent_id=a, target="192.0.2.5", port=22, user_id=None, kind="ssh")
    assert await console_relay.redeem_ticket(sid, t, agent_id=b) is None     # 別台代理拿到也沒用（而且票已被取走）
    sid2 = console_relay.new_session_id()
    t2 = await console_relay.issue_ticket(sid2, agent_id=a, target="192.0.2.5", port=22, user_id=None, kind="ssh")
    assert await console_relay.redeem_ticket(sid2, "wrong", agent_id=a) is None
    sid3 = console_relay.new_session_id()
    t3 = await console_relay.issue_ticket(sid3, agent_id=a, target="192.0.2.5", port=22, user_id=None, kind="ssh")
    got = await console_relay.redeem_ticket(sid3, t3, agent_id=a)
    assert got["target"] == "192.0.2.5"
    assert await console_relay.redeem_ticket(sid3, t3, agent_id=a) is None   # 第二次就沒了
    assert t and t2


async def test_per_agent_session_limit(fake_redis) -> None:
    from app.services import console_relay
    a = uuid.uuid4()
    assert await console_relay.acquire_slot(a, "s1", 2)
    assert await console_relay.acquire_slot(a, "s2", 2)
    assert not await console_relay.acquire_slot(a, "s3", 2)
    await console_relay.release_slot(a, "s1")
    assert await console_relay.acquire_slot(a, "s3", 2)


async def test_agent_errors_reach_the_waiting_console_quickly(db_session, fake_redis) -> None:
    """代理拒絕（例如目標不在它的子網路）要馬上告訴使用者，不讓他乾等 15 秒；舊代理不認得也講清楚。"""
    from app.services import agent_probe, console_relay
    agent, _sub, _ipa = await _setup(db_session)
    sid = console_relay.new_session_id()
    job = await agent_probe.create_relay_job(db_session, agent_id=agent.id, sid=sid, ticket="t" * 20,
                                             target="192.0.2.50", port=22, requested_by=None)
    await db_session.commit()
    assert await agent_probe.finish_job(db_session, agent_id=agent.id, job_id=job.id,
                                        error="relay_target_not_allowed: 192.0.2.50:22")
    await db_session.commit()
    ready = await console_relay.wait_ready(sid, timeout=1)
    err = console_route._agent_error(agent.name, ready)
    assert err.code == "relay_target_not_allowed"
    assert "ticket" not in (job.params or {})                        # 票證用完就擦掉
    old = console_route._agent_error(agent.name, {"error": "unsupported probe", "reason": ""})
    assert old.code == "relay_agent_not_capable"


async def test_relay_jobs_cannot_be_created_through_the_probe_api() -> None:
    """工具頁的探測 API 走 validate_params：relay_open 不在允許清單，使用者不可能自己派中繼工作。"""
    from app.services.agent_probe import ProbeJobError, validate_params
    with pytest.raises(ProbeJobError):
        validate_params("relay_open", {"targets": "192.0.2.1"})


async def test_open_route_times_out_with_a_clear_error_and_never_goes_direct(db_session, fake_redis,
                                                                           monkeypatch) -> None:
    from app.services import console_relay
    agent, _sub, ipa = await _setup(db_session)
    monkeypatch.setattr(console_relay, "READY_TIMEOUT", 1)
    route = await console_route.resolve_route(db_session, ipa)
    with pytest.raises(console_route.RelayError) as exc:
        await console_route.open_route(route, "192.0.2.50", 22)
    assert exc.value.code == "relay_agent_timeout"
    assert await console_relay.active_count(agent.id) == 0            # 名額還回去
    # 單次 BLPOP 不可以比 Redis 用戶端的 socket 逾時（redis-py 8 預設 5 秒）長，否則先爆 TimeoutError
    assert fake_redis.blpop_timeouts
    assert max(fake_redis.blpop_timeouts) <= 2
    with pytest.raises(console_route.RelayError) as exc:
        await console_route.open_route(route, "192.0.2.50", 8080)     # 代理沒宣告的埠：不派工作
    assert exc.value.code == "relay_port_not_allowed"


# ─────────────────── 端到端：代理的 WebSocket 客戶端 ⇄ 標準 WebSocket 伺服器 ⇄ 目標 ───────────────────
class _Echo:
    """目標主機：回聲，外加開頭一行 banner（證明資料是從目標那端來的）。"""

    def __init__(self) -> None:
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        conn, _ = self.srv.accept()
        conn.sendall(b"SSH-2.0-relay-test\r\n")
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
        conn.close()


def test_agent_pump_interoperates_with_a_real_websocket_server(monkeypatch) -> None:
    """代理自寫的 WebSocket 子集 ⇄ websockets 套件（uvicorn 用的同一套）：握手、遮罩、大框、ping、關閉。"""
    import websockets.sync.server as wss

    mod = _agent_module()
    target = _Echo()
    got: list[bytes] = []
    pings: list[bytes] = []
    big = bytes(range(256)) * 512            # 128 KiB：會被切成多框
    headers_seen: dict[str, str] = {}

    def handler(ws: Any) -> None:
        headers_seen.update({k.lower(): v for k, v in ws.request.headers.raw_items()})
        banner = ws.recv(timeout=5)
        got.append(banner)
        ws.ping(b"hb")
        ws.send(b"hello")
        got.append(ws.recv(timeout=5))
        ws.send(big[:65536])
        ws.send(big[65536:])
        echoed = b""
        while len(echoed) < len(big):
            m = ws.recv(timeout=5)
            if isinstance(m, bytes):
                echoed += m
        got.append(echoed)
        ws.close()

    server = wss.serve(handler, "127.0.0.1", 0, max_size=None)
    port = server.socket.getsockname()[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(mod, "SERVER", f"http://127.0.0.1:{port}")
        monkeypatch.setattr(mod, "KEY", "agent-key-for-test")
        ws = mod._ws_connect("/api/v1/scan-agents/relay/" + "a" * 32 + "/ws", {"X-Relay-Ticket": "tk-" + "x" * 20})
        tsock = socket.create_connection(("127.0.0.1", target.port))
        orig = ws.send

        def spy(opcode, payload):
            if opcode == 0xA:
                pings.append(payload)
            orig(opcode, payload)
        ws.send = spy
        reason = mod._relay_pump(tsock, ws)
    finally:
        server.shutdown()
    assert headers_seen["x-agent-key"] == "agent-key-for-test"
    assert headers_seen["x-relay-ticket"].startswith("tk-")
    assert got[0] == b"SSH-2.0-relay-test\r\n"        # 目標的 banner 經代理送到伺服器
    assert got[1] == b"hello"                         # 伺服器送的經代理到目標、再回聲回來
    assert got[2] == big                              # 128 KiB 雙向完整
    assert pings == [b"hb"]                           # ping 要回 pong
    assert reason == "server_closed"


async def test_server_side_relay_moves_bytes_and_audits(db_session, fake_redis) -> None:
    """worker A：開本機埠、通知等待者、搬位元組、結束寫稽核（雙向位元組數與原因）。"""
    from app.api.v1.endpoints.scan_agent_relay import serve_relay
    from app.models.audit import AuditLog
    from app.services import console_relay
    from sqlalchemy import select

    class FakeWS:
        def __init__(self) -> None:
            self.inbox: asyncio.Queue = asyncio.Queue()
            self.sent: list[bytes] = []
            self.closed = False

        async def send_bytes(self, b: bytes) -> None:
            self.sent.append(b)
            if b == b"bye":
                await self.inbox.put({"type": "websocket.disconnect"})

        async def send_text(self, t: str) -> None:
            pass

        async def receive(self) -> dict:
            return await self.inbox.get()

        async def close(self, code: int = 1000) -> None:
            self.closed = True

    agent, _sub, _ipa = await _setup(db_session)
    sid = console_relay.new_session_id()
    ws = FakeWS()
    task = asyncio.create_task(serve_relay(ws, sid=sid, ticket={"user_id": None, "target": "192.0.2.50",
                                                                   "port": 22, "kind": "ssh"},
                                           agent_id=agent.id, agent_name=agent.name))
    ready = await console_relay.wait_ready(sid, timeout=5)
    reader, writer = await asyncio.open_connection("127.0.0.1", ready["port"])
    await ws.inbox.put({"type": "websocket.receive", "bytes": b"from-target"})
    assert await asyncio.wait_for(reader.readexactly(11), 5) == b"from-target"
    writer.write(b"bye")
    await writer.drain()
    stats = await asyncio.wait_for(task, 5)
    assert stats == {"to_target": 3, "from_target": 11, "reason": "agent_closed"}
    assert ws.closed
    # 第二個連線不會被接受（只收第一個）
    with pytest.raises(OSError):
        await asyncio.wait_for(asyncio.open_connection("127.0.0.1", ready["port"]), 2)
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "console_relay"))).scalars().all()
    assert rows
    assert rows[-1].diff["bytes_from_target"] == 11
    assert json.dumps(rows[-1].diff)


# ─────────────────── 長輪詢：代理掛斷後不可以替它領工作 ───────────────────
async def test_jobs_long_poll_stops_claiming_once_the_agent_hangs_up(db_session) -> None:
    """代理重啟／斷線時，舊的長輪詢不可以再替它領工作（領走後回給死連線＝工作遺失，主控台乾等 15 秒）。

    要走**完整的 app**（含三層 BaseHTTPMiddleware）：`request.is_disconnected()` 在 BaseHTTPMiddleware 底下
    永遠回 False（它用預先取消的 scope 探測，被 middleware 的 task group 先打斷）—— 2026-10-02 實機抓到，
    單看 endpoint 的測試看不出來。這裡直接呼叫 ASGI，讓代理在 1 秒後掛斷，之後才建立工作。"""
    import hashlib
    from datetime import UTC, datetime, timedelta

    from app.main import create_app
    from app.models.agent_probe_job import STATUS_PENDING, AgentProbeJob

    agent = ScanAgent(name=f"hang-{uuid.uuid4().hex[:6]}", enroll_key_hash=hashlib.sha256(b"hangup-key").hexdigest())
    db_session.add(agent)
    await db_session.commit()

    app = create_app()
    calls = 0

    async def receive():
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(1.0)
        return {"type": "http.disconnect"}

    sent: list[dict] = []

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
             "scheme": "http", "path": "/api/v1/scan-agents/jobs", "raw_path": b"/api/v1/scan-agents/jobs",
             "query_string": b"wait=8", "root_path": "", "client": ("127.0.0.1", 50000),
             "server": ("test", 80), "headers": [(b"host", b"test"), (b"x-agent-key", b"hangup-key")]}
    started = time.monotonic()
    task = asyncio.create_task(app(scope, receive, send))
    await asyncio.sleep(2.5)                              # 代理已經掛斷 1.5 秒
    job = AgentProbeJob(agent_id=agent.id, kind="relay_open", status=STATUS_PENDING,
                        params={"sid": "0" * 32, "target": "192.0.2.1", "port": 22},
                        expires_at=datetime.now(UTC) + timedelta(seconds=30))
    db_session.add(job)
    await db_session.commit()
    await asyncio.wait_for(task, timeout=15)
    await db_session.refresh(job)
    assert job.status == STATUS_PENDING, "死掉的長輪詢把工作領走了"
    assert time.monotonic() - started < 6, "代理掛斷後長輪詢還在等"
