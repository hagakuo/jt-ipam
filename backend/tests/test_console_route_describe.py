"""連線表單上的「連線路徑」：開主控台之前就看得到會走直連、哪台跳板或哪台掃描代理，以及設定在 IP 還是子網路上；
走不通（跳板停用、代理沒被允許中繼…）要在按連線之前就講，而不是按下去才失敗。與實際連線用同一套 resolve_route。"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.jump_host import JumpHost
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import console_route


async def _jump(db, **kw) -> JumpHost:
    """有密碼的跳板（沒設認證資料時 resolve_route 會先以 jump_host_no_key 擋下，測不到想測的狀態）。"""
    jump = JumpHost(name=f"j-{uuid.uuid4().hex[:6]}", host="198.51.100.9", username="j", auth_kind="password", **kw)
    db.add(jump)
    await db.flush()
    jump.password_enc, jump.password_nonce = console_route.encrypt_secret_for(jump.id, "password", "pw")
    return jump


async def _ip(db, **subnet_kw):
    sec = Section(name=f"rd-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24", **subnet_kw)
    db.add(sub)
    await db.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="192.0.2.9")
    db.add(ipa)
    await db.commit()
    return sub, ipa


async def test_direct(db_session) -> None:
    _sub, ipa = await _ip(db_session)
    d = await console_route.describe_route(db_session, ipa)
    assert d == {"kind": "direct", "name": None, "source": None, "ok": True}


async def test_subnet_agent_and_ip_override(db_session) -> None:
    from app.services.system_config import set_console_relay_enabled
    await set_console_relay_enabled(db_session, enabled=True)
    agent = ScanAgent(name=f"ag-{uuid.uuid4().hex[:6]}", relay_allowed=True,
                      relay_caps={"enabled": True, "ports": [], "max": 0})
    jump = await _jump(db_session, enabled=True, host_key_fingerprint="SHA256:x")
    db_session.add(agent)
    await db_session.flush()
    sub, ipa = await _ip(db_session, scan_agent_id=agent.id, console_agent_id=agent.id)
    d = await console_route.describe_route(db_session, ipa)
    assert (d["kind"], d["name"], d["source"], d["ok"]) == ("agent", agent.name, "subnet", True)
    ipa.jump_host_id = jump.id                       # IP 層級覆寫子網路
    await db_session.commit()
    d = await console_route.describe_route(db_session, ipa)
    assert (d["kind"], d["name"], d["source"], d["ok"]) == ("jump", jump.name, "ip", True)


async def test_unusable_routes_say_why_before_connecting(db_session) -> None:
    jump = await _jump(db_session, enabled=False)
    agent = ScanAgent(name=f"ag-{uuid.uuid4().hex[:6]}", relay_allowed=False)
    db_session.add(agent)
    await db_session.flush()
    _sub, ipa = await _ip(db_session, jump_host_id=jump.id)
    d = await console_route.describe_route(db_session, ipa)
    assert (d["kind"], d["ok"], d["code"]) == ("jump", False, "jump_host_disabled")
    assert d["name"] == jump.name
    jump.enabled = True                              # 啟用了但還沒釘選主機金鑰 → 連線時會被擋
    await db_session.commit()
    d = await console_route.describe_route(db_session, ipa)
    assert (d["ok"], d["code"]) == (False, "jump_host_key_unpinned")
    sub2, ipa2 = await _ip(db_session, scan_agent_id=agent.id, console_agent_id=agent.id)
    d = await console_route.describe_route(db_session, ipa2)
    assert (d["kind"], d["ok"], d["code"]) == ("agent", False, "relay_disabled_system")


async def test_endpoint(client, auth_headers, db_session) -> None:
    _sub, ipa = await _ip(db_session)
    r = await client.get(f"/api/v1/addresses/{ipa.id}/console-route", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "direct"
    assert r.json()["subnet_id"] == str(_sub.id)
