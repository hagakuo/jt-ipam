"""對外曝險偵測。

這是**規則**，不是 AI 推測 —— NAT／防火牆規則／DNS 都是同步回來的事實，算得出來就直接
講，不必加「可能」。所以放在異常偵測，不是 AI 巡檢。

四條規則：
1. exposed_unmonitored — 對外開放，但沒有任何監控涵蓋（Wazuh agent／LibreNMS 都沒有）
2. exposed_offline     — 對外開放，但目標主機已離線
3. dns_to_offline      — DNS 還指著這個位址，主機卻已離線
4. exposed_archived    — 所在子網路已歸檔，NAT 卻還開著

刻意**不用 owner 當主訊號**：實機上 360 個 IP 只有 1 個填了 owner，用它判斷會把幾乎
每一台對外主機都標成問題，變成沒人看的雜訊。owner 只當附註帶出去。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.nat import NATTranslation
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.anomaly import detect_external_exposure


async def _subnet(db_session, cidr="203.0.113.0/24", **kw):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr=cidr, description="t", **kw)
    db_session.add(sn)
    await db_session.flush()
    return sn


async def _ip(db_session, sn, addr, **kw):
    ipa = IPAddress(subnet_id=sn.id, ip=addr, **kw)
    db_session.add(ipa)
    await db_session.flush()
    return ipa


async def _nat(db_session, ipa, **kw):
    n = NATTranslation(name=f"pf-{uuid.uuid4().hex[:6]}", type="port_forward",
                       dst_ip_id=ipa.id, dst_port=443, protocol="tcp", **kw)
    db_session.add(n)
    await db_session.flush()
    return n


@pytest.mark.anyio
async def test_exposed_but_unmonitored_is_reported(db_session):
    sn = await _subnet(db_session)
    ipa = await _ip(db_session, sn, "203.0.113.10", hostname="web-01",
                    effective_status="online")
    await _nat(db_session, ipa)
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    hits = [x for x in out if x["ip"] == "203.0.113.10"]
    assert hits, "對外開放又沒有任何監控涵蓋 → 要報"
    assert hits[0]["kind"] == "exposed_unmonitored"
    assert hits[0]["ports"], "要講出開了哪個埠，不然使用者無從查起"


@pytest.mark.anyio
async def test_disabled_nat_is_not_exposure(db_session):
    """停用的規則不算對外開放 —— 把它算進來，清單會被永遠不會生效的規則灌爆。"""
    sn = await _subnet(db_session)
    ipa = await _ip(db_session, sn, "203.0.113.11", effective_status="online")
    await _nat(db_session, ipa, disabled=True)
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    assert not [x for x in out if x["ip"] == "203.0.113.11"]


@pytest.mark.anyio
async def test_exposed_and_offline_outranks_unmonitored(db_session):
    """已離線卻還對外開放，比「沒監控」嚴重，要報成 exposed_offline 而不是兩筆。"""
    sn = await _subnet(db_session)
    ipa = await _ip(db_session, sn, "203.0.113.12", hostname="ws-old",
                    effective_status="offline")
    await _nat(db_session, ipa)
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    hits = [x for x in out if x["ip"] == "203.0.113.12"]
    assert len(hits) == 1, "同一個位址不要重複報"
    assert hits[0]["kind"] == "exposed_offline"


@pytest.mark.anyio
async def test_monitored_host_is_not_reported(db_session):
    """有 Wazuh agent 看著就不是曝險 —— 否則每一台正常對外服務都會被列出來。"""
    from app.models.wazuh import WazuhAgent, WazuhInstance
    sn = await _subnet(db_session)
    ipa = await _ip(db_session, sn, "203.0.113.13", effective_status="online")
    await _nat(db_session, ipa)
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://x",
                         api_user="u", api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="001",
                              jt_ipam_address_id=ipa.id, status="active"))
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    assert not [x for x in out if x["ip"] == "203.0.113.13"]


@pytest.mark.anyio
async def test_archived_subnet_still_exposed(db_session):
    sn = await _subnet(db_session, cidr="203.0.113.128/25",
                       archived_at=datetime.now(UTC) - timedelta(days=5))
    ipa = await _ip(db_session, sn, "203.0.113.130", effective_status="online")
    await _nat(db_session, ipa)
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    hits = [x for x in out if x["ip"] == "203.0.113.130"]
    assert hits and hits[0]["kind"] == "exposed_archived"


@pytest.mark.anyio
async def test_included_in_report_and_counts(db_session):
    """要真的接進 run_detection，否則規則寫了也沒人跑。"""
    from app.services.anomaly import run_detection
    sn = await _subnet(db_session, cidr="203.0.113.192/26")
    ipa = await _ip(db_session, sn, "203.0.113.200", effective_status="online")
    await _nat(db_session, ipa)
    await db_session.commit()

    rep = await run_detection(db_session, notify_admins=False)
    d = rep.to_dict()
    assert "external_exposure" in d
    assert any(x["ip"] == "203.0.113.200" for x in d["external_exposure"])
    assert d["total"] >= len(d["external_exposure"])


@pytest.mark.anyio
async def test_wan_firewall_rule_counts_as_exposure(db_session):
    """曝險來源不只 NAT：WAN 介面上的 pass 規則直接指到內部主機，也是對外開放。"""
    from app.models.firewall import OPNsenseFirewall
    from app.models.firewall_rule import OPNsenseRule
    sn = await _subnet(db_session, cidr="203.0.113.64/26")
    ipa = await _ip(db_session, sn, "203.0.113.70", effective_status="online")
    fw = OPNsenseFirewall(name=f"fw-{uuid.uuid4().hex[:6]}", api_url="https://x",
                          api_key_enc=b"a", api_key_nonce=b"b",
                          api_secret_enc=b"c", api_secret_nonce=b"d")
    db_session.add(fw)
    await db_session.flush()
    db_session.add(OPNsenseRule(
        firewall_id=fw.id, legacy_uuid=uuid.uuid4().hex, enabled=True, action="pass",
        interface="WAN", direction="in", protocol="TCP",
        destination_net="203.0.113.70", destination_port="8443",
        description="對外服務"))
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    hits = [x for x in out if x["ip"] == "203.0.113.70"]
    assert hits, "WAN 上的 pass 規則要算成曝險"
    assert any(r["source"] == "firewall_rule" for r in hits[0]["rules"])
    assert "tcp/8443" in hits[0]["ports"]


@pytest.mark.anyio
async def test_lan_rule_is_not_exposure(db_session):
    """內部往內部的放行不是曝險 —— 不排除的話清單會被內網規則淹沒。"""
    from app.models.firewall import OPNsenseFirewall
    from app.models.firewall_rule import OPNsenseRule
    sn = await _subnet(db_session, cidr="203.0.113.32/27")
    await _ip(db_session, sn, "203.0.113.40", effective_status="online")
    fw = OPNsenseFirewall(name=f"fw-{uuid.uuid4().hex[:6]}", api_url="https://x",
                          api_key_enc=b"a", api_key_nonce=b"b",
                          api_secret_enc=b"c", api_secret_nonce=b"d")
    db_session.add(fw)
    await db_session.flush()
    db_session.add(OPNsenseRule(
        firewall_id=fw.id, legacy_uuid=uuid.uuid4().hex, enabled=True, action="pass",
        interface="LAN", direction="in", protocol="TCP",
        destination_net="203.0.113.40", destination_port="22"))
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    assert not [x for x in out if x["ip"] == "203.0.113.40"]


@pytest.mark.anyio
async def test_dns_pointing_at_offline_host(db_session):
    """DNS 還指著、主機卻離線 —— 用 IP 值比對，不靠 ipam_address_id（實機上全是空的）。"""
    from app.models.dns import DNSRecord, DNSServer, DNSZone
    sn = await _subnet(db_session, cidr="203.0.113.224/27")
    await _ip(db_session, sn, "203.0.113.230", hostname="old-www",
              effective_status="offline")
    srv = DNSServer(name=f"dns-{uuid.uuid4().hex[:6]}", type="bind9")
    db_session.add(srv)
    await db_session.flush()
    z = DNSZone(server_id=srv.id, name="example.test", type="forward")
    db_session.add(z)
    await db_session.flush()
    db_session.add(DNSRecord(zone_id=z.id, name="www.example.test", type="A",
                             value="203.0.113.230", ttl=300))
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    hits = [x for x in out if x["kind"] == "dns_to_offline" and x["ip"] == "203.0.113.230"]
    assert hits, "DNS 指向已離線的主機要報"
    assert "www.example.test" in hits[0]["names"]


@pytest.mark.anyio
async def test_every_finding_has_the_same_shape(db_session):
    """所有 kind 的欄位要一致 —— 前端只有一個渲染路徑，少一個鍵就是一個 undefined。"""
    from app.models.dns import DNSRecord, DNSServer, DNSZone
    sn = await _subnet(db_session, cidr="203.0.113.96/27")
    exposed = await _ip(db_session, sn, "203.0.113.100", effective_status="online")
    await _nat(db_session, exposed)
    await _ip(db_session, sn, "203.0.113.101", effective_status="offline")
    srv = DNSServer(name=f"dns-{uuid.uuid4().hex[:6]}", type="bind9")
    db_session.add(srv)
    await db_session.flush()
    z = DNSZone(server_id=srv.id, name=f"z{uuid.uuid4().hex[:6]}.test", type="forward")
    db_session.add(z)
    await db_session.flush()
    db_session.add(DNSRecord(zone_id=z.id, name="a.z.test", type="A",
                             value="203.0.113.101", ttl=300))
    await db_session.commit()

    out = await detect_external_exposure(db_session)
    mine = [x for x in out if x["ip"].startswith("203.0.113.10")]
    assert len({x["kind"] for x in mine}) >= 2, "前提：這批要涵蓋一種以上的 kind"
    shapes = {frozenset(x) for x in mine}
    assert len(shapes) == 1, f"欄位不一致：{[sorted(s) for s in shapes]}"
