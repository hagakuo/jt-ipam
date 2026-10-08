"""變更影響預演：確定性引擎（規格 §15 的 T01–T14、T26、T27）。

直接呼叫引擎（不經 API），用 RFC 5737／3849 的位址造合成資料。API、權限、作業、AI 在別的檔案。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.models.address import IPAddress
from app.models.dns import DNSRecord, DNSServer, DNSZone
from app.models.nat import NATTranslation
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.change_impact.config import DEFAULTS
from app.services.change_impact.engine import analyze
from app.services.change_impact.scenario import ScenarioError

CFG: dict[str, Any] = {**DEFAULTS, "enabled": True}


async def _net(db, cidr: str = "198.51.100.0/24", **kw: Any) -> Subnet:  # type: ignore[no-untyped-def]
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr, **kw)
    db.add(sub)
    await db.flush()
    return sub


async def _ip(db, sub: Subnet, ip: str, **kw: Any) -> IPAddress:  # type: ignore[no-untyped-def]
    a = IPAddress(subnet_id=sub.id, ip=ip, state=kw.pop("state", "active"), **kw)
    db.add(a)
    await db.flush()
    return a


async def _dns(db, records: list[tuple[str, str, str]], *, zone: str = "example.net", ztype: str = "forward",
               server_type: str = "powerdns", synced: bool = True) -> DNSServer:  # type: ignore[no-untyped-def]
    srv = DNSServer(name=f"dns-{uuid.uuid4().hex[:6]}", type=server_type, enabled=True,
                    last_sync_at=datetime.now(UTC) if synced else None)
    db.add(srv)
    await db.flush()
    z = DNSZone(server_id=srv.id, name=zone, type=ztype)
    db.add(z)
    await db.flush()
    for name, typ, value in records:
        db.add(DNSRecord(zone_id=z.id, name=name, type=typ, value=value, ttl=300))
    await db.flush()
    return srv


async def _opnsense(db, *, aliases: dict[str, list[str]] | None = None,  # type: ignore[no-untyped-def]
                    rules: list[dict[str, Any]] | None = None, sync_nat: bool = False,
                    last_sync: datetime | None = None, last_error: str | None = None) -> Any:
    from app.models.firewall import OPNsenseFirewall, OPNsenseSyncedAlias
    from app.models.firewall_rule import OPNsenseRule
    fw = OPNsenseFirewall(name=f"fw-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.254", api_key_enc=b"x",
                          api_key_nonce=b"x", api_secret_enc=b"x", api_secret_nonce=b"x", enabled=True,
                          sync_nat=sync_nat, last_sync_at=last_sync if last_sync is not None else datetime.now(UTC),
                          last_error=last_error)
    db.add(fw)
    await db.flush()
    for name, content in (aliases or {}).items():
        db.add(OPNsenseSyncedAlias(firewall_id=fw.id, name=name, alias_type="host", content=content, enabled=True,
                                   member_count=len(content)))
    for i, r in enumerate(rules or []):
        db.add(OPNsenseRule(firewall_id=fw.id, legacy_uuid=uuid.uuid4().hex, enabled=r.get("enabled", True),
                            sequence=i, action="pass", source_net=r.get("src"), destination_net=r.get("dst"),
                            description=r.get("descr", f"rule {i}"), raw=r.get("raw") or {},
                            last_synced_at=datetime.now(UTC)))
    await db.flush()
    return fw


async def _run(db, user, root: IPAddress | Any, new_ip: str | None = None,  # type: ignore[no-untyped-def]
               scenario: str = "ip_renumber", **params: Any):
    await db.commit()
    if scenario == "ip_renumber":
        return await analyze(db, user=user, scenario_type=scenario, target_type="ip_address", target_id=root.id,
                             parameters={"new_ip": new_ip, **params}, cfg=CFG)
    return await analyze(db, user=user, scenario_type=scenario, target_type="device", target_id=root.id,
                         parameters={}, cfg=CFG)


def _rules(res) -> list[str]:  # type: ignore[no-untyped-def]
    return [f.rule_id for f in res.findings]


def _gap_codes(res) -> set[str]:  # type: ignore[no-untyped-def]
    return {g.reason_code for g in res.gaps}


# ─────────────────── T01：A、PTR、NAT 的精確引用 ───────────────────

async def test_t01_a_ptr_and_nat_references_are_traceable(db_session, admin_user) -> None:
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.10", hostname="erp.example.net")
    await _dns(db_session, [("erp", "A", "198.51.100.10"), ("other", "A", "198.51.100.11")])
    await _dns(db_session, [("10", "PTR", "erp.example.net.")], zone="100.51.198.in-addr.arpa", ztype="reverse")
    db_session.add(NATTranslation(name="erp-web", type="port_forward", dst_ip_id=old.id, protocol="tcp", dst_port=443))
    res = await _run(db_session, admin_user, old, "198.51.100.80")
    rules = _rules(res)
    assert rules.count("dns.address_record") == 1
    assert rules.count("dns.ptr_record") == 1
    assert rules.count("nat.translation") == 1
    for f in res.findings:
        if f.rule_id.startswith(("dns.", "nat.")):
            assert f.evidence_keys, "每個發現都要能追到證據"
            ev = next(e for e in res.evidence if e.key == f.evidence_keys[0])
            assert ev.collected_at is not None
    a = next(e for e in res.evidence if e.object_type == "dns_record" and e.payload["type"] == "A")
    assert a.payload["ttl"] == 300 and a.payload["ttl_known"] is True and a.integration_ref.startswith("dns_server:")


# ─────────────────── T02：198.51.100.2 不可以比中 .20 ───────────────────

async def test_t02_text_hint_respects_token_boundaries(db_session, admin_user) -> None:
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.2")
    await _ip(db_session, sub, "198.51.100.30", description="backup of 198.51.100.20 and 10.198.51.100.2")
    hinted = await _ip(db_session, sub, "198.51.100.31", note="talks to 198.51.100.2.")
    res = await _run(db_session, admin_user, old, "198.51.100.90")
    hints = [f for f in res.findings if f.rule_id == "text.hint"]
    assert [f.subject_id for f in hints] == [hinted.id]
    assert hints[0].match_kind == "text_hint"
    assert all(f.rule.disposition == "review" and (f.strength or f.rule.strength) == "inferred" for f in hints)


# ─────────────────── T03：新舊位址都在同一個 CIDR 規則內 ───────────────────

async def test_t03_cidr_covering_both_addresses_needs_no_change(db_session, admin_user) -> None:
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.10")
    await _opnsense(db_session, rules=[{"src": "198.51.100.0/24", "descr": "lan out"},
                                       {"dst": "198.51.100.0/28", "descr": "small range"}])
    res = await _run(db_session, admin_user, old, "198.51.100.80")
    by = {f.subject_label.split(" ", 1)[1]: f for f in res.findings if f.rule_id.startswith("fw.")}
    assert by["lan out"].rule_id == "fw.rule_range_both"
    assert by["lan out"].rule.disposition == "informational"
    # /28 只包含舊位址：要人確認範圍（不會要求改整段，但也不是「不用管」）
    assert by["small range"].rule_id == "fw.rule_range" and by["small range"].match_kind == "cidr_contains"


# ─────────────────── T04：群組循環 ───────────────────

async def test_t04_group_cycle_ends_and_reports_a_gap(db_session, admin_user) -> None:
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.10")
    await _opnsense(db_session, aliases={"A": ["B", "198.51.100.10"], "B": ["A"]},
                    rules=[{"dst": "B", "descr": "via B"}])
    res = await _run(db_session, admin_user, old, "198.51.100.80")
    assert "fw_object_cycle" in _gap_codes(res)
    assert res.completeness == "partial"
    via = [f for f in res.findings if f.rule_id == "fw.rule_group"]
    assert via and via[0].params["value"] == "B"


# ─────────────────── T05：同一個私有位址分屬兩個單位 ───────────────────

async def test_t05_same_private_ip_in_two_units_is_not_mixed(db_session, admin_user) -> None:
    from app.models.customer import Customer
    c1, c2 = Customer(name=f"c1-{uuid.uuid4().hex[:4]}"), Customer(name=f"c2-{uuid.uuid4().hex[:4]}")
    db_session.add_all([c1, c2])
    await db_session.flush()
    s1 = await _net(db_session, "192.0.2.0/24", customer_id=c1.id, allow_overlap=True) if hasattr(Subnet, "allow_overlap") \
        else await _net(db_session, "192.0.2.0/24", customer_id=c1.id)
    s2 = await _net(db_session, "192.0.2.0/24", customer_id=c2.id)
    a1 = await _ip(db_session, s1, "192.0.2.10", hostname="one")
    await _ip(db_session, s2, "192.0.2.10", hostname="two")
    other = await _ip(db_session, s2, "192.0.2.80", hostname="taken-in-unit-two")
    res = await _run(db_session, admin_user, a1, "192.0.2.80", target_subnet_id=str(s1.id))
    assert res.scenario.roots[0].ip_id == a1.id and res.scenario.target_subnet_id == s1.id
    # 第二個單位的 .80 不是同一個子網路：不是「已被占用」
    assert "ipam.new_ip_assigned" not in _rules(res)
    assert all(f.subject_id != other.id or f.rule_id != "ipam.new_ip_assigned" for f in res.findings)


# ─────────────────── T06：新位址已指派、保留、有租約 ───────────────────

async def test_t06_new_ip_assigned_or_reserved_is_a_blocker(db_session, admin_user) -> None:
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.10")
    await _ip(db_session, sub, "198.51.100.80", hostname="someone-else")
    await _ip(db_session, sub, "198.51.100.81", state="reserved")
    r1 = await _run(db_session, admin_user, old, "198.51.100.80")
    assert "ipam.new_ip_assigned" in _rules(r1) and r1.decision == "blocked"
    r2 = await _run(db_session, admin_user, old, "198.51.100.81")
    assert "ipam.new_ip_reserved" in _rules(r2) and r2.decision == "blocked"


async def test_t06_new_ip_with_a_dhcp_reservation_for_another_mac_is_a_blocker(db_session, admin_user) -> None:
    from app.models.dhcp import DHCPReservation
    from app.models.dhcp_standalone import KeaDhcpServer
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.10", mac="00:00:5e:00:53:10")
    kea = KeaDhcpServer(name=f"kea-{uuid.uuid4().hex[:4]}", api_url="https://192.0.2.53:8000", enabled=True,
                        last_sync_at=datetime.now(UTC))
    db_session.add(kea)
    await db_session.flush()
    db_session.add(DHCPReservation(source_type="kea_dhcp", source_id=kea.id, ip="198.51.100.80",
                                   mac="00:00:5e:00:53:99"))
    res = await _run(db_session, admin_user, old, "198.51.100.80")
    assert "dhcp.new_ip_reserved" in _rules(res) and res.decision == "blocked"
    assert "dhcp_lease_unmatched_not_stored" in _gap_codes(res)


# ─────────────────── T07：新位址沒有任何證據 ───────────────────

async def test_t07_no_evidence_is_not_safe(db_session, admin_user) -> None:
    sub = await _net(db_session)
    old = await _ip(db_session, sub, "198.51.100.10")
    res = await _run(db_session, admin_user, old, "198.51.100.80")
    assert res.decision != "blocked"
    assert "not_configured" in _gap_codes(res), "沒有接整合時要講清楚是沒觀測，不是沒依賴"
    # 有人在用（ARP 看到）→ 擋下
    from app.models.librenms import ARPEntry
    db_session.add(ARPEntry(ip="198.51.100.80", mac="00:00:5e:00:53:80", source="scanner", subnet_id=sub.id,
                            first_seen_at=datetime.now(UTC), last_seen_at=datetime.now(UTC)))
    from app.models.librenms import LibreNMSInstance
    db_session.add(LibreNMSInstance(name=f"nms-{uuid.uuid4().hex[:4]}", api_url="https://192.0.2.9",
                                    api_token_enc=b"x", api_token_nonce=b"x", enabled=True,
                                    last_sync_at=datetime.now(UTC)))
    res2 = await _run(db_session, admin_user, old, "198.51.100.80")
    assert "activity.new_ip_seen" in _rules(res2) and res2.decision == "blocked"


# ─────────────────── T08：/31、/32、IPv6 ───────────────────

@pytest.mark.parametrize(("cidr", "old", "new", "ok"), [
    ("198.51.100.0/24", "198.51.100.10", "198.51.100.0", False),        # 網路位址
    ("198.51.100.0/24", "198.51.100.10", "198.51.100.255", False),      # 廣播
    ("198.51.100.0/31", "198.51.100.0", "198.51.100.1", True),          # /31 兩個都能用
    ("2001:db8:1::/64", "2001:db8:1::10", "2001:DB8:1:0::80", True),    # 壓縮與大小寫
    ("2001:db8:1::/64", "2001:db8:1::10", "2001:db8:1::", True),        # IPv6 沒有廣播
    ("198.51.100.0/24", "198.51.100.10", "2001:db8::1", False),         # 跨 family
    ("198.51.100.0/24", "198.51.100.10", "198.51.100.10", False),       # 跟舊的一樣
])
async def test_t08_address_legality(db_session, admin_user, cidr, old, new, ok) -> None:
    sub = await _net(db_session, cidr)
    root = await _ip(db_session, sub, old)
    if ok:
        res = await _run(db_session, admin_user, root, new)
        assert res.scenario.new_ip == str(__import__("ipaddress").ip_address(new))
    else:
        with pytest.raises(ScenarioError) as exc:
            await _run(db_session, admin_user, root, new)
        assert exc.value.code in ("impact_invalid_target_address", "impact_target_scope_mismatch")


# ─────────────────── T09：跨子網路但沒有閘道資料 ───────────────────

async def test_t09_cross_subnet_lists_checks_and_does_not_guess_a_gateway(db_session, admin_user) -> None:
    a = await _net(db_session, "198.51.100.0/24")
    b = await _net(db_session, "203.0.113.0/24")
    root = await _ip(db_session, a, "198.51.100.10")
    res = await _run(db_session, admin_user, root, "203.0.113.10")
    items = {f.subject_key for f in res.findings if f.rule_id == "network.cross_subnet"}
    assert items == {"vlan", "gateway", "route", "acl", "dhcp", "physical_port"}
    assert all(f.rule.impact == "unknown" for f in res.findings if f.rule_id == "network.cross_subnet")
    assert "gateway_unknown" in _gap_codes(res)
    assert res.scenario.target_subnet_id == b.id


# ─────────────────── T10：DNS view 與 CNAME ───────────────────

async def test_t10_dns_view_and_cname_are_reported_as_gaps(db_session, admin_user) -> None:
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10")
    await _dns(db_session, [("www", "A", "198.51.100.10")])
    res = await _run(db_session, admin_user, root, "198.51.100.80")
    assert {"dns_cname_not_collected", "dns_view_not_modeled"} <= _gap_codes(res)


async def test_dns_ttl_from_a_source_that_does_not_report_it_is_marked_unknown(db_session, admin_user) -> None:
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10")
    await _dns(db_session, [("www", "A", "198.51.100.10")], server_type="unbound_opnsense")
    res = await _run(db_session, admin_user, root, "198.51.100.80")
    f = next(f for f in res.findings if f.rule_id == "dns.address_record")
    assert f.params["ttl"] is None
    assert "ttl_unknown" in _gap_codes(res)


# ─────────────────── T11：停用規則與不支援的動態物件 ───────────────────

async def test_t11_disabled_rules_and_unknown_semantics_are_separate(db_session, admin_user) -> None:
    from app.models.firewall import OPNsenseSyncedAlias
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10")
    fw = await _opnsense(db_session, rules=[{"dst": "198.51.100.10", "descr": "old rule", "enabled": False},
                                            {"dst": "198.51.100.10", "descr": "live rule"},
                                            {"src": "198.51.100.10", "descr": "negated", "raw": {"source_not": "1"}}])
    db_session.add(OPNsenseSyncedAlias(firewall_id=fw.id, name="geo_block", alias_type="geoip", content=["TW"],
                                       enabled=True, member_count=1))
    res = await _run(db_session, admin_user, root, "198.51.100.80")
    by = {f.subject_label.split(" ", 1)[1]: f.rule_id for f in res.findings if f.rule_id.startswith("fw.")}
    assert by == {"old rule": "fw.rule_disabled", "live rule": "fw.rule_exact", "negated": "fw.rule_negated"}
    assert "unknown_semantics" in _gap_codes(res)


# ─────────────────── T12：憑證只寫 DNS 名稱 ───────────────────

async def test_t12_dns_only_certificate_is_not_flagged_for_reissue(db_session, admin_user) -> None:
    from app.models.certificate import Certificate, CertVersion
    from tests.test_cert_fetch import _cert
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10", hostname="erp.example.net")
    pem, _key, _ = _cert(cn="erp.example.net")
    c = Certificate(name=f"erp-{uuid.uuid4().hex[:4]}")
    db_session.add(c)
    await db_session.flush()
    db_session.add(CertVersion(certificate_id=c.id, cert_pem=pem, not_after=datetime.now(UTC) + timedelta(days=60),
                               fingerprint_sha256=uuid.uuid4().hex * 2, key_enc=b"never-read", key_nonce=b"x",
                               is_current=True))
    res = await _run(db_session, admin_user, root, "198.51.100.80")
    assert "cert.ip_san" not in _rules(res)
    assert "cert.dns_san_only" in _rules(res)
    ev = next(e for e in res.evidence if e.object_type == "certificate")
    assert "never-read" not in str(ev.payload)


# ─────────────────── T13：除役的裝置用了共用別名 ───────────────────

async def test_t13_shared_alias_is_flagged_without_a_delete_instruction(db_session, admin_user) -> None:
    from app.models.device import Device
    sub = await _net(db_session)
    dev = Device(name=f"old-srv-{uuid.uuid4().hex[:4]}")
    db_session.add(dev)
    await db_session.flush()
    await _ip(db_session, sub, "198.51.100.10", device_id=dev.id)
    await _opnsense(db_session, aliases={"web_servers": ["198.51.100.10", "198.51.100.11"],
                                         "only_me": ["198.51.100.10"]})
    res = await _run(db_session, admin_user, dev, scenario="device_decommission")
    by = {f.params.get("object"): f.rule_id for f in res.findings if f.rule_id.startswith("fw.object")}
    assert by == {"web_servers": "fw.object_shared", "only_me": "fw.object_member"}
    assert all("delete" not in str(f.suggested_action or {}) for f in res.findings)


# ─────────────────── T14：一個來源過期、另一個部分失敗 ───────────────────

async def test_t14_stale_and_partially_failed_sources_make_the_result_partial(db_session, admin_user) -> None:
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10")
    await _opnsense(db_session, last_sync=datetime.now(UTC) - timedelta(days=3))
    await _opnsense(db_session, last_error="部分區段失敗：nat: timeout")
    res = await _run(db_session, admin_user, root, "198.51.100.80")
    codes = [g.reason_code for g in res.gaps]
    assert "source_stale" in codes and "source_partial" in codes
    assert res.completeness == "partial" and res.decision == "needs_review"
    stale = next(g for g in res.gaps if g.reason_code == "source_stale")
    assert stale.params["last_sync_at"]


# ─────────────────── T26：沒有引用、但來源從未同步 ───────────────────

async def test_t26_no_references_with_a_never_synced_source_is_not_safe(db_session, admin_user) -> None:
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10")
    await _dns(db_session, [], synced=False)
    res = await _run(db_session, admin_user, root, "198.51.100.80")
    assert "source_never_synced" in _gap_codes(res)
    assert res.completeness == "partial" and res.decision == "needs_review"


# ─────────────────── T27：同樣的輸入 → 同樣的結果 ───────────────────

async def test_t27_same_snapshot_same_findings_same_order(db_session, admin_user) -> None:
    sub = await _net(db_session)
    root = await _ip(db_session, sub, "198.51.100.10", hostname="erp.example.net")
    await _dns(db_session, [("erp", "A", "198.51.100.10"), ("erp2", "A", "198.51.100.10")])
    await _opnsense(db_session, aliases={"servers": ["198.51.100.10"]},
                    rules=[{"dst": "servers"}, {"src": "198.51.100.10"}, {"dst": "198.51.100.0/24"}])
    r1 = await _run(db_session, admin_user, root, "198.51.100.80")
    r2 = await _run(db_session, admin_user, root, "198.51.100.80")
    assert [f.fingerprint() for f in r1.findings] == [f.fingerprint() for f in r2.findings]
    assert r1.snapshot_hash == r2.snapshot_hash and r1.scenario_hash == r2.scenario_hash
    assert [f.sort_key() for f in r1.findings] == sorted(f.sort_key() for f in r1.findings)
