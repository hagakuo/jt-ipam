"""調查加強（2026-10-05）：每個整合對這個位址知道什麼，都收進同一份檔案。

使用者看著一台 Windows 主機的調查視窗說：「我們現在整合不少東西，例如 OCS，調查功能應該也要配合加強」。
原本只有主機名稱、OS、Wazuh、LibreNMS（只認裝置關聯）、ARP、異動記錄，以及全域讀取才有的 DNS／NAT／
OPNsense 規則。OCS、RustDesk、Zabbix、虛擬化、DHCP、交換器埠、防火牆的逐來源證據、探測、異常、
主控台連線……都要跳到別頁去看。

這裡守的是：
- 每一段有資料時出現、沒資料時不出現（不留空標題）
- 某一段壞掉（程式錯誤或 SQL 錯誤）不會拖垮整份檔案
- 權限分層：逐物件資料給看得到子網路的人、全域基礎設施只給全域讀取、稽核類只給管理員
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.permission import Permission
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.user import User
from app.services import investigate as inv
from app.services.investigate import collect_dossier

IP = "198.51.100.77"
MAC = "00:11:22:33:44:77"          # 廠商燒錄的位址（第一個位元組的本地管理位元是 0）
RANDOM_MAC = "02:11:22:33:44:88"   # 本地管理（隨機／私人）位址

NEW_SECTIONS = ("identity", "probe", "agents", "virtualization", "dhcp", "switch_ports",
                "fw_evidence", "last_seen", "anomalies", "ai_findings", "firewall_refs",
                "dhcp_rogue", "console_sessions")


@pytest.fixture
async def target(db_session):
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="198.51.100.0/24", description="服務網段")
    db_session.add(sn)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sn.id, ip=IP, hostname="win11-desk-01", mac=MAC)
    db_session.add(ipa)
    await db_session.commit()
    return sn, ipa


async def _user(db_session, *, subnet_id=None, wildcard=False) -> User:
    """部門帳號（只被指派一個子網路）或全域讀取帳號（萬用授權、但不是管理員）。"""
    from app.core.security import hash_password
    u = User(username=f"u-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local",
             display_name="U", password_hash=hash_password("TestPassword2026!"),
             auth_provider="local", is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.flush()
    db_session.add(Permission(object_type="subnet", object_id=None if wildcard else subnet_id,
                              principal_type="user", principal_id=u.id, level="read"))
    await db_session.commit()
    return u


def _now() -> datetime:
    return datetime.now(UTC)


# ─────────────────────────── 沒資料就不出現 ───────────────────────────

@pytest.mark.anyio
async def test_a_bare_record_has_no_empty_sections(db_session, admin_user):
    """只有一筆什麼都沒有的 IP 記錄：新加的每一段都不該出現（畫面不放空標題）。"""
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="203.0.113.0/24")
    db_session.add(sn)
    await db_session.flush()
    db_session.add(IPAddress(subnet_id=sn.id, ip="203.0.113.5"))
    await db_session.commit()

    d = await collect_dossier(db_session, user=admin_user, ip="203.0.113.5")
    assert d["found"] is True
    present = [k for k in NEW_SECTIONS if d.get(k)]
    assert present == [], f"沒有資料卻出現了：{present}"
    assert d["conflicts"] == []


# ─────────────────────────── 身分 ───────────────────────────

@pytest.mark.anyio
async def test_identity_carries_kind_os_reason_and_nic(db_session, admin_user, target):
    from app.models.oui import OUIVendor
    from app.models.wazuh import WazuhAgent, WazuhInstance
    _sn, ipa = target
    ipa.device_kind, ipa.device_model = "windows", "Dell OptiPlex"
    ipa.os_family, ipa.os_guess = "windows", "Microsoft Windows 11"
    db_session.add(OUIVendor(prefix="001122", short_name="CiscoTest", name="Cisco Test Vendor",
                             source="manual"))
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://wazuh.example",
                         api_user="u", api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="007", name="win11-desk-01", ip=IP,
                              status="active", os_platform="windows", last_keep_alive=_now(),
                              jt_ipam_address_id=ipa.id))
    await db_session.commit()

    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    ident = d["identity"]
    assert ident["device_kind"] == "windows"
    assert ident["device_model"] == "Dell OptiPlex"
    assert ident["os_family"] == "windows"
    assert ident["os_guess"] == "Microsoft Windows 11"
    # 類型怎麼決定的：Wazuh 代理回報 Windows（device_identity.resolve_kind 的依據）
    assert ident["kind_reason"] == "wazuh:windows"
    assert ident["nic_vendor"] == "CiscoTest"
    assert ident["mac_random"] is False


@pytest.mark.anyio
async def test_identity_flags_a_randomized_mac(db_session, admin_user, target):
    _sn, ipa = target
    ipa.mac = RANDOM_MAC
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert d["identity"]["mac_random"] is True


# ─────────────────────────── 最近一次探測（管理員） ───────────────────────────

async def _probe_job(db_session, *, ip=IP, status="done", result=None):
    from app.models.agent_probe_job import AgentProbeJob
    from app.models.scan_agent import ScanAgent
    agent = ScanAgent(name=f"ag-{uuid.uuid4().hex[:6]}", enroll_key_hash=uuid.uuid4().hex * 2, enabled=True)
    db_session.add(agent)
    await db_session.flush()
    job = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": [ip]}, status=status,
                        result=result if result is not None else {
                            "nmap": {"available": True, "ports": [
                                {"port": 3389, "proto": "tcp", "state": "open", "service": "ms-wbt-server"},
                                {"port": 445, "proto": "tcp", "state": "open", "service": "microsoft-ds"},
                            ]},
                            "names": {"netbios": "WIN11-DESK-01"}},
                        finished_at=_now(), expires_at=_now() + timedelta(minutes=10))
    db_session.add(job)
    await db_session.commit()
    return job


@pytest.mark.anyio
async def test_latest_identify_probe_is_summarized_for_admins(db_session, admin_user, target):
    await _probe_job(db_session)
    await _probe_job(db_session, status="failed", result={})     # 失敗的不算
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    p = d["probe"]
    assert p["at"]
    assert any(s.startswith("3389/tcp") for s in p["services"])
    assert "WIN11-DESK-01" in p["names"]
    assert p["device_type"]


@pytest.mark.anyio
async def test_probe_results_are_admin_only(db_session, target):
    """探測頁（REST /addresses/{id}/identify）只給管理員；調查不可以變成繞過它的另一道門。"""
    sn, _ipa = target
    await _probe_job(db_session)
    u = await _user(db_session, subnet_id=sn.id)
    d = await collect_dossier(db_session, user=u, ip=IP)
    assert "probe" not in d


# ─────────────────────────── 電腦上的代理：OCS、RustDesk ───────────────────────────

@pytest.mark.anyio
async def test_ocs_inventory_on_the_record(db_session, admin_user, target):
    _sn, ipa = target
    ipa.os_ocs = "Microsoft Windows 11 Pro"
    ipa.last_seen_ocs = _now()
    ipa.ocs_id, ipa.ocs_tag, ipa.ocs_agent = 42, "HQ-IT", "OCS-NG_WINDOWS_AGENT_v2.10"
    ipa.ocs_hw = {"system": {"vendor": "Dell Inc.", "model": "OptiPlex 7090", "serial": "ABC123"},
                  "cpus": [{"model": "Intel Core i7-11700", "count": 1}],
                  "memory": {"total_mb": 16384, "modules": []}, "disks": [{"model": "NVMe 512GB", "size_mb": 512000}]}
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    ocs = d["agents"]["ocs"]
    assert ocs["os"] == "Microsoft Windows 11 Pro"
    assert ocs["tag"] == "HQ-IT"
    assert ocs["ocs_id"] == 42
    assert ocs["system"] == "Dell Inc. OptiPlex 7090"
    assert ocs["serial"] == "ABC123"
    assert ocs["memory_mb"] == 16384
    assert "Intel Core i7-11700" in ocs["cpu"]


@pytest.mark.anyio
async def test_rustdesk_peer_with_key_problem(db_session, admin_user, target):
    from app.models.rustdesk import RustDeskPeer, RustDeskServer
    _sn, ipa = target
    srv = RustDeskServer(name=f"rd-{uuid.uuid4().hex[:6]}")
    db_session.add(srv)
    await db_session.flush()
    db_session.add(RustDeskPeer(server_id=srv.id, rustdesk_id="123456789", online=True,
                                last_online_at=_now(), address_id=ipa.id, match_status="matched",
                                match_evidence=["report_ip"], hostname="WIN11-DESK-01",
                                os_name="Windows 11", username="alice",
                                key_fail_at=_now() - timedelta(minutes=5), key_fail_count=3,
                                key_fail_scope="hbbr"))
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    rd = d["agents"]["rustdesk"]
    assert len(rd) == 1
    p = rd[0]
    assert p["id"] == "123456789"
    assert p["online"] is True
    assert p["os"] == "Windows 11"
    assert p["hostname"] == "WIN11-DESK-01"
    assert p["username"] == "alice"
    assert p["match_status"] == "matched"
    assert p["key_problem"] is True


# ─────────────────────────── 監控：LibreNMS 依位址、Zabbix ───────────────────────────

@pytest.mark.anyio
async def test_librenms_found_by_primary_ip_without_a_device_link(db_session, admin_user, target):
    """以前只認裝置關聯：IP 沒掛裝置時，LibreNMS 明明在監控它，調查卻說沒有。"""
    from app.models.librenms import LibreNMSDevice, LibreNMSInstance
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(LibreNMSDevice(instance_id=inst.id, legacy_device_id=9, hostname="win11-desk-01",
                                  primary_ip=IP, os="windows", status="1", type="server"))
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    ln = d["monitoring"]["librenms"]
    assert ln["hostname"] == "win11-desk-01"
    assert ln["matched_by"] == "primary_ip"


@pytest.mark.anyio
async def test_zabbix_host(db_session, admin_user, target):
    from app.models.zabbix import ZabbixHost, ZabbixInstance
    _sn, ipa = target
    inst = ZabbixInstance(name=f"zbx-{uuid.uuid4().hex[:6]}", api_url="https://zbx.example")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(ZabbixHost(instance_id=inst.id, hostid="10101", host="win11-desk-01", name="Win11 Desk 01",
                              status="monitored", available="up", maintenance=True, ip=IP,
                              jt_ipam_address_id=ipa.id, last_seen_at=_now()))
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    z = d["monitoring"]["zabbix"]
    assert z[0]["name"] == "Win11 Desk 01"
    assert z[0]["status"] == "monitored"
    assert z[0]["maintenance"] is True
    assert z[0]["available"] == "up"


# ─────────────────────────── 虛擬化 ───────────────────────────

async def _vm(db_session, *, ip=IP, mac=MAC):
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface
    cl = VirtCluster(name=f"pve-{uuid.uuid4().hex[:4]}", type="proxmox")
    db_session.add(cl)
    await db_session.flush()
    vm = VirtualMachine(cluster_id=cl.id, name="win11-vm", status="running", kind="vm", node="pve1",
                        legacy_vmid=105)
    db_session.add(vm)
    await db_session.flush()
    db_session.add(VMInterface(vm_id=vm.id, name="net0", primary_ip=ip, mac=mac))
    await db_session.commit()
    return cl, vm


@pytest.mark.anyio
async def test_virtual_machine_matched_to_the_address(db_session, admin_user, target):
    cl, _vm_row = await _vm(db_session)
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    v = d["virtualization"]
    assert v["vm"] == "win11-vm"
    assert v["kind"] == "vm"
    assert v["node"] == "pve1"
    assert v["status"] == "running"
    assert v["cluster"] == cl.name
    assert v["platform"] == "proxmox"


@pytest.mark.anyio
async def test_vm_whose_nic_mac_disagrees_is_not_this_host(db_session, admin_user, target):
    """DHCP 位址換了主人：VM 網卡的 MAC 跟這個 IP 現在的不同 → 不是它（fw_lookup.vm_match_for 的規則）。"""
    await _vm(db_session, mac="bc:24:11:00:00:66")
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert "virtualization" not in d


# ─────────────────────────── DHCP ───────────────────────────

@pytest.mark.anyio
async def test_dhcp_reservation_lease_and_pool(db_session, admin_user, target):
    from app.models.dhcp import DHCPLeaseSighting, DHCPPoolRange, DHCPReservation
    from app.models.windows_dhcp import WindowsDhcpServer
    _sn, ipa = target
    ipa.in_dhcp_lease = True
    ipa.dhcp_reserved = True
    srv = WindowsDhcpServer(name="dc01-dhcp", host="dc01.example", username="u",
                            password_enc=b"x", password_nonce=b"y")
    db_session.add(srv)
    await db_session.flush()
    db_session.add_all([
        DHCPReservation(source_type="windows_dhcp", source_id=srv.id, source_name="dc01-dhcp",
                        ip=IP, mac=MAC, hostname="win11-desk-01", source="windows"),
        DHCPLeaseSighting(ip_address_id=ipa.id, source_type="windows_dhcp", source_id=srv.id),
        DHCPPoolRange(source_type="windows_dhcp", source_id=srv.id, source_name="dc01-dhcp",
                      start_ip="198.51.100.50", end_ip="198.51.100.99", source="windows"),
    ])
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    dh = d["dhcp"]
    assert dh["in_lease"] is True
    assert dh["reserved"] is True
    assert dh["in_pool"] is True
    assert dh["reservations"][0]["mac"] == MAC
    assert dh["leases"][0]["source_type"] == "windows_dhcp"
    assert dh["leases"][0]["source_name"] == "dc01-dhcp"
    assert dh["pools"][0]["start"] == "198.51.100.50"


@pytest.mark.anyio
async def test_dhcp_pool_ranges_are_global_data(db_session, target):
    """部門帳號看得到「在發放範圍內」這個旗標（IP 詳細資料本來就有），但看不到範圍本身的設定。"""
    from app.models.dhcp import DHCPPoolRange
    sn, _ipa = target
    db_session.add(DHCPPoolRange(source_type="kea_dhcp", source_id=uuid.uuid4(), source_name="kea1",
                                 start_ip="198.51.100.50", end_ip="198.51.100.99", source="kea"))
    await db_session.commit()
    u = await _user(db_session, subnet_id=sn.id)
    d = await collect_dossier(db_session, user=u, ip=IP)
    assert d["dhcp"]["in_pool"] is True
    assert "pools" not in d["dhcp"]


# ─────────────────────────── 接在哪裡（FDB） ───────────────────────────

@pytest.mark.anyio
async def test_switch_ports_from_librenms_and_mikrotik(db_session, admin_user, target):
    """fdb_entries 有兩種列：LibreNMS（device_id 是 LibreNMS 裝置）與 MikroTik（switch_device_id 是 jt-ipam 裝置）。"""
    from app.models.device import Device
    from app.models.librenms import FDBEntry, LibreNMSDevice, LibreNMSInstance
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    sw = Device(name="core-sw-2")
    db_session.add_all([inst, sw])
    await db_session.flush()
    ln = LibreNMSDevice(instance_id=inst.id, legacy_device_id=3, hostname="access-sw-1", sysname="access-sw-1")
    db_session.add(ln)
    await db_session.flush()
    db_session.add_all([
        FDBEntry(mac=MAC, device_id=ln.id, port_name="Gi1/0/7", vlan_id_num=10, source="librenms",
                 last_seen_at=_now()),
        FDBEntry(mac=MAC, port_name="ether5", source="mikrotik", switch_device_id=sw.id,
                 last_seen_at=_now() - timedelta(hours=1)),
    ])
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    ports = {(p["switch"], p["port"]) for p in d["switch_ports"]}
    assert ("access-sw-1", "Gi1/0/7") in ports
    assert ("core-sw-2", "ether5") in ports


# ─────────────────────────── 防火牆的逐來源證據、各來源最後出現 ───────────────────────────

@pytest.mark.anyio
async def test_firewall_evidence_and_last_seen_by_source(db_session, admin_user, target):
    _sn, ipa = target
    now = _now()
    ipa.arp_seen = {"arp:opnsense": now.isoformat(), "lease:mikrotik": (now - timedelta(days=2)).isoformat()}
    ipa.last_seen_scanner = now - timedelta(minutes=3)
    ipa.last_seen_dns = now - timedelta(days=1)
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    ev = {e["key"]: e for e in d["fw_evidence"]}
    assert ev["arp:opnsense"]["kind"] == "arp"
    assert ev["arp:opnsense"]["vendor"] == "opnsense"
    assert ev["arp:opnsense"]["aging"] is True
    assert ev["lease:mikrotik"]["aging"] is False       # 租約不代表現在活著（evidence 登記表）

    seen = {r["source"]: r for r in d["last_seen"]["rows"]}
    assert seen["scanner"]["verdict"] == "fresh"
    assert seen["arp:opnsense"]["verdict"] == "fresh"
    assert seen["lease:mikrotik"]["verdict"] == "ignored"     # 預設不採信
    assert seen["dns"]["verdict"] == "ignored"
    assert d["last_seen"]["minutes"] > 0


# ─────────────────────────── 異常與 AI 巡檢（管理員） ───────────────────────────

@pytest.mark.anyio
async def test_open_anomalies_and_ai_findings_for_admins(db_session, admin_user, target):
    from app.models.ai_finding import AIFinding
    from app.services.system_config import set_anomaly_report
    _sn, _ipa = target
    await set_anomaly_report(db_session, {
        "ip_conflicts": [{"ip": IP, "macs": [MAC, RANDOM_MAC], "kind": "arp"}],
        "ghost_ips": [{"ip": "198.51.100.200", "hostname": "someone-else"}],
    }, trigger="schedule")
    db_session.add_all([
        AIFinding(run_id=uuid.uuid4(), severity="medium", category="exposure", title="RDP 對外開放",
                  detail="…", evidence={"ips": [IP]}, status="open"),
        AIFinding(run_id=uuid.uuid4(), severity="low", category="other", title="已忽略的",
                  detail="…", evidence={"ips": [IP]}, status="dismissed"),
        AIFinding(run_id=uuid.uuid4(), severity="low", category="other", title="別台的",
                  detail="…", evidence={"ips": ["198.51.100.200"]}, status="open"),
    ])
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert [a["category"] for a in d["anomalies"]] == ["ip_conflicts"]
    assert [f["title"] for f in d["ai_findings"]] == ["RDP 對外開放"]


@pytest.mark.anyio
async def test_anomalies_and_ai_findings_are_admin_only(db_session, target):
    """REST（/anomaly/last、/ai-audit/findings）與 MCP（list_anomalies、list_ai_findings）都只給管理員。"""
    from app.models.ai_finding import AIFinding
    from app.services.system_config import set_anomaly_report
    await set_anomaly_report(db_session, {"ip_conflicts": [{"ip": IP}]}, trigger="schedule")
    db_session.add(AIFinding(run_id=uuid.uuid4(), severity="low", category="x", title="t",
                             detail="", evidence={"ips": [IP]}, status="open"))
    await db_session.commit()
    u = await _user(db_session, wildcard=True)       # 全域讀取，但不是管理員
    d = await collect_dossier(db_session, user=u, ip=IP)
    assert d["global_read"] is True
    assert "anomalies" not in d
    assert "ai_findings" not in d


# ─────────────────────────── 全域基礎設施：防火牆物件與政策、非法 DHCP ───────────────────────────

async def _firewalls(db_session):
    from app.models.fortigate import FortiGateAddressObject, FortiGateFirewall, FortiGatePolicy
    from app.models.mikrotik import MikroTikAddressList, MikroTikRouter
    from app.models.paloalto import PaloAltoAddressObject, PaloAltoFirewall, PaloAltoPolicy
    from app.models.pfsense import PfSenseFirewall, PfSenseSyncedAlias
    fg = FortiGateFirewall(name="fg-1", api_url="https://192.0.2.3", api_token_enc=b"x", api_token_nonce=b"y")
    pa = PaloAltoFirewall(name="pa-1", api_url="https://192.0.2.4", api_key_enc=b"x", api_key_nonce=b"y")
    pf = PfSenseFirewall(name="pf-1", api_url="https://192.0.2.2", api_key_enc=b"x", api_key_nonce=b"y")
    mt = MikroTikRouter(name="mt-1", api_url="https://192.0.2.5", api_username="u",
                        api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add_all([fg, pa, pf, mt])
    await db_session.flush()
    db_session.add_all([
        # FortiGate 的 subnet 存成「位址/遮罩」；政策欄位是以逗號串起來的物件名稱
        FortiGateAddressObject(firewall_id=fg.id, name="h-win11", obj_type="ipmask", kind="address",
                               value=f"{IP}/255.255.255.255"),
        FortiGateAddressObject(firewall_id=fg.id, name="all", obj_type="ipmask", kind="address",
                               value="0.0.0.0/0.0.0.0"),
        FortiGatePolicy(firewall_id=fg.id, policyid="12", name="rdp-in", action="accept",
                        srcaddr="all", dstaddr="h-other, h-win11", service="RDP"),
        PaloAltoAddressObject(firewall_id=pa.id, name="win11", obj_type="ip-range", kind="address",
                              value="198.51.100.70-198.51.100.80"),
        PaloAltoPolicy(firewall_id=pa.id, name="allow-win11", action="allow", source="any",
                       destination="win11"),
        PfSenseSyncedAlias(firewall_id=pf.id, name="desktops", alias_type="host", members=[IP]),
        MikroTikAddressList(router_id=mt.id, list_name="trusted", address=IP),
    ])
    await db_session.commit()


@pytest.mark.anyio
async def test_firewall_objects_and_policies_on_every_vendor(db_session, admin_user, target):
    await _firewalls(db_session)
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    refs = d["firewall_refs"]
    aliases = {(a["source_type"], a["name"]) for a in refs["aliases"]}
    assert {("fortigate", "h-win11"), ("paloalto", "win11"), ("pfsense", "desktops"),
            ("mikrotik", "trusted")} <= aliases
    assert ("fortigate", "all") not in aliases, "涵蓋全部位址的物件（0.0.0.0/0）每個 IP 都命中，列了只是雜訊"
    rules = {(r["source_type"], r["descr"]) for r in refs["rules"]}
    assert ("fortigate", "rdp-in") in rules, "政策以物件名稱引用（而且跟別的物件寫在同一欄）也要反查得到"
    assert ("paloalto", "allow-win11") in rules


@pytest.mark.anyio
async def test_rogue_dhcp_offer_of_this_address(db_session, admin_user, target):
    from app.models.dhcp_sighting import DHCPSighting
    sn, _ipa = target
    db_session.add(DHCPSighting(subnet_id=sn.id, server_ip="198.51.100.254", server_mac="00:aa:bb:cc:dd:ee",
                                offered_ip=IP, first_seen_at=_now(), last_seen_at=_now()))
    await db_session.commit()
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert d["dhcp_rogue"][0]["server_ip"] == "198.51.100.254"


@pytest.mark.anyio
async def test_department_user_gets_no_global_sections(db_session, target):
    from app.models.dhcp_sighting import DHCPSighting
    sn, _ipa = target
    await _firewalls(db_session)
    db_session.add(DHCPSighting(subnet_id=sn.id, server_ip="198.51.100.254", offered_ip=IP,
                                first_seen_at=_now(), last_seen_at=_now()))
    await db_session.commit()
    u = await _user(db_session, subnet_id=sn.id)
    d = await collect_dossier(db_session, user=u, ip=IP)
    assert d["found"] is True
    assert d["global_read"] is False
    assert "firewall_refs" not in d
    assert "dhcp_rogue" not in d


# ─────────────────────────── 主控台連線（管理員） ───────────────────────────

async def _console_audit(db_session, ipa, actor):
    from app.core.audit import append_audit
    for action, diff in (("ssh.session_open", {"host": IP, "username": "root"}),
                         ("ssh.session_close", {"host": IP, "duration_seconds": 12}),
                         ("rdp.session_open", {"host": IP, "username": "alice"}),
                         ("ip_address.update", None)):
        await append_audit(db_session, actor_user_id=str(actor.id), actor_ip="192.0.2.50",
                           actor_user_agent=None, object_type="ip", object_id=str(ipa.id),
                           action=action, diff=diff, request_id=None)
    await db_session.commit()


@pytest.mark.anyio
async def test_recent_console_sessions_for_admins(db_session, admin_user, target):
    _sn, ipa = target
    await _console_audit(db_session, ipa, admin_user)
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    cs = d["console_sessions"]
    assert [c["kind"] for c in cs] == ["rdp", "ssh"], "只列開啟連線那一筆、由新到舊"
    assert cs[0]["user"] == admin_user.username
    assert cs[0]["remote_user"] == "alice"
    assert cs[0]["at"]
    # 連了多久：配對同一個人、同一種主控台、之後的那筆結束記錄（使用者 2026-10-06 問「有記錄連線多久嗎」）
    assert cs[1]["duration_seconds"] == 12
    assert "duration_seconds" not in cs[0], "還沒有結束記錄的不可以亂配"


@pytest.mark.anyio
async def test_console_session_durations_pair_in_order(db_session, admin_user, target):
    """同一個人對同一台開了兩個 SSH：先開的配先結束的那筆；別人的、別種主控台的結束記錄不可以配進來。"""
    from app.core.audit import append_audit
    _sn, ipa = target
    other = await _user(db_session, wildcard=True)
    for actor, action, diff in ((admin_user, "ssh.session_open", {"host": IP, "username": "a"}),
                                (admin_user, "ssh.session_open", {"host": IP, "username": "b"}),
                                (other, "ssh.session_close", {"host": IP, "duration_seconds": 99}),
                                (admin_user, "sftp_close", {"host": IP, "duration_seconds": 77}),
                                (admin_user, "ssh.session_close", {"host": IP, "duration_seconds": 30}),
                                (admin_user, "ssh.session_close", {"host": IP, "duration_seconds": 5})):
        await append_audit(db_session, actor_user_id=str(actor.id), actor_ip="192.0.2.50",
                           actor_user_agent=None, object_type="ip", object_id=str(ipa.id),
                           action=action, diff=diff, request_id=None)
    await db_session.commit()
    cs = (await collect_dossier(db_session, user=admin_user, ip=IP))["console_sessions"]
    assert [(c["remote_user"], c.get("duration_seconds")) for c in cs] == [("b", 5), ("a", 30)]


@pytest.mark.anyio
async def test_console_sessions_are_admin_only(db_session, admin_user, target):
    _sn, ipa = target
    await _console_audit(db_session, ipa, admin_user)
    u = await _user(db_session, wildcard=True)
    d = await collect_dossier(db_session, user=u, ip=IP)
    assert "console_sessions" not in d


# ─────────────────────────── 一段壞掉不拖垮整份 ───────────────────────────

@pytest.mark.anyio
async def test_a_failing_section_does_not_break_the_dossier(db_session, admin_user, target, monkeypatch):
    _sn, ipa = target
    ipa.arp_seen = {"arp:opnsense": _now().isoformat()}
    await db_session.commit()

    async def boom(_c):
        raise RuntimeError("整合壞了")

    monkeypatch.setattr(inv, "_sec_zabbix", boom)
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert d["found"] is True
    assert "zabbix" not in d["monitoring"]
    assert d["fw_evidence"], "其他段落照常"


@pytest.mark.anyio
async def test_a_sql_error_in_one_section_does_not_poison_the_rest(db_session, admin_user, target, monkeypatch):
    """SQL 錯誤會讓整個交易進入 aborted 狀態，之後每一段都會失敗 —— 每段要包在 SAVEPOINT 裡。"""
    from sqlalchemy import text
    _sn, ipa = target
    ipa.arp_seen = {"arp:opnsense": _now().isoformat()}
    await db_session.commit()

    async def bad_sql(c):
        await c.session.execute(text("SELECT * FROM no_such_table_for_investigate"))

    monkeypatch.setattr(inv, "_sec_identity", bad_sql)
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert d["found"] is True
    assert "identity" not in d
    assert d["fw_evidence"], "後面的段落仍查得到"
    assert d["last_seen"], "後面的段落仍查得到"


# ─────────────────────────── 主機名稱正規化與矛盾清單 ───────────────────────────

def test_hostname_variants_of_the_same_name_are_one_name():
    """實機：OPNsense 回 `win11-desk-01.`（尾端有點）、NetBIOS 回 `WIN11-DESK-01`，畫面卻說「不一致（2 種）」。"""
    assert inv.distinct_hostnames(["win11-desk-01", "win11-desk-01.", "WIN11-DESK-01"]) == ["win11-desk-01"]
    # 短名稱等於某個 FQDN 的第一段 → 同一個名字
    assert inv.distinct_hostnames(["win11-desk-01", "win11-desk-01.corp.example"]) == ["win11-desk-01.corp.example"]
    assert inv.distinct_hostnames(["web01", "db01"]) == ["db01", "web01"]
    assert inv.distinct_hostnames(["", None, "  "]) == []


async def _obs(db_session, ipa, pairs):
    from app.models.ip_hostname import IPHostnameObservation
    for src, name in pairs:
        db_session.add(IPHostnameObservation(ip_id=ipa.id, source=src, hostname=name))
    await db_session.commit()


@pytest.mark.anyio
async def test_case_and_trailing_dot_are_not_a_conflict(db_session, admin_user, target):
    _sn, ipa = target
    await _obs(db_session, ipa, [("scanner", "win11-desk-01"), ("opnsense", "win11-desk-01."),
                                 ("netbios", "WIN11-DESK-01")])
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    assert not [c for c in d["conflicts"] if c["code"] == "names"]


@pytest.mark.anyio
async def test_different_names_are_a_conflict(db_session, admin_user, target):
    _sn, ipa = target
    await _obs(db_session, ipa, [("scanner", "web01"), ("dns", "db01.corp.example")])
    d = await collect_dossier(db_session, user=admin_user, ip=IP)
    names = [c for c in d["conflicts"] if c["code"] == "names"]
    assert names
    assert names[0]["params"]["n"] == 2


def test_conflicts_cover_the_existing_kinds():
    """原本在前端算的那幾種矛盾，改由後端算一次：AI 判讀與四種匯出拿到的是同一份。"""
    d = {
        "hostname_sources": [{"hostname": "a"}, {"hostname": "b"}],
        "monitoring": {"wazuh": {"name": "old-laptop", "still_represents_this_ip": False}},
        "other_records": [{"subnet": "198.51.100.64/28"}],
        "arp": [{"mac": "00:11:22:00:00:01"}, {"mac": "00:11:22:00:00:02"}, {"mac": "00:11:22:00:00:03"}],
        "address": {"mac": MAC},
        "dhcp": {"reservations": [{"mac": "00:11:22:99:99:99", "source_name": "dc01"}]},
    }
    by = {c["code"]: c["params"] for c in inv.compute_conflicts(d)}
    assert by["names"]["n"] == 2
    assert by["stale_agent"]["name"] == "old-laptop"
    assert by["duplicate"]["n"] == 2
    assert by["macs"]["n"] == 3
    assert by["reservation_mac"]["reserved"] == "00:11:22:99:99:99"
    assert by["reservation_mac"]["current"] == MAC


def test_random_macs_are_reported_as_the_softer_kind():
    d = {"arp": [{"mac": "00:11:22:00:00:01"}, {"mac": "02:00:00:00:00:02"}, {"mac": "06:00:00:00:00:03"}]}
    by = {c["code"]: c["params"] for c in inv.compute_conflicts(d)}
    assert "macs" not in by
    assert by["macs_random"] == {"n": 3, "r": 2}


def test_same_reservation_mac_in_a_different_spelling_is_not_a_conflict():
    d = {"address": {"mac": "00:11:22:33:44:77"},
         "dhcp": {"reservations": [{"mac": "00-11-22-33-44-77"}]}}
    assert not [c for c in inv.compute_conflicts(d) if c["code"] == "reservation_mac"]


# ─────────────────────────── 端點 ───────────────────────────

@pytest.mark.anyio
async def test_endpoint_returns_the_new_sections_and_conflicts(client, auth_headers, db_session, target):
    """經由 HTTP 端點（JSON 序列化、正式的 session）拿到的是同一份。"""
    _sn, ipa = target
    ipa.arp_seen = {"arp:opnsense": _now().isoformat()}
    await db_session.commit()
    r = await client.get("/api/v1/investigate", params={"ip": IP}, headers=auth_headers)
    assert r.status_code == 200, r.text
    d = r.json()["dossier"]
    assert d["fw_evidence"][0]["key"] == "arp:opnsense"
    assert d["conflicts"] == []


# ─────────────────────────── 給模型的版本要精簡 ───────────────────────────

def test_prompt_view_is_bounded_and_drops_empty_values():
    d = {"found": True, "ip": IP, "address": {"ip_address_id": str(uuid.uuid4()), "hostname": "h",
                                               "owner": None, "description": ""},
         "arp": [{"mac": f"00:11:22:00:00:{i:02x}", "last_seen_at": "2026-10-05T00:00:00"} for i in range(20)],
         "dns": [], "agents": {"ocs": {"notes": ["x" * 2000]}}}
    v = inv.prompt_view(d)
    assert "owner" not in v["address"]
    assert "description" not in v["address"]
    assert "ip_address_id" not in v["address"], "內部識別碼對判讀沒有用，只佔篇幅"
    assert len(v["arp"]) == inv.PROMPT_ROWS
    assert v["arp_total"] == 20
    assert "dns" not in v
    assert len(v["agents"]["ocs"]["notes"][0]) <= inv.PROMPT_TEXT + 1
