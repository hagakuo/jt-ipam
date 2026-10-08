"""IP「探測」判斷出的設備類型要寫回 IP 記錄；定期偵測只有 OS 指紋時不可以把具體類型蓋回「伺服器」（2026-10-04）。

正式環境實例：198.51.100.114（Foscam 攝影機）手動探測看到 554/tcp rtsp → 攝影機，IP 頁卻寫「伺服器／電腦」：
探測結果從沒寫回 IP 記錄；定期偵測沒開「連接埠」探測時只掃 22／80／443／445／3389／8006，看不到 554，
只剩「Linux」的 TCP/IP 指紋 → 一般主機。
"""
from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.device_identity import apply_summary

CAMERA = {"device_type": "camera", "os": "Linux 3.2 - 3.8", "vendor": "ReecamTech", "model": None,
          "evidence": ["os:Linux 3.2 - 3.8 (100%)", "service:554/tcp rtsp", "oui:ReecamTech"]}
FINGERPRINT_ONLY = {"device_type": "server", "os": "Linux 3.2 - 3.8", "vendor": "ReecamTech", "model": None,
                    "evidence": ["os:Linux 3.2 - 3.8 (100%)", "osclass:general purpose", "oui:ReecamTech"]}


async def _ip(db) -> IPAddress:
    sec = Section(name=f"dk-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.114", mac="e8:ab:fa:00:01:14")
    db.add(ip)
    await db.flush()
    return ip


async def test_fingerprint_only_does_not_turn_a_camera_back_into_a_server(db_session) -> None:
    ip = await _ip(db_session)
    await apply_summary(db_session, ip, CAMERA, source="identify")
    assert ip.device_kind == "camera"
    await apply_summary(db_session, ip, FINGERPRINT_ONLY)            # 定期偵測（scanner）
    assert ip.device_kind == "camera", "只有 OS 指紋說是一般主機，不足以推翻攝影機"
    logs = (await db_session.execute(select(IPChangeLog).where(
        IPChangeLog.ip_id == ip.id, IPChangeLog.event_type == "kind_changed"))).scalars().all()
    assert not logs, "不可以因此出現「類型突變」"


async def test_strong_evidence_still_changes_the_kind(db_session) -> None:
    ip = await _ip(db_session)
    await apply_summary(db_session, ip, CAMERA, source="identify")
    printer = {"device_type": "printer", "os": None, "vendor": "HP", "model": "LaserJet",
               "evidence": ["service:9100/tcp jetdirect"]}
    await apply_summary(db_session, ip, printer)
    assert ip.device_kind == "printer", "服務證據講出另一種設備：照樣改（位址可能換了主人，要記異動）"
    virt = {"device_type": "server", "os": "Linux", "evidence": ["virt:guest"]}
    storage_ip = await _ip(db_session)
    storage_ip.device_kind = "storage"
    await apply_summary(db_session, storage_ip, virt)
    assert storage_ip.device_kind == "server", "虛擬化整合確認是 VM／容器：可以改掉指紋誤判的儲存設備"


async def test_generic_kind_can_be_refined_by_fingerprint(db_session) -> None:
    ip = await _ip(db_session)
    await apply_summary(db_session, ip, FINGERPRINT_ONLY)
    assert ip.device_kind == "server"
    await apply_summary(db_session, ip, CAMERA)
    assert ip.device_kind == "camera"


async def test_finished_identify_writes_the_kind_to_the_ip_record(db_session, monkeypatch) -> None:
    from app.models.agent_probe_job import STATUS_DONE, AgentProbeJob
    from app.models.background_task import BackgroundTask
    from app.services import identify_tasks

    from datetime import UTC, datetime, timedelta

    from app.models.scan_agent import ScanAgent
    ip = await _ip(db_session)
    agent = ScanAgent(name=f"dk-agent-{uuid.uuid4().hex[:6]}", enroll_key_hash=uuid.uuid4().hex * 2, enabled=True)
    db_session.add(agent)
    await db_session.flush()
    job = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": [str(ip.ip).split("/")[0]]},
                        status=STATUS_DONE, result={"nmap": {"available": True}},
                        expires_at=datetime.now(UTC) + timedelta(minutes=10))
    db_session.add(job)
    await db_session.flush()
    db_session.add(BackgroundTask(kind=identify_tasks.KIND, status="running", trigger="manual",
                                  target_type="ip_address", target_id=ip.id, target_label="x",
                                  summary={"job_id": str(job.id), "ip": "198.51.100.114"}))
    await db_session.flush()
    monkeypatch.setattr("app.services.ip_identify.summarize", lambda *a, **k: dict(CAMERA, services=[]))
    await identify_tasks.on_finished(db_session, job)
    assert ip.device_kind == "camera" and ip.device_model == "ReecamTech"


def test_periodic_os_probe_looks_at_ports_that_identify_devices(monkeypatch) -> None:
    """沒開「連接埠」探測時，定期 OS 偵測也要看攝影機（554）、印表機（9100）這類埠；不做 OS 偵測時維持原本的少數幾個。"""
    import importlib.util
    import pathlib
    from types import SimpleNamespace

    path = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"
    spec = importlib.util.spec_from_file_location(f"jt_agent_dk_{uuid.uuid4().hex[:6]}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    calls: list[list[str]] = []

    def fake_run(args, **_kw):  # noqa: ANN001
        calls.append(list(args))
        return SimpleNamespace(stdout="", stderr="", returncode=0)
    monkeypatch.setattr(mod.shutil, "which", lambda _n: "/usr/bin/nmap")
    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    mod._nmap_os_ports("198.51.100.7", True, False)
    ports = set(calls[0][calls[0].index("-p") + 1].split(","))
    assert {"554", "9100", "22", "443"} <= ports
    calls.clear()
    mod._nmap_os_ports("198.51.100.7", False, False)
    ports = set(calls[0][calls[0].index("-p") + 1].split(","))
    assert ports == {str(p) for p in mod.TCP_PROBE_PORTS}


async def test_a_desktop_os_fingerprint_can_correct_a_wrong_camera(db_session) -> None:
    """2026-10-05：Mac 的 AirPlay（5000／7000 RTSP）曾被判成攝影機寫進 IP 記錄。規則修好之後，定期偵測的指紋
    說 macOS ＝ 不是嵌入式設備，要能改回來；Linux 的指紋仍然推翻不了攝影機（上面那個測試）。"""
    ip = await _ip(db_session)
    ip.device_kind, ip.os_family = "camera", "macos"
    mac = {"device_type": "server", "os": "Apple macOS 11 (Big Sur) (Darwin 20.6.0)", "vendor": "CalDigit",
           "evidence": ["os:Apple macOS 11 (Big Sur) (Darwin 20.6.0) (96%)", "osclass:general purpose"]}
    await apply_summary(db_session, ip, mac)
    assert ip.device_kind == "server"
    win_ip = await _ip(db_session)
    win_ip.device_kind, win_ip.os_family = "camera", "windows"
    await apply_summary(db_session, win_ip, {"device_type": "windows", "os": "Microsoft Windows 10 1607",
                                             "evidence": ["os:Microsoft Windows 10 1607 (98%)"]})
    assert win_ip.device_kind == "windows"


# ── 依證據強弱決定類型：IPAM 已知的事實優先於埠號與指紋的推測（2026-10-05 全段比對）──────────────

from datetime import UTC, datetime, timedelta  # noqa: E402

from app.services.device_identity import resolve_kind, Facts  # noqa: E402

LINUX_RDP = {"device_type": "windows", "os": None, "evidence": ["service:3389/tcp ms-wbt-server xrdp"]}


def test_resolve_order_device_record_then_librenms_then_agents() -> None:
    # 裝置記錄的具體類型最優先
    assert resolve_kind("server", Facts(device_type="firewall"))[0] == "firewall"
    # LibreNMS 的分類：firewall／wireless／printer／storage／power
    assert resolve_kind("printer", Facts(lnms_type="firewall", lnms_os="opnsense"))[0] == "firewall"
    assert resolve_kind("server", Facts(lnms_type="wireless", lnms_os="unifi"))[0] == "wireless_ap"
    assert resolve_kind("server", Facts(lnms_type="network", lnms_os="openwrt"))[0] == "router"
    assert resolve_kind("server", Facts(lnms_type="network", lnms_os="dlink"))[0] == "switch"
    assert resolve_kind("server", Facts(lnms_type="storage", lnms_os="dsm"))[0] == "storage"
    # LibreNMS 的 proxmox 只是看核心字串的「-pve」：LXC 容器、Mail Gateway、Datacenter Manager 都會被認成 proxmox
    #（對抗式驗證 2026-10-05）。只有主機名稱就是 PVE 節點時才算虛擬化主機
    assert resolve_kind("server", Facts(lnms_type="server", lnms_os="proxmox", pve_node=True))[0] == "hypervisor"
    assert resolve_kind("server", Facts(lnms_type="server", lnms_os="proxmox"))[0] == "server"
    assert resolve_kind("hypervisor", Facts(lnms_type="server", lnms_os="proxmox", guest=True,
                                            guest_kind="ct"))[0] == "server"
    assert resolve_kind("server", Facts(lnms_type="server", lnms_os="proxmox", agent_family="linux",
                                        agent_source="wazuh"))[1] == "wazuh:linux", "依據寫代理回報的，不寫 LibreNMS"
    # 裝置記錄是籠統的 server／other 時不算數，交給下一層
    assert resolve_kind("printer", Facts(device_type="other", lnms_type="printer", lnms_os="jetdirect"))[0] == "printer"


def test_agents_mean_a_general_purpose_computer() -> None:
    """裝得了 Wazuh／RustDesk／OCS 代理＝一般電腦：不會是印表機、攝影機、交換器；作業系統以代理回報為準。"""
    assert resolve_kind("windows", Facts(agent_family="linux", agent_source="wazuh"))[0] == "server", \
        "ws-ud24：Linux 裝了 xrdp，3389 開著 → 不是 Windows 主機"
    assert resolve_kind("camera", Facts(agent_family="macos", agent_source="rustdesk"))[0] == "server"
    assert resolve_kind("server", Facts(agent_family="windows", agent_source="ocs"))[0] == "windows"
    assert resolve_kind("printer", Facts(agent_family="linux", agent_source="wazuh"))[0] == "server"
    assert resolve_kind(None, Facts(agent_family="android", agent_source="rustdesk"))[0] == "mobile"
    # 角色類（虛擬化主機、儲存、防火牆）跟一般電腦不矛盾，保留
    assert resolve_kind("hypervisor", Facts(agent_family="linux", agent_source="wazuh"))[0] == "hypervisor"


def test_virtual_guests_are_not_hardware() -> None:
    for k in ("switch", "wireless_ap", "printer", "camera", "voip", "hypervisor", "mobile"):
        assert resolve_kind(k, Facts(guest=True, guest_kind="ct"))[0] == "server", k
        assert resolve_kind(k, Facts(guest=True, guest_kind="vm"))[0] is None, "虛擬機可能是防火牆或 Windows：只排除硬體類"
    assert resolve_kind(None, Facts(guest=True, guest_kind="vm"))[0] is None
    assert resolve_kind(None, Facts(guest=True, guest_kind="ct"))[0] == "server", "LXC 容器一定是 Linux"
    assert resolve_kind("firewall", Facts(guest=True))[0] == "firewall", "pfSense／OPNsense 常跑在虛擬機裡"
    assert resolve_kind("windows", Facts(guest=True))[0] == "windows"


def test_no_facts_keeps_the_scan_result() -> None:
    assert resolve_kind("camera", Facts())[0] == "camera"
    assert resolve_kind(None, Facts())[0] is None


async def test_stale_agent_and_vm_facts_are_ignored(db_session) -> None:
    """192.0.2.166：DHCP 位址換了主人（現在是 iPhone），Wazuh 代理是上一任（一個月沒回報）、
    PVE 記得 vm-lab-02 的網卡用過這個 IP（MAC 不同）→ 這些都不算數。"""
    from app.models.wazuh import WazuhAgent, WazuhInstance
    from app.services.device_identity import ipam_facts
    ip = await _ip(db_session)
    ip.mac = "d2:11:22:33:44:66"
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://wazuh.example.net", api_user="u",
                         api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="901", name="old-pc", os_platform="windows",
                              last_keep_alive=datetime.now(UTC) - timedelta(days=31), jt_ipam_address_id=ip.id))
    await db_session.flush()
    f = await ipam_facts(db_session, ip)
    assert f.agent_family is None
    a2 = await _ip(db_session)
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="902", name="ws-ud24", os_platform="ubuntu",
                              last_keep_alive=datetime.now(UTC) - timedelta(minutes=5), jt_ipam_address_id=a2.id))
    await db_session.flush()
    f2 = await ipam_facts(db_session, a2)
    assert f2.agent_family == "linux" and f2.agent_source == "wazuh"


async def test_apply_summary_uses_ipam_facts(db_session) -> None:
    from app.models.wazuh import WazuhAgent, WazuhInstance
    ip = await _ip(db_session)
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://wazuh.example.net", api_user="u",
                         api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="903", name="ws-ud24", os_platform="ubuntu",
                              last_keep_alive=datetime.now(UTC), jt_ipam_address_id=ip.id))
    await db_session.flush()
    await apply_summary(db_session, ip, LINUX_RDP, source="identify")
    assert ip.device_kind == "server"


async def test_explicit_identify_that_cannot_tell_clears_an_old_guess(db_session) -> None:
    """手動探測（最完整的一次）說不出是什麼，舊的推測（多半是舊規則或上一任主人的）不可以留著。"""
    ip = await _ip(db_session)
    ip.device_kind = "wireless_ap"
    await apply_summary(db_session, ip, {"device_type": "unknown", "evidence": []}, source="identify")
    assert ip.device_kind is None
    ip.device_kind = "wireless_ap"
    await apply_summary(db_session, ip, {"device_type": "no_response", "no_response": True, "evidence": []},
                        source="identify")
    assert ip.device_kind == "wireless_ap", "沒有回應＝什麼都沒看到，不改"


async def test_device_model_does_not_keep_the_nic_vendor(db_session) -> None:
    """以前型號欄寫的是網卡的 OUI（IP 頁「攝影機 · CalDigit」）：新判讀沒有設備廠牌時要清掉。"""
    ip = await _ip(db_session)
    ip.device_kind, ip.device_model = "server", "CalDigit"
    await apply_summary(db_session, ip, {"device_type": "server", "vendor": None, "nic_vendor": "CalDigit",
                                         "evidence": []}, source="identify")
    assert ip.device_model is None


def test_ip_record_hints_vrrp_mac_and_hostname() -> None:
    """192.0.2.236 是 CARP／VRRP 的虛擬位址（00:00:5e:00:01:xx）；opnsense-backup-02 只開著 tcpwrapped 的 22／443。"""
    assert resolve_kind(None, Facts(mac="00:00:5e:00:01:02"))[0] == "router"
    # CARP（OPNsense／pfSense）用同一段 MAC：同網段有防火牆時判防火牆（對抗式驗證 2026-10-05）
    assert resolve_kind(None, Facts(mac="00:00:5e:00:01:02", vrrp_owner="firewall"))[0] == "firewall"
    assert resolve_kind("server", Facts(guest=True, hostname="opnsense-backup-02"))[0] == "firewall"
    assert resolve_kind(None, Facts(hostname="edge-mikrotik-01"))[0] == "router"
    # 代理說是一般電腦時，主機名稱不蓋過它
    assert resolve_kind("server", Facts(agent_family="linux", agent_source="wazuh", hostname="pfsense-backup"))[0] == "server"
    # 探測已有具體結論時不蓋
    assert resolve_kind("printer", Facts(hostname="opnsense-printer"))[0] == "printer"


def test_librenms_hardware_model_beats_coarse_types() -> None:
    """VigorAP903：裝置記錄寫 router（匯入時粗分）、LibreNMS 分類 network；硬體型號說是 AP。
    Synology RT1900ac：LibreNMS 把 SRM 當成 dsm／storage；硬體型號說是路由器。"""
    assert resolve_kind("server", Facts(device_type="router", lnms_type="network", lnms_os="draytek",
                                        lnms_hw="VigorAP903"))[0] == "wireless_ap"
    assert resolve_kind("server", Facts(lnms_type="storage", lnms_os="dsm", lnms_hw="RT1900ac"))[0] == "router"
    assert resolve_kind("server", Facts(lnms_type="storage", lnms_os="dsm", lnms_hw="DS918+"))[0] == "storage"


def test_hostname_hints_for_consumer_devices() -> None:
    """198.51.100.0/24：什麼服務都沒開的設備只剩主機名稱可看（證據最弱，只在沒有更強的證據時用）。"""
    for name, kind in (("Galaxy-A53-5G", "mobile"), ("iPhone", "mobile"), ("ipcam4", "camera"),
                       ("epson3a2b1c", "printer"), ("user-ThinkPad-T440p", "server"), ("ap-3f-02", "wireless_ap")):
        assert resolve_kind(None, Facts(hostname=name))[0] == kind, name
    # 型號字要網卡廠牌相符；同時講兩種類型的、gw（預設閘道）不猜（對抗式驗證第二輪）
    for name in ("HS300", "P105"):
        assert resolve_kind(None, Facts(hostname=name, nic_vendor="TPLink"))[0] == "specialized", name
    for name in ("smart-gw", "voip-router-2"):
        assert resolve_kind(None, Facts(hostname=name))[0] is None, name
    assert resolve_kind("server", Facts(hostname="ipcam5"))[0] == "camera", "指紋只說一般 Linux 時，名稱更具體"
    assert resolve_kind("printer", Facts(hostname="ipcam5"))[0] == "printer", "服務已有具體結論時不蓋"
    assert resolve_kind(None, Facts(hostname="web-01"))[0] is None
    assert resolve_kind("server", Facts(hostname="camera-archive", agent_family="linux",
                                        agent_source="wazuh"))[0] == "server", "有代理的電腦不看名稱"


def test_librenms_os_table_covers_devices_beyond_this_network() -> None:
    """規則要涵蓋所有設備，不只某個環境裡有的（使用者 2026-10-05）：LibreNMS 的 815 個作業系統定義都整理過。"""
    cases = {("firewall", "fortigate"): "firewall", ("network", "arubaos-cx"): "switch",
             ("wireless", "ruckuswireless-sz"): "wireless_ap", ("network", "edgeos"): "router",
             ("printer", "ricoh"): "printer", ("power", "apc"): "specialized", ("storage", "netapp"): "storage",
             ("server", "vmware-esxi"): "hypervisor", ("network", "ios"): None, ("server", "linux"): "server"}
    for (t, os_), kind in cases.items():
        got = resolve_kind(None, Facts(lnms_type=t, lnms_os=os_))[0]
        assert got == kind, (os_, got)
    # LibreNMS 沒有真的用 SNMP 認出（type 空白）時不查表：198.51.100.195 是 TP-Link 的智慧插座，os 卻寫 tplink
    assert resolve_kind(None, Facts(lnms_type="", lnms_os="tplink"))[0] is None
    # LibreNMS 說是一般主機（windows／server 類）時，探測認出的角色（虛擬化主機、儲存）保留
    assert resolve_kind("hypervisor", Facts(lnms_type="server", lnms_os="windows"))[0] == "hypervisor"
    assert resolve_kind("printer", Facts(lnms_type="server", lnms_os="windows"))[0] == "windows"


# ── 對抗式驗證第二輪（2026-10-05）──────────────────────────────────────────────────────────────

def test_hostname_model_codes_need_the_matching_nic_vendor() -> None:
    """「P105」「HS300」是 TP-Link 插座的型號：在別的網路上可能是教室、印表機、專案主機 → 網卡廠牌對得上才算。"""
    from app.services.device_identity import Facts, resolve_kind
    assert resolve_kind("unknown", Facts(hostname="P105", nic_vendor="TPLink"))[0] == "specialized"
    assert resolve_kind("unknown", Facts(hostname="HS300", nic_vendor="TP-LINK TECHNOLOGIES CO.,LTD."))[0] \
        == "specialized"
    assert resolve_kind("unknown", Facts(hostname="P105"))[0] is None
    assert resolve_kind("unknown", Facts(hostname="P105", nic_vendor="Dell"))[0] is None


def test_hostname_words_that_name_two_kinds_decide_nothing() -> None:
    """「voip-router-2」同時講 VoIP 與路由器；「smart-gw」的 gw 多半是預設閘道 → 都不猜。"""
    from app.services.device_identity import Facts, resolve_kind
    assert resolve_kind("unknown", Facts(hostname="voip-router-2"))[0] is None
    assert resolve_kind("unknown", Facts(hostname="smart-gw", nic_vendor="TPLink"))[0] is None
    assert resolve_kind("unknown", Facts(hostname="core-router-01"))[0] == "router"


def test_proxmox_node_reason_names_the_virtualization_fact() -> None:
    """節點是虛擬化整合回報的，依據寫那個事實，不寫 LibreNMS 的 proxmox（那只是看核心字串）。"""
    from app.services.device_identity import Facts, resolve_kind
    assert resolve_kind("server", Facts(lnms_type="server", lnms_os="proxmox", pve_node=True)) \
        == ("hypervisor", "virt:pve-node")


def test_librenms_hardware_of_a_guest_is_the_host_hardware() -> None:
    """LXC 在 LibreNMS 的硬體型號是宿主的（Supermicro Super Server）：容器／虛擬機一律不看硬體型號。"""
    from app.services.device_identity import Facts, resolve_kind
    assert resolve_kind("server", Facts(lnms_hw="VigorAP903", guest=True, guest_kind="ct"))[0] == "server"
