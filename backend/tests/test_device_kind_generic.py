"""設備類型判讀要涵蓋所有設備，不只某個環境裡有的（使用者 2026-10-05）。

這裡的設備都不在當初拿來校正規則的正式環境網段裡：攝影機、IP 電話、UPS、NAS、防火牆、AP、印表機、虛擬化主機、
BMC、工控、樓宇自動化、串流播放器、手機，以及網卡廠牌的子字串陷阱、主機名稱的角色否決。
對照表在 services/device_kind_knowledge.py；證據的先後在 ip_identify.summarize 與 device_identity.resolve_kind。
"""
from __future__ import annotations

from typing import Any

import pytest
from app.services.device_identity import Facts, resolve_kind
from app.services.ip_identify import summarize


def _res(ports: list[dict[str, Any]] | None = None, os: list[tuple] | None = None, **nmap: Any) -> dict:
    """os: (name, accuracy, type, vendor, family)"""
    return {"nmap": {"available": True, "closed": 900,
                     "os": [{"name": n, "accuracy": a, "type": t, "vendor": v, "family": f}
                            for n, a, t, v, f in (os or [])],
                     "ports": [{"proto": "tcp", "state": "open", **p} for p in (ports or [])], **nmap}}


def _kind(ports: list[dict[str, Any]] | None = None, os: list[tuple] | None = None, **kw: Any) -> str:
    return summarize(_res(ports, os), **kw)["device_type"]


SILENT = {"nmap": {"available": True, "closed": 999, "ports": [], "os": []}}
LINUX = [("Linux 4.15 - 5.8", 96, "general purpose", "Linux", "Linux")]
#: 「這不是那種設備」：只有 Linux 指紋、沒有一般主機的正面證據時是「不明」（對抗式驗證 2026-10-05），
#: 有證據時是一般主機
_NOT_A_DEVICE = ("server", "unknown")


# ─────────────────── 服務自己講的產品字樣（每個欄位分開比對） ───────────────────

@pytest.mark.parametrize(("port", "expected"), [
    # 攝影機
    ({"port": 80, "service": "http", "scripts": {"http-server-header": "App-webs/"}}, "camera"),           # Hikvision
    ({"port": 80, "service": "http", "scripts": {"http-title": "AXIS M3106-L Mk II Network Camera"}}, "camera"),
    ({"port": 554, "service": "rtsp", "product": "Dahua IP camera rtspd"}, "camera"),
    # IP 電話
    ({"port": 80, "service": "http", "product": "Yealink VoIP phone httpd"}, "voip"),
    ({"port": 80, "service": "http", "scripts": {"http-server-header": "Polycom SoundPoint IP Telephone HTTPd"}},
     "voip"),
    # UPS／PDU 的網路卡
    ({"port": 21, "service": "ftp", "product": "APC AOS ftpd"}, "specialized"),
    ({"port": 80, "service": "http", "scripts": {"http-title": "CyberPower RMCARD205"}}, "specialized"),
    # NAS
    ({"port": 8080, "service": "http", "scripts": {"http-title": "QNAP Turbo NAS"}}, "storage"),
    ({"port": 5000, "service": "http", "scripts": {"http-title": "Synology&nbsp;DiskStation"}}, "storage"),
    # 防火牆
    ({"port": 443, "service": "https", "product": "Fortinet FortiGate 50B or FortiWifi 60C or 80C firewall http config"},
     "firewall"),
    ({"port": 443, "service": "https", "scripts": {"http-title": "Sophos Firewall"}}, "firewall"),
    ({"port": 443, "service": "https", "product": "Palo Alto PanWeb httpd"}, "firewall"),
    # 無線 AP／控制器
    ({"port": 443, "service": "https", "scripts": {"http-title": "Aruba Instant On AP22"}}, "wireless_ap"),
    ({"port": 443, "service": "https", "scripts": {"http-title": "Ruckus Wireless Admin"}}, "wireless_ap"),
    # 印表機
    ({"port": 80, "service": "http", "product": "Brother HL-L2350DW series"}, "printer"),
    ({"port": 80, "service": "http", "scripts": {"http-title": "Web Image Monitor"}}, "printer"),     # Ricoh
    # 虛擬化主機
    ({"port": 443, "service": "https", "product": "VMware ESXi SOAP API", "version": "7.0.3"}, "hypervisor"),
    ({"port": 443, "service": "https", "scripts": {"http-title": "XCP-ng"}}, "hypervisor"),
    # BMC
    ({"port": 443, "service": "https", "product": "Dell iDRAC http admin"}, "specialized"),
    ({"port": 443, "service": "https", "scripts": {"http-title": "iLO 5"}}, "specialized"),
    # 影音
    ({"port": 8008, "service": "http", "product": "Google Chromecast httpd"}, "media"),
])
def test_product_text_identifies_devices(port: dict, expected: str) -> None:
    assert _kind([port]) == expected


def test_a_guard_in_one_field_does_not_hide_a_product_in_another() -> None:
    """Plex 是跑在 NAS 上的軟體（排除條件），同一台的另一個欄位講出 Synology：還是儲存設備。"""
    ports = [{"port": 32400, "service": "http", "product": "Plex Media Server httpd"},
             {"port": 5000, "service": "http", "product": "nginx", "scripts": {"http-title": "Synology DiskStation"}}]
    assert _kind(ports, LINUX) == "storage"


def test_software_that_looks_like_a_device_is_not_the_device() -> None:
    # 錄影軟體（Blue Iris）的頁面寫著 NVR、開著 RTSP：主機是 Windows 電腦
    vms = [{"port": 81, "service": "http", "product": "Blue Iris"}, {"port": 554, "service": "rtsp", "product": "Blue Iris"}]
    assert _kind(vms) != "camera"
    # node_exporter 有認出產品的 9100 不是印表機（沒有作業系統指紋也一樣）
    assert _kind([{"port": 9100, "service": "jetdirect", "product": "Prometheus node_exporter"}]) != "printer"
    # UniFi Network（控制器軟體）不是 AP
    assert _kind([{"port": 8443, "service": "https", "scripts": {"http-title": "UniFi Network"}}], LINUX) in _NOT_A_DEVICE
    # nmap「沒有跟著轉址」的訊息裡的網址不是標題
    redirect = [{"port": 80, "service": "http",
                 "scripts": {"http-title": "Did not follow redirect to https://printer.example.net/"}}]
    assert _kind(redirect, LINUX) in _NOT_A_DEVICE


def test_amt_in_a_vpro_desktop_is_not_a_bmc() -> None:
    """Intel AMT（vPro 電腦）也回應 623：同一台開著 AMT 的網頁埠時不是伺服器的 BMC。"""
    amt = [{"port": 623, "service": "asf-rmcp"}, {"port": 16992, "service": "amt-soap-http"}]
    assert _kind(amt) != "specialized"
    assert _kind([{"port": 623, "service": "asf-rmcp"}]) == "specialized"


# ─────────────────── 開著的埠（廠牌專屬協定） ───────────────────

@pytest.mark.parametrize(("port", "proto", "expected"), [
    (102, "tcp", "specialized"),         # Siemens S7（PLC）
    (44818, "tcp", "specialized"),       # EtherNet/IP
    (47808, "udp", "specialized"),       # BACnet/IP 控制器
    (37777, "tcp", "camera"),            # Dahua DVR／NVR
    (8291, "tcp", "router"),             # MikroTik Winbox
    (4786, "tcp", "switch"),             # Cisco Smart Install
    (8060, "tcp", "media"),              # Roku
    (1400, "tcp", "media"),              # Sonos
    (5985, "tcp", "windows"),            # WinRM
])
def test_vendor_protocol_ports(port: int, proto: str, expected: str) -> None:
    assert _kind([{"port": port, "proto": proto, "service": "unknown"}]) == expected


def test_industrial_protocols_on_a_general_os_are_scada_software() -> None:
    """BACnet／Modbus 在 Windows、Linux 上是 SCADA／BMS 軟體，不是控制器本身。"""
    win = [("Microsoft Windows 10 1809", 96, "general purpose", "Microsoft", "Windows")]
    assert _kind([{"port": 47808, "proto": "udp", "service": "bacnet"}], win) == "windows"
    assert _kind([{"port": 502, "service": "mbap"}], LINUX) in _NOT_A_DEVICE


def test_a_vendor_port_yields_to_a_single_purpose_nic_vendor() -> None:
    """9999 是 TP-Link Kasa 插座的區網協定，但 ATOM Cam 攝影機也開著：網卡是只做攝影機的廠牌時不採信埠號。"""
    assert _kind([{"port": 9999, "service": "abyss"}], mac_vendor="ATOMtech") == "camera"
    assert _kind([{"port": 9999, "service": "abyss"}], mac_vendor="TPLink") == "specialized"


# ─────────────────── nmap 服務偵測附的類別與 method（代理 1.17.2） ───────────────────

def test_nmap_service_devicetype_is_evidence() -> None:
    cam = [{"port": 80, "service": "http", "product": "lighttpd", "method": "probed", "devicetype": "webcam"}]
    assert _kind(cam) == "camera"
    ups = [{"port": 80, "service": "http", "product": "GoAhead WebServer", "method": "probed",
            "devicetype": "power-device"}]
    assert _kind(ups, LINUX) == "specialized"
    # 產品名稱說明是視訊會議（nmap 把 Polycom、Tandberg 的視訊會議設備標成 webcam）：依名稱覆寫成 VoIP
    vc = [{"port": 80, "service": "http", "product": "Tandberg 6000 MXP video conferencing http config",
           "devicetype": "webcam"}]
    assert _kind(vc) == "voip"
    assert summarize(_res(vc))["evidence"][0].endswith("(devicetype: webcam)")
    # macOS 的 AirPlay 接收器：nmap 的服務類別是 media device，但 Mac 不是影音設備
    mac_os = [("Apple macOS 12 (Monterey)", 96, "general purpose", "Apple", "macOS")]
    airplay = [{"port": 7000, "service": "rtsp", "product": "AirTunes rtspd", "method": "probed",
                "devicetype": "media device"}]
    assert _kind(airplay, mac_os) == "server"
    # 照埠號表猜的服務沒有 devicetype 可信
    table = [{"port": 9100, "service": "jetdirect", "method": "table", "devicetype": "printer"}]
    assert _kind(table, LINUX) in _NOT_A_DEVICE


def test_a_port_table_guess_is_not_a_confirmed_service() -> None:
    """nmap 沒有探針比中、只照埠號表寫名稱（method="table"）：445 的 microsoft-ds、135 的 msrpc 只代表埠開著
    （Linux 的 Samba 也是），631 的 ipp 等同沒認出產品的 9100。"""
    assert _kind([{"port": 445, "service": "microsoft-ds", "method": "table"}]) == "unknown"
    assert _kind([{"port": 135, "service": "msrpc", "method": "table"}]) == "unknown"
    assert _kind([{"port": 445, "service": "microsoft-ds"}]) == "windows"           # 舊代理沒有 method：照舊
    assert _kind([{"port": 631, "service": "ipp", "method": "table"}], LINUX) in _NOT_A_DEVICE
    assert _kind([{"port": 631, "service": "ipp", "method": "table"}]) == "printer"
    assert _kind([{"port": 631, "service": "ipp", "method": "probed"}], LINUX) == "printer"


# ─────────────────── TCP/IP 指紋的類別 ───────────────────

def test_fingerprint_classes_beyond_the_old_table() -> None:
    esxi = [("VMware ESXi 6.5 - 7.0", 98, "specialized", "VMware", "ESXi")]
    assert _kind([], esxi) == "hypervisor"
    # 指紋的廠牌 VMware 是作業系統的作者：網卡是伺服器廠牌也不算廠牌對不上，作業系統照寫
    on_dell = summarize(_res([], esxi), mac_vendor="Dell")
    assert on_dell["device_type"] == "hypervisor"
    assert on_dell["os"] == "VMware ESXi 6.5 - 7.0"
    assert on_dell["vendor"] is None
    win = [("Microsoft Windows 11 21H2", 97, "general purpose", "Microsoft", "Windows")]
    assert _kind([], win, mac_vendor="IntelCorpora") == "windows"
    ps = [("Sony PlayStation 4", 95, "game console", "Sony", "embedded")]
    assert _kind([], ps, mac_vendor="SonyInteract") == "media"
    ios = [("Apple iOS 12.0 - 13.4", 95, "media device", "Apple", "iOS")]
    assert _kind([], ios) == "mobile"
    android = [("Android 10 - 12 (Linux 4.14 - 4.19)", 96, "phone", "Google", "Android")]
    assert _kind([], android) == "mobile"
    # 嵌入式核心（lwIP、VxWorks）的 general purpose 不是伺服器：說不出來，交給網卡廠牌
    lwip = [("lwIP 1.4.0 - 2.1.x", 95, "general purpose", "lwIP", "lwIP")]
    assert _kind([], lwip) == "unknown"
    assert _kind([], lwip, mac_vendor="Espressif") == "specialized"


# ─────────────────── 網卡廠牌（完全相等才算） ───────────────────

@pytest.mark.parametrize(("vendor", "expected"), [
    ("HikvisionDig", "camera"), ("AxisCommunic", "camera"), ("ZhejiangDahu", "camera"),
    ("YealinkNetwo", "voip"), ("Polycom", "voip"),
    ("AmericanPowe", "specialized"), ("Synology", "storage"), ("QNAP", "storage"),
    ("PaloAltoNetw", "firewall"), ("RuckusWirele", "wireless_ap"), ("BrotherIndus", "printer"),
    ("Roku", "media"), ("Sonos", "media"), ("SonyInteract", "media"), ("OnePlusTechn", "mobile"),
    # 子字串陷阱：以前都會中
    ("SonoSite", "unknown"), ("CarloGavazzi", "unknown"), ("BoserTechnol", "unknown"),
    ("DahuaScaleFa", "unknown"), ("McKayBrother", "unknown"),
    # 混合廠牌不猜
    ("Apple", "unknown"), ("Ubiquiti", "unknown"), ("TPLink", "unknown"),
])
def test_nic_vendor_hint_uses_exact_short_names(vendor: str, expected: str) -> None:
    assert summarize(SILENT, mac_vendor=vendor)["device_type"] == expected


def test_nic_vendor_of_a_random_or_virtual_mac_says_nothing() -> None:
    assert summarize(SILENT, mac_vendor="Espressif", mac="24:0a:c4:12:34:56")["device_type"] == "specialized"
    assert summarize(SILENT, mac_vendor="Espressif", mac="b2:11:22:33:44:55")["device_type"] == "unknown"
    assert summarize(SILENT, mac_vendor="Synology", mac="00:0c:29:12:34:56")["device_type"] == "unknown"
    # 廠牌是 nmap 自己查的：用 nmap 回報的 MAC 判斷
    random_mac = {"nmap": {**SILENT["nmap"], "mac": "da:a1:19:00:00:01", "mac_vendor": "Espressif"}}
    assert summarize(random_mac)["device_type"] == "unknown"


def test_a_medium_nic_vendor_needs_nothing_contradicting_it() -> None:
    """Canon 也做網路攝影機、Avaya 的 OUI 也用在交換器：開著的埠講出另一種設備時，medium 的廠牌線索不採用。"""
    assert summarize(SILENT, mac_vendor="Canon")["device_type"] == "printer"
    cast = _res([{"port": 8009, "service": "ajp13"}])
    assert summarize(cast, mac_vendor="Canon")["device_type"] == "unknown"
    # high 的廠牌照用
    assert summarize(cast, mac_vendor="BrotherIndus")["device_type"] == "printer"


def test_nas_vendor_with_file_sharing_uses_exact_names() -> None:
    smb = [{"port": 445, "service": "microsoft-ds", "product": "Samba smbd", "version": "4"}]
    assert _kind(smb, LINUX, mac_vendor="QNAP") == "storage"
    assert _kind(smb, LINUX, mac_vendor="DataRobotics") == "storage"     # Drobo（以前的 "drobo" 對不到）
    assert _kind(smb, LINUX, mac_vendor="SomeNASLikeName") == "server"


# ─────────────────── Recog（需要指紋庫：用測試用的小指紋檔） ───────────────────

def _matcher(xml: bytes, name: str) -> Any:
    from app.services import recog
    db = recog.parse_database(xml, name)
    return recog.Matcher("9.9.9", {db.key: (db.preference, db.fingerprints)})


SECURITY_APPLIANCE_XML = b"""<fingerprints matches="html_title" preference="0.9">
  <fingerprint pattern="^Tenable Core$">
    <description>Tenable Core appliance</description>
    <example>Tenable Core</example>
    <param pos="0" name="hw.vendor" value="Tenable"/>
    <param pos="0" name="hw.device" value="Security Appliance"/>
    <param pos="0" name="hw.product" value="Tenable Core"/>
  </fingerprint>
</fingerprints>"""

AIRPLAY_XML = b"""<fingerprints matches="http_header.server" preference="0.9">
  <fingerprint pattern="^AirTunes/([\\d.]+)$">
    <description>Apple AirTunes RTSP</description>
    <example>AirTunes/366.0</example>
    <param pos="0" name="hw.vendor" value="Apple"/>
    <param pos="0" name="hw.device" value="Media Server"/>
  </fingerprint>
</fingerprints>"""


def test_recog_security_appliance_is_not_a_firewall() -> None:
    """Recog 的 Security Appliance 多半不是防火牆（Tenable、FireEye、Duo 閘道器…）：不當成防火牆。"""
    m = _matcher(SECURITY_APPLIANCE_XML, "xml/html_title.xml")
    res = _res([{"port": 443, "service": "https", "scripts": {"http-title": "Tenable Core"}}], LINUX)
    assert summarize(res, recog=m)["device_type"] in _NOT_A_DEVICE


def test_recog_airplay_on_a_mac_is_not_a_media_device() -> None:
    m = _matcher(AIRPLAY_XML, "xml/http_servers.xml")
    port = [{"port": 7000, "service": "http", "scripts": {"http-server-header": "AirTunes/366.0"}}]
    assert summarize(_res(port), recog=m)["device_type"] == "media"
    mac_os = [("Apple macOS 12 (Monterey)", 96, "general purpose", "Apple", "macOS")]
    assert summarize(_res(port, mac_os), recog=m)["device_type"] == "server"


# ─────────────────── 主機名稱（IPAM 層，最弱的證據） ───────────────────

@pytest.mark.parametrize(("hostname", "expected"), [
    ("DESKTOP-4G7P2QK", "windows"), ("LAPTOP-0OLV8C5N", "windows"), ("WIN-3J5KT8VQ0FR", "windows"),
    ("desktop-support", None),
    ("idrac-7XK2Q12", "specialized"), ("BRN30055C123456", "printer"), ("SEP001122334455", "voip"),
    ("DiskStation", "storage"), ("esxi01", "hypervisor"), ("Roku-Ultra", "media"), ("shellyplug-s-A1B2C3", "specialized"),
    # 伺服器角色的字眼否決設備類：存錄影的伺服器不是攝影機
    ("nvr-server", None), ("camera-archive-01", None), ("ups-api", None),
    # 只看第一段：劍橋大學的網域不是攝影機
    ("cam.ac.uk", None), ("www.cam.ac.uk", None),
])
def test_hostname_hints(hostname: str, expected: str | None) -> None:
    assert resolve_kind(None, Facts(hostname=hostname))[0] == expected


def test_hostname_cannot_turn_a_windows_box_into_hardware() -> None:
    """位址換了主人：叫 printer-2f 的位址現在是一台 Windows 電腦，類型要寫 Windows（異常偵測靠這個看出設備換了）。"""
    assert resolve_kind("windows", Facts(hostname="printer-2f"))[0] == "windows"
    assert resolve_kind("server", Facts(hostname="printer-2f"))[0] == "printer"
    assert resolve_kind("server", Facts(hostname="Living-Room-TV"), os_family="macos")[0] == "server"
    # Windows 的預設名稱跟作業系統矛盾時不採用
    assert resolve_kind("server", Facts(hostname="DESKTOP-4G7P2QK"), os_family="linux")[0] == "server"
    assert resolve_kind("server", Facts(hostname="DESKTOP-4G7P2QK"))[0] == "windows"
