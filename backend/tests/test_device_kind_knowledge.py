"""設備類型的知識表（services/device_kind_knowledge.py，2026-10-05）本身的檢查。

表是從 nmap、Recog、Wireshark manuf 的原始資料逐條整理的；每條產品樣式與主機名稱線索都附了範例與反例，
這裡逐一驗證，之後改表時不會默默改壞別的條目。整合進判讀流程的行為在 test_device_kind_generic.py。
"""
from __future__ import annotations

import re

import pytest
from app.services import device_kind_knowledge as kk

# nmap-os-db 的 Class 行與 nmap-service-probes 的 d/ 欄位裡出現過的全部類別（2026-10-05）
NMAP_TYPES_SEEN = ("general purpose", "switch", "WAP", "printer", "specialized", "storage-misc", "phone",
                   "media device", "broadband router", "router", "firewall", "remote management", "VoIP phone",
                   "webcam", "VoIP adapter", "power-device", "proxy server", "print server", "load balancer",
                   "bridge", "security-misc", "PBX", "game console", "terminal", "terminal server", "PDA",
                   "telecom-misc", "storage", "power-misc", "hub")


def _kind_ok(kind: str | None) -> bool:
    return kind is None or kind in kk.KINDS


def test_kinds_are_the_ipam_kinds() -> None:
    from app.services.device_identity import KINDS
    assert kk.KINDS == KINDS


def test_every_nmap_device_type_is_mapped() -> None:
    for t in NMAP_TYPES_SEEN:
        assert t in kk.NMAP_DEVICE_TYPES, t
    for t, v in kk.NMAP_DEVICE_TYPES.items():
        assert _kind_ok(v.kind), t
        assert v.confidence in kk.CONFIDENCES
    for o in kk.NMAP_CLASS_OVERRIDES:
        assert _kind_ok(o.kind), o
        assert o.device_type == "*" or o.device_type in kk.NMAP_DEVICE_TYPES, o
        for rx in (o.vendor, o.osfamily, o.name):
            re.compile(rx)


def test_every_recog_device_value_is_mapped() -> None:
    assert len(kk.RECOG_DEVICE) == 117
    for k, v in kk.RECOG_DEVICE.items():
        assert _kind_ok(v.kind), k
    for o in kk.RECOG_OVERRIDES:
        assert _kind_ok(o.kind), o
        assert o.device == "*" or o.device in kk.RECOG_DEVICE, o
        assert o.field in ("vendor", "product", "description"), o
        assert o.condition in ("", "not_desktop_os"), o


def test_oui_tables_are_consistent() -> None:
    seen: dict[str, tuple[str, ...]] = {}
    for h in kk.OUI_SINGLE_PURPOSE:
        assert h.kind in kk.KINDS, h.shorts
        assert h.confidence in kk.CONFIDENCES, h.shorts
        for t in h.tokens:
            assert t not in seen, (t, seen.get(t), h.shorts)
            seen[t] = h.shorts
            assert t not in kk.OUI_MIXED_TOKENS, t
        # 每個 manuf 短名稱（IPAM 實際拿到的字串）都要對回自己那一條
        for s in h.shorts:
            assert kk.oui_hint(s) is h, s
    # 'private' 是 manuf 對私人登記區塊的通用名稱，不可以當成任何廠牌的別名
    assert all("private" not in h.aliases for h in kk.OUI_SINGLE_PURPOSE)


@pytest.mark.parametrize("vendor", [
    "SonoSite",          # 超音波儀器，曾被子字串 "sonos" 判成影音設備
    "sonoscape",
    "CarloGavazzi",      # 工控，曾被子字串 "arlo" 判成攝影機
    "BoserTechnol",      # 曾被子字串 "bose" 判成影音設備
    "DahuaScaleFa",      # 上海大華「秤」廠，以前子字串 "dahua" 只對得到這家
    "McKayBrother",      # 曾被子字串 "brother" 判成印表機
    "SchneiderDis",
    "HanwhaNxMD",
    "Intelbras",
    "Intel", "Apple", "Ubiquiti", "SuperMicroCo", "TPLink", "Private", "",
])
def test_oui_traps_and_mixed_vendors_give_no_hint(vendor: str) -> None:
    assert kk.oui_hint(vendor) is None


def test_oui_exact_short_names() -> None:
    assert kk.oui_hint("ZhejiangDahu").kind == "camera"       # Dahua 的 manuf 短名稱（截成 12 個字元）
    assert kk.oui_hint("AmericanPowe").kind == "specialized"  # APC
    assert kk.oui_hint("SonyInteract").kind == "media"        # PlayStation
    assert kk.oui_hint("KyoceraWirel").kind == "mobile"       # 京瓷的手機，不是印表機
    assert kk.oui_hint("Hangzhou Hikvision Digital Technology").kind == "camera"   # nmap 的全名也認得


def test_oui_is_never_read_from_random_virtual_or_zero_macs() -> None:
    assert kk.oui_hint("Espressif", "b2:11:22:33:44:55") is None      # 本機管理（隨機）
    assert kk.oui_hint("Espressif", "da:a1:19:00:00:01") is None
    assert kk.oui_hint("Synology", "00:0c:29:12:34:56") is None       # VMware 虛擬網卡
    assert kk.oui_hint("Synology", "bc:24:11:12:34:56") is None       # Proxmox 虛擬網卡
    assert kk.oui_hint("Xerox", "00:00:00:00:00:00") is None          # nmap 把全零寫成 Xerox
    assert kk.oui_hint("Espressif", "24:0a:c4:12:34:56").kind == "specialized"
    assert kk.oui_hint("Espressif").kind == "specialized"             # 沒有 MAC、只有廠牌名稱


def test_service_pattern_examples_and_counter_examples() -> None:
    for p in kk.SERVICE_PRODUCT_PATTERNS:
        assert _kind_ok(p.kind), p.pattern[:40]
        assert p.confidence in kk.CONFIDENCES
        assert p.condition in ("", "not_desktop_os", "not_general_os", "pve")
        for ex in p.examples:
            got = kk.classify_service_text(ex)
            assert got is not None, ex
            assert got.kind == p.kind, (ex, got.pattern[:50])
        for ex in p.counter:
            got = kk.classify_service_text(ex)
            assert got is not p, (ex, p.pattern[:50])


def test_service_conditions() -> None:
    # AirPlay 在 macOS／Windows／iOS 上是電腦自己的接收器
    assert kk.classify_service_text("Apple AirTunes rtspd").kind == "media"
    assert kk.classify_service_text("Apple AirTunes rtspd", os_family="macos") is None
    # 工控協定名稱：SCADA／BMS 伺服器也講這些
    assert kk.classify_service_text("BACnet building automation").kind == "specialized"
    assert kk.classify_service_text("BACnet building automation", os_family="windows") is None
    # Proxmox VE 只在 Debian、不是虛擬機的主機上
    assert kk.classify_service_text("Proxmox VE").kind == "hypervisor"
    assert kk.classify_service_text("Proxmox VE", guest=True) is None
    assert kk.classify_service_text("Proxmox VE", debian=False) is None
    # 標題常帶 HTML 實體
    assert kk.classify_service_text("Synology&nbsp;DiskStation").kind == "storage"


def test_hostname_examples_counter_examples_and_veto() -> None:
    for h in kk.HOSTNAME_HINTS:
        assert _kind_ok(h.kind)
        vendor = h.vendors[0] if h.vendors else None
        for ex in h.examples:
            got = kk.hostname_kind(ex, vendor)
            assert got is not None, (ex, kk.normalize_hostname(ex))
            assert got.kind == h.kind, (ex, got.kind)
        for ex in h.counter:
            got = kk.hostname_kind(ex, vendor)
            assert got is None or got.kind != h.kind, (ex, got.kind)
    for n in ("nvr-server", "camera-archive-01", "ups-api", "pve-backup-01", "kodi-db", "canon-printserver",
              "tv-server", "fw-log-collector", "sonos-api", "dvr-recorder-vm", "printserver"):
        got = kk.hostname_kind(n)
        assert got is None or got.kind in kk.HOSTNAME_VETO_EXEMPT_KINDS, (n, got.kind)


def test_hostname_uses_only_the_first_label() -> None:
    assert kk.normalize_hostname("Johns-iPhone.local") == "johns iphone"
    assert kk.hostname_kind("cam.ac.uk") is None
    assert kk.hostname_kind("www.cam.ac.uk") is None
    assert kk.hostname_kind("ip-10-0-0-1.ap-northeast-1.compute.internal") is None
    assert kk.hostname_kind("cam01.example.net").kind == "camera"
    assert kk.hostname_kind("DESKTOP-4G7P2QK.corp.example").kind == "windows"


def test_port_signatures_are_well_formed() -> None:
    for s in kk.PORT_SIGNATURES:
        assert _kind_ok(s.kind), s.port
        assert s.condition in kk.PORT_CONDITIONS, s.port
        assert s.strength in ("strong", "needs-corroboration"), s.port
        assert s.proto in ("tcp", "udp"), s.port
    assert [s.kind for s in kk.port_signatures(102)] == ["specialized"]
    assert [s.kind for s in kk.port_signatures(47808, "udp")] == ["specialized"]
    assert kk.port_signatures(47808, "tcp") == []
    assert kk.port_signatures("not a port") == []          # type: ignore[arg-type]


@pytest.mark.parametrize(("args", "want"), [
    (("specialized", "VMware", "ESXi", "VMware ESXi 6.5 - 7.0"), "hypervisor"),
    (("media device", "Apple", "iOS", "Apple iOS 12.0 - 13.4"), "mobile"),
    (("media device", "Apple", "Apple TV", "Apple TV 5.2.1 or 5.3"), "media"),
    (("phone", "Apple", "iOS", "Apple iOS 14.0 - 15.6 or tvOS 14.3 - 16.1 (Darwin 20.0.0 - 22.1.0)"), "mobile"),
    (("broadband router", "Ambit", "embedded",
      "Ambit U10C018 or Cisco EPC3925 cable modem, or Tandberg video conferencing system"), "router"),
    (("general purpose", "Microsoft", "Windows", "Microsoft Windows 10 1607"), "windows"),
    (("general purpose", "Linux", "Linux", "Linux 5.0 - 5.14"), "server"),
    (("general purpose", "Wind River", "VxWorks", "Canon imageRUNNER 2525 printer (VxWorks)"), None),
    (("general purpose", "lwIP", "lwIP", "lwIP 1.4.0 - 2.1.x"), None),
    (("specialized", "Linux", "Linux", "Linux 5.4"), None),
    (("specialized", "Linux", "Linux", "HIKVISION DS-7600 Linux Embedded NVR (Linux 2.6.10)"), "camera"),
    (("WAP", "Arcadyan", "embedded", "Arcadyan ARV7519 WAP"), "router"),
    (("WAP", "Ubiquiti", "AirOS", "Ubiquiti AirOS 5.5.9"), "wireless_ap"),
    (("bridge", "Oracle", "Virtualbox", "Oracle Virtualbox Slirp NAT bridge"), None),
    (("webcam", "Polycom", "embedded", "Polycom VSX 8000 videoconferencing system"), "voip"),
    (("remote management", "Cisco", "AireOS", "Cisco AireOS 8.2 (Linux 2.6.21)"), "wireless_ap"),
    (("remote management", "Dell", "embedded", "Dell Integrated Remote Access Controller (iDRAC9)"), "specialized"),
    (("storage-misc", "Linux", "Linux", "Linux 2.6.32 - 3.10"), None),
    (("storage-misc", "Synology", "DiskStation Manager", "Synology DiskStation Manager 5.2"), "storage"),
    (("terminal server", "Lantronix", "embedded", "Lantronix ETS16 terminal server"), "specialized"),
    (("security-misc", "Lenel", "embedded", "Lenel LNL-2220 access control board"), "specialized"),
    (("security-misc", "Fortinet", "FortiOS", "Fortinet FortiOS 7"), "firewall"),
    (("game console", "Sony", "embedded", "Sony PlayStation 4"), "media"),
    (("media device", "Dish", "embedded", "Dish Network VIP 722k DVR (Linux 2.6)"), "media"),
    (("WAP", "AVM", "FritzOS", "AVM FRITZ!WLAN Repeater 450E (FritzOS 6.51)"), "wireless_ap"),
    (("wap", None, None, "x"), "wireless_ap"),            # 類別不分大小寫
    (("no such type", None, None, None), None),
])
def test_nmap_kind(args: tuple, want: str | None) -> None:
    assert kk.nmap_kind(*args)[0] == want


@pytest.mark.parametrize(("args", "kw", "want"), [
    (("Tablet", "NVIDIA", "SHIELD"), {}, "media"),
    (("Tablet", "Apple", "iPad Air"), {}, "mobile"),
    (("DVR", "Tivo"), {}, "media"),
    (("DVR", "Hikvision"), {}, "camera"),
    (("Security Appliance", "Cisco", "Meraki MX"), {}, "firewall"),
    (("Security Appliance", "Tenable", "Tenable Appliance"), {}, None),
    (("Networking", "Ubiquiti", "UDM Pro"), {}, "router"),
    (("Laptop", "Apple"), {}, "server"),
    (("ip camera",), {}, "camera"),                       # 不分大小寫
    (("Media Server", "Apple", None, "Apple AirTunes RTSP"), {}, "media"),
    (("Media Server", "Apple", None, "Apple AirTunes RTSP"), {"os_family": "macos"}, None),
])
def test_recog_kind(args: tuple, kw: dict, want: str | None) -> None:
    assert kk.recog_kind(*args, **kw)[0] == want
