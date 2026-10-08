"""設備類型判讀的知識表（IP 探測與定期偵測共用：services/ip_identify、services/device_identity）。

把主動探測看到的事實（nmap 的 OS 指紋類別與服務類別、Recog 比中的設備、網卡的 OUI 廠牌、服務的產品字樣、
開著的埠、主機名稱）對應到 IPAM 的設備類型。內容是通用的業界知識，不針對任何一個環境調整。

資料來源（2026-10-05 取得）：
  * nmap-os-db、nmap-service-probes、nmap-mac-prefixes：https://svn.nmap.org/nmap/（trunk，6,108 個 OS 指紋）
  * Recog 指紋庫：https://github.com/rapid7/recog（main @ 2d19677，2026-09-29）
  * Wireshark manuf：https://www.wireshark.org/download/automated/data/manuf
來源只提供事實（某個指紋、某段 OUI、某個服務字樣屬於誰）；「這算哪一種設備類型」是 jt-ipam 自己的整理與判斷，
每一條都附上理由（reason／note 欄位，英文，用語與來源一致，方便對照原始資料）。

約定：
  * 表裡的 None ＝「認得，但刻意不當成類型的證據」（太籠統、同一家的產品橫跨多種類型、或是跑在一般主機上的
    軟體）。呼叫端要往下看其他證據，不可以把 None 當成某個類型。
  * 信心："high" ＝可以單獨當成最後的線索；"medium" ＝沒有矛盾的證據時才用，遇到服務／產品的證據要讓位。
  * 埠的強度："strong" ＝條件成立時可以單獨採用；"needs-corroboration" ＝只能佐證其他線索已經指出的類型。
  * 這裡只放資料與小型純函式；證據的先後順序在 ip_identify.summarize 與 device_identity.resolve_kind。
  * 每一條樣式與名稱範例都有測試（tests/test_device_kind_knowledge.py），新增的正規表示式也要通過
    tests/test_ip_identify_regex_safety.py 的回溯檢查。
"""
from __future__ import annotations

import html
import re
from collections.abc import Iterable
from functools import lru_cache
from typing import NamedTuple

KINDS = frozenset({"router", "switch", "firewall", "wireless_ap", "printer", "camera", "voip", "storage",
                   "hypervisor", "media", "specialized", "server", "windows", "mobile"})
CONFIDENCES = frozenset({"high", "medium"})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. nmap 的設備類別（device type）
#    同一套詞彙用在兩個地方：
#      * OS 偵測：<osclass type="...">（nmap-os-db 的「Class 廠牌 | OS 家族 | 世代 | 類別」）
#      * 服務偵測：<service devicetype="...">（nmap-service-probes 的「d/類別/」）
#    下面的數字是 nmap-os-db 的筆數（os）與 nmap-service-probes 的比對行數（svc），2026-10-05。
# ════════════════════════════════════════════════════════════════════════════════════════════════

class NmapType(NamedTuple):
    kind: str | None
    confidence: str          # "high"｜"medium"（kind 不是 None 時才有意義）
    reason: str


NMAP_DEVICE_TYPES: dict[str, NmapType] = {
    # os=3140 svc=0。Linux／Windows／BSD／macOS／AIX／Solaris…，但「也」包含 lwIP（25）、VxWorks（32）、QNX、
    # NetBSD 核心的印表機 —— 見 NMAP_CLASS_OVERRIDES：Windows → windows、iOS／Android → mobile、RTOS → None。
    "general purpose": NmapType("server", "medium",
                                "general-purpose OS; refine with overrides (Windows/mobile/embedded RTOS)"),
    "router": NmapType("router", "high", "os=233 svc=325; Cisco IOS, Juniper, MikroTik, Vyatta..."),
    "broadband router": NmapType("router", "high",
                                 "os=258 svc=314; SOHO/ISP gateways (DrayTek, AVM, Netgear, ZyXEL, ISP CPE)"),
    "switch": NmapType("switch", "high", "os=462 svc=258; managed switches (Cisco, HP ProCurve, Netgear, D-Link)"),
    "hub": NmapType("switch", "medium",
                    "documented type; os=0 svc=1 (HP AdvanceStack hub); a repeater hub is closest to switch"),
    "firewall": NmapType("firewall", "high",
                         "os=160 svc=172; SonicWALL, Check Point, Fortinet, WatchGuard, IPCop, Cisco ASA/PIX"),
    "WAP": NmapType("wireless_ap", "medium",
                    "os=450 svc=410; real APs but ALSO consumer Wi-Fi routers and ISP gateways (2Wire, Arcadyan, "
                    "AVM, Linksys) and 101 generic 'Linux' entries - see overrides; require vendor agreement"),
    "printer": NmapType("printer", "high", "os=445 svc=393"),
    "print server": NmapType("printer", "high",
                             "os=41 svc=106; external print servers (JetDirect boxes, TP-Link, Lantronix, AXIS)"),
    "webcam": NmapType("camera", "high",
                       "os=85 svc=241; IP cameras/DVRs, BUT Polycom/Tandberg video-conferencing units are also "
                       "'webcam' (-> voip override)"),
    "phone": NmapType("mobile", "high",
                      "os=306: Android/iOS/Symbian/BlackBerry handsets. In service probes (svc=41) 'phone' also "
                      "covers Snom/Gigaset DECT phones and netTALK adapters (-> voip override)"),
    "VoIP phone": NmapType("voip", "high", "os=101 svc=134; desk/DECT IP phones"),
    "VoIP adapter": NmapType("voip", "high", "os=58 svc=110; ATAs (Linksys/Cisco SPA, Grandstream HT, FRITZ!Box FXS)"),
    "PBX": NmapType("voip", "high", "os=24 svc=72; PBX appliances and Asterisk/3CX/FreePBX (IPAM convention: PBX=voip)"),
    "telecom-misc": NmapType("voip", "medium", "os=4 svc=18; Avaya CM, Aastra, voicemail, media gateways, T1 units"),
    "storage-misc": NmapType("storage", "medium",
                             "os=315 svc=130; NAS/SAN/tape. 54 Linux + 29 FreeBSD entries are generic kernels "
                             "(new Linux kernels match 'HP P2000 G3 NAS' within 0-1%) -> override to None"),
    "storage": NmapType("storage", "high", "os=1 (NetApp ONTAP); undocumented spelling of storage-misc"),
    "media device": NmapType("media", "medium",
                             "os=273 svc=342; set-top boxes, TVs, AV receivers, Chromecast, Roku, BUT 37 entries "
                             "are Apple iOS/iPhone OS (iPod touch / iPhone era) -> mobile override; Hikvision DVR "
                             "service matches are also tagged 'media device' -> camera override"),
    "game console": NmapType("media", "high", "os=23 svc=14; PlayStation, Nintendo, Xbox, Ouya"),
    "specialized": NmapType("specialized", "medium",
                            "os=361 svc=160; PLCs, Hue bridges, lwIP gadgets, POS, medical, BUT also VMware ESXi "
                            "(44), XenServer, Oracle VM, Proxmox VE (-> hypervisor), watchOS (-> mobile), Nest Hub "
                            "(-> media) and 24 plain 'Linux N.N' kernels (-> None)"),
    "power-device": NmapType("specialized", "high", "os=48 svc=59; APC/Eaton/Liebert UPS, PDUs, solar inverters"),
    "power-misc": NmapType("specialized", "high",
                           "svc=21 only (not in nmap-os-db); smart plugs, energy meters, web power switches"),
    "remote management": NmapType("specialized", "medium",
                                  "os=115 svc=87; iLO/iDRAC/IPMI/KVM-over-IP/console servers, BUT Cisco AireOS and "
                                  "ArubaOS wireless controllers (-> wireless_ap) and Teradici/Wyse PCoIP zero "
                                  "clients (-> server) also live here"),
    "terminal server": NmapType("specialized", "high",
                                "os=12 svc=29; SERIAL terminal/console servers (Lantronix, Digi, Perle, Avocent). "
                                "NOT Windows Terminal Services/RDS"),
    "bridge": NmapType("specialized", "medium",
                       "os=41 svc=32; mostly serial-to-Ethernet bridges (Digi/Lantronix/Moxa); also wireless "
                       "bridges (-> wireless_ap), powerline adapters, and VirtualBox/Slirp NAT engines (-> None)"),
    "security-misc": NmapType(None, "medium",
                              "os=32 svc=102; mixes physical security (access control, alarm panels -> "
                              "specialized) with network security appliances (FortiOS, Cisco AsyncOS, WAF, SSL-VPN "
                              "-> firewall); decide by vendor override"),
    "proxy server": NmapType(None, "medium",
                             "os=42 svc=32; Blue Coat/Websense/McAfee gateways and VPN concentrators (-> firewall "
                             "override), WAN optimizers (Riverbed/Silver Peak -> router), but also squid on Linux"),
    "load balancer": NmapType(None, "medium",
                              "os=41 svc=59; F5/NetScaler/Kemp/Radware/HAProxy - no matching kind (closest would be "
                              "router); left unclassified on purpose"),
    "terminal": NmapType("server", "medium",
                         "os=22 svc=8; thin clients (Wyse ThinOS, IGEL, Teradici, Chip PC) = desktop endpoints"),
    "PDA": NmapType("mobile", "medium",
                    "os=7 svc=7; Windows Mobile handhelds; rugged scanners (Intermec/Symbol) -> specialized override"),
}


class NmapOverride(NamedTuple):
    device_type: str     # 套用在哪個 nmap 類別；"*" ＝任何類別（general purpose 除外）
    vendor: str          # 比對 <osclass vendor> 的正規表示式，"" ＝不限
    osfamily: str        # 比對 <osclass osfamily> 的正規表示式，"" ＝不限
    name: str            # 比對 <osmatch name>「第一個候選」的正規表示式（見 first_alternative()），"" ＝不限
    kind: str | None
    reason: str


# 第一個符合的為準；先於 NMAP_DEVICE_TYPES 套用。所有正規表示式都是不分大小寫的 search。
NMAP_CLASS_OVERRIDES: tuple[NmapOverride, ...] = (
    # --- 名稱直接講出是什麼設備（general purpose 以外的類別都會被蓋過）---
    NmapOverride("media device", "", "", r"\bDVR\b(?!.*(?:security|surveillance|CCTV))", "media",
                 "consumer TV DVRs (DirecTV, DISH, FiOS, TiVo) are typed media device - keep them media"),
    NmapOverride("*", "", "", r"\b(?:NVR|DVR|surveillance|IP camera|network camera|video recorder)\b", "camera",
                 "e.g. 'HIKVISION DS-7600 Linux Embedded NVR' and 'Rebranded surveillance DVR' are typed specialized"),
    NmapOverride("*", "", "", r"apple tv|tvos", "media", "Apple TV / tvOS"),
    NmapOverride("*", "", "", r"wireless lan controller|\bWLC\b|wireless controller|WLAN controller|"
                              r"wireless LAN switch", "wireless_ap",
                 "Cisco/Aruba/HP/Motorola WLAN controllers are typed 'remote management'"),
    NmapOverride("*", "", "", r"video ?conferenc|ViewStation|TelePresence|\bHDX\b|\bVSX ?\d{4}|RealPresence", "voip",
                 "Polycom/Tandberg/Cisco conferencing units typed 'webcam'"),
    NmapOverride("*", "", "", r"\bDECT\b", "voip", "DECT phones typed 'phone'"),
    NmapOverride("*", "", "", r"thin client|zero client|PCoIP", "server",
                 "thin/zero clients are desktop endpoints (typed terminal or remote management)"),
    NmapOverride("*", "", "", r"Proxmox Virtual Environment|VMware ESXi?\b|XenServer|Oracle VM Server", "hypervisor",
                 "hypervisors are typed 'specialized' (ESXi x44, XenServer, Oracle VM, Proxmox VE)"),
    # --- 虛擬化主機／虛擬化的產物 ---
    NmapOverride("specialized", r"^VMware$", r"ESXi?|ESX Server", "", "hypervisor", "ESX/ESXi"),
    NmapOverride("specialized", r"^Citrix$", r"XenServer", "", "hypervisor", "Citrix XenServer"),
    NmapOverride("specialized", r"^VMware$", r"Player", "", None, "VMware Player NAT engine, not a device"),
    NmapOverride("bridge", r"^(?:Oracle|Slirp)$", r"Virtualbox|Slirp", "", None,
                 "VirtualBox/Slirp user-mode NAT answered the probe, not the target device"),
    # --- 手機／影音的細分 ---
    NmapOverride("specialized", r"^Apple$", r"watchOS", "", "mobile", "Apple Watch"),
    NmapOverride("specialized", r"^Google$", r"Fuchsia", "", "media", "Google Nest Hub (smart display)"),
    NmapOverride("media device", r"^Apple$", r"^(?:iOS|iPhone OS)$", "", "mobile",
                 "nmap types many iOS fingerprints (iPod touch era) as media device; on today's LANs they are "
                 "iPhones/iPads (Apple TV is caught earlier by name / tvOS)"),
    NmapOverride("media device", r"^RIM$", r"Tablet OS", "", "mobile", "BlackBerry PlayBook"),
    NmapOverride("media device", r"^Google$", r"^Android$", r"^(?!.*(?:\bTV\b|Chromecast|Shield|Nexus Player)).*$",
                 None, "plain Android 'media device' could be a TV box or a tablet"),
    NmapOverride("general purpose", r"^Microsoft$", r"Windows Mobile|Windows Phone", "", "mobile", "Windows Mobile/Phone"),
    NmapOverride("general purpose", r"^Microsoft$", r"^Windows$", "", "windows", "Windows desktop/server"),
    NmapOverride("general purpose", r"^Apple$", r"^(?:iOS|iPhone OS|iPadOS)$", "", "mobile", "iOS"),
    NmapOverride("general purpose", r"^Google$", r"^Android$", "", "mobile", "Android"),
    NmapOverride("general purpose", r"^(?:lwIP|Wind River|QNX|RISE SICS|KA9Q|Interpeak|Green Hills|Microware|"
                                    r"TenAsys|Phar Lap|Precise Software Technologies|On Time|George Robotics)$",
                 "", "", None,
                 "embedded RTOS/TCP stacks typed 'general purpose' (lwIP, VxWorks, QNX...): the device is embedded "
                 "(Canon/Ricoh printers, Hirschmann/Netgear switches run VxWorks) - never call it a server"),
    NmapOverride("general purpose", r"^NetBSD$", r"^NetBSD$", "", None,
                 "NetBSD fingerprints double as Ricoh printers, Apple AirPort/Time Capsule, EqualLogic arrays"),
    NmapOverride("phone", r"^(?:Gigaset|Snom|Siemens)$", "", "", "voip", "DECT/IP desk phones typed 'phone'"),
    # --- 標成 WAP、其實是家用／ISP 閘道器（路由器）---
    NmapOverride("WAP", r"^(?:2Wire|Arcadyan|AVM|Ubee|Pirelli|Vodafone|Orange|Technicolor|Thomson|Sagemcom|"
                        r"Netopia|Westell|Actiontec|Telsey|Comtrend|Zhone|T-Home|Telekom|Deutsche Telekom|Netia|"
                        r"Novatel|Sky|BT)$",
                 "", r"^(?!.*(?:repeater|\bAP ?\d)).*$", "router",
                 "ISP/home gateways (routers with Wi-Fi) typed WAP (not their repeaters/APs; Huawei/ZTE excluded: "
                 "they also make enterprise APs)"),
    # --- remote management／終端機 ---
    NmapOverride("remote management", r"^Cisco$", r"AireOS", "", "wireless_ap", "Cisco WLC"),
    NmapOverride("remote management", r"^Aruba$", r"ArubaOS", "", "wireless_ap", "Aruba mobility controllers"),
    NmapOverride("remote management", r"^(?:Teradici|Wyse)$", "", "", "server", "PCoIP zero/thin clients"),
    NmapOverride("terminal", r"^Belkin$", "", r"KVM", "specialized", "Belkin KVM console"),
    NmapOverride("PDA", r"^(?:Intermec|Symbol|Motorola|Datalogic|Honeywell|Zebra)$", "", "", "specialized",
                 "rugged handheld scanners"),
    # --- bridge ---
    NmapOverride("bridge", "", "", r"wireless (?:Ethernet )?bridge|Canopy|\bPTP\b", "wireless_ap",
                 "point-to-point wireless bridges"),
    NmapOverride("bridge", "", "", r"powerline|coax", None, "powerline/coax Ethernet adapters"),
    NmapOverride("bridge", "", "", r"\brouter\b", "router", "e.g. Sagemcom WiMAX router typed bridge"),
    # --- security-misc／proxy server 依廠牌拆開 ---
    NmapOverride("security-misc", r"^(?:Lenel|HID|Paxton Access|Virdi|ZKTeco|ZKSoftware|Henry Electronic|Satel|"
                                  r"DMP|Bosch|Napco|Kaba|Thales)$", "", "", "specialized",
                 "access control, alarm panels, HSM"),
    NmapOverride("security-misc", r"^(?:Fortinet|ZyXEL|Draytek|Netgear|NSFOCUS|Imperva|Barracuda Networks|Cisco|"
                                  r"Symantec|Citrix|SonicWALL|Juniper)$", "", "", "firewall",
                 "UTM/VPN/WAF/email-security appliances"),
    NmapOverride("proxy server", r"^(?:Blue Coat|WebSense|McAfee|SonicWALL|Eicon|Cisco|Citrix)$", "", "",
                 "firewall", "secure web gateways and VPN concentrators"),
    NmapOverride("proxy server", r"^(?:Riverbed|Silver Peak)$", "", "", "router", "WAN optimizers / SD-WAN"),
    # --- nmap 標成設備的通用核心 ---
    NmapOverride("specialized", r"^Linux$", r"^Linux$", r"^Linux [\d.]+(?: - [\d.]+)?$", None,
                 "a bare 'Linux N.N' kernel typed specialized says nothing about the device"),
    NmapOverride("storage-misc", r"^(?:Linux|FreeBSD)$", "", r"^(?:Linux|FreeBSD) [\d.]", None,
                 "generic Linux/FreeBSD kernels typed storage-misc (P2000 G3 look-alike); need a NAS product/OUI"),
)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Recog 的 hw.device／os.device 值（rapid7/recog main @ 2d19677 的全部 117 個值）
#    鍵是 Recog 的原始拼法；不分大小寫的查詢用 RECOG_DEVICE_LC。
#    數字：hw ＝當成 hw.device 的指紋數，os ＝當成 os.device 的指紋數。
# ════════════════════════════════════════════════════════════════════════════════════════════════

class RecogKind(NamedTuple):
    kind: str | None
    confidence: str
    reason: str


_P, _R, _S, _F, _A = "printer", "router", "switch", "firewall", "wireless_ap"
_C, _V, _ST, _H, _M = "camera", "voip", "storage", "hypervisor", "media"
_SP, _SV, _W, _MO = "specialized", "server", "windows", "mobile"

RECOG_DEVICE: dict[str, RecogKind] = {
    "Access Control": RecogKind(_SP, "high", "hw=13; S2, iSTAR, AMAG, Axis door controllers, Mercury"),
    "ADSL Modem": RecogKind(_R, "high", "hw=1 os=2"),
    "ADSL Router": RecogKind(_R, "high", "os=1"),
    "Alarm Panel": RecogKind(_SP, "high", "hw=2 os=1; Bosch alarm panels"),
    "Appliance": RecogKind(None, "medium", "hw=13 os=7; OSSIM, FortiMail, FortiManager, Tenable Core, VMware SRM, "
                                           "Sophos (unclear which product) - mostly server/VM appliances, mixed"),
    "ATM DSL Unit": RecogKind(_R, "medium", "os=1; Paradyne WAN access unit"),
    "Audio Encoder": RecogKind(_M, "medium", "hw=3; Axis audio modules, Barix Instreamer"),
    "AV Receiver": RecogKind(_M, "high", "hw=1; Yamaha"),
    "Broadband Router": RecogKind(_R, "high", "hw=26 os=17"),
    "Building Automation": RecogKind(_SP, "high", "hw=4; ELAN, Loxone"),
    "Cable Modem": RecogKind(_R, "high", "hw=2 os=4; ARRIS, 3Com"),
    "Check Scanner": RecogKind(_SP, "high", "hw=1 os=1; MagTek"),
    "Cloud Network Video Recorder": RecogKind(_C, "high", "hw=1; D-Link DNR"),
    "Copier": RecogKind(_P, "high", "os=1; Oce"),
    "Data Terminal": RecogKind(_SP, "medium", "hw=1; LINX industrial data terminal"),
    "Desktop": RecogKind(_SV, "high", "hw=45; iMac/Mac mini/Mac Pro (from mDNS/DHCP model strings) - "
                                      "general-purpose computer"),
    "Device": RecogKind(None, "medium", "hw=22; Shelly, Nanoleaf, Roomba, Grandstream, Freebox, TP-Link httpd... "
                                        "too generic (see RECOG_OVERRIDES for vendor-based refinements)"),
    "Device Hub": RecogKind(_SP, "high", "hw=2; Hubitat"),
    "Device Server": RecogKind(_SP, "high", "hw=16 os=23; Digi/Moxa/Lantronix serial device & terminal servers"),
    "Display Controller": RecogKind(_SP, "medium", "hw=5; Extron control processors/touch panels (AV control)"),
    "DOCSIS Cable Modem": RecogKind(_R, "high", "hw=1"),
    "DSL Modem": RecogKind(_R, "high", "hw=2 os=1"),
    "DSLAM": RecogKind(_R, "medium", "os=3; carrier access multiplexers - no exact kind, WAN edge"),
    "DSU/CSU": RecogKind(_R, "medium", "os=2; WAN access units"),
    "DVR": RecogKind(_C, "high", "hw=23 os=10; security DVR/NVRs (Hikvision, UniFi NVR, Lorex, Nuuo), BUT also "
                                 "TiVo and NAGRA OpenTV consumer DVRs (-> media override)"),
    "Environment Control": RecogKind(_SP, "high", "hw=2; Liebert iCOM, compressor controls"),
    "Ethernet Adapter": RecogKind(_SP, "medium", "hw=9; all are industrial comms modules (Allen-Bradley, Siemens, "
                                                 "Anybus) despite the generic name"),
    "Fax Server": RecogKind(_P, "medium", "os=1; Castelle FaxPress (print/fax peripheral)"),
    "Firewall": RecogKind(_F, "high", "hw=31 os=42; OPNsense, pfSense, PAN-OS, FortiOS, ASA/FTD, Check Point, "
                                      "SonicOS, WatchGuard, Zyxel USG"),
    "Frame Relay": RecogKind(_R, "medium", "os=1; Paradyne WAN unit"),
    "Handheld Scanner": RecogKind(_SP, "high", "hw=1; Datalogic rugged handheld"),
    "HMI Controller": RecogKind(_SP, "high", "hw=3 os=2; Allen-Bradley, Siemens HMI"),
    "Hub": RecogKind(_S, "high", "os=2; HP ProCurve hubs"),
    "Hypervisor": RecogKind(_H, "high", "hw=10 os=10; ESX/ESXi, XenServer"),
    "IDS": RecogKind(_F, "medium", "os=1; Juniper IDP (inline security appliance)"),
    "Industrial Control": RecogKind(_SP, "high", "hw=2; Fidelix, Moxa MGate"),
    "IP Camera": RecogKind(_C, "high", "hw=45 os=13"),
    "IPS": RecogKind(_F, "medium", "hw=3 os=3; TippingPoint"),
    "IPTV": RecogKind(_M, "high", "hw=1 os=1; Eltex set-top box"),
    "JTAG Adapter": RecogKind(_SP, "high", "hw=2; Segger J-Link"),
    "KVM": RecogKind(_SP, "high", "hw=4 os=6; ATEN/Avocent/Raritan KVM-over-IP"),
    "Laptop": RecogKind(_SV, "high", "hw=70; MacBook family (mDNS/DHCP model strings)"),
    "Light Bulb": RecogKind(_SP, "high", "hw=3; Philips Hue, Shelly bulb"),
    "Lights Out Management": RecogKind(_SP, "high", "hw=39 os=25; iLO, iDRAC, ILOM, XCC, MegaRAC, Supermicro, CIMC"),
    "Load Balancer": RecogKind(None, "medium", "os=1; no matching kind (same decision as nmap 'load balancer')"),
    "Mainframe": RecogKind(_SV, "high", "os=1; IBM z/OS"),
    "Management Processor": RecogKind(_SP, "high", "os=1; HP Integrity MP"),
    "Media Gateway": RecogKind(_V, "medium", "os=6; Avaya telephony media gateways (ADTRAN TotalAccess -> router "
                                             "override)"),
    "Media Player": RecogKind(_MO, "medium", "hw=7; every Recog entry is an iPod touch (iOS handheld behaves like a "
                                             "phone on the LAN: 62078, randomized MAC). Revisit if Recog adds "
                                             "set-top players under this label"),
    "Media Receiver": RecogKind(_M, "high", "hw=2; Crestron receivers, Lencore"),
    "Media Server": RecogKind(_M, "medium", "hw=24 os=1; Apple TV, HomePod, Chromecast, Roku, HDHomeRun, BrightSign, "
                                            "BUT the generic 'Apple AirTunes/AirPlay RTSP' fingerprint also matches "
                                            "macOS 12+ (AirPlay receiver) -> skip when the OS is macOS/iOS"),
    "Medical": RecogKind(_SP, "high", "hw=1 os=1; Baxter infusion pump"),
    "Mobile": RecogKind(_MO, "high", "os=3; iOS, Windows Phone"),
    "Mobile Phone": RecogKind(_MO, "high", "hw=33; iPhone models"),
    "Monitoring": RecogKind(_SP, "medium", "hw=8 os=5; AVTECH Room Alert, NetBotz, Siemens industrial PCs; also "
                                           "Gigamon packet brokers (closer to switch)"),
    "Multifunction Device": RecogKind(_P, "high", "hw=10 os=48"),
    "Multiplexer": RecogKind(_R, "medium", "hw=3 os=5; FatPipe multi-WAN/SD-WAN, ADTRAN multiplexers"),
    "NAC": RecogKind(None, "medium", "os=1; Nortel SNAS - network access control appliance, no matching kind"),
    "NAS": RecogKind(_ST, "high", "hw=29 os=18; Synology, QNAP, ReadyNAS, NetApp, Isilon, TrueNAS, OMV "
                                  "(HPE SimpliVity -> hypervisor override)"),
    "Network": RecogKind(None, "medium", "os=1; H3C Comware via SSH - Comware runs on switches AND routers"),
    "Network Appliance": RecogKind(None, "medium", "hw=19; BlueCat, Cisco APIC/HyperFlex/AppDynamics, Meraki, "
                                                   "ClearPass, Device42, INDECT parking - mixed"),
    "Network Audio": RecogKind(_M, "high", "hw=5 os=1; Bose SoundTouch, Sonos"),
    "Network Management Device": RecogKind(None, "medium", "hw=17 os=21; NetScaler, Cisco NAM/DNA Center/NFVIS, "
                                                           "UCS - mixed (load balancers, controller VMs)"),
    "Network Scanner": RecogKind(_P, "medium", "os=1; Epson network document scanner (imaging fleet)"),
    "Networking": RecogKind(None, "medium", "hw=10 os=10; Ubiquiti UniFi (APs, switches, gateways). UDM/UCG/UDR "
                                            "gateways -> router via override"),
    "Onboard Administrator": RecogKind(_SP, "high", "os=1; HP BladeSystem OA"),
    "PDU": RecogKind(_SP, "high", "os=1; Raritan PX"),
    "PLC": RecogKind(_SP, "high", "hw=3 os=7"),
    "Point of Sale": RecogKind(_SP, "high", "os=2; IBM 4690, Intermec data collection"),
    "Power Device": RecogKind(_SP, "high", "hw=29 os=9; APC, ServerTech, Panduit, Eaton, CyberPower, SMA"),
    "Power Meter": RecogKind(_SP, "high", "hw=1; Schneider PowerLogic"),
    "Power Relay": RecogKind(_SP, "high", "hw=2; Ethernet relay boards"),
    "Powerline": RecogKind(None, "medium", "hw=1; AVM FRITZ!Powerline - L2 bridge (some models add Wi-Fi)"),
    "Print Server": RecogKind(_P, "high", "hw=7 os=19"),
    "Printer": RecogKind(_P, "high", "hw=69 os=146"),
    "Relay Controller": RecogKind(_SP, "high", "hw=2"),
    "Remote Access Server": RecogKind(None, "medium", "os=2; MRV LX console server (specialized) vs MultiTech "
                                                      "dial-up RAS (router)"),
    "Remote Terminal": RecogKind(_R, "medium", "os=1; ADTRAN TotalAccess SCU (carrier access shelf)"),
    "Router": RecogKind(_R, "high", "hw=84 os=87"),
    "Sandbox": RecogKind(None, "medium", "hw=1; FortiSandbox - analysis appliance, not an inline firewall"),
    "Scanner": RecogKind(_P, "medium", "hw=3 os=4; HP Digital Sender, Canon ScanFront document scanners"),
    "SD-WAN Appliance": RecogKind(_R, "medium", "hw=4 os=3; FatPipe/XRoads edges; Cisco vManage is a controller VM "
                                                "(-> None override)"),
    "Security Appliance": RecogKind(None, "medium", "hw=16 os=5; Axonius, Tetration, Duo gateways, FireEye, "
                                                    "Stealthwatch, PGP KMS, Tenable, Riverbed - mostly NOT firewalls "
                                                    "(Meraki MX -> firewall override)"),
    "Sensor": RecogKind(_SP, "high", "hw=3; SpotterRF"),
    "SIP Device": RecogKind(_V, "high", "hw=8 os=7"),
    "SIP Gateway": RecogKind(_V, "high", "hw=26 os=12; Grandstream HT/UCM, NEC SV, Wildix, AudioCodes, PIAF"),
    "Smart TV": RecogKind(_M, "high", "hw=5; LG webOS, Sony/Vizio Android TV"),
    "Storage": RecogKind(_ST, "high", "hw=11 os=23; Data Domain, EqualLogic, 3PAR, MSA, tape libraries"),
    "Storage Appliance": RecogKind(_ST, "medium", "hw=5; Pure Storage; 'Internet Archive Warrior' is a VM "
                                                  "(-> None override)"),
    "Support Appliance": RecogKind(_SV, "medium", "hw=5; Bomgar, KACE systems-management appliances (server role)"),
    "Switch": RecogKind(_S, "high", "hw=38 os=105 (HP Virtual Library -> storage, Nexus 1000V -> None overrides)"),
    "Tablet": RecogKind(_MO, "high", "hw=27; iPads, BUT NVIDIA SHIELD TV is also labelled Tablet (-> media override)"),
    "Tape Library": RecogKind(_ST, "high", "hw=3 os=2"),
    "Telecom": RecogKind(_V, "medium", "hw=4; Huawei softswitch/UMG (Systech payment gateway -> None override)"),
    "Test Instrument": RecogKind(_SP, "high", "hw=12 os=3; Keysight, Agilent, R&S"),
    "Thin Client": RecogKind(_SV, "medium", "hw=2; PCoIP zero clients, Wyse - desktop endpoints"),
    "UnixWare": RecogKind(_SV, "medium", "os=1; SCO UnixWare (value used as os.device by mistake)"),
    "UPS": RecogKind(_SP, "high", "hw=1 os=5"),
    "USB Server": RecogKind(_SP, "high", "os=1; Digi AnywhereUSB"),
    "Video Conferencing": RecogKind(_V, "high", "hw=36 os=21; Cisco TelePresence, Polycom, Lifesize, Crestron"),
    "Video Decoder": RecogKind(_M, "medium", "hw=2; Haivision Makito"),
    "Video Encoder": RecogKind(_C, "medium", "hw=6; Axis/Siqura CCTV encoders (VBrick is broadcast media)"),
    "ViewStation": RecogKind(_V, "high", "os=1; Polycom ViewStation"),
    "Voice Appliance": RecogKind(_V, "high", "hw=1; Telliris IVR"),
    "VoIP": RecogKind(_V, "high", "hw=56 os=29"),
    "VoIP Gateway": RecogKind(_V, "high", "hw=8 os=8"),
    "VoIP Server": RecogKind(_V, "high", "hw=2; Panasonic KX-NS1000, Samsung CM"),
    "VoIP Switch": RecogKind(_V, "high", "hw=1 os=1; ShoreTel"),
    "VPN": RecogKind(_F, "medium", "hw=11 os=8; SonicWALL, Pulse Secure, Juniper SSL VPN, Cisco VPN 3000, Cyberoam "
                                   "(OpenVPN Access Server is software on a server -> None override)"),
    "WAN Accelerator": RecogKind(_R, "medium", "os=1; Silver Peak"),
    "WAP": RecogKind(_A, "high", "hw=47 os=42"),
    "Web Cam": RecogKind(_C, "high", "hw=5; Bosch AutoDome"),
    "Web Proxy": RecogKind(None, "medium", "os=7; Blue Coat appliances but also 'Akamai Global Host' (CDN edge)"),
    "Whiteboard": RecogKind(_M, "medium", "hw=1; Kaptivo meeting-room capture"),
    "Wireless Controller": RecogKind(_A, "high", "hw=14 os=8; Cisco WLC, Aruba, Ruckus ZoneDirector, UniFi CloudKey"),
    "Wireless Presenter": RecogKind(_M, "high", "hw=6 os=3; Barco ClickShare, Mersive Solstice"),
    "WLAN Repeater": RecogKind(_A, "high", "hw=1; FRITZ!WLAN Repeater"),
}
RECOG_DEVICE_LC: dict[str, RecogKind] = {k.lower(): v for k, v in RECOG_DEVICE.items()}


class RecogOverride(NamedTuple):
    device: str          # Recog 的 hw.device／os.device 值（不分大小寫），"*" ＝任何值
    field: str           # 正規表示式比對哪個欄位："vendor"（hw.vendor／os.vendor）、"product"、
                         # 或 "description"（指紋的 <description>）
    pattern: str         # 不分大小寫的正規表示式
    kind: str | None
    reason: str
    condition: str = ""  # "" ｜ "not_desktop_os"（作業系統是 macOS／Windows／iOS 時不套用）


RECOG_OVERRIDES: tuple[RecogOverride, ...] = (
    RecogOverride("Tablet", "vendor", r"^NVIDIA$", _M, "NVIDIA SHIELD TV is labelled Tablet"),
    RecogOverride("DVR", "vendor", r"^(?:Tivo|NAGRA)$", _M, "consumer TV DVRs"),
    RecogOverride("DVR", "product", r"OpenTV", _M, "NAGRA OpenTV set-top"),
    RecogOverride("Security Appliance", "product", r"Meraki MX", _F, "Meraki MX security appliance"),
    RecogOverride("Networking", "product", r"\b(?:UDM|UCG|UDR|UXG|USG)\b", _R, "UniFi gateways"),
    RecogOverride("VPN", "description", r"OpenVPN Access Server", None, "software on a general-purpose server"),
    RecogOverride("Web Proxy", "vendor", r"^Blue Coat$", _F, "Blue Coat secure web gateway appliances"),
    RecogOverride("Media Server", "description", r"AirTunes|AirPlay", _M,
                  "generic AirPlay RTSP: media ONLY if the OS is not macOS/iOS (Macs run an AirPlay receiver)",
                  "not_desktop_os"),
    RecogOverride("SD-WAN Appliance", "product", r"vManage", None, "SD-WAN controller (VM)"),
    RecogOverride("NAS", "product", r"SimpliVity|OmniStack", _H, "HPE SimpliVity hyperconverged node"),
    RecogOverride("Storage Appliance", "product", r"Warrior", None, "Internet Archive Warrior VM"),
    RecogOverride("Switch", "product", r"Virtual Library", _ST, "HP Virtual Library System (tape emulation)"),
    RecogOverride("Switch", "product", r"Nexus 1000V", None, "virtual switch VM"),
    RecogOverride("Media Gateway", "vendor", r"^ADTRAN$", _R, "ADTRAN TotalAccess access platform"),
    RecogOverride("Telecom", "description", r"Payment Gateway", None, "Systech payment gateway"),
    RecogOverride("Remote Access Server", "vendor", r"^MRV", _SP, "MRV LX console server"),
    RecogOverride("Remote Access Server", "vendor", r"^MultiTech$", _R, "dial-up RAS"),
    RecogOverride("Monitoring", "vendor", r"^Gigamon$", None, "network packet broker"),
    RecogOverride("Device", "vendor", r"^(?:Shelly|Nanoleaf|iRobot|Wyze|GoGogate|Bird Home Automation|Hubitat|"
                                      r"Schneider Electric|Wifx|Bobcat|iTach)$", _SP, "IoT gadgets"),
    RecogOverride("Device", "description", r"Fermentrack", _SP, "brewing monitor"),
    RecogOverride("Device", "vendor", r"^Grandstream$", _V, "Grandstream favicon (phones/ATAs dominate)"),
    RecogOverride("Device", "vendor", r"^(?:Asus|Freebox)$", _R, "ASUS router UI / Freebox"),
    RecogOverride("Device", "vendor", r"^GigaBlue$", _M, "satellite receiver"),
)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. 網卡廠牌（OUI）的線索 —— 最後才用、最弱的證據
#    IPAM 顯示的是 Wireshark manuf 的「短名稱」（第 2 欄，最多 12 個字元，例如 'ZhejiangDahu'、'AmericanPowe'、
#    'SonyInteract'）；nmap 自己的 mac_vendor 用 nmap-mac-prefixes 的全名。正規化＝轉小寫、只留 a-z。
#    要跟 `tokens`＋`aliases`「完全相等」才算（oui_hint()）；子字串比對是陷阱：'sonos' 在 'sonosite'（超音波）
#    裡、'arlo' 在 'carlogavazzi' 裡、'eve' 在 136 個名稱裡、'ring' 在 43 個名稱裡、'intel' 在 'intelbras' 裡。
#    本機管理（隨機）的 MAC 一律不查。oui_count ＝這些短名稱底下的 manuf 區塊數（2026-10-05）。
# ════════════════════════════════════════════════════════════════════════════════════════════════

class OuiHint(NamedTuple):
    shorts: tuple[str, ...]      # Wireshark manuf 的短名稱（原樣）
    tokens: tuple[str, ...]      # 短名稱正規化之後（IPAM 的正規化結果）
    aliases: tuple[str, ...]     # 同一批區塊在 IEEE 登記與 nmap-mac-prefixes 的全名（正規化之後）
    kind: str
    confidence: str
    oui_count: int
    note: str


OUI_SINGLE_PURPOSE: tuple[OuiHint, ...] = (
    OuiHint(('HikvisionDig', 'PramaHikvisi'), ('hikvisiondig', 'pramahikvisi'),
            ('hangzhouhikvisiondigitaltechnology', 'hangzhouhikvisiondigitaltechnologycoltd',
              'pramahikvisionindiaprivatelimited'),
            _C, 'high', 86,
            'Hikvision/HiLook/Ezviz parent; cameras, NVR/DVR, intercoms (DS-3E switches exist but are rare)'),
    OuiHint(('ZhejiangDahu',), ('zhejiangdahu',),
            ('zhejiangdahuatechnology', 'zhejiangdahuatechnologyco', 'zhejiangdahuatechnologycoltd',
              'zhejiangdahuazhilian', 'zhejiangdahuazhiliancoltd'),
            _C, 'high', 33,
            'Dahua/Imou: cameras, NVR/XVR, intercoms'),
    OuiHint(('AxisCommunic',), ('axiscommunic',),
            ('axiscommunicationsab',),
            _C, 'high', 4,
            'Axis: cameras/encoders; also door controllers, intercoms, network speakers (minor)'),
    OuiHint(('HanwhaVision', 'SamsungTechw'), ('hanwhavision', 'samsungtechw'),
            ('hanwhavisionvietnam', 'hanwhavisionvietnamcompanylimited', 'samsungtechwin', 'samsungtechwincoltd'),
            _C, 'high', 3,
            'Hanwha Vision / Samsung Techwin (Wisenet)'),
    OuiHint(('ZhejiangUniv',), ('zhejianguniv',),
            ('zhejianguniviewtechnologies', 'zhejianguniviewtechnologiescoltd'),
            _C, 'high', 5,
            'Uniview (UNV)'),
    OuiHint(('Vivotek',), ('vivotek',),
            ('vivotekinc',),
            _C, 'high', 1,
            'VIVOTEK cameras/NVR'),
    OuiHint(('Mobotix',), ('mobotix',),
            ('mobotixag',),
            _C, 'high', 1,
            'MOBOTIX cameras/door stations'),
    OuiHint(('ReolinkInnov',), ('reolinkinnov',),
            ('reolinkinnovationlimited',),
            _C, 'high', 1,
            'Reolink cameras/NVR/doorbells'),
    OuiHint(('AmcrestTechn',), ('amcresttechn',),
            ('amcresttechnologies',),
            _C, 'high', 4,
            'Amcrest (Dahua OEM) cameras/NVR'),
    OuiHint(('EzvizSoftwar',), ('ezvizsoftwar',),
            ('hangzhouezvizsoftware', 'hangzhouezvizsoftwarecoltd'),
            _C, 'high', 15,
            'EZVIZ (Hikvision consumer): cameras, doorbells; also some locks/vacuums'),
    OuiHint(('WyzeLabs',), ('wyzelabs',),
            ('wyzelabsinc',),
            _C, 'medium', 6,
            'Wyze: cameras dominate, but also plugs, bulbs, locks, sensors hub'),
    OuiHint(('ArloTechnolo',), ('arlotechnolo',),
            ('arlotechnology',),
            _C, 'high', 3,
            'Arlo cameras/base stations/doorbells'),
    OuiHint(('BlinkbyAmazo',), ('blinkbyamazo',),
            ('blinkbyamazon',),
            _C, 'high', 6,
            'Blink cameras/sync modules'),
    OuiHint(('Ring',), ('ring',),
            ('ringllc',),
            _C, 'medium', 13,
            "Ring doorbells/cameras; Ring Alarm base station is specialized. Normalized token 'ring' must be matched "
            'exactly (substring of hundreds of names)'),
    OuiHint(('Verkada',), ('verkada',),
            ('verkadainc',),
            _C, 'medium', 1,
            'Verkada: cameras dominate; also access control, sensors, alarm panels'),
    OuiHint(('GeoVision',), ('geovision',),
            ('geovisioninc',),
            _C, 'high', 1,
            'GeoVision cameras/NVR (also access controllers)'),
    OuiHint(('TiandyTechno',), ('tiandytechno',),
            ('tiandytechnologies', 'tiandytechnologiescoltd'),
            _C, 'high', 3,
            'Tiandy cameras/NVR'),
    OuiHint(('LorexTechnol',), ('lorextechnol',),
            ('lorextechnology', 'lorextechnologyinc'),
            _C, 'high', 1,
            'Lorex consumer cameras/NVR'),
    OuiHint(('SwannCommuni', 'Swanncommuni'), ('swanncommuni',),
            ('swanncommunications', 'swanncommunicationsptyltd'),
            _C, 'high', 2,
            'Swann consumer cameras/DVR'),
    OuiHint(('NightOwlSP',), ('nightowlsp',),
            (),
            _C, 'high', 1,
            'Night Owl security cameras/DVR'),
    OuiHint(('ReecamTech',), ('reecamtech',),
            ('shenzhenreecamtechltd',),
            _C, 'high', 1,
            'Reecam IP cameras (Foscam-style OEM)'),
    OuiHint(('ATOMtech',), ('atomtech',),
            ('atomtechinc',),
            _C, 'medium', 1,
            'ATOM tech Inc. (ATOM Cam, Japan)'),
    OuiHint(('HoneywellVid',), ('honeywellvid',),
            ('honeywellvideosystems',),
            _C, 'high', 1,
            'Honeywell Video Systems (CCTV)'),
    OuiHint(('BoschSecurit',), ('boschsecurit',),
            ('boschsecuritysystems', 'boschsecuritysystemsinc', 'boschzhuhaisecuritysystemscompanyltd'),
            _C, 'medium', 4,
            'Bosch Security Systems: cameras dominate, but also alarm panels, PA and conference systems'),
    OuiHint(('BrotherIndus', 'Brotherindus'), ('brotherindus',),
            ('brotherindustries', 'brotherindustriesltd'),
            _P, 'high', 7,
            'Brother printers/MFP/label printers/document scanners'),
    OuiHint(('KYOCERADocum',), ('kyoceradocum',),
            ('kyoceradocumentsolutions', 'kyoceradocumentsolutionsinc'),
            _P, 'high', 1,
            'KYOCERA Document Solutions'),
    OuiHint(('Kyocera', 'KYOCERA'), ('kyocera',),
            ('kyoceracorporation',),
            _P, 'medium', 11,
            'Kyocera Corporation: printers, but Kyocera Corp also ships phones (TORQUE/DuraForce/BASIO)'),
    OuiHint(('KYOCERADispl',), ('kyoceradispl',),
            ('kyoceradisplay', 'kyoceradisplaycorporation'),
            _P, 'medium', 3,
            '00:C0:EE and 00:17:C8 are long-standing Kyocera(Mita) printer OUIs that the IEEE registry now lists as '
            "'KYOCERA Display Corporation'"),
    OuiHint(('Ricoh',), ('ricoh',),
            ('ricohcompany', 'ricohcompanyltd'),
            _P, 'high', 3,
            'Ricoh/Savin/Lanier/Gestetner MFPs (Ricoh THETA cameras are rare on LANs)'),
    OuiHint(('Xerox',), ('xerox',),
            ('xeroxcorporation',),
            _P, 'high', 13,
            "Xerox. TRAP: an all-zero MAC 00:00:00:00:00:00 is 'Xerox' in nmap-mac-prefixes; ignore it"),
    OuiHint(('LexmarkInter',), ('lexmarkinter',),
            ('lexmarkinternational', 'lexmarkinternationalinc'),
            _P, 'high', 5,
            'Lexmark printers/MFP'),
    OuiHint(('KonicaMinolt',), ('konicaminolt',),
            ('konicaminoltaholdings', 'konicaminoltaholdingsinc'),
            _P, 'high', 3,
            'Konica Minolta bizhub MFPs'),
    OuiHint(('FUJIFILMBusi',), ('fujifilmbusi',),
            ('fujifilmbusinessinnovation', 'fujifilmbusinessinnovationcorp'),
            _P, 'high', 2,
            'FUJIFILM Business Innovation (ex Fuji Xerox) MFPs'),
    OuiHint(('SeikoEpson',), ('seikoepson',),
            ('seikoepsoncorporation',),
            _P, 'medium', 22,
            'Epson: printers dominate, but also network projectors (classrooms/offices), POS terminals, scanners, '
            'robots'),
    OuiHint(('Canon',), ('canon',),
            ('canoninc',),
            _P, 'medium', 25,
            'Canon Inc.: printers dominate, but also Wi-Fi cameras/camcorders, VB-series network cameras, projectors'),
    OuiHint(('OkiElectricI',), ('okielectrici',),
            ('okielectricindustry', 'okielectricindustrycoltd'),
            _P, 'medium', 4,
            'OKI printers (00:80:87, 00:25:36); OKI also makes PBX/ATM/telecom gear'),
    OuiHint(('ToshibaTEC',), ('toshibatec',),
            ('toshibateccorporationinc',),
            _P, 'medium', 1,
            'Toshiba TEC: e-STUDIO MFPs and POS terminals'),
    OuiHint(('ZhuhaiPantum',), ('zhuhaipantum',),
            ('zhuhaipantumelectronics', 'zhuhaipantumelectronicscoltd'),
            _P, 'high', 1,
            'Pantum printers'),
    OuiHint(('SindohTechno',), ('sindohtechno',),
            ('sindohtechnocoltd',),
            _P, 'high', 1,
            'Sindoh printers/MFP (also 3D printers)'),
    OuiHint(('TriumphAdler',), ('triumphadler',),
            ('triumphadlerag',),
            _P, 'medium', 1,
            'Triumph-Adler/UTAX copiers (Kyocera group)'),
    OuiHint(('Printronix',), ('printronix',),
            ('printronixinc',),
            _P, 'high', 1,
            'Printronix line/label printers'),
    OuiHint(('Sato',), ('sato',),
            ('satocorporation',),
            _P, 'high', 1,
            "SATO label printers; token 'sato' must be matched exactly"),
    OuiHint(('Bixolon',), ('bixolon',),
            ('bixoloncoltd',),
            _P, 'high', 1,
            'Bixolon receipt/label printers'),
    OuiHint(('YealinkNetwo', 'XiamenYealin'), ('xiamenyealin', 'yealinknetwo'),
            ('xiamenyealinknetworktechnology', 'xiamenyealinknetworktechnologycoltd',
              'yealinkxiamennetworktechnology', 'yealinkxiamennetworktechnologycoltd'),
            _V, 'high', 11,
            'Yealink IP phones, DECT, video conferencing (all UC endpoints)'),
    OuiHint(('Polycom',), ('polycom',),
            (),
            _V, 'high', 2,
            'Polycom phones/video'),
    OuiHint(('Plantronics',), ('plantronics',),
            ('plantronicsinc',),
            _V, 'medium', 10,
            'Plantronics/Poly: networked Plantronics-OUI devices are Poly phones/video bars (headsets are '
            'USB/Bluetooth only)'),
    OuiHint(('GrandstreamN',), ('grandstreamn',),
            ('grandstreamnetworks', 'grandstreamnetworksinc'),
            _V, 'medium', 4,
            'Grandstream: phones/ATAs/UCM PBX, but also GWN Wi-Fi APs, switches, routers and GSC/GXV cameras'),
    OuiHint(('snomtechnolo',), ('snomtechnolo',),
            ('snomtechnologygmbh',),
            _V, 'high', 2,
            'snom IP/DECT phones'),
    OuiHint(('FanvilTechno',), ('fanviltechno',),
            ('fanviltechnology', 'fanviltechnologycoltd'),
            _V, 'high', 1,
            'Fanvil phones and SIP intercoms'),
    OuiHint(('Mitel', 'MITEL', 'MitelNetwork', 'AastraTeleco'), ('aastrateleco', 'mitel', 'mitelnetwork'),
            ('aastratelecom', 'mitelcorporation', 'mitelnetworks', 'mitelnetworkscorporation', 'mitelsrl'),
            _V, 'high', 5,
            'Mitel/Aastra phones and PBX'),
    OuiHint(('ShoreTel',), ('shoretel',),
            ('shoretelinc',),
            _V, 'high', 1,
            'ShoreTel (Mitel) phones/switches'),
    OuiHint(('UnifySoftwar',), ('unifysoftwar',),
            ('unifysoftwareandsolutionsgmbhcokg', 'unifysoftwareandsolutionsgmbhkg'),
            _V, 'high', 2,
            'Unify/Atos OpenScape phones'),
    OuiHint(('ObihaiTechno',), ('obihaitechno',),
            ('obihaitechnology', 'obihaitechnologyinc'),
            _V, 'high', 1,
            'Obihai ATAs'),
    OuiHint(('Digium',), ('digium',),
            (),
            _V, 'high', 1,
            'Digium phones/telephony cards'),
    OuiHint(('SangomaTechn',), ('sangomatechn',),
            ('sangomatechnologies',),
            _V, 'high', 1,
            'Sangoma phones/gateways/PBX appliances'),
    OuiHint(('XiamenYeasta',), ('xiamenyeasta',),
            ('xiamenyeastardigitaltechnology', 'xiamenyeastardigitaltechnologycoltd'),
            _V, 'high', 2,
            'Yeastar IP-PBX and VoIP gateways'),
    OuiHint(('AlgoCommunic',), ('algocommunic',),
            ('algocommunicationproducts', 'algocommunicationproductsltd'),
            _V, 'high', 1,
            'Algo SIP paging speakers/strobes'),
    OuiHint(('Cyberdata',), ('cyberdata',),
            ('cyberdatacorporation',),
            _V, 'high', 1,
            'CyberData SIP intercoms/speakers'),
    OuiHint(('AkuvoxNetwor',), ('akuvoxnetwor',),
            ('akuvoxxiamennetworks', 'akuvoxxiamennetworkscoltd'),
            _V, 'high', 1,
            'Akuvox SIP intercoms/door phones'),
    OuiHint(('2NTELEKOMUNI',), ('ntelekomuni',),
            ('ntelekomunikaceas',),
            _V, 'medium', 5,
            "2N SIP intercoms (also access-control units). Normalized token drops the digit: 'ntelekomuni'"),
    OuiHint(('GuangzhouEsc',), ('guangzhouesc',),
            ('guangzhouescenecomputertechnologylimited',),
            _V, 'high', 1,
            'Escene IP phones'),
    OuiHint(('Spectralink', 'KIRKtelecom'), ('kirktelecom', 'spectralink'),
            ('kirktelecomas', 'spectralinkinc'),
            _V, 'high', 2,
            'Spectralink/KIRK Wi-Fi and DECT phones/base stations'),
    OuiHint(('AscomTateco',), ('ascomtateco',),
            ('ascomtatecoab',),
            _V, 'medium', 1,
            'Ascom on-site wireless phones'),
    OuiHint(('VTechTelecom', 'VtechTelecom'), ('vtechtelecom',),
            ('vtechtelecommunications', 'vtechtelecommunicationslimited', 'vtechtelecommunicationsltd'),
            _V, 'medium', 5,
            'VTech Telecommunications: DECT/SIP phones (VTech toys use other OUIs)'),
    OuiHint(('ClearOne',), ('clearone',),
            ('clearoneinc',),
            _V, 'medium', 1,
            'ClearOne conferencing audio'),
    OuiHint(('ZultysTechno',), ('zultystechno',),
            ('zultystechnologies',),
            _V, 'high', 2,
            'Zultys phones/PBX'),
    OuiHint(('Innovaphone',), ('innovaphone',),
            ('innovaphoneag',),
            _V, 'high', 1,
            'innovaphone phones/PBX'),
    OuiHint(('AudiocodesUS',), ('audiocodesus',),
            ('audiocodesusa', 'audiocodesusainc'),
            _V, 'high', 1,
            'AudioCodes gateways/SBCs/phones'),
    OuiHint(('HanlongTechn',), ('hanlongtechn',),
            ('hanlongtechnology', 'hanlongtechnologycoltd'),
            _V, 'medium', 1,
            'Nanjing Hanlong = Htek IP phones'),
    OuiHint(('Auerswald',), ('auerswald',),
            ('auerswaldgmbhcokg', 'auerswaldgmbhkg'),
            _V, 'high', 1,
            'Auerswald PBX/phones'),
    OuiHint(('Avaya',), ('avaya',),
            ('avayainc', 'avayallc'),
            _V, 'medium', 53,
            'Avaya phones dominate, but ex-Nortel/Avaya data switches (ERS/VSP, now Extreme) share these OUIs'),
    OuiHint(('GigasetTechn', 'GigasetCommu'), ('gigasetcommu', 'gigasettechn'),
            ('gigasetcommunicationsgmbh', 'gigasettechnologiesgmbh'),
            _V, 'medium', 3,
            'Gigaset DECT/IP phones (Gigaset also sold Android phones and smart-home kits)'),
    OuiHint(('PattonElectr',), ('pattonelectr',),
            ('pattonelectronics', 'pattonelectronicsco'),
            _V, 'medium', 1,
            'Patton SmartNode VoIP gateways/SBCs (also modems/routers)'),
    OuiHint(('Synology',), ('synology',),
            ('synologyincorporated',),
            _ST, 'high', 2,
            'Synology NAS; also SRM routers (RT2600ac/RT6600ax/WRX560) and BC500/TC500 cameras (minor)'),
    OuiHint(('QNAP',), ('qnap',),
            ('qnapsystems', 'qnapsystemsinc'),
            _ST, 'high', 2,
            'QNAP NAS; also QSW switches and QHora routers (minor)'),
    OuiHint(('Asustor',), ('asustor',),
            ('asustorinc',),
            _ST, 'high', 1,
            'ASUSTOR NAS'),
    OuiHint(('DataRobotics',), ('datarobotics',),
            ('dataroboticsincorporated',),
            _ST, 'high', 1,
            'Drobo'),
    OuiHint(('NetApp',), ('netapp',),
            (),
            _ST, 'high', 4,
            'NetApp filers'),
    OuiHint(('NimbleStorag',), ('nimblestorag',),
            ('nimblestorage',),
            _ST, 'high', 1,
            'Nimble Storage arrays'),
    OuiHint(('ThecusTechno',), ('thecustechno',),
            ('thecustechnology', 'thecustechnologycorp'),
            _ST, 'high', 1,
            'Thecus NAS'),
    OuiHint(('Iomega',), ('iomega',),
            ('iomegacorporation',),
            _ST, 'high', 1,
            'Iomega StorCenter NAS'),
    OuiHint(('InfortrendTe',), ('infortrendte',),
            ('infortrendtechnology', 'infortrendtechnologyinc'),
            _ST, 'high', 1,
            'Infortrend EonStor/EonNAS'),
    OuiHint(('PromiseTechn',), ('promisetechn',),
            ('promisetechnology', 'promisetechnologyinc'),
            _ST, 'high', 1,
            'Promise VTrak/VessRAID storage'),
    OuiHint(('Quantum',), ('quantum',),
            ('quantumcoltd', 'quantumcorp', 'quantumcorporation', 'quantumsystemsgmbh'),
            _ST, 'high', 6,
            'Quantum tape libraries/DXi/StorNext'),
    OuiHint(('EMC',), ('emc',),
            ('emccorporation',),
            _ST, 'high', 1,
            'EMC Corporation (pre-Dell) storage'),
    OuiHint(('HitachiData',), ('hitachidata',),
            ('hitachidatasystems',),
            _ST, 'high', 1,
            'Hitachi Data Systems storage'),
    OuiHint(('Tintri',), ('tintri',),
            (),
            _ST, 'high', 2,
            'Tintri VM-aware storage'),
    OuiHint(('OverlandStor',), ('overlandstor',),
            ('overlandstorage', 'overlandstorageinc'),
            _ST, 'high', 1,
            'Overland tape/NAS'),
    OuiHint(('SpectraLogic',), ('spectralogic',),
            (),
            _ST, 'high', 1,
            'Spectra Logic tape libraries'),
    OuiHint(('QsanTechnolo',), ('qsantechnolo',),
            ('qsantechnology', 'qsantechnologyinc'),
            _ST, 'high', 1,
            'QSAN storage'),
    OuiHint(('SeagateCloud',), ('seagatecloud',),
            ('seagatecloudsystems', 'seagatecloudsystemsinc'),
            _ST, 'high', 4,
            'Seagate Cloud Systems (ex Dot Hill/Xyratex arrays)'),
    OuiHint(('SeagateTechn',), ('seagatetechn',),
            ('seagatetechnology', 'seagatetechnologythailandltd'),
            _ST, 'medium', 10,
            'Seagate NAS/Personal Cloud (drives themselves are not on the LAN)'),
    OuiHint(('WesternDigit',), ('westerndigit',),
            ('westerndigital', 'westerndigitalcorporation', 'westerndigitaltechnologies',
              'westerndigitaltechnologiesinc'),
            _ST, 'medium', 4,
            'WD My Cloud NAS (legacy WD TV media players also used WD OUIs)'),
    OuiHint(('Nintendo',), ('nintendo',),
            ('nintendocoltd',),
            _M, 'high', 110,
            'Nintendo consoles'),
    OuiHint(('SonyInteract', 'SonyComputer'), ('sonycomputer', 'sonyinteract'),
            ('sonycomputerentertainmentamerica', 'sonyinteractiveentertainment', 'sonyinteractiveentertainmentinc'),
            _M, 'high', 45,
            'PlayStation'),
    OuiHint(('SonyHomeEnte', 'SonyVideoSou', 'SONYVisualPr'), ('sonyhomeente', 'sonyvideosou', 'sonyvisualpr'),
            ('sonyhomeentertainmentsoundproducts', 'sonyhomeentertainmentsoundproductsinc', 'sonyvideosoundproducts',
              'sonyvideosoundproductsinc', 'sonyvisualproducts', 'sonyvisualproductsinc'),
            _M, 'high', 6,
            "Sony TVs/AV receivers/projectors (NOT 'Sony' = Sony Corporation, which is mixed)"),
    OuiHint(('Roku',), ('roku',),
            ('rokuinc',),
            _M, 'high', 32,
            'Roku players/TVs (Roku-branded cameras are minor)'),
    OuiHint(('Sonos',), ('sonos',),
            ('sonosinc',),
            _M, 'high', 16,
            "Sonos speakers. Normalized 'sonos' is a substring of 'sonosite' (SonoSite ultrasound): match exactly. "
            "00:04:3C 'SONOS Co., Ltd.' normalizes to the same token and is an unrelated legacy OUI"),
    OuiHint(('Bose',), ('bose',),
            ('bosecorporation',),
            _M, 'high', 14,
            "Bose speakers/soundbars. 'bose' is a substring of 'bosertechnol': match exactly"),
    OuiHint(('D&MHoldings', 'SoundUnited'), ('dmholdings', 'soundunited'),
            ('dmholdingsinc', 'soundunitedllc'),
            _M, 'high', 5,
            'Denon/Marantz/HEOS'),
    OuiHint(('OnkyoTechnol',), ('onkyotechnol',),
            ('onkyotechnologykk',),
            _M, 'high', 2,
            'Onkyo/Integra AV receivers'),
    OuiHint(('Pioneer',), ('pioneer',),
            ('pioneercorporation',),
            _M, 'medium', 3,
            'Pioneer AV receivers (and car/DJ gear)'),
    OuiHint(('BangOlufsen',), ('bangolufsen',),
            ('bangolufsenas',),
            _M, 'high', 1,
            'Bang & Olufsen'),
    OuiHint(('LenbrookIndu',), ('lenbrookindu',),
            ('lenbrookindustrieslimited',),
            _M, 'high', 1,
            'Bluesound/NAD'),
    OuiHint(('LinnProducts',), ('linnproducts',),
            ('linnproductsltd',),
            _M, 'high', 2,
            'Linn streamers'),
    OuiHint(('NaimAudio',), ('naimaudio',),
            (),
            _M, 'high', 1,
            'Naim streamers'),
    OuiHint(('TiVo',), ('tivo',),
            (),
            _M, 'high', 1,
            'TiVo DVRs/boxes'),
    OuiHint(('SlingMedia',), ('slingmedia',),
            ('slingmediainc',),
            _M, 'high', 1,
            'Slingbox'),
    OuiHint(('SilicondustE',), ('siliconduste',),
            ('silicondustengineering', 'silicondustengineeringltd'),
            _M, 'high', 1,
            'HDHomeRun tuners'),
    OuiHint(('Vizio',), ('vizio',),
            ('vizioinc',),
            _M, 'high', 17,
            'VIZIO TVs/soundbars'),
    OuiHint(('HisenseVisua',), ('hisensevisua',),
            ('hisensevisualtechnology', 'hisensevisualtechnologycoltd'),
            _M, 'high', 11,
            'Hisense Visual Technology (TVs). Other Hisense OUIs are mixed (phones, A/C, broadband)'),
    OuiHint(('TCLKingElect',), ('tclkingelect',),
            ('tclkingelectricalapplianceshuizhou', 'tclkingelectricalapplianceshuizhouco',
              'tclkingelectricalapplianceshuizhoucoltd'),
            _M, 'medium', 14,
            'TCL King Electrical (TV maker). Other TCL OUIs are phones/ODM'),
    OuiHint(('TPVisionBelg',), ('tpvisionbelg',),
            ('tpvisionbelgiumnv', 'tpvisionbelgiumnvinnovationsitebrugge'),
            _M, 'high', 2,
            'TP Vision = Philips TVs'),
    OuiHint(('BrightSign',), ('brightsign',),
            ('brightsignllc',),
            _M, 'high', 1,
            'BrightSign signage players'),
    OuiHint(('Kaleidescape',), ('kaleidescape',),
            (),
            _M, 'high', 1,
            'Kaleidescape movie servers/players'),
    OuiHint(('DishTechnolo',), ('dishtechnolo',),
            ('dishtechnologies', 'dishtechnologiescorp'),
            _M, 'high', 7,
            'DISH set-top boxes'),
    OuiHint(('OPPODigital',), ('oppodigital',),
            ('oppodigitalinc',),
            _M, 'high', 1,
            'OPPO Digital Blu-ray players (not OPPO Mobile)'),
    OuiHint(('OculusVR',), ('oculusvr',),
            ('oculusvrllc',),
            _M, 'high', 1,
            'Oculus VR headsets'),
    OuiHint(('MetaPlatform',), ('metaplatform',),
            ('metaplatforms', 'metaplatformsinc'),
            _M, 'medium', 13,
            'Meta Quest headsets, Portal; smart glasses'),
    OuiHint(('Valve',), ('valve',),
            ('valvecorporation',),
            _M, 'medium', 1,
            'Valve Steam Deck (a handheld Linux PC) / Index / Steam Link'),
    OuiHint(('ChristieDigi',), ('christiedigi',),
            ('christiedigitalsystems', 'christiedigitalsystemsinc'),
            _M, 'high', 1,
            'Christie projectors'),
    OuiHint(('Barco',), ('barco',),
            ('barconv',),
            _M, 'medium', 1,
            'Barco ClickShare/projectors (also medical displays)'),
    OuiHint(('CrestronElec',), ('crestronelec',),
            ('crestronelectronics', 'crestronelectronicsinc'),
            _M, 'medium', 3,
            'Crestron AV-over-IP, AirMedia, touch panels; control processors are arguably specialized'),
    OuiHint(('ExtronElectr',), ('extronelectr',),
            ('extronelectronics',),
            _M, 'medium', 1,
            'Extron AV switching/streaming/control'),
    OuiHint(('PanasonicAVC',), ('panasonicavc',),
            ('panasonicavcnetworkscompany', 'panasoniccorporationavcnetworkscompany'),
            _M, 'medium', 7,
            'Panasonic AVC Networks (TVs, Blu-ray, AV). Other Panasonic OUIs are mixed'),
    OuiHint(('AmericanPowe', 'APCbySchneid'), ('americanpowe', 'apcbyschneid'),
            ('americanpowerconversion', 'americanpowerconversioncorp', 'apcbyschneiderelectric'),
            _SP, 'high', 2,
            "APC network management cards/UPS/PDU. 'AmericanPowe' is the truncated short name (normalized "
            "'americanpowe', NOT 'americanpower')"),
    OuiHint(('SchneiderEle',), ('schneiderele',),
            ('controlmicrosystems', 'schneiderelectric', 'schneiderelectricasiapacific',
              'schneiderelectricasiapacificltd', 'schneiderelectricaustralia', 'schneiderelectriccanada',
              'schneiderelectriccanadainc', 'schneiderelectricchinacoltdshenzhenbranch',
              'schneiderelectricfiresecurityoy', 'schneiderelectricgmbh', 'schneiderelectricjapanholdings',
              'schneiderelectricjapanholdingsltd', 'schneiderelectrickorea', 'schneiderelectricmotion',
              'schneiderelectricmotionincusa', 'schneiderelectricmotionusa', 'schneiderelectricultraterminal',
              'schneiderelectricusa'),
            _SP, 'medium', 27,
            'Schneider Electric: PLCs, meters, UPS, building/home automation (ConneXium switches are a minority)'),
    OuiHint(('Eaton', 'EatonElectri', 'EatonAutomat'), ('eaton', 'eatonautomat', 'eatonelectri'),
            ('eatonautomationag', 'eatoncorpelectricalgroupdatacentersolutionspulizzi', 'eatoncorporation',
              'eatonelectricalgroupdatacentersolutionspulizzi'),
            _SP, 'high', 9,
            'Eaton UPS cards/ePDU/automation'),
    OuiHint(('CyberPower',), ('cyberpower',),
            ('cyberpowersystems', 'cyberpowersystemsinc'),
            _SP, 'high', 1,
            'CyberPower UPS RMCARD'),
    OuiHint(('EmersonNetwo',), ('emersonnetwo',),
            ('emersonnetworkpower', 'emersonnetworkpoweravocentdivision', 'emersonnetworkpowercoltd',
              'emersonnetworkpowerindiapvtltd'),
            _SP, 'medium', 3,
            'Emerson Network Power/Avocent (UPS, KVM, console servers)'),
    OuiHint(('LiebertHiros',), ('lieberthiros',),
            ('lieberthirossspa',),
            _SP, 'high', 1,
            'Liebert cooling/UPS'),
    OuiHint(('RaritanCompu',), ('raritancompu',),
            ('raritancomputer', 'raritancomputerinc'),
            _SP, 'high', 1,
            'Raritan PDUs/KVM-over-IP'),
    OuiHint(('ServerTechno',), ('servertechno',),
            ('servertechnology', 'servertechnologyinc'),
            _SP, 'high', 1,
            'Server Technology PDUs'),
    OuiHint(('TrippLite',), ('tripplite',),
            (),
            _SP, 'high', 2,
            'Tripp Lite UPS/PDU/KVM'),
    OuiHint(('Socomec',), ('socomec',),
            (),
            _SP, 'high', 1,
            'Socomec UPS/meters'),
    OuiHint(('Legrand',), ('legrand',),
            (),
            _SP, 'medium', 1,
            'Legrand PDUs/lighting control/home systems'),
    OuiHint(('Panduit',), ('panduit',),
            ('panduitcorp',),
            _SP, 'medium', 1,
            'Panduit PDUs/monitoring'),
    OuiHint(('NetBotz',), ('netbotz',),
            ('netbotzinc',),
            _SP, 'high', 1,
            'NetBotz environmental monitors'),
    OuiHint(('Akcp',), ('akcp',),
            (),
            _SP, 'high', 1,
            'AKCP sensorProbe monitors'),
    OuiHint(('Gude',), ('gude',),
            ('gudesystemsgmbh',),
            _SP, 'high', 1,
            'Gude PDUs/Expert Power Control'),
    OuiHint(('DigitalLogge', 'ComputerPerf'), ('computerperf', 'digitallogge'),
            ('computerperformancedbadigitalloggers', 'computerperformanceincdbadigitalloggersinc',
              'digitalloggersinc'),
            _SP, 'high', 2,
            'Digital Loggers web power switches'),
    OuiHint(('Powercom',), ('powercom',),
            ('powercomcoltd', 'shenzhenpowercom', 'shenzhenpowercomcoltd'),
            _SP, 'medium', 2,
            'Powercom UPS'),
    OuiHint(('Chloride',), ('chloride',),
            ('chloridesrl',),
            _SP, 'medium', 1,
            'Chloride UPS'),
    OuiHint(('Espressif', 'EspressifPte'), ('espressif', 'espressifpte'),
            ('espressifinc', 'espressifsystemssingaporepteltd'),
            _SP, 'medium', 360,
            'ESP8266/ESP32 Wi-Fi modules: overwhelmingly plugs/bulbs/sensors/appliances; a minority are cameras '
            '(ESP32-CAM), speakers, 3D-printer boards'),
    OuiHint(('TuyaSmart',), ('tuyasmart',),
            ('tuyasmartinc',),
            _SP, 'high', 42,
            'Tuya modules (plugs, switches, lighting)'),
    OuiHint(('ShellyEurope',), ('shellyeurope',),
            ('shellyeuropeltd',),
            _SP, 'high', 1,
            'Shelly relays/plugs (older Shelly devices use Espressif OUIs)'),
    OuiHint(('PhilipsLight', 'Signify'), ('philipslight', 'signify'),
            ('philipslightingbv', 'signifybv'),
            _SP, 'high', 4,
            "Philips Hue bridge / Signify lighting. Short name is 'PhilipsLight' (normalized 'philipslight')"),
    OuiHint(('WiZConnected', 'WiZIoT'), ('wizconnected', 'wiziot'),
            ('wizconnectedlightingcompanylimited', 'wiziotcompanylimited'),
            _SP, 'high', 2,
            'WiZ smart lighting'),
    OuiHint(('Intellirocks',), ('intellirocks',),
            ('shenzhenintellirockstech', 'shenzhenintellirockstechcoltd'),
            _SP, 'high', 4,
            'Shenzhen Intellirocks = Govee lighting/sensors'),
    OuiHint(('ecobee',), ('ecobee',),
            ('ecobeeinc',),
            _SP, 'high', 1,
            'ecobee thermostats (ecobee cameras are minor)'),
    OuiHint(('NestLabs',), ('nestlabs',),
            ('nestlabsinc',),
            _SP, 'medium', 2,
            'Nest thermostats/Protect; older Nest Cams also use these OUIs'),
    OuiHint(('Dyson',), ('dyson',),
            ('dysonlimited',),
            _SP, 'high', 4,
            'Dyson purifiers/fans/vacuums'),
    OuiHint(('iRobot',), ('irobot',),
            ('irobotcorporation',),
            _SP, 'high', 3,
            'Roomba/Braava robots'),
    OuiHint(('RoborockTech',), ('roborocktech',),
            ('beijingroborocktechnology', 'beijingroborocktechnologycoltd'),
            _SP, 'high', 3,
            'Roborock robot vacuums'),
    OuiHint(('Withings',), ('withings',),
            (),
            _SP, 'high', 2,
            'Withings scales/sleep/BPM'),
    OuiHint(('Nanoleaf',), ('nanoleaf',),
            (),
            _SP, 'high', 2,
            'Nanoleaf lighting'),
    OuiHint(('MerossTechno',), ('merosstechno',),
            ('chengdumerosstechnology', 'chengdumerosstechnologycoltd'),
            _SP, 'high', 3,
            'Meross plugs/garage openers'),
    OuiHint(('IKEASweden',), ('ikeasweden',),
            ('ikeaofswedenab',),
            _SP, 'high', 1,
            'IKEA DIRIGERA/TRADFRI gateways (SYMFONISK speakers carry Sonos OUIs)'),
    OuiHint(('LutronElectr',), ('lutronelectr',),
            ('lutronelectronics', 'lutronelectronicscoinc'),
            _SP, 'high', 1,
            'Lutron Caseta/RadioRA bridges'),
    OuiHint(('ChamberlainG',), ('chamberlaing',),
            ('thechamberlaingroup', 'thechamberlaingroupinc'),
            _SP, 'high', 5,
            'Chamberlain/LiftMaster myQ'),
    OuiHint(('AugustHome', 'AssaAbloyYal'), ('assaabloyyal', 'augusthome'),
            ('assaabloyabyale', 'augusthomeinc'),
            _SP, 'high', 2,
            'August/Yale smart-lock bridges'),
    OuiHint(('Netatmo',), ('netatmo',),
            (),
            _SP, 'medium', 1,
            'Netatmo weather/thermostat; Netatmo cameras/doorbells also exist'),
    OuiHint(('tado',), ('tado',),
            ('tadogmbh',),
            _SP, 'high', 2,
            "tado thermostats. 'tado' is a substring of 'mbmontador': match exactly"),
    OuiHint(('Eve',), ('eve',),
            ('evesystemsgmbh',),
            _SP, 'high', 1,
            "Eve Systems (HomeKit/Thread). Token 'eve' MUST be matched exactly"),
    OuiHint(('Hubitat',), ('hubitat',),
            ('hubitatinc',),
            _SP, 'high', 1,
            'Hubitat hub'),
    OuiHint(('SmartThings',), ('smartthings',),
            ('smartthingsinc',),
            _SP, 'high', 1,
            'SmartThings hub'),
    OuiHint(('LumiUnitedTe',), ('lumiunitedte',),
            ('lumiunitedtechnology', 'lumiunitedtechnologycoltd'),
            _SP, 'medium', 2,
            'Aqara (Lumi) hubs; camera-hub models exist'),
    OuiHint(('GDMideaAirCo', 'MideaGroup'), ('gdmideaairco', 'mideagroup'),
            ('gdmideaairconditioningequipment', 'gdmideaairconditioningequipmentcoltd', 'mideagroupcoltd'),
            _SP, 'high', 54,
            'Midea Wi-Fi air conditioners/appliances'),
    OuiHint(('GreeElectric',), ('greeelectric',),
            ('greeelectricappliancesincofzhuhai', 'greeelectricappliancesofzhuhai'),
            _SP, 'high', 6,
            'Gree Wi-Fi air conditioners'),
    OuiHint(('BroadLinkTec',), ('broadlinktec',),
            ('hangzhoubroadlinktechnology', 'hangzhoubroadlinktechnologycoltd'),
            _SP, 'high', 8,
            "BroadLink IR blasters/plugs (Hangzhou BroadLink only; 'Broadlink Pty' is a different company)"),
    OuiHint(('LevitonManuf',), ('levitonmanuf',),
            ('levitonmanufacturing', 'levitonmanufacturingcoinc'),
            _SP, 'high', 3,
            'Leviton smart switches/dimmers'),
    OuiHint(('SenseLabs',), ('senselabs',),
            ('senselabsinc',),
            _SP, 'high', 1,
            'Sense energy monitors'),
    OuiHint(('EmporiaRenew',), ('emporiarenew',),
            ('emporiarenewableenergycorp',),
            _SP, 'high', 1,
            'Emporia energy monitors/EV chargers'),
    OuiHint(('Tesla',), ('tesla',),
            ('teslainc',),
            _SP, 'medium', 7,
            "Tesla vehicles, Powerwall gateways, Wall Connectors. Token also covers unrelated 'TESLA, a.s.'"),
    OuiHint(('EnphaseEnerg',), ('enphaseenerg',),
            ('enphaseenergy',),
            _SP, 'high', 1,
            'Enphase Envoy/IQ gateways'),
    OuiHint(('SolarEdgeTec', 'Solaredge'), ('solaredge', 'solaredgetec'),
            ('solaredgeltd', 'solaredgetechnologies'),
            _SP, 'high', 6,
            'SolarEdge inverters'),
    OuiHint(('SMASolarTech',), ('smasolartech',),
            ('smasolartechnologyag',),
            _SP, 'high', 1,
            'SMA inverters/Sunny Home Manager'),
    OuiHint(('FroniusSchwe',), ('froniusschwe',),
            ('froniusschweissmaschinen',),
            _SP, 'high', 1,
            'Fronius inverters/welders'),
    OuiHint(('Zaptec',), ('zaptec',),
            (),
            _SP, 'high', 2,
            'Zaptec EV chargers'),
    OuiHint(('Arduino',), ('arduino',),
            ('arduinoag',),
            _SP, 'high', 1,
            'Arduino boards'),
    OuiHint(('ParticleIndu',), ('particleindu',),
            ('particleindustries', 'particleindustriesinc'),
            _SP, 'high', 1,
            'Particle IoT modules'),
    OuiHint(('BouffaloLab', 'HongKongBouf'), ('bouffalolab', 'hongkongbouf'),
            ('bouffalolabnanjing', 'bouffalolabnanjingcoltd', 'hongkongbouffalolablimited'),
            _SP, 'medium', 31,
            'Bouffalo BL60x/BL61x IoT Wi-Fi SoCs'),
    OuiHint(('Beken',), ('beken',),
            ('bekencorporation',),
            _SP, 'medium', 3,
            'Beken BK72xx IoT Wi-Fi SoCs (Tuya modules); some cheap cameras'),
    OuiHint(('WinnerMicroe',), ('winnermicroe',),
            ('beijingwinnermicroelectronics', 'beijingwinnermicroelectronicscoltd'),
            _SP, 'medium', 2,
            'WinnerMicro W600/W800 IoT Wi-Fi SoCs'),
    OuiHint(('MXCHIPInform', 'MXCHIP'), ('mxchip', 'mxchipinform'),
            ('mxchipcompanylimited', 'shanghaimxchipinformationtechnology',
              'shanghaimxchipinformationtechnologycoltd'),
            _SP, 'medium', 8,
            'MXCHIP IoT Wi-Fi modules'),
    OuiHint(('HighFlyingEl', 'Hiflyingelec'), ('hiflyingelec', 'highflyingel'),
            ('hiflyingelectronicstechnology', 'hiflyingelectronicstechnologycoltd',
              'shanghaihighflyingelectronicstechnology', 'shanghaihighflyingelectronicstechnologycoltd'),
            _SP, 'medium', 11,
            'High-Flying HF-LPx IoT/serial Wi-Fi modules'),
    OuiHint(('NordicSemico',), ('nordicsemico',),
            ('nordicsemiconductorasa',),
            _SP, 'medium', 2,
            'Nordic nRF70 IoT Wi-Fi (mostly BLE otherwise)'),
    OuiHint(('DavisInstrum',), ('davisinstrum',),
            ('davisinstruments', 'davisinstrumentsinc'),
            _SP, 'high', 1,
            'Davis weather stations'),
    OuiHint(('PelotonInter',), ('pelotoninter',),
            ('pelotoninteractive', 'pelotoninteractiveinc'),
            _SP, 'medium', 2,
            'Peloton fitness equipment (Android consoles)'),
    OuiHint(('SzDjiTechnol',), ('szdjitechnol',),
            ('szdjitechnology', 'szdjitechnologycoltd'),
            _SP, 'medium', 10,
            'DJI drones/gimbals'),
    OuiHint(('RockwellAuto',), ('rockwellauto',),
            ('rockwellautomation',),
            _SP, 'high', 14,
            'Rockwell/Allen-Bradley PLCs, drives, HMIs (Stratix switches are a minority)'),
    OuiHint(('MoxaTechnolo', 'Moxa'), ('moxa', 'moxatechnolo'),
            ('moxainc', 'moxatechnologies', 'moxatechnologiescorpltd'),
            _SP, 'medium', 2,
            'Moxa: device servers/gateways/IO dominate; EDS switches, EDR routers and AWK APs also common'),
    OuiHint(('BeckhoffAuto',), ('beckhoffauto',),
            ('beckhoffautomationgmbh',),
            _SP, 'high', 1,
            'Beckhoff PLC/IPC'),
    OuiHint(('WAGOKontaktt',), ('wagokontaktt',),
            ('wagokontakttechnikgmbh',),
            _SP, 'high', 1,
            'WAGO controllers/IO'),
    OuiHint(('PhoenixConta',), ('phoenixconta',),
            ('phoenixcontactgmbhcokg', 'phoenixcontactgmbhkg'),
            _SP, 'medium', 3,
            'Phoenix Contact PLCs/IO; FL SWITCH and mGuard firewalls also use these OUIs'),
    OuiHint(('B&RIndustria',), ('brindustria',),
            ('brindustrialautomationgmbh',),
            _SP, 'high', 3,
            'B&R automation'),
    OuiHint(('OMRON', 'OmronTateisi'), ('omron', 'omrontateisi'),
            ('omroncorporation', 'omrontateisielectronics', 'omrontateisielectronicsco'),
            _SP, 'high', 3,
            'OMRON PLCs/automation (and OMRON UPS in Japan)'),
    OuiHint(('OmronHealthc', 'OMRONHEALTHC'), ('omronhealthc',),
            ('omronhealthcare', 'omronhealthcarecoltd'),
            _SP, 'medium', 2,
            'OMRON Healthcare devices'),
    OuiHint(('SchweitzerEn',), ('schweitzeren',),
            ('schweitzerengineering',),
            _SP, 'high', 1,
            'SEL protective relays/RTACs'),
    OuiHint(('RedLionContr',), ('redlioncontr',),
            ('redlioncontrols', 'redlioncontrolsinc', 'redlioncontrolslp'),
            _SP, 'medium', 5,
            'Red Lion HMIs/data stations (also industrial routers/switches)'),
    OuiHint(('ProsoftTechn',), ('prosofttechn',),
            ('prosofttechnology', 'prosofttechnologyinc'),
            _SP, 'medium', 1,
            'ProSoft gateways/radios'),
    OuiHint(('HMSIndustria',), ('hmsindustria',),
            ('hmsindustrialnetworks', 'hmsindustrialnetworksslu'),
            _SP, 'medium', 6,
            'HMS Anybus/Ewon/Ixxat'),
    OuiHint(('TURCK',), ('turck',),
            ('turckinc',),
            _SP, 'high', 1,
            'Turck IO/sensors'),
    OuiHint(('Pilz',), ('pilz',),
            ('pilzgmbh', 'pilzgmbhco'),
            _SP, 'high', 1,
            'Pilz safety controllers'),
    OuiHint(('Festo',), ('festo',),
            ('festoagcokg', 'festoagkg'),
            _SP, 'high', 1,
            'Festo automation'),
    OuiHint(('Sick',), ('sick',),
            ('sickag',),
            _SP, 'high', 1,
            "SICK sensors/scanners; token 'sick' must be matched exactly"),
    OuiHint(('Keyence',), ('keyence',),
            ('keyencecorporation',),
            _SP, 'high', 2,
            'Keyence sensors/vision'),
    OuiHint(('Cognex',), ('cognex',),
            ('cognexcorporation',),
            _SP, 'high', 3,
            'Cognex machine vision'),
    OuiHint(('BannerEngine',), ('bannerengine',),
            ('bannerengineering',),
            _SP, 'high', 1,
            'Banner sensors'),
    OuiHint(('PepperlFuchs',), ('pepperlfuchs',),
            ('pepperlfuchsgmbh',),
            _SP, 'high', 1,
            'Pepperl+Fuchs'),
    OuiHint(('EndressHause',), ('endresshause',),
            ('endresshausergmbh', 'endresshausergmbhco'),
            _SP, 'high', 1,
            'Endress+Hauser instruments'),
    OuiHint(('Lantronix',), ('lantronix',),
            (),
            _SP, 'high', 4,
            'Lantronix device/console servers, Spider KVM'),
    OuiHint(('OpenGear',), ('opengear',),
            ('opengearinc',),
            _SP, 'high', 1,
            'Opengear console servers'),
    OuiHint(('Perle',), ('perle',),
            ('perlesystemslimited',),
            _SP, 'medium', 1,
            'Perle device/console servers (also industrial switches)'),
    OuiHint(('BoschRexroth',), ('boschrexroth',),
            ('boschrexrothag', 'boschrexrothchangzhoucoltd'),
            _SP, 'high', 3,
            'Bosch Rexroth drives/controls'),
    OuiHint(('Danfoss', 'DanfossDrive'), ('danfoss', 'danfossdrive'),
            ('danfossas', 'danfossdrivesas', 'danfossinc'),
            _SP, 'high', 3,
            'Danfoss drives/HVAC'),
    OuiHint(('Hilscher',), ('hilscher',),
            ('hilschergmbh',),
            _SP, 'high', 1,
            'Hilscher fieldbus'),
    OuiHint(('WeidmüllerIn',), ('weidmllerin',),
            ('weidmllerinterfacegmbhcokg', 'weidmllerinterfacegmbhkg'),
            _SP, 'medium', 1,
            "Weidmuller IO (also switches). Normalized token loses the umlaut: 'weidmllerin'"),
    OuiHint(('MitsubishiEl',), ('mitsubishiel',),
            ('mitsubishielectric', 'mitsubishielectricautomationchina', 'mitsubishielectricautomationchinaltd',
              'mitsubishielectriccorporation', 'mitsubishielectriceuropebvukbranch', 'mitsubishielectricindiapvtltd',
              'mitsubishielectricklimattransportationsystemsspa',
              'mitsubishielectricmicrocomputerapplicationsoftwarecoltd', 'mitsubishielectricsystemservice',
              'mitsubishielectricsystemservicecoltd', 'mitsubishielectricusinc',
              'mitsubishielectronicslogisticsupport', 'mitsubishielectronicslogisticsupportco'),
            _SP, 'medium', 27,
            'Mitsubishi Electric PLCs, A/C Wi-Fi adapters; also projectors/TVs'),
    OuiHint(('EmersonRosem', 'FisherRosemo', 'Rosemount', 'RosemountAna'), ('emersonrosem', 'fisherrosemo', 'rosemount', 'rosemountana'),
            ('emersonrosemountanalytical', 'fisherrosemountsystems', 'fisherrosemountsystemsinc',
              'rosemountanalytical', 'rosemountinc'),
            _SP, 'high', 7,
            'Emerson/Rosemount process instruments'),
    OuiHint(('ABB', 'Abb', 'ABBSwitzerla', 'ABBTransmiss', 'ABBRobotics', 'ABBDrives', 'AbbIndustria', 'ABBAutomatio'), ('abb', 'abbautomatio', 'abbdrives', 'abbindustria', 'abbrobotics', 'abbswitzerla', 'abbtransmiss'),
            ('abbag', 'abbautomationproductsgmbh', 'abbinc', 'abbindustrialsystemsab', 'abbltd', 'abboy',
              'abboydrives', 'abbspa', 'abbstotzkontaktgmbh', 'abbswitzerland', 'abbswitzerlandinc',
              'abbswitzerlandltd', 'abbtransmissionanddistributionautomationequipmentxiamencoltd'),
            _SP, 'high', 36,
            'ABB drives, robots, meters, KNX, EV chargers'),
    OuiHint(('GeneralElect',), ('generalelect',),
            ('generalelectric', 'generalelectriccompany', 'generalelectricconsumerandindustrial',
              'generalelectriccorporation', 'generalelectricdigitalenergy', 'generalelectricglobalresearch',
              'generalelectricwaterprocesstechnologies'),
            _SP, 'medium', 6,
            'General Electric industrial/medical/appliances'),
    OuiHint(('JohnsonContr',), ('johnsoncontr',),
            ('johnsoncontrols', 'johnsoncontrolsinc', 'johnsoncontrolsirsabroecontrols'),
            _SP, 'high', 2,
            'Johnson Controls Metasys/BAS'),
    OuiHint(('Tridium',), ('tridium',),
            ('tridiuminc',),
            _SP, 'high', 1,
            'Tridium JACE'),
    OuiHint(('DistechContr',), ('distechcontr',),
            ('distechcontrols',),
            _SP, 'high', 1,
            'Distech BAS controllers'),
    OuiHint(('Carrier',), ('carrier',),
            ('carriercorporation',),
            _SP, 'medium', 2,
            'Carrier HVAC controls'),
    OuiHint(('Trane', 'TraneTechnol'), ('trane', 'tranetechnol'),
            ('thetranecompany', 'tranetechnologies'),
            _SP, 'high', 3,
            'Trane HVAC controls'),
    OuiHint(('KmcControls',), ('kmccontrols',),
            (),
            _SP, 'high', 1,
            'KMC BAS controllers'),
    OuiHint(('DeltaControl',), ('deltacontrol',),
            ('deltacontrolgmbh', 'deltacontrols', 'deltacontrolsinc'),
            _SP, 'high', 2,
            'Delta Controls BAS'),
    OuiHint(('LOYTECelectr',), ('loytecelectr',),
            ('loytecelectronicsgmbh',),
            _SP, 'high', 1,
            'LOYTEC BAS'),
    OuiHint(('FrSauter', 'FrSauterAG'), ('frsauter', 'frsauterag'),
            (),
            _SP, 'high', 14,
            'Sauter BAS'),
    OuiHint(('BELIMOAutoma',), ('belimoautoma',),
            ('belimoautomationag',),
            _SP, 'high', 2,
            'Belimo actuators'),
    OuiHint(('SiemensHealt', 'SiemensBuild', 'SiemensEnerg', 'SiemensNumer'), ('siemensbuild', 'siemensenerg', 'siemenshealt', 'siemensnumer'),
            ('siemensagenergymanagementdivision', 'siemensaghealthcaresector', 'siemensbuilding',
              'siemensbuildingtechnologiesag', 'siemensenergyautomation', 'siemensenergyglobalgmbhcokg',
              'siemensenergyglobalgmbhcokggtprm', 'siemensenergyglobalgmbhkggtprm', 'siemenshealthcarediagnostics',
              'siemenshealthcarediagnosticsinc', 'siemenshealthcarediagnosticsmanufacturing',
              'siemenshealthcarediagnosticsmanufacturingltd', 'siemensnumericalcontrolltdnanjing',
              'siemensnumericalcontrolnanjing'),
            _SP, 'high', 13,
            "Siemens Healthcare / Building Technologies / Energy / CNC sub-OUIs (plain 'Siemens' is mixed)"),
    OuiHint(('SiemensIndus',), ('siemensindus',),
            ('siemensindustrialautomationproductschengdu', 'siemensindustrialautomationproductsltdchengdu',
              'siemensindustriesincretailcommercialsystems', 'siemensindustry', 'siemensindustryinc',
              'siemensindustrysoftwareinc'),
            _SP, 'medium', 9,
            'Siemens industrial automation sub-OUIs'),
    OuiHint(('AtenInternat',), ('ateninternat',),
            ('ateninternational', 'ateninternationalcoltd'),
            _SP, 'high', 1,
            'ATEN KVM-over-IP/PDU (Supermicro BMCs run ATEN firmware but carry Supermicro OUIs)'),
    OuiHint(('AmericanMega',), ('americanmega',),
            ('americanmegatrends', 'americanmegatrendsinc'),
            _SP, 'medium', 1,
            'AMI (MegaRAC BMC) OUI'),
    OuiHint(('GEMedicalSys', 'GEHealthcare'), ('gehealthcare', 'gemedicalsys'),
            ('gemedicalsystemchina', 'gemedicalsystemchinacoltd'),
            _SP, 'high', 3,
            'GE Healthcare'),
    OuiHint(('PhilipsMedic', 'PhilipsHealt'), ('philipshealt', 'philipsmedic'),
            ('philipshealthcarepcci', 'philipsmedicalsystemscardiacandmonitoringsystemscm'),
            _SP, 'high', 2,
            'Philips patient monitoring'),
    OuiHint(('BaxterIntern',), ('baxterintern',),
            ('baxterinternational', 'baxterinternationalinc'),
            _SP, 'high', 3,
            'Baxter infusion'),
    OuiHint(('BectonDickin', 'Carefusion'), ('bectondickin', 'carefusion'),
            ('bectondickinson', 'bectondickinsonandcompany'),
            _SP, 'high', 10,
            'BD/CareFusion (Alaris, Pyxis)'),
    OuiHint(('DraegerMedic', 'DrägerwerkaA'), ('draegermedic', 'drgerwerkaa'),
            ('draegermedical', 'draegermedicalsystems', 'draegermedicalsystemsinc', 'drgerwerkagcokgaa',
              'drgerwerkagkgaa'),
            _SP, 'high', 3,
            'Draeger medical'),
    OuiHint(('Mindray', 'MindrayDSUSA', 'MindrayNorth'), ('mindray', 'mindraydsusa', 'mindraynorth'),
            ('mindraycoltd', 'mindraydsusainc', 'mindraynorthamerica'),
            _SP, 'high', 4,
            'Mindray patient monitoring'),
    OuiHint(('Masimo',), ('masimo',),
            ('masimocorp', 'masimocorporation'),
            _SP, 'high', 8,
            'Masimo'),
    OuiHint(('HillRom', 'WelchAllyn'), ('hillrom', 'welchallyn'),
            ('welchallyninc',),
            _SP, 'high', 2,
            'Hillrom/Welch Allyn'),
    OuiHint(('NihonKohdenA',), ('nihonkohdena',),
            ('nihonkohdenamerica',),
            _SP, 'high', 1,
            'Nihon Kohden'),
    OuiHint(('SpacelabsMed',), ('spacelabsmed',),
            ('spacelabsmedical',),
            _SP, 'high', 1,
            'Spacelabs'),
    OuiHint(('FreseniusMed',), ('freseniusmed',),
            ('freseniusmedicalcare', 'freseniusmedicalcaredeutschlandgmbh', 'freseniusmedicalcarerdshanghaicoltd'),
            _SP, 'high', 3,
            'Fresenius dialysis'),
    OuiHint(('BBraunMelsun',), ('bbraunmelsun',),
            ('bbraunmelsungenag',),
            _SP, 'high', 1,
            'B. Braun infusion'),
    OuiHint(('ICUMedical',), ('icumedical',),
            ('icumedicalinc',),
            _SP, 'high', 2,
            'ICU Medical (Hospira) pumps'),
    OuiHint(('MedtronicCRM', 'MedtronicDia'), ('medtroniccrm', 'medtronicdia'),
            ('medtronicdiabetes',),
            _SP, 'high', 2,
            'Medtronic'),
    OuiHint(('ZOLLLifecor',), ('zolllifecor',),
            ('zolllifecorcorporation',),
            _SP, 'high', 1,
            'ZOLL'),
    OuiHint(('Verifone', 'VeriFone'), ('verifone',),
            ('verifoneinc', 'verifonesystemschinainc'),
            _SP, 'high', 7,
            'Verifone payment terminals'),
    OuiHint(('IngenicoTerm', 'Ingenico'), ('ingenico', 'ingenicoterm'),
            ('ingenicoterminalssas',),
            _SP, 'high', 6,
            'Ingenico payment terminals'),
    OuiHint(('PAXComputerT',), ('paxcomputert',),
            ('paxcomputertechnologyshenzhen', 'paxcomputertechnologyshenzhenltd'),
            _SP, 'high', 7,
            'PAX payment terminals'),
    OuiHint(('Square',), ('square',),
            ('squareinc',),
            _SP, 'high', 4,
            'Square terminals/registers'),
    OuiHint(('CloverNetwor',), ('clovernetwor',),
            ('clovernetwork', 'clovernetworkinc'),
            _SP, 'high', 2,
            'Clover POS'),
    OuiHint(('Ncr',), ('ncr',),
            ('ncrcorporation',),
            _SP, 'medium', 1,
            'NCR POS/ATM'),
    OuiHint(('Posiflex',), ('posiflex',),
            ('posiflexinc',),
            _SP, 'medium', 1,
            'Posiflex POS terminals (Windows/Android PCs)'),
    OuiHint(('Elotouchsolu',), ('elotouchsolu',),
            ('elotouchsolutions',),
            _SP, 'medium', 2,
            'Elo touch POS/kiosk'),
    OuiHint(('Suprema',), ('suprema',),
            ('supremainc',),
            _SP, 'high', 1,
            'Suprema biometric access control'),
    OuiHint(('GallagherGro',), ('gallaghergro',),
            ('gallaghergrouplimited', 'pecnz'),
            _SP, 'high', 2,
            'Gallagher access control'),
    OuiHint(('MercurySecur',), ('mercurysecur',),
            ('mercurysecurity', 'mercurysecuritycorporation'),
            _SP, 'high', 1,
            'Mercury access-control panels'),
    OuiHint(('CrossmatchTe', 'CrossMatchTe'), ('crossmatchte',),
            ('crossmatchtechnologies', 'crossmatchtechnologieshidglobal', 'crossmatchtechnologiesinc'),
            _SP, 'medium', 3,
            'Crossmatch/HID biometrics'),
    OuiHint(('PrusaResearc', 'Ultimaker', 'Formlabs'), ('formlabs', 'prusaresearc', 'ultimaker'),
            ('prusaresearchsro', 'ultimakerbv'),
            _SP, 'high', 3,
            '3D printers'),
    OuiHint(('KeysightTech', 'AgilentTechn', 'RohdeSchwarz', 'Tektronix', 'NationalInst'), ('agilenttechn', 'keysighttech', 'nationalinst', 'rohdeschwarz', 'tektronix'),
            ('agilenttechnologies', 'agilenttechnologiesinc', 'keysighttechnologies', 'keysighttechnologiesinc',
              'nationalinstruments', 'nationalinstrumentscorp', 'rohdeschwarzgmbhcokg', 'rohdeschwarzgmbhkg',
              'tektronixinc'),
            _SP, 'high', 10,
            'Test & measurement instruments'),
    OuiHint(('PeplinkInter',), ('peplinkinter',),
            ('peplinkinternational', 'peplinkinternationalltd'),
            _R, 'high', 4,
            'Peplink/Pepwave SD-WAN routers'),
    OuiHint(('TeltonikaNet',), ('teltonikanet',),
            ('teltonikanetworksuab',),
            _R, 'high', 1,
            'Teltonika Networks cellular routers (TSW switches/TAP APs minor)'),
    OuiHint(('Teltonika',), ('teltonika',),
            (),
            _R, 'medium', 1,
            'Teltonika (older allocation)'),
    OuiHint(('CradlePoint',), ('cradlepoint',),
            ('cradlepointinc',),
            _R, 'high', 2,
            'Cradlepoint cellular routers'),
    OuiHint(('Keenetic',), ('keenetic',),
            ('keeneticlimited',),
            _R, 'high', 2,
            'Keenetic routers'),
    # DrayTek 不列：Vigor 路由器、VigorAP、VigorSwitch 用同一批 OUI（198.51.100.2 的 VigorAP903 被判成路由器，
    # 對抗式驗證 2026-10-05）—— 要靠型號（Vigor2927／VigorAP 903／VigorSwitch）分
    OuiHint(('GLTechnologi',), ('gltechnologi',),
            ('gltechnologieshongkonglimited',),
            _R, 'medium', 1,
            'GL.iNet travel routers (GL.iNet Comet KVM is specialized)'),
    OuiHint(('HitronTechno',), ('hitrontechno',),
            ('hitrontechnologies', 'hitrontechnologiesinc', 'hitrontechnology', 'hitrontechnologyinc'),
            _R, 'medium', 33,
            'Hitron cable gateways'),
    OuiHint(('UbeeInteract',), ('ubeeinteract',),
            ('ubeeinteractivecolimited', 'ubeeinteractivelimited'),
            _R, 'medium', 14,
            'Ubee cable gateways'),
    OuiHint(('CompalBroadb',), ('compalbroadb',),
            ('compalbroadbandnetworks', 'compalbroadbandnetworksinc'),
            _R, 'medium', 9,
            'Compal Broadband cable gateways'),
    OuiHint(('MitraStarTec',), ('mitrastartec',),
            ('mitrastartechnology', 'mitrastartechnologycorp'),
            _R, 'medium', 21,
            'MitraStar ISP gateways/ONTs'),
    OuiHint(('PaloAltoNetw',), ('paloaltonetw',),
            ('paloaltonetworks',),
            _F, 'high', 40,
            'Palo Alto Networks firewalls'),
    OuiHint(('CheckPointSo',), ('checkpointso',),
            ('checkpointsoftwaretechnologies', 'checkpointsoftwaretechnologiesltd'),
            _F, 'high', 4,
            'Check Point gateways/management appliances'),
    OuiHint(('Deciso',), ('deciso',),
            ('decisobv',),
            _F, 'high', 1,
            'Deciso (OPNsense appliances)'),
    OuiHint(('Firewalla',), ('firewalla',),
            ('firewallainc',),
            _F, 'high', 1,
            'Firewalla'),
    OuiHint(('Stormshield',), ('stormshield',),
            (),
            _F, 'high', 1,
            'Stormshield'),
    OuiHint(('HillstoneNet',), ('hillstonenet',),
            ('hillstonenetworks', 'hillstonenetworkscorp', 'hillstonenetworksinc'),
            _F, 'high', 3,
            'Hillstone firewalls'),
    OuiHint(('Clavister',), ('clavister',),
            ('clavisterab',),
            _F, 'high', 1,
            'Clavister firewalls'),
    OuiHint(('Sophos',), ('sophos',),
            ('sophosltd',),
            _F, 'medium', 4,
            'Sophos XGS/SG; Sophos APX APs, switches and RED devices also exist'),
    OuiHint(('WatchGuardTe',), ('watchguardte',),
            ('watchguardtechnologies', 'watchguardtechnologiesinc'),
            _F, 'medium', 2,
            'WatchGuard Firebox; WatchGuard APs also exist'),
    OuiHint(('Sonicwall', 'SonicWall', 'SonicWALL'), ('sonicwall',),
            (),
            _F, 'medium', 7,
            'SonicWall; SonicWave APs and SonicWall switches also exist'),
    OuiHint(('BarracudaNet',), ('barracudanet',),
            ('barracudanetworks', 'barracudanetworksinc'),
            _F, 'medium', 1,
            'Barracuda CloudGen; also email/backup/WAF appliances'),
    OuiHint(('SangforTechn',), ('sangfortechn',),
            ('sangfortechnologies', 'sangfortechnologiesinc'),
            _F, 'medium', 1,
            'Sangfor NGAF; also SD-WAN, HCI, VDI appliances'),
    OuiHint(('LannerElectr',), ('lannerelectr',),
            ('lannerelectronics', 'lannerelectronicsinc'),
            _F, 'medium', 2,
            'Lanner white-box network/security appliances'),
    OuiHint(('Mist',), ('mist',),
            ('mistsystems', 'mistsystemsinc'),
            _A, 'high', 17,
            "Juniper Mist APs. Token 'mist' must be matched exactly"),
    OuiHint(('PlumeDesign',), ('plumedesign',),
            ('plumedesigninc',),
            _A, 'high', 1,
            'Plume pods'),
    OuiHint(('RuckusWirele',), ('ruckuswirele',),
            ('ruckuswireless',),
            _A, 'medium', 100,
            'Ruckus APs/controllers; some newer ICX switches carry Ruckus OUIs'),
    OuiHint(('CambiumNetwo',), ('cambiumnetwo',),
            ('cambiumnetworkslimited',),
            _A, 'medium', 9,
            'Cambium APs and PtP/PtMP radios; cnMatrix switches minor'),
    OuiHint(('EnGeniusTech',), ('engeniustech',),
            ('engeniustechnologies', 'engeniustechnologiesinc'),
            _A, 'medium', 2,
            'EnGenius APs; also switches'),
    OuiHint(('eero',), ('eero',),
            ('eeroinc',),
            _A, 'medium', 117,
            'eero mesh: every node is an AP, one of them is also the router'),
    OuiHint(('AirTiesWirel',), ('airtieswirel',),
            ('airtieswirelessnetworks',),
            _A, 'medium', 5,
            'AirTies mesh extenders (also ISP set-top boxes)'),
    OuiHint(('BrocadeCommu',), ('brocadecommu',),
            ('brocadecommunicationssystems', 'brocadecommunicationssystemsllc'),
            _S, 'high', 25,
            'Brocade FC SAN and ICX/VDX switches'),
    OuiHint(('AristaNetwor',), ('aristanetwor',),
            ('aristanetwork', 'aristanetworkinc', 'aristanetworks', 'aristanetworksinc'),
            _S, 'medium', 57,
            'Arista switches (Arista-branded APs/routers are a minority)'),
    OuiHint(('EdgecoreNetw', 'EdgeCoreNetw', 'EdgecoreAmer'), ('edgecoreamer', 'edgecorenetw'),
            ('edgecoreamericasnetworking', 'edgecoreamericasnetworkingcorporation', 'edgecorenetworks',
              'edgecorenetworkscorporation'),
            _S, 'medium', 31,
            'Edgecore switches (also APs/OLTs)'),
    OuiHint(('AlliedTelesi', 'Alliedtelesi'), ('alliedtelesi',),
            ('alliedtelesis', 'alliedtelesishongkong', 'alliedtelesishongkongltd', 'alliedtelesisinc',
              'alliedtelesisinternational', 'alliedtelesisinternationalcorporation', 'alliedtelesiskk',
              'alliedtelesislabs', 'alliedtelesislabsinc', 'alliedtelesislabsltd'),
            _S, 'medium', 15,
            'Allied Telesis switches (also APs/routers)'),
    OuiHint(('HirschmannAu', 'BeldenHirsch'), ('beldenhirsch', 'hirschmannau'),
            ('beldenhirschmannindustriessuzhoulimited', 'hirschmannaustriagmbh', 'hirschmannautomation',
              'hirschmannautomationandcontrolgmbh'),
            _S, 'medium', 10,
            'Hirschmann industrial switches (also EAGLE firewalls, BAT APs)'),
    OuiHint(('OnePlusTechn', 'OnePlusElect', 'OnePlusTech'), ('onepluselect', 'oneplustech', 'oneplustechn'),
            ('onepluselectronicsshenzhen', 'onepluselectronicsshenzhencoltd', 'oneplustechnologyshenzhen',
              'oneplustechnologyshenzhencoltd', 'oneplustechshenzhen', 'oneplustechshenzhenltd'),
            _MO, 'high', 21,
            'OnePlus phones/tablets'),
    OuiHint(('OppoMobileTe',), ('oppomobilete',),
            ('guangdongoppomobiletelecommunications', 'guangdongoppomobiletelecommunicationscorpltd'),
            _MO, 'high', 190,
            'OPPO phones'),
    OuiHint(('vivoMobileCo',), ('vivomobileco',),
            ('vivomobilecommunication', 'vivomobilecommunicationcoltd'),
            _MO, 'high', 170,
            'vivo phones'),
    OuiHint(('RealmeChongq',), ('realmechongq',),
            ('realmechongqingmobiletelecommunications', 'realmechongqingmobiletelecommunicationscorpltd'),
            _MO, 'high', 64,
            'realme phones'),
    OuiHint(('HMDGlobal',), ('hmdglobal',),
            ('hmdglobaloy',),
            _MO, 'high', 31,
            'HMD/Nokia phones'),
    OuiHint(('FairPhone', 'Fairphone'), ('fairphone',),
            ('fairphonebv',),
            _MO, 'high', 5,
            'Fairphone'),
    OuiHint(('NothingTechn',), ('nothingtechn',),
            ('nothingtechnologylimited',),
            _MO, 'high', 4,
            'Nothing phones'),
    OuiHint(('MotorolaMobi',), ('motorolamobi',),
            ('motorolamobilityalenovocompany', 'motorolamobilityllcalenovocompany',
              'motorolawuhanmobilitytechnologiescommunication', 'motorolawuhanmobilitytechnologiescommunicationcoltd'),
            _MO, 'high', 145,
            "Motorola Mobility (Lenovo) phones/tablets. NOT 'Motorola'/'MotorolaSolu' (radios, legacy cable gear)"),
    OuiHint(('TecnoMobile', 'Infinixmobil'), ('infinixmobil', 'tecnomobile'),
            ('infinixmobilitylimited', 'tecnomobilelimited'),
            _MO, 'high', 93,
            'Transsion TECNO/Infinix phones'),
    OuiHint(('MEIZUTechnol',), ('meizutechnol',),
            ('meizutechnology', 'meizutechnologycoltd'),
            _MO, 'high', 4,
            'Meizu phones'),
    OuiHint(('EssentialPro',), ('essentialpro',),
            ('essentialproducts', 'essentialproductsinc'),
            _MO, 'high', 1,
            'Essential phone'),
    OuiHint(('LenovoMobile',), ('lenovomobile',),
            ('lenovomobilecommunicationtechnology', 'lenovomobilecommunicationtechnologyltd',
              'lenovomobilecommunicationwuhancompanylimited'),
            _MO, 'high', 18,
            "Lenovo Mobile phones/tablets (plain 'Lenovo' is mixed)"),
    OuiHint(('NubiaTechnol',), ('nubiatechnol',),
            ('nubiatechnology', 'nubiatechnologycoltd'),
            _MO, 'high', 2,
            'nubia/RedMagic phones'),
    OuiHint(('TINNOMobileT', 'TinnoMobileT'), ('tinnomobilet',),
            ('shenzhentinnomobiletechnology', 'shenzhentinnomobiletechnologycorp'),
            _MO, 'high', 21,
            'TINNO phone ODM (Wiko etc.)'),
    OuiHint(('KyoceraWirel',), ('kyocerawirel',),
            ('kyocerawireless', 'kyocerawirelesscorp'),
            _MO, 'high', 2,
            'Kyocera Wireless phones'),
    OuiHint(('MicrosoftMob',), ('microsoftmob',),
            ('microsoftmobileoy',),
            _MO, 'high', 11,
            'Microsoft Mobile Oy (Lumia, legacy)'),
    OuiHint(('HonorDevice',), ('honordevice',),
            ('honordevicecoltd',),
            _MO, 'medium', 64,
            'HONOR phones/tablets (HONOR laptops exist)'),
    OuiHint(('HTC',), ('htc',),
            ('htccorporation',),
            _MO, 'medium', 29,
            'HTC phones; HTC Vive headsets also'),
    OuiHint(('BlackBerryRT',), ('blackberryrt',),
            ('blackberryrts',),
            _MO, 'medium', 13,
            'BlackBerry handsets (legacy)'),
    OuiHint(('LongcheerTel', 'LongcheerTec'), ('longcheertec', 'longcheertel'),
            ('longcheertechnologysingaporepte', 'longcheertechnologysingaporepteltd',
              'longcheertelecommunicationlimited', 'shanghailongcheertechnology', 'shanghailongcheertechnologycoltd'),
            _MO, 'medium', 7,
            'Longcheer phone/tablet ODM'),
    OuiHint(('WingtechMobi',), ('wingtechmobi',),
            ('wingtechmobilecommunications', 'wingtechmobilecommunicationscoltd'),
            _MO, 'medium', 8,
            'Wingtech phone/tablet ODM (also laptops)'),
    OuiHint(('HuaqinTeleco',), ('huaqinteleco',),
            ('huaqintelecomhongkongltd', 'huaqintelecomtechnology', 'huaqintelecomtechnologycoltd',
              'shanghaihuaqintelecomtechnology', 'shanghaihuaqintelecomtechnologycoltd'),
            _MO, 'medium', 8,
            'Huaqin Telecom phone ODM'),
    OuiHint(('PanasonicMob',), ('panasonicmob',),
            ('panasonicmobilecommunications', 'panasonicmobilecommunicationscoltd'),
            _MO, 'medium', 3,
            'Panasonic Mobile (Toughpad/phones)'),
    OuiHint(('FrameworkCom',), ('frameworkcom',),
            ('frameworkcomputer', 'frameworkcomputerinc'),
            _SV, 'high', 1,
            'Framework laptops (OS unknown: Windows or Linux)'),
    OuiHint(('Clevo',), ('clevo',),
            ('clevoco',),
            _SV, 'medium', 3,
            'Clevo laptop ODM (System76, Tuxedo, XMG ...)'),
    OuiHint(('LCFCElectron',), ('lcfcelectron',),
            ('lcfchefeielectronicstechnology', 'lcfchefeielectronicstechnologycoltd'),
            _SV, 'medium', 31,
            'LCFC = Lenovo laptop/desktop factory (Hefei)'),
)


class OuiMixed(NamedTuple):
    shorts: tuple[str, ...]
    tokens: tuple[str, ...]
    reason: str


# 熱門但「絕不可以單獨使用」的廠牌（同一家的 OUI 橫跨好幾種類型）。
OUI_MIXED_DO_NOT_USE: tuple[OuiMixed, ...] = (
    OuiMixed(('Intel',),
             ('intel',),
             'Wi-Fi/Ethernet in laptops, desktops, servers, NUCs, and the NICs of OPNsense/pfSense boxes and '
             "hypervisor hosts. Also a substring of 'intelbras' (cameras/routers) and every 'intelligent...' vendor"),
    OuiMixed(('RealtekSemic',),
             ('realteksemic',),
             'NIC/Wi-Fi chips in PCs, routers, cameras, TV boxes, USB adapters'),
    OuiMixed(('TpLinkTechno', 'TPLink'),
             ('tplink', 'tplinktechno'),
             'routers, APs (Omada EAP), switches (JetStream), Kasa/Tapo plugs and cameras, USB adapters'),
    OuiMixed(('Cisco', 'CiscoMeraki', 'CiscoSPVTG', 'CiscoLinksys'),
             ('cisco', 'ciscolinksys', 'ciscomeraki', 'ciscospvtg'),
             'switches, routers, firewalls, APs, phones, cameras (Meraki MV), set-top boxes (SPVTG), UCS vNIC pool '
             '00:25:B5'),
    OuiMixed(('HewlettPacka', 'HP'),
             ('hewlettpacka', 'hp'),
             "HPE servers/iLO, Aruba APs+switches (Aruba OUIs were re-registered to HPE, so 'aruba' never appears in "
             'manuf), HP Inc printers+laptops'),
    OuiMixed(('Dell', 'DellEMC', 'DellTechnolo'),
             ('dell', 'dellemc', 'delltechnolo'),
             'servers, iDRAC, laptops/desktops, switches, storage'),
    OuiMixed(('Apple',),
             ('apple',),
             'iPhone/iPad (mobile), Mac (server/general), Apple TV/HomePod (media), AirPort (AP)'),
    OuiMixed(('SamsungElect',),
             ('samsungelect',),
             'phones, TVs, appliances, printers (legacy), SmartThings'),
    OuiMixed(('HuaweiTechno', 'HuaweiDevice'),
             ('huaweidevice', 'huaweitechno'),
             'phones/tablets/laptops and routers, switches, APs, ONTs, LTE CPE'),
    OuiMixed(('XiaomiCommun', 'XiaomiMobile', 'XiaomiElectr'),
             ('xiaomicommun', 'xiaomielectr', 'xiaomimobile'),
             'phones, routers, TV boxes, Mi Home IoT, robot vacuums'),
    OuiMixed(('Microsoft',),
             ('microsoft',),
             'Surface (Windows), Xbox (media), Hyper-V guest NICs (00:15:5D)'),
    OuiMixed(('NVIDIA', 'Nvidia'),
             ('nvidia',),
             'Shield TV (media), Jetson, DGX/servers, ex-Mellanox NICs'),
    OuiMixed(('SuperMicroCo',),
             ('supermicroco',),
             'server LOMs and their BMCs share these OUIs (cannot tell host from BMC)'),
    OuiMixed(('ASUSTekCOMPU',),
             ('asustekcompu',),
             'routers, motherboards/laptops, phones (Zenfone)'),
    OuiMixed(('GigaByteTech',),
             ('gigabytetech',),
             'motherboards/servers and BMCs'),
    OuiMixed(('MicroStarINT', 'MicroStarInt'),
             ('microstarint',),
             'motherboards/laptops'),
    OuiMixed(('Lenovo',),
             ('lenovo',),
             'laptops, servers, XCC BMCs, tablets'),
    OuiMixed(('Ubiquiti',),
             ('ubiquiti',),
             'UniFi APs, switches, gateways (routers), cameras (Protect), NVRs'),
    OuiMixed(('Netgear',),
             ('netgear',),
             'routers, Orbi mesh, switches, APs, Arlo (legacy)'),
    OuiMixed(('DLinkInterna', 'DLink'),
             ('dlink', 'dlinkinterna'),
             'routers, switches, APs, cameras, NAS'),
    OuiMixed(('ZyxelCommuni',),
             ('zyxelcommuni',),
             'firewalls (USG/ATP), switches, APs, DSL/5G routers, NAS'),
    OuiMixed(('CalDigit',),
             ('caldigit',),
             'Thunderbolt docks: the NIC belongs to whatever laptop is docked'),
    OuiMixed(('PlugableTech', 'StarTechcom', 'UgreenGroup', 'ASIXElectron', 'AnkerEast'),
             ('ankereast', 'asixelectron', 'plugabletech', 'startechcom', 'ugreengroup'),
             "USB/Thunderbolt Ethernet adapters and docks: the NIC is a laptop's (UGREEN also sells NAS now)"),
    OuiMixed(('BelkinIntern',),
             ('belkinintern',),
             'Wemo plugs, Linksys routers made under Belkin, USB-C Ethernet adapters/docks'),
    OuiMixed(('AdvantechTec', 'Advantech'),
             ('advantech', 'advantechtec'),
             'industrial PCs (Windows/Linux), routers, IO, switches'),
    OuiMixed(('AzureWaveTec', 'MurataManufa', 'UniversalGlo', 'LiteonTechno', 'HonHaiPrecis', 'Wistron',
              'CompalInform', 'Pegatron', 'QuantaComput', 'Inventec', 'ChiconyElect'),
             ('azurewavetec', 'chiconyelect', 'compalinform', 'honhaiprecis', 'inventec', 'liteontechno',
               'muratamanufa', 'pegatron', 'quantacomput', 'universalglo', 'wistron'),
             'Wi-Fi module / ODM vendors that ship inside laptops, phones, TVs, consoles and IoT alike'),
    OuiMixed(('RaspberryPi', 'RaspberryPiT', 'RaspberryPiF'),
             ('raspberrypi', 'raspberrypif', 'raspberrypit'),
             'general-purpose SBC: servers (Pi-hole, Home Assistant), kiosks, media centres, cameras, PiKVM'),
    OuiMixed(('TexasInstrum',),
             ('texasinstrum',),
             'chips in phones, set-top boxes, IoT, BeagleBone'),
    OuiMixed(('MicrochipTec',),
             ('microchiptec',),
             'USB-Ethernet chips (Raspberry Pi 3B+/4 LAN78xx) and embedded MCUs'),
    OuiMixed(('QuectelWirel', 'SierraWirele'),
             ('quectelwirel', 'sierrawirele'),
             'cellular modules in laptops, routers, vehicles, POS'),
    OuiMixed(('Sony',),
             ('sony',),
             'Sony Corporation: Xperia phones, TVs, cameras, VAIO (legacy)'),
    OuiMixed(('LGElectronic', 'LgElectronic'),
             ('lgelectronic',),
             'TVs, phones (legacy), appliances, monitors'),
    OuiMixed(('AmazonTechno',),
             ('amazontechno',),
             'Echo/Fire TV (media) vs Kindle/Fire tablets (mobile); eero/Ring/Blink have their own OUIs'),
    OuiMixed(('Google',),
             ('google',),
             'Pixel phones, Nest speakers/displays, Chromecast, Nest Wifi, Nest cams'),
    OuiMixed(('Sharp', 'SHARP'),
             ('sharp',),
             'MFPs, AQUOS TVs and phones, appliances'),
    OuiMixed(('Yamaha',),
             ('yamaha',),
             'AV receivers/MusicCast and Yamaha RTX routers/SWX switches/WLX APs'),
    OuiMixed(('Siemens',),
             ('siemens',),
             'PLCs (specialized) but also SCALANCE switches/routers/APs and legacy Gigaset phones'),
    OuiMixed(('Buffalo',),
             ('buffalo',),
             'NAS (LinkStation/TeraStation) and AirStation Wi-Fi routers and switches'),
    OuiMixed(('AVMAudiovisu', 'AVM'),
             ('avm', 'avmaudiovisu'),
             'FRITZ!Box routers but also FRITZ!Repeater APs and Powerline bridges'),
    OuiMixed(('ZebraTechnol',),
             ('zebratechnol',),
             'label printers and Android rugged handhelds, RFID readers, legacy Motorola WLAN APs'),
    OuiMixed(('Intermec',),
             ('intermec',),
             'handheld computers and label printers'),
    OuiMixed(('Routerboardc',),
             ('routerboardc',),
             'MikroTik: routers, CRS/CSS switches, cAP/wAP APs (RouterOS says router, hardware varies)'),
    OuiMixed(('JuniperNetwo',),
             ('junipernetwo',),
             'SRX firewalls, EX/QFX switches, MX/PTX routers'),
    OuiMixed(('ExtremeNetwo',),
             ('extremenetwo',),
             'switches, APs (incl. ex-Aerohive), routers'),
    OuiMixed(('Fortinet',),
             ('fortinet',),
             'FortiGate firewalls, FortiAP, FortiSwitch, FortiCamera, FortiFone'),
    OuiMixed(('NewH3CTechno', 'H3CTechnolog'),
             ('hctechnolog', 'newhctechno'),
             'switches, routers, APs, servers, storage'),
    OuiMixed(('RuijieNetwor',),
             ('ruijienetwor',),
             'switches, APs, Reyee routers'),
    OuiMixed(('MellanoxTech',),
             ('mellanoxtech',),
             'server NICs and switches'),
    OuiMixed(('PLANETTechno',),
             ('planettechno',),
             'switches, cameras, routers, media converters'),
    OuiMixed(('AcctonTechno',),
             ('acctontechno',),
             'white-box ODM for many brands'),
    OuiMixed(('zte',),
             ('zte',),
             'phones and routers/ONTs/5G CPE'),
    OuiMixed(('Nokia', 'NokiaSolutio', 'NokiaShangha'),
             ('nokia', 'nokiashangha', 'nokiasolutio'),
             'phones (legacy), carrier routers, ONTs/Wi-Fi beacons'),
    OuiMixed(('SagemcomBroa', 'Arcadyan', 'AskeyCompute', 'Sercomm', 'GemtekTechno', 'ActiontecEle', 'Commscope',
              'VantivaUSA', 'Thomson', 'Calix', 'Adtran'),
             ('actiontecele', 'adtran', 'arcadyan', 'askeycompute', 'calix', 'commscope', 'gemtektechno',
               'sagemcombroa', 'sercomm', 'thomson', 'vantivausa'),
             'ISP CPE ODMs: gateways (router) but also set-top boxes, ONTs, extenders and white-label cameras'),
    OuiMixed(('HUMAX',),
             ('humax',),
             'set-top boxes and ISP gateways'),
    OuiMixed(('Arris',),
             ('arris',),
             'cable gateways and set-top boxes'),
    OuiMixed(('EltexEnterpr',),
             ('eltexenterpr',),
             'ONTs, switches, routers, phones, set-top boxes'),
    OuiMixed(('HGSTWesternD',),
             ('hgstwesternd',),
             'HGST drives/enterprise storage (rarely a LAN host)'),
    OuiMixed(('Nutanix',),
             ('nutanix',),
             '50:6B:8D is the AHV guest-VM MAC prefix: a virtual machine, not a host'),
    OuiMixed(('VMware',),
             ('vmware',),
             'virtual NICs of guests (00:50:56/00:0C:29/00:05:69/00:1C:14); 00:50:56 is also used by ESXi vmkernel '
             'ports'),
    OuiMixed(('ProxmoxServe',),
             ('proxmoxserve',),
             'BC:24:11 is the Proxmox VE guest-VM/CT MAC prefix'),
    OuiMixed(('Xensource', 'Parallels', 'PCSSystemtec'),
             ('parallels', 'pcssystemtec', 'xensource'),
             'virtual NICs (Xen 00:16:3E, Parallels 00:1C:42, VirtualBox 08:00:27)'),
    OuiMixed(('DeltaElectro',),
             ('deltaelectro',),
             'UPS/power supplies and Delta Networks ODM switches/APs'),
    OuiMixed(('Honeywell',),
             ('honeywell',),
             'building automation, scanners/handhelds, thermostats, cameras'),
    OuiMixed(('Motorola', 'MotorolaSolu'),
             ('motorola', 'motorolasolu'),
             'two-way radios, legacy cable modems/set-top boxes, Symbol handhelds'),
)

# 虛擬網卡的 MAC 前綴（類型不知道，但這是虛擬機／容器 —— 所以不會是印表機、攝影機、交換器、AP、電話、
# 實體虛擬化主機）。用前綴不用廠牌：這些廠牌本身是混合的。
OUI_VIRTUAL_NIC_PREFIXES: dict[str, str] = {
    "00:50:56": "VMware guest (also ESXi vmkernel ports vmk1+, so not proof of a guest on its own)",
    "00:0C:29": "VMware guest (auto-generated)",
    "00:05:69": "VMware (legacy)",
    "00:1C:14": "VMware (Horizon/legacy)",
    "00:15:5D": "Microsoft Hyper-V guest (also the Hyper-V host's internal/default switch vNICs)",
    "00:03:FF": "Microsoft Virtual PC / Virtual Server",
    "00:16:3E": "Xen / XCP-ng / XenServer guest",
    "08:00:27": "Oracle VirtualBox guest (manuf: PCSSystemtec)",
    "0A:00:27": "VirtualBox host-only adapter on the HOST (locally administered)",
    "00:1C:42": "Parallels guest",
    "BC:24:11": "Proxmox VE guest VM/CT (manuf: ProxmoxServe)",
    "50:6B:8D": "Nutanix AHV guest VM",
    "52:54:00": "QEMU/KVM/libvirt default (locally administered)",
    "00:18:51": "SWsoft / Virtuozzo / OpenVZ container",
    "00:21:F6": "Oracle VM Server for x86 guest",
    "02:42": "Docker default bridge (locally administered; 02:42:xx:xx:xx:xx)",
}
# Cisco UCS 把 00:25:B5 的位址池指派給「實體」刀鋒／機架伺服器的 vNIC：是伺服器，不是虛擬機。
OUI_PHYSICAL_POOL_PREFIXES: dict[str, str] = {"00:25:B5": "Cisco UCS service-profile vNIC pool (physical server)"}


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. 服務的產品字樣／banner 樣式
#    每個埠的每個文字「欄位」分開比對（不要串在一起 —— 一個欄位裡的排除條件不可以蓋掉另一個欄位的產品）：
#    (a) nmap 的 product＋version＋extrainfo，(b) http-title 的第一行，(c) http-server-header，
#    (d) Recog 的 service.product。不要餵 TLS 憑證的 CN／SAN（那是主機名稱），也不要餵 nmap 單純的服務
#    「名稱」（常常只是照埠號表猜的）。
#    依序比對，每個欄位「第一個符合的為準」。kind None ＝「認得的軟體，但說明不了是什麼設備」
#    （這種排除條件放在會被它誤觸發的設備樣式前面）。
#    condition："" ｜ "not_desktop_os"（作業系統家族是 macOS／Windows／iOS 時不套用）
#               ｜ "not_general_os"（作業系統家族是 Windows／macOS／iOS／Linux／BSD 時不套用）
#               ｜ "pve"（只限 Debian、不是虛擬機／容器、不是 Mail Gateway／Backup Server）
# ════════════════════════════════════════════════════════════════════════════════════════════════

class ServicePattern(NamedTuple):
    kind: str | None
    pattern: str
    confidence: str
    note: str
    examples: tuple[str, ...]
    counter: tuple[str, ...] = ()
    condition: str = ""


def _sp(kind: str | None, pattern: str, confidence: str, note: str, examples: Iterable[str],
        counter: Iterable[str] = (), condition: str = "") -> ServicePattern:
    return ServicePattern(kind, pattern, confidence, note, tuple(examples), tuple(counter), condition)


SERVICE_PRODUCT_PATTERNS: tuple[ServicePattern, ...] = (
    # ───────────── 排除條件：跑在一般主機上的軟體（或有歧義的）─────────────
    _sp(None, r"\bcups\b|easy software products|apple airprint server|\bpapercut\b", "high",
        "CUPS/PaperCut print servers run on Linux/macOS/Windows; not a printer",
        ["CUPS 2.4", "Easy Software Products CUPS", "Home - CUPS 2.4.2", "PaperCut MF"], ["HP LaserJet Pro M404"]),
    _sp(None, r"node[ _-]?exporter|prometheus|grafana", "high",
        "Prometheus node_exporter listens on 9100 (nmap's port table calls it jetdirect)",
        ["Prometheus node_exporter", "Node Exporter"]),
    _sp(None, r"powerchute|apcupsd|powerpanel\w*|"
              r"eaton (?:intelligent power|ipp|ipm)|network shutdown|poweralert (?:local|device manager)", "high",
        "UPS monitoring SOFTWARE on servers/PCs (PowerChute, apcupsd, PowerPanel, Eaton IPP/IPM, PowerAlert Local)",
        ["APC PowerChute Network Shutdown", "apcupsd", "PowerPanel Business Agent", "Eaton Intelligent Power Manager"],
        ["APC Network Management Card"]),
    _sp(_M, r"plex for roku", "high", "Plex client running ON a Roku", ["Plex for Roku"]),
    _sp(None, r"\bplex media server\b|\bplex\b|\bjellyfin\b|\bemby\b|logitech media server|\blyrion\b|"
              r"\bnavidrome\b|\bsubsonic\b|\bminidlna\b|\breadymedia\b|\bserviio\b", "high",
        "media SERVER applications: the host is a server/NAS/desktop, not a media device",
        ["Plex Media Server httpd", "Jellyfin", "Emby Server", "MiniDLNA 1.3"]),
    _sp(None, r"unifi (?:network|controller)(?! .*(?:switch|ap\b))|\bunifi os\b|ubiquiti unifi guest|"
              r"omada (?:software )?controller|omada sdn controller|\baruba central\b|airwave", "high",
        "Wi-Fi controller SOFTWARE (UniFi Network app, Omada Software Controller, AirWave) on servers/VMs/"
        "Cloud Keys; not an AP",
        ["UniFi Network", "UniFi Controller", "Omada Controller", "UniFi OS", "Aruba AirWave httpd"]),
    _sp(None, r"vmware (?:vcenter|virtualcenter|vsphere web client|horizon|view|vcloud|converter|srm|"
              r"site recovery|appliance management)|\bvcenter\b|\bvcsa\b|xen orchestra|\bxoa\b|"
              r"ovirt engine|xclarity administrator|openmanage enterprise|prism central|universal management suite|"
              r"global management system|\binsightiq\b|\bnetcache\b", "high",
        "virtualization MANAGEMENT appliances are VMs, not hypervisors",
        ["VMware VirtualCenter Web service", "VMware vCenter Server", "Xen Orchestra", "VMware Horizon"],
        ["VMware ESXi Server httpd"]),
    _sp(None, r"proxmox (?:mail gateway|backup server|datacenter manager)|\bpmg\b|\bpbs\b(?=.*proxmox)", "high",
        "PMG (also on 8006!) and PBS (8007) are Proxmox products that are NOT Proxmox VE",
        ["Proxmox Mail Gateway", "Proxmox Backup Server"]),
    _sp(None, r"esphome dashboard|home assistant supervisor", "high",
        "ESPHome Dashboard (6052) is the build server, not an ESP device", ["ESPHome Dashboard"]),
    _sp(None, r"\bblue ?iris\b|\bmilestone\b|\bxprotect\b|\bfrigate\b|\bzoneminder\b|\bshinobi\b|"
              r"\bmotioneye\b|agent dvr|\bispy\b|\bdigifort\b|\bgenetec\b|avigilon control center|\bhikcentral\b|"
              r"nx witness|dw spectrum|\bivms-?4200\b|synology surveillance station|\bqvr pro\b|\bdahua dss\b|"
              r"\bsecurityspy\b|exacqvision|\byawcam\b|\bdorgem\b|webcam 7|\bmotion(?:-httpd| webcam)\b|"
              r"\bateas\b|menuetos|\bsimplecam\b|\bcccam\b|\bnewcs\b|\boscam\b", "high",
        "video-management SOFTWARE (VMS/NVR apps on Windows/Linux/NAS) - pages say NVR/camera but the host is a "
        "server or NAS", ["Blue Iris", "Milestone XProtect", "Frigate", "ZoneMinder Console", "Avigilon Control Center httpd"]),
    _sp(None, r"\bpi-?hole\b|adguard home|\bportainer\b|\bdocker\b|\bnextcloud\b|\bminio\b|\bceph\b|\bwebmin\b|"
              r"\busermin\b|\bcockpit\b|\bzabbix\b|\blibrenms\b|\bnagios\b|\bprtg\b", "high",
        "server software; also runs on NAS/routers, so it says nothing about the device",
        ["Pi-hole", "AdGuard Home", "Portainer", "Webmin httpd", "MiniServ (Webmin)"]),
    _sp(_SV, r"home assistant|\bhass\.io\b|\bopenhab\b|node-?red|\bhomebridge\b|\bdomoticz\b|\bfhem\b|"
             r"\biobroker\b|zigbee2mqtt|\bscrypted\b", "medium",
        "home-automation software: a general-purpose host (Pi/NUC/VM) - IPAM convention: server",
        ["Home Assistant", "openHAB", "Node-RED", "Homebridge UI"]),
    _sp(None, r"\bzoiper\b|\bmicrosip\b|csipsimple|\bpjsua\b|\bpjsip\b|\bsipek\b|\blinphone\b|\bjitsi\b|"
              r"\bx-lite\b|\bbria\b|counterpath|ibm notes|\blotus\b|glassfish|\bwowza\b|\bdionaea\b|"
              r"\becholink\b|office communications server|\blync\b|skype for business|communigate", "high",
        "softphones and SIP-capable server software (desktop/server hosts, honeypots), not VoIP devices",
        ["Zoiper for Windows sipd", "MicroSIP sipd", "PJSIP pjsua sipd Darwin", "Dionaea Honeypot sipd"]),
    _sp(None, r"\bxlpd\b|netsarang|bartender|\bweprint\b|\bcirrato\b|\bubserver\b|printer driver", "high",
        "printing SOFTWARE on PCs/servers (NetSarang Xlpd, BarTender, WePrint, Cirrato)",
        ["NetSarang Xlpd HP LaserJet 4", "Seagull BarTender printer driver httpd", "WePrint printer sharing server"]),
    _sp(_MO, r"ip webcam android|\bip webcam httpd\b|android (?:phone|app)\b|\bairdroid\b|swiftp|wifi keyboard for android",
        "medium", "Android apps that expose a web server (IP Webcam, AirDroid): the device is a phone/tablet",
        ["IP Webcam Android app", "AirDroid httpd", "IP Webcam httpd"]),
    _sp(_W, r"microsoft[- ]iis|microsoft[- ]httpapi|microsoft windows (?:rpc|netbios|\d|xp|vista|longhorn|server|embedded)|"
            r"microsoft terminal services|windows remote management|\bwinrm\b", "medium",
        "IIS/http.sys/RPC/RDP only exist on Windows (beware: a reverse proxy can pass an IIS Server header through)",
        ["Microsoft IIS httpd 10.0", "Microsoft HTTPAPI httpd 2.0", "Microsoft Windows RPC"],
        ["Samba smbd 4.6.2", "xrdp"]),
    _sp(None, r"intel(?:\(r\))? (?:active management|standard manageability)|\bintel amt\b", "high",
        "Intel AMT/vPro (16992-16995, 623/664) lives inside desktops/laptops - NOT a BMC",
        ["Intel Active Management Technology User Notification Service", "Intel(R) Standard Manageability"]),

    # ───────────── 防火牆 ─────────────
    _sp(_F, r"\bopnsense\b", "high", "OPNsense web UI/favicon", ["Login | OPNsense", "OPNsense"]),
    _sp(_F, r"\bpfsense\b|netgate (?:\d{4}|appliance)", "high", "pfSense / Netgate", ["pfSense - Login", "Netgate 6100"]),
    _sp(_F, r"\bforti(?:gate|wifi|os)\b|fortinet fortigate|fortinet (?:firewall|ssl vpn)|fortiguard (?:http proxy|block)",
        "high", "FortiGate/FortiWiFi (NOT FortiMail/FortiManager/FortiAP/FortiSwitch/FortiClient)",
        ["Fortinet FortiGate 50B or FortiWifi 60C or 80C firewall http config", "FortiGate", "FortiOS"],
        ["FortiMail smtpd", "FortiClient firewall http config", "FortiAP"]),
    _sp(_F, r"\bpan-?os\b|palo ?alto (?:networks )?(?:firewall|pa-\d|panweb)|\bpanweb\b|globalprotect (?:portal|gateway)",
        "high", "Palo Alto PAN-OS / GlobalProtect portal (served by the firewall)",
        ["Palo Alto PanWeb httpd", "Palo Alto GlobalProtect Gateway httpd", "PAN-OS"]),
    _sp(_F, r"sophos (?:xgs?|utm|sg|firewall|sfos)|\bsfos\b|\bcyberoam\b|sophos (?:user|webadmin) portal", "high",
        "Sophos XG/XGS/UTM/SG, Cyberoam", ["Sophos UTM http proxy", "Sophos Firewall", "Cyberoam SSL VPN"],
        ["Sophos PureMessage spam filter http interface", "Sophos Message Router"]),
    _sp(_F, r"watchguard (?:fire(?:box|ware)|xtm|firewall|soho|http proxy|smtp proxy)|\bfireware\b|prosafe (?:\S+ )?(?:vpn )?firewall|\bfv[sx]\d{3}\b", "high",
        "WatchGuard Firebox/Fireware", ["WatchGuard Fireware XTM web UI", "WatchGuard Firebox http config"],
        ["WatchGuard Authentication Gateway SSO"]),
    _sp(_F, r"\bsonicos\b|sonicwall (?:firewall|nsa|tz\d|nsv|network security|ssl-?vpn|viewpoint)|"
        r"sonicwall\b(?!.*(?:email|sonicpoint|sonicwave))",
        "high", "SonicWall firewalls/SSL-VPN", ["SonicWALL firewall http config", "SonicOS", "SonicWall SSL VPN"],
        ["SonicWALL Email Security smtpd"]),
    _sp(_F, r"check ?point|firewall-1|\bfw-?1\b|\bgaia\b(?= (?:os|portal|r\d))|smartcenter|\bvpn-1\b", "high",
        "Check Point gateways/management", ["Check Point Firewall-1 httpd", "Check Point SVN foundation", "Gaia Portal"]),
    _sp(_F, r"barracuda (?:cloudgen|nextgen|ng) ?firewall|barracuda (?:web application )?firewall|barracudahttp",
        "high", "Barracuda CloudGen/NextGen/WAF (Barracuda spam/backup appliances are not firewalls)",
        ["Barracuda NextGen Firewall SSL VPN", "BarracudaHTTP"], ["Barracuda Backup 490 appliance http admin"]),
    _sp(_F, r"\buntangle\b|\bipfire\b|endian firewall|\bsmoothwall\b|\bipcop\b|\bclearos\b|\bzeroshell\b|"
            r"\bstormshield\b|\bnetasq\b|\bhillstone\b|sangfor (?:ngaf|af\b)|kerio control|\bclavister\b|"
            r"\bfirewalla\b|\bsecurepoint\b|\bgateprotect\b|\bforcepoint (?:ngfw|stonesoft)|\bstonesoft\b", "high",
        "other firewall distributions/appliances", ["IPFire", "Endian Firewall", "Smoothwall http proxy", "Stormshield"]),
    _sp(_F, r"\bsrx ?\d{3,4}\b|\bnetscreen\b|\bscreenos\b|juniper (?:srx|firewall)", "high",
        "Juniper SRX/NetScreen (plain Junos is NOT enough: EX/MX run it too)", ["Juniper SRX300", "NetScreen ScreenOS"]),
    _sp(_F, r"\bzywall\b|zyxel (?:usg|atp|zywall|vpn\d)|\busg ?flex\b|\bzld\b", "high",
        "Zyxel ZyWALL/USG/ATP (must precede the generic 'usg' UniFi pattern)",
        ["ZyXEL ZyWALL USG 200 firewall http config", "Zyxel USG FLEX 100"]),
    _sp(_F, r"cisco (?:asa|adaptive security appliance|firepower|ftd|pix)|\basdm\b|firepower threat defense|"
            r"meraki mx\b|cisco meraki firewall", "high", "Cisco ASA/FTD/PIX, Meraki MX",
        ["Cisco ASA firewall http config", "Cisco Adaptive Security Appliance", "Cisco Meraki firewall httpd"]),
    _sp(_F, r"scalance ?s(?:c)?\d|\bmguard\b|moxa edr|tofino", "high", "industrial firewalls (SCALANCE S, mGuard, Moxa EDR)",
        ["SCALANCE SC646-2C", "mGuard rs4000", "Moxa EDR-G903"]),

    # ───────────── 路由器 ─────────────
    _sp(_S, r"\bswos\b|mikrotik swos", "high", "MikroTik SwOS = switch (must precede RouterOS)", ["MikroTik SwOS"]),
    _sp(_R, r"\bmikrotik\b|\brouteros\b|\bwinbox\b|\brouterboard\b", "high",
        "MikroTik RouterOS (also on CRS switches/cAP APs, but RouterOS = router)",
        ["MikroTik RouterOS sshd", "MikroTik router config httpd", "MikroTik WinBox"]),
    _sp(_R, r"synology\s+router|\bsrm\b(?= \d|.*synology)|\brt(?:1900|2600)ac\b|\brt6600ax\b|\bwrx560\b", "high",
        "Synology SRM routers (must precede Synology NAS)", ["Synology Router Manager", "Synology RT2600ac"]),
    _sp(_S, r"\bqsw-\w+", "high", "QNAP QSW switches (must precede QNAP NAS)", ["QNAP QSW-M408-4C"]),
    _sp(_A, r"vigor ?ap", "high", "DrayTek VigorAP (must precede Vigor)", ["VigorAP 903"]),
    _sp(_S, r"vigor ?switch", "high", "DrayTek VigorSwitch (must precede Vigor)", ["VigorSwitch G1282"]),
    _sp(_R, r"\bvigor ?\d{3,4}|\b(?:draytek|vigor)\b.{0,40}\brouter\b", "high",
        "DrayTek Vigor routers: a model number or the word router (a bare 'DrayTek Vigor' title is also on VigorAP)",
        ["DrayTek Vigor ADSL router httpd", "Vigor2927"], ["DrayTek Vigor", "Vigor"]),
    _sp(_A, r"fritz!?\s?(?:repeater|wlan repeater)", "high", "FRITZ!Repeater", ["FRITZ!Repeater 1200"]),
    _sp(None, r"fritz!?\s?powerline", "high", "FRITZ!Powerline bridge", ["FRITZ!Powerline 1260E"]),
    _sp(_R, r"fritz!?\s?box|fritz!os", "high", "AVM FRITZ!Box (nmap also tags it WAP/VoIP adapter)",
        ["AVM FRITZ!Box 7590 sipd", "FRITZ!Box http config", "AVM FRITZ!OS SIP"]),
    _sp(_R, r"\bedge ?(?:os|router)\b|ubiquiti edge router|unifi (?:security gateway|dream (?:machine|router)|"
            r"cloud gateway|express|gateway)|\b(?:udm|udr|ucg|uxg)(?:[- ](?:pro|se|max|ultra|lite|fiber|\d+))*\b",
        "high", "EdgeRouter/EdgeOS and UniFi gateways",
        ["Ubiquiti Edge router httpd", "EdgeOS", "UniFi Dream Machine Pro", "UDM-Pro", "UCG-Ultra"]),
    _sp(_R, r"\bvyos\b|\bvyatta\b", "high", "VyOS/Vyatta", ["VyOS telnetd"]),
    _sp(_R, r"\bopenwrt\b|\bluci\b|\blede\b|\bdd-?wrt\b|freshtomato|tomatousb|advancedtomato|tomato (?:wap )?firmware|"
            r"\basuswrt\b|\bgargoyle\b|\bpadavan\b", "medium",
        "router firmwares (OpenWrt/DD-WRT/Tomato also run on dumb APs; nmap often says WAP)",
        ["OpenWrt uHTTPd", "LuCI Lua http config", "DD-WRT milli_httpd", "Tomato WAP firmware httpd", "ASUSWRT"]),
    _sp(_R, r"\bpeplink\b|\bpepwave\b|\bteltonika\b|\brutos\b|\brut(?:x|m)?\d{3}\b|\bcradlepoint\b|\bkeenetic\b|"
            r"gl\.?inet|\bgl-(?:mt|ar|axt|ax|be|sft|x|e|xe)\d{3,4}|\bmiwifi\b|\bkeeneticos\b", "high",
        "SD-WAN/cellular/travel routers", ["Peplink Balance 20X", "Teltonika RUT950", "GL.iNet Admin Panel"]),
    _sp(_R, r"\b(?:rt|gt|tuf|zenwifi)[- ][a-z]{0,4}\d{2,5}[a-z]*\b(?=.*asus)|asus (?:wireless )?router|asus wrt", "high",
        "ASUS routers (RT-AX88U, GT-AXE16000, ZenWiFi)", ["ASUS Wireless Router RT-AX88U", "ASUS WRT http admin"]),
    _sp(_R, r"netgear (?:\S+ )?router|\bnighthawk\b|\borbi\b(?! micro)|tp-?link (?:\S+ )?(?:wireless )?router|"
            r"\barcher [a-z]{0,2}\d{1,4}\b|\bdeco (?:m|x|xe|be|s)\d{1,3}\b|linksys (?:smart wi-?fi|router|velop|wrt)|"
            r"\bvelop\b|google ?wifi|nest ?wifi|\bonhub\b|\beero\b", "medium",
        "consumer routers / mesh systems (satellite nodes act as APs)",
        ["Netgear R7000 router http config", "TP-LINK Archer C7 router http config", "Linksys Smart Wi-Fi"]),
    _sp(_R, r"technicolor (?:tg|dga|cga)\d|sagemcom (?:f@st|fast)|\bf@st\b|\blivebox\b|\bspeedport\b|"
            r"vodafone station|\bbbox\b|\bfreebox server\b|zyxel (?:vmg|ex|dx|nbg|armor)\d|\bvmg\d{4}|"
            r"fiber ?(?:gateway|home gateway)|home gateway|tr-069", "medium",
        "ISP CPE / home gateways", ["Technicolor TG789vac", "Sagemcom F@st 5366", "Huawei EchoLife Home Gateway"]),
    _sp(_R, r"cisco (?:isr|asr|\d{3,4} series )?router|cisco ios[- ]?xr|\bios[- ]?xr\b|cisco (?:isr|asr) ?\d{3,4}|"
            r"juniper (?:mx|router)|\bnetvanta\b|huawei ar\d{3,4}|procurve secure router|hp (?:\S+ )?router\b|"
            r"\b(?:a-)?msr ?\d{2}", "high",
        "enterprise routers (plain 'Cisco IOS'/'Junos' are NOT enough: switches run them too)",
        ["Cisco ISR 4331", "Cisco IOS XR", "Juniper router http config"], ["Cisco IOS 15.2"]),
    _sp(_R, r"scalance ?m\d|moxa oncell|\bewon\b|red lion (?:rt|sixnet)|\bsixnet\b|insys icom", "medium",
        "industrial/cellular routers", ["SCALANCE M876-4", "Ewon Cosy 131"]),

    # ───────────── 無線 AP／控制器 ─────────────
    _sp(_A, r"catalyst 9800|\bc9800\b|cisco (?:\S+ )?wlan controller|cisco (?:wireless lan controller|wlc|aironet|mobility express|"
            r"embedded wireless controller)|\baireos\b|\baironet\b|meraki mr\d*|cisco (?:4402|4400|2500|5500) "
            r"(?:wlan|wireless)", "high", "Cisco WLC/Aironet/Meraki MR (Catalyst 9800 is a WLC, not a switch)",
        ["Cisco WLC sshd", "Cisco WLAN controller telnetd", "Cisco Catalyst 9800-L", "AireOS"]),
    _sp(_A, r"aruba (?:instant|iap|ap-?\d|rap|mobility (?:controller|conductor|master)|controller|wireless switch)|"
            r"instant on (?:ap|ap\d+)|\barubaos\b(?![- ]?(?:cx|s)(?:\b|_))|aruba networks ap", "high",
        "Aruba Instant/controllers (ArubaOS-CX/-S are switches)",
        ["Aruba RAP Console", "Aruba wireless switch http admin", "Aruba Instant On AP22"], ["ArubaOS-CX 10.10"]),
    _sp(_A, r"\bruckus\b(?! media)(?!.*\bicx\b)|smartzone|zone ?director|\bunleashed\b(?=.*ruckus)", "high",
        "Ruckus APs/controllers", ["Ruckus Wireless Admin", "SmartZone 100", "ZoneDirector 1200"]),
    _sp(_A, r"unifi (?:ap|access point|u6|u7|in-?wall)|\buap-(?:ac|nanohd|flexhd|iw|xg|lr|pro|lite|hd)\w*|"
            r"\bu[67]-(?:lite|lr|pro|mesh|enterprise|plus|iw|in-wall|ent)\w*", "high", "UniFi APs",
        ["UniFi AP-AC-Pro", "UAP-AC-Lite", "U6-LR"]),
    _sp(_A, r"\bairos\b|\bairmax\b|\bairfiber\b|\bnanostation\b|\bnanobeam\b|\blitebeam\b|\bpowerbeam\b|"
            r"\brocket ?(?:m|prism|ac)\d*\b|\bltu\b|\bwave ?(?:ap|pro)\b", "high", "Ubiquiti airOS/UISP radios",
        ["airOS", "NanoStation 5AC loco"]),
    _sp(_A, r"omada (?:eap|access point)|\beap ?(?:1\d\d|2\d\d|6\d\d|7\d\d)(?:[- ](?:hd|outdoor|wall|lite|pro))?\b",
        "medium", "TP-Link Omada EAP APs ('EAP' alone also means 802.1X EAP in RADIUS UIs)",
        ["Omada EAP245", "EAP660 HD"], ["EAP-TLS configuration"]),
    _sp(_A, r"\bengenius\b(?! esr)|\bmist (?:ap|systems)\b|juniper mist|\bcambium\b|\bcnpilot\b|\bepmp\b|"
            r"\bhiveos\b|\baerohive\b|\bfortiap\b|grandstream gwn ?7[6-9]\d\d|\bgwn76\d\d|netgear (?:wac|wax)\d{3}|"
            r"sophos apx|\bsonicwave\b|\bsonicpoint\b|procurve (?:ap|access point)\b|\bscalance ?w\d|moxa awk|\bvigorap\b", "high",
        "other AP vendors/products", ["EnGenius telnetd", "Juniper Mist AP43", "cnPilot e600", "FortiAP-231F"]),


    # ───────────── 交換器 ─────────────
    _sp(_S, r"cisco (?:catalyst|nexus|sg\d{3}|sf\d{3}|cbs\d{3}|small business (?:managed )?switch|ie-?\d{4})|"
            r"catalyst (?:switch|\d{4})|\bnx-?os\b|\bcatos\b|cisco (?:\S+ )?switch", "high", "Cisco switches",
        ["Cisco Catalyst switch http config", "Cisco SG300-28 Managed Switch", "Cisco Nexus NX-OS"]),
    _sp(_S, r"\bprocurve\b(?! (?:access point|ap\b|secure router|threat))|aruba ?os[- ]?(?:cx|s)(?:\b|_)|\baos-?(?:cx|s)\b|"
            r"aruba (?:cx|instant on) ?(?:\d{4}|switch)|hpe? (?:officeconnect|flexnetwork|flexfabric|\S+ switch)|"
            r"\bcomware\b(?!.*\brouter\b)|\bv1910\b|\b(?:1810|1820|1920s?|1950|5130|5900)-\d", "high",
        "HPE/Aruba/ProCurve/Comware switches", ["HP ProCurve Switch 2810-24G", "ArubaOS-CX 10.10", "HPE OfficeConnect Switch"]),
    _sp(_S, r"\bprosafe\b(?!.*(?:firewall|vpn))|netgear (?:\S+ ){0,2}switch|netgear (?:gs|gsm|xs|xsm|m4)\d|\bd-?link (?:\S+ )?switch|"
            r"\bd[gx]s-\d{3,4}|\bdes-\d{4}|tp-?link (?:\S+ )?switch|\bjetstream\b|\btl-sg\d{3,4}|"
            r"easy smart switch|omada (?:\S+ )?switch|\bedge ?switch\b|unifi (?:switch|usw)|\busw-[\w-]+|"
            r"\bus-\d{2}-\d{2,3}w?\b", "high", "SMB managed switches",
        ["NetGear GS724T switch http config", "D-Link DGS-1210-28", "TP-LINK Easy Smart switch admin httpd", "USW-Pro-24-PoE"]),
    _sp(_S, r"juniper (?:ex|qfx)\d|\b(?:ex|qfx)\d{4}(?:-[\w-]+)?\b|zyxel (?:\S+ )?switch|\b(?:xgs|gs|xs|xmg)\d{4}"
            r"(?:hp)?-\d+|arista (?:networks )?eos|\barista dcs-|\bpowerconnect\b|dell (?:emc )?networking|"
            r"\bos10\b|\bfastiron\b|\bicx ?\d{4}|brocade (?:icx|vdx|fabric os|\d{4} switch)|\bfabric ?os\b|"
            r"\bextremexos\b|(?<!calix )\bexos\b|\bvoss\b|h3c (?:s\d{4}|switch)|huawei (?:s\d{4}|cloudengine|quidway s)|"
            r"\balliedware\b|\bawplus\b|cumulus linux|\bsonic (?:os|switch)\b|fibre channel switch|\bfc switch\b|mellanox onyx|nvidia onyx", "high",
        "enterprise/DC switches", ["Juniper EX2300-24P", "Arista Networks EOS", "Brocade ICX 7150", "Dell PowerConnect 5524"]),
    _sp(_S, r"\bhirschmann\b|\bhios\b|scalance ?x[a-z]?\d|moxa (?:eds|ics|iks|sds|tsn)|\beds-\d{3}|\bfl switch\b|"
            r"\bstratix\b|westermo lynx|\bruggedcom\b|\brugged ?com\b", "high", "industrial switches",
        ["Hirschmann HiOS", "SCALANCE XC208", "Moxa EDS-510E", "Stratix 5700", "RUGGEDCOM RS900"]),


    # ───────────── 印表機 ─────────────
    _sp(_M, r"epson (?:eb-|powerlite|projector|web control)|\bpjlink\b|projector", "high",
        "Epson/other PROJECTORS (must precede Epson printers)", ["EPSON Web Control", "EPSON EB-L200F", "PJLink projector control"]),
    _sp(_C, r"canon (?:webview|vb-[a-z]|network camera)", "high", "Canon network cameras (must precede Canon printers)",
        ["Canon WebView VB150 http config"]),
    _sp(_P, r"jet ?direct|hp (?:laserjet|officejet|deskjet|designjet|pagewide|color laserjet|envy (?:\d|photo|inspire|pro)|"
            r"smart tank|neverstop|embedded web server|ews)|\blaserjet\b|\bofficejet\b|\bdeskjet\b|\bdesignjet\b|"
            r"\bpagewide\b|hp[- ]chaisoe|hp http server", "high", "HP printers (HP EWS, JetDirect)",
        ["HP JetDirect printer embedded httpd", "HP LaserJet Pro MFP config httpd", "HP Embedded Web Server", "HP HTTP Server"],
        ["HP iLO 5", "HP ProCurve Switch"]),
    _sp(_P, r"brother (?:hl|mfc|dcp|ql|pt|td|ads|printer|industries|ws-print)|\b(?:hl|mfc|dcp)-[a-z]{0,2}\d{3,4}|"
            r"\bdebut/\d", "high", "Brother ('debut/x.y' is Brother's embedded web server)",
        ["Brother HL-L2350DW series", "Brother printer smtpd", "debut/1.30"]),
    _sp(_P, r"canon (?:imagerunner|imageclass|i-sensys|lbp|mf\d|pixma|maxify|ipf|imageprograf|imagepress|ir-adv|"
            r"selphy|printer|.{0,20}remote ui)|\bremote ui\b|\bimagerunner\b|\bpixma\b|\bmaxify\b|canon http server",
        "high", "Canon printers ('Remote UI' is Canon's printer web UI)",
        ["Canon imageRUNNER 2520 printer http config", "Canon Pixma printer http config", "Remote UI"]),
    _sp(_P, r"epson (?:wf-|et-|xp-|l\d|workforce|ecotank|expression|stylus|aculaser|surecolor|tm-|ds-|artisan|"
            r"\S+ printer|ippd|print server|network print)|epsonnet|epson[_ -]linux upnp|epson-http", "high",
        "Epson printers/scanners", ["Epson WorkForce WF-2540 printer UPnP", "EpsonNet WebAssist printer configuration"]),
    _sp(_P, r"\bkyocera\b|\btaskalfa\b|\becosys\b|command center rx|km-mfp-http", "high", "Kyocera",
        ["Kyocera TASKalfa printer httpd", "Kyocera Mita FS-1350DN printer http config"]),
    _sp(_P, r"\bricoh\b(?! theta)|\baficio\b|web image monitor|\bsavin\b|\blanier\b|\bnashuatec\b|\bgestetner\b|"
            r"\binfoprint\b", "high", "Ricoh family ('Web Image Monitor' is Ricoh's UI)",
        ["Ricoh Aficio MP C4000 http config", "Web Image Monitor"]),
    _sp(_P, r"\bxerox\b|\bphaser(?:link)?\b|workcentre|(?<!westell )versalink|altalink|docucentre|docuprint|apeos(?:port)?|centreware|"
            r"primelink", "high", "Xerox / Fuji Xerox / FUJIFILM BI", ["Xerox WorkCentre 7855 http config", "Fuji Xerox DocuPrint ftpd"]),
    _sp(_P, r"\blexmark\b|\bmarknet\b|\boptra\b", "high", "Lexmark", ["Lexmark lpd service", "Lexmark Optra T610 printer http config"]),
    _sp(_P, r"konica ?minolta|\bbizhub\b|pagescope|\bmagicolor\b|\bineo\b", "high", "Konica Minolta",
        ["Konica Minolta bizhub printer http config", "Konica Minolta PageScope Web Connection"]),
    _sp(_P, r"sharp (?:mx-|ar-|bp-|\S+ printer|osa|printer)|e-studio|toshiba tec|topaccess|\bokidata\b|"
            r"oki (?:printer|mc\d|mb\d|c\d{3}|b\d{3}|es\d)|samsung (?:clp|clx|ml|scx|sl-|xpress|proxpress|multixpress)|"
            r"\bsyncthru\b|\bpantum\b|\bsindoh\b|\bbixolon\b|zebranet|zebra (?:\S+ )?printer|\bzt\d{3}\b|\bzd\d{3}\b|"
            r"\butax\b|triumph-adler|dell (?:\S+ )?(?:laser |color )?(?:mfp|printer)", "high", "other printer brands",
        ["Sharp MX-M350N printer smbd", "Samsung SyncThru Web Service", "ZebraNet", "Toshiba e-STUDIO"]),


    # ───────────── 攝影機／NVR ─────────────
    _sp(_C, r"\bhikvision\b|\bhik ?connect\b|\b(?:dnvrs|dvrdvs)-webs\b|\bapp-webs\b|hikvision-webs|"
            r"\bds-(?:2c|2d|2t|7[0-9]|9[0-9]|k)\w*|\bhilook\b|\bannke\b", "high",
        "Hikvision (and white labels). Note nmap tags Hikvision DVR services 'media device' - this wins",
        ["Hikvision DVR web UI", "HikVision NVR or camera http config", "DNVRS-Webs", "App-webs/"]),
    _sp(_C, r"\bdahua\b|\bdh-(?:ipc|nvr|xvr|hac|sd)|\bipc-h[df]w\w*|\bnvr\d{4}-|\bxvr\d{4}|\bimou\b|\blechange\b|"
            r"\bamcrest\b|\blorex\b|\bswann\b|\bnight owl\b", "high", "Dahua and Dahua OEMs",
        ["Dahua IP camera rtspd", "Amcrest IP camera http interface", "DH-IPC-HFW2431S"]),
    _sp(_P, r"\baxis\b.{0,40}print server|axis thinwizard", "high", "legacy AXIS print servers (before Axis cameras)",
        ["AXIS 560 print server", "AXIS 5600 print server http config"]),
    _sp(_C, r"\baxis\b(?!.*\baudio\b).{0,25}(?:camera|network (?:camera|video|dome)|video (?:server|encoder)|ptz|webcam|q\d{4}|"
            r"p\d{4}|m\d{4})|axis communications|\bvapix\b|\baxis \d{3,4}\b", "high", "Axis cameras/encoders",
        ["AXIS 207W or 212 PTZ network camera rtspd", "AXIS $1 camera httpd", "AXIS Q6155-E"], ["AXIS 560 print server"]),
    _sp(_C, r"\bhanwha\b|\bwisenet\b|samsung techwin|\b(?:snp|xnv|qnv|pnm|xnp|xno|qno|pno|xnd|qnd)-\d", "high",
        "Hanwha/Wisenet", ["Wisenet XNV-6080", "Samsung Techwin SNP-6320"]),
    _sp(_C, r"\buniview\b|\breolink\b|\brlc-\d{3}|\bfoscam\b|\bvivotek\b|\bmobotix\b|\bavigilon\b|\bpelco\b|"
            r"\bsarix\b|\barecont\b|\bacti\b.{0,20}(?:camera|nvr)|\bgeovision\b|\btiandy\b|\bmilesight (?:network "
            r"camera|nvr|ipc)|\bezviz\b|\bwyze ?cam\b|\bdoorbird\b|\biqinvision\b|\biqeye\b|\bdinion\b|\bautodome\b|"
            r"\bflexidome\b|\bvideojet\b|bosch (?:dinion|autodome|flexidome|video|divar)|\bi-pro\b|"
            r"panasonic (?:network camera|wv-|\S+ webcam)|\bwv-[a-z]{1,3}\d|sony (?:snc|network camera)|"
            r"\bsnc-[a-z]{1,3}\d|unifi (?:protect|video|nvr|g[3456]\b)|\buvc-g\d|\bunvr\b|tapo c\d{3}|"
            r"\bkguard\b|\bavtech\b(?!.*(?:room ?alert|tem ?pager|pager|router))|\bviostor\b|\bdedicated micros\b|"
            r"\bverkada\b|\brhombus\b", "high", "other camera brands/products",
        ["Vivotek Network Camera http config", "Reolink", "UniFi Protect", "Avigilon ONVIF camera rtspd"],
        ["Avigilon Control Center httpd"]),


    # ───────────── VoIP ─────────────
    _sp(_V, r"\basterisk\b|\bfreepbx\b|\bissabel\b|\belastix\b|\bvitalpbx\b|\bfusionpbx\b|\bfreeswitch\b|\b3cx\b|"
            r"\byeastar\b|\bucm\d{4}|\bkamailio\b|\bopensips\b|cisco unified communications manager|\bcucm\b|"
            r"\bwazo\b|\bip-?pbx\b|\bpbx\b|avaya (?:aura|communication manager|ip office)|\bmitel\b|\bshoretel\b|"
            r"\bcallpilot\b|\bipecs\b|panasonic kx-(?:ns|ncp|tde|tda)|\bkx-(?:ns|ncp|tde|tda)\d", "high",
        "PBX software/appliances (IPAM convention: PBX=voip; on a VM the guest rule turns it into server)",
        ["Asterisk PBX httpd", "FreePBX", "3CX PhoneSystem PBX", "Cisco Unified Communications Manager"]),
    _sp(_V, r"\byealink\b|\bsip-t\d{2}[a-z]?\b|\bpolycom\b|\bpoly (?:vvx|ccx|edge|trio|studio|g7500|x[357]0)\b|"
            r"\bvvx ?\d{3}|\bsoundpoint\b|\bsoundstation\b|realpresence|\bgrandstream\b(?! gwn)|\bgxp ?\d{4}|"
            r"\bgrp ?\d{4}|\bgxv-?\d{4}|\bht ?8\d\d\b|\bdp ?7\d\d\b|\bwp8\d\d\b|cisco (?:spa|ip phone|unified (?:ip|sip) "
            r"phone|cp-\d{4}|ata ?\d{3})|\bspa ?\d{3}[a-z]?\b|\bsipura\b|linksys spa|\bsnom\b|\bfanvil\b|"
            r"\bgigaset\b(?! m7\d\d)(?!.*\b(?:wap|router|se\d{3}|sx\d{3})\b)|\bobi(?:hai)? ?\d{3}\b|\bobihai\b|avaya (?:\d{4}|j\d{3}|ip phone|e1\d\d)|\baastra\b|"
            r"\bhtek\b|\baudiocodes\b|\bmediapack\b|\bmediant\b|\bsmartnode\b|\balgo (?:\d{4}|sip)|\bcyberdata\b|"
            r"\bakuvox\b|2n (?:ip|helios)|\bspectralink\b|panasonic kx-(?:hdv|ut|tgp)|\bkx-(?:hdv|ut|tgp)\d|"
            r"\bescene\b|\bflyingvoice\b|\bdigium\b", "high", "IP phones/ATAs/intercoms/gateways",
        ["Yealink VoIP phone httpd", "Polycom SoundPoint VoIP phone http config", "Grandstream GXP2000 http config",
         "Cisco SPA112 VoIP adapter http config", "Snom 300 VoIP phone http config"],
        ["Grandstream GWN7660"]),


    # ───────────── 儲存設備 ─────────────
    _sp(_ST, r"\bsynology\b|\bdiskstation\b|\brackstation\b|\bbeestation\b|\bdsm \d|\bqnap\b|\bqts\b|"
             r"\bquts ?hero\b|\btruenas\b|\bfreenas\b|\bxigmanas\b|\bnas4free\b|\bixsystems\b|\bunraid\b|"
             r"openmediavault|\basustor\b|\bterramaster\b|\breadynas\b|\braidiator\b|\blinkstation\b|"
             r"\bterastation\b|wd ?my ?cloud|\bmy ?cloud (?:ex|pr|home|mirror)|\bdrobo\b|\bthecus\b|"
             r"zyxel nas\d|\bseagate (?:nas|personal cloud|goflex)", "high", "NAS families",
        ["Synology DiskStation NAS ftpd", "QNAP NAS http config", "TrueNAS", "Lime Technology unRAID Server httpd"]),
    _sp(_ST, r"\bnetapp\b(?! (?:netcache|bluexp|dfm|oncommand|cloud manager))|\bdata ontap\b|\bontap\b|\bpure ?storage\b|\bisilon\b|\bonefs\b|\bpowerscale\b|"
             r"\bpowerstore\b|\bdata ?domain\b|\bpowervault\b|\bequallogic\b|\bcompellent\b|\bvnx\b|\bvmax\b|"
             r"\bcelerra\b|\b3par\b|\bstoreonce\b|\bmsa ?\d{4}\b|\bprimera\b|\balletra\b|\bstorageworks\b(?!.*switch)|"
             r"\bhitachi (?:vsp|hnas)|\binfortrend\b|\beonstor\b|\bqsan\b|\bstorwize\b|\bflashsystem\b|"
             r"\btape (?:library|autoloader)\b|\bstoreever\b|\bscalar i\d|\bvtrak\b|\bbarracuda backup\b|"
             r"\bdatto\b|\bexagrid\b|\bnimble storage\b|\btintri\b", "high", "enterprise storage / backup appliances",
        ["NetApp Data ONTAP sshd", "Pure Storage", "HP StorageWorks tape autoloader telnetd", "Barracuda Backup 490 appliance http admin"]),

    # ───────────── 虛擬化主機 ─────────────
    _sp(_H, r"vmware esxi?\b|\besxi\b|vmware hostd|vmware (?:esx|server \d)|vmware authentication daemon", "high",
        "ESXi (902/authd also exists on Windows/Linux hosts running VMware Workstation - check OS)",
        ["VMware ESXi Server httpd", "VMware ESXi 4.1 Server httpd", "VMware Authentication Daemon"],
        ["VMware VirtualCenter Web service"], "not_desktop_os"),
    _sp(_H, r"proxmox (?:virtual environment|ve)\b|proxmox ve|\bpve-?manager\b|proxmox", "high",
        "Proxmox VE (guards above remove PMG/PBS/PDM); only on Debian and not inside a VM/CT",
        ["Proxmox Virtual Environment REST API", "Proxmox VE"], ["Proxmox Mail Gateway"], "pve"),
    _sp(_H, r"\bxcp-?ng\b|\bxenserver\b|citrix hypervisor|xen cloud platform|\bxapi\b|citrix xen simple http", "high",
        "XCP-ng/XenServer", ["XenServer", "Xen Cloud Platform httpd", "XCP-ng"]),
    _sp(_H, r"\bhyper-v server\b|microsoft hyper-v|\bnutanix\b|\bacropolis\b|\bahv\b|prism element|ovirt node|"
            r"\brhvh\b|\blibvirt\b|\bharvester\b|\bsmartos\b|virtuozzo hybrid server", "medium",
        "other hypervisors (Nutanix Prism lives on the CVM, a VM next to the host - medium)",
        ["Microsoft Hyper-V Server 2019", "Nutanix Prism Element", "libvirt"]),

    # ───────────── BMC／頻外管理／KVM／console ─────────────
    _sp(_SP, r"\bidrac\d*\b|integrated dell remote access|dell remote access controller|\bdrac ?\d\b|"
             r"chassis management controller|integrated lights-?out|\bilo ?\d\b|hpe?[- ]ilo\b|onboard administrator|"
             r"remote insight lights-out|\bilom\b|integrated lights out manager|advanced lights out|"
             r"\bxclarity controller\b|\bxcc\b(?=.*lenovo)|integrated management module|\bimm2\b|\bopenbmc\b|"
             r"\bmegarac\b|american megatrends|\bcimc\b|cisco integrated management controller|\birmc\b|\bibmc\b|"
             r"asrock ?rack|supermicro (?:bmc|ipmi)|\bipmi\b|\bbmc\b(?= (?:web|ui|login|firmware))|"
             r"bladecenter (?:advanced )?management module|virtual connect manager|stratus ftserver (?:vtm|virtual)", "high",
        "BMC/out-of-band controllers", ["Dell iDRAC http admin", "HP Integrated Lights-Out http config",
                                         "SuperMicro IPMI advertiserd", "Lenovo XClarity Controller", "MegaRAC SP-X",
                                         "HPE-iLO-Server/1.0"]),
    _sp(_SP, r"\bpikvm\b|\btinypilot\b|\bjetkvm\b|\bnanokvm\b|\bblikvm\b|gl\.?inet comet|raritan dominion|"
             r"\bdominion (?:kx|sx|px)\b|avocent (?:dsr|mergepoint|acs|autoview|switchview)|lantronix spider|"
             r"kvm[- ]over[- ]ip|\bip ?kvm\b|aten (?:cn|kn|kh|kvm)|\baten kvm\b|\bopengear\b|"
             r"lantronix (?:slc|eds|uds|xport|mss|ets)|digi (?:connect|portserver|passport|anywhereusb|realport|etherlite)|"
             r"perle (?:iolan|scs)|\bcyclades\b(?!.*router)|(?<!management )console server|serial (?:device|terminal) server|"
             r"(?<!windows )terminal server|avocent\b.{0,20}kvm|(?<!synergy )\bkvm switch\b", "high",
        "KVM-over-IP and console/device servers", ["ATEN KVM-over-IP VNC", "Raritan Dominion SX32 http config", "PiKVM"]),

    # ───────────── 電力 ─────────────
    _sp(_SP, r"network management card|\bapc\b.{0,30}(?:nmc|ups|pdu|smart-?ups|back-?ups|aos|web/snmp)|\baos\b(?= \d.*apc)|"
             r"\bpowernet\b|\bnetbotz\b|\beaton\b.{0,30}(?:ups|pdu|network-?m2|gigabit network card|epdu|powerware|"
             r"management card|rack monitor)|\bpowerware\b|\bconnectups\b|\bcyberpower\b|\brmcard\d*\b|\bliebert\b|"
             r"\bintellislot\b|\bvertiv\b|\bgeist\b|\braritan\b|server technology|\bsentry\b.{0,20}(?:cdu|pdu|switched|ups)|"
             r"tripp ?lite (?:snmpwebcard|webcardlx|pdu|ups)|\bwebcardlx\b|\bsnmpwebcard\b|\bnetio\b|digital loggers|"
             r"web power switch|\bgude\b|expert power control|net-?pwrctrl|\bsynaccess\b|\bwti\b.{0,10}(?:nps|ips|vmr)|"
             r"\bpanduit\b|\benlogic\b|\bschleifenbauer\b|\bsocomec\b|\bnet ?vision\b|\briello\b|netman 20\d|"
             r"para systems sentry|\beltek\b|masterswitch|network power switch|netagent", "high",
        "UPS/PDU cards, power switches and monitors (after the PowerChute/apcupsd guard)",
        ["APC network management card telnetd", "APC AOS ftpd", "CyberPower sshd", "Digital Loggers Web Power Switch",
         "Eaton Powerware Environmental Rack Monitor httpd"], ["APC PowerChute Network Shutdown"]),
    _sp(_SP, r"\bfronius\b|solar-?log|sunny (?:webbox|boy|tripower|home manager|island)|\bsma (?:sunny|webbox|inverter)|"
             r"\benphase\b|\benvoy\b(?=.*enphase)|\bsolaredge\b|\bsun2000\b|\bgoodwe\b|\bvictron\b|\bvenus os\b|"
             r"\bopendtu\b|\bahoy ?dtu\b|\bhuawei smartlogger\b|\bpowerwall\b|\bwallbox\b|\bzaptec\b|\beasee\b|"
             r"\bopenevse\b|\bgo-?echarger\b|\bjuicebox\b|wall connector|\bkeba\b|\bchargepoint\b", "high",
        "solar, battery and EV-charger controllers", ["SMA Sunny WebBox", "Fronius Datamanager", "SolarLog 400e power monitor httpd"]),

    # ───────────── 影音 ─────────────
    _sp(_M, r"\broku\b|\bsonos\b|chromecast|google ?cast|\bcastv2\b|google (?:home|nest) (?:mini|hub|audio|max)|"
            r"nest (?:audio|hub|mini)|apple ?tv|\bhomepod\b|\btvos\b|\baudioos\b|\bwebos\b(?=.*tv)|"
            r"lg (?:webos )?(?:smart )?tv|samsung (?:smart )?tv|\btizen\b(?=.*tv)|\bbravia\b|android ?tv|google ?tv|"
            r"fire ?tv|\bvizio\b|\bsmartcast\b|\bvidaa\b|philips (?:tv|android tv)|\bjointspace\b|\bsaphi\b|"
            r"sharp tv|\bplaystation\b|\bxbox\b|nintendo (?:switch|wii|3ds)|\bwii ?u\b|\bsteam ?deck\b|steam ?link|"
            r"\bdreambox\b|\benigma2\b|\bopenwebif\b|\bvu\+|\bzgemma\b|\btivo\b|\bslingbox\b|\bhdhomerun\b|"
            r"\bsilicondust\b|nvidia shield|\bmediaroom\b|\bdirectv\b|\binfomir\b|\bformuler\b|set[- ]top box", "high",
        "streaming players, TVs, consoles, set-top boxes",
        ["Roku remote API", "Sonos speaker rtspd", "Google Chromecast httpd", "LG webOS TV", "Xbox 360 XML UPnP"],
        ["Plex Media Server httpd"]),
    _sp(_M, r"\bdenon\b|\bmarantz\b|\bheos\b|yamaha (?:rx-|cx-|aventage|musiccast|av receiver|net radio)|\bmusiccast\b|"
            r"\bonkyo\b|pioneer (?:vsx|sc-|\S+ av|icontrolav)|bose soundtouch|\bsoundtouch\b|\bbluesound\b|"
            r"bang ?& ?olufsen|\bbeosound\b|\bbeoplay\b|\blinn (?:ds|kazoo)\b|\bnaim (?:uniti|mu-so)\b|"
            r"frontier silicon|\bundok\b|\bvolumio\b|\bmoode\b|\bsqueezebox\b|\bpiCorePlayer\b|\bshairport\b|"
            r"\bspotify connect\b|\bkodi\b|\bxbmc\b|libreelec|coreelec|\bosmc\b", "high",
        "AV receivers, network audio, media centres (Kodi on a PC is still a media centre)",
        ["Denon AVR-X2700H", "Yamaha Net Radio", "XBMC JSON-RPC", "Kodi upnpd"]),
    _sp(_M, r"\bbrightsign\b|\bclickshare\b|\bsolstice ?pod\b|\bairmedia\b|christie (?:projector|griffyn|\S+ projector)|"
            r"\boptoma\b|benq (?:\S+ )?projector|nec (?:projector|display)|\bbarco\b(?! control rooms)|\bextron\b|"
            r"crestron (?:dm-|nvx|airmedia|tsw|tss|uc-|flex|mercury)|\bkaptivo\b|digital signage|\batlona\b|"
            r"(?:video|matrix|hdmi) switch", "high",
        "signage, projectors, meeting-room AV", ["BrightSign Digital Signage Player", "Barco ClickShare", "Extron MediaLink Controller"]),
    _sp(_M, r"\bairplay\b|\bairtunes\b|\braop\b", "medium",
        "AirPlay receivers: Apple TV/HomePod/speakers/TVs - but macOS 12+ also runs an AirPlay receiver (5000/7000)",
        ["Apple AirTunes rtspd", "AirTunes rtspd", "Apple AirPlay httpd"], (), "not_desktop_os"),

    # ───────────── 工控／樓宇／醫療／POS／智慧家庭（專用設備）─────────────
    _sp(_SP, r"\bsimatic\b|\bs7-?(?:200|300|400|1200|1500)\b|siemens (?:s7|cpu ?\d{3,4}|logo!?|sentron|sinamics|sinumerik|"
             r"desigo|apogee)|\blogo!\s?8|\bsitop\b|\bsicam\b|\bsiprotec\b|allen-?bradley|rockwell automation|"
             r"\bcontrollogix\b|\bcompactlogix\b|\bmicrologix\b|\bpowerflex\b|\bpanelview\b|\b17(?:56|69|66|63)-|"
             r"\bmodicon\b|schneider electric|\bpowerlogic\b|\becostruxure\b|\bmelsec\b|mitsubishi (?:plc|melsec|"
             r"\S+ plc)|\bomron\b(?! healthcare)|\bsysmac\b|\bbeckhoff\b|\btwincat\b|\bwago\b|\bpfc ?(?:100|200)\b|"
             r"phoenix contact|\bplcnext\b|moxa (?:nport|mgate|iologik|uc-)|\bnport\b|\bmgate\b|\biologik\b|"
             r"moxahttp|\bfanuc\b|\bb&r\b|\bhilscher\b|\bpilz\b|\bfesto\b|\bkeyence\b|"
             r"\bcognex\b|\bin-sight\b|banner engineering|\bturck\b|\bdanfoss\b|\babb robotics\b|\bcomau\b|"
             r"red lion (?:crimson|g3|data station)|\bgot ?\d{4}\b|\bjace\b|"
             r"johnson controls|\bmetasys\b|\bdistech\b|delta controls|\benteliweb\b|reliable controls|"
             r"\bloytec\b|\bsauter\b|\bbelimo\b|trane tracer|\btracer (?:sc|summit|ensemble)\b|\bloxone\b|"
             r"\bwebs-?ax\b|\bhoneywell (?:excel|spyder|webs|optimizer)", "high",
        "PLC/HMI/IO/BAS controller brands and products",
        ["MoxaHttp", "Siemens SIMATIC S7-1200", "Allen-Bradley 1766-L32BXB PLC", "Mitsubishi Q-series PLC ftpd"]),
    _sp(_SP, r"\bmodbus\b|\bbacnet\b|ethernet/ip|\bprofinet\b|\bdnp3\b|iec[- ]?(?:60870|61850)|\bknx(?:net)?\b|"
             r"\blonworks\b|\bcodesys\b|\bs7comm\b|\bopc[- ]?ua\b|niagara (?:ax|4|n4|fox|supervisor)\b|\btridium\b|\bfins\b(?= ?(?:udp|tcp))",
        "medium", "industrial/BAS PROTOCOL names: SCADA/BMS servers (Windows/Linux) speak them too",
        ["Modbus TCP", "BACnet building automation", "Tridium Niagara httpd"], (), "not_general_os"),
    _sp(_SP, r"\balaris\b|\bbaxter\b|sigma spectrum|\bmindray\b|\bdraeger\b|\bdräger\b|\bintellivue\b|"
             r"ge (?:carescape|dash|datex)|\bcarescape\b|\bspacelabs\b|welch allyn|\bomnicell\b|\bpyxis\b|"
             r"b\. ?braun|\bspaceom\b|\bfresenius\b|\bmasimo\b|nihon kohden|\bverifone\b|\bingenico\b|"
             r"pax (?:a\d{2,3}|s\d{2,3}|technology)|clover (?:station|mini|flex)|square (?:register|terminal|stand)|"
             r"ncr (?:aloha|radiant|realpos)|micros (?:workstation|simphony)|toshiba (?:tcx|4690)|ibm 4690|"
             r"\bposiflex\b|wincor nixdorf|\bdiebold\b", "high", "medical devices, payment/POS terminals, ATMs",
        ["Baxter SIGMA Spectrum", "Verifone MX915", "Wincor Nixdorf ATM service"]),
    _sp(_SP, r"hid (?:vertx|edge|mercury)|\bmercury (?:lp|ep)\d{4}|\blenel\b|s2 (?:netbox|access)|\bzkteco\b|"
             r"\bzksoftware\b|\bsuprema\b|\bbiostar\b(?! 2 server)|\bpaxton\b|gallagher controller|"
             r"bosch (?:alarm|b\d{4}|g series)|dsc (?:neo|powerseries)|honeywell (?:vista|galaxy)|\bajax hub\b|"
             r"dmp xr\d|\bnapco\b|\bsatel\b|\benvisalink\b|istar (?:ultra|pro|edge)|(?<!wireless )access control|alarm (?:panel|system)|"
             r"room ?alert|\bakcp\b|\bsensorprobe\b|\bhw ?group\b|\bposeidon\b|\bdamocles\b|\bsensatronics\b|"
             r"comet (?:system|web sensor)|\bpapouch\b|\bmeinberg\b|\blantime\b|\bsymmetricom\b|\bsyncserver\b|"
             r"\bkeysight\b|\bagilent\b|rohde ?& ?schwarz|\btektronix\b(?!.*(?:printer|phaser))|national instruments|\blabview\b|\blxi\b|"
             r"\boctoprint\b|\bmoonraker\b|\bmainsail\b|\bfluidd\b|\bklipper\b|prusa ?(?:link|connect)|"
             r"\bultimaker\b|bambu ?lab|duet ?web ?control|\brepetier\b", "high",
        "access control/alarms, environmental sensors, time servers, lab instruments, 3D printers",
        ["ZKSoftware ZEM500 fingerprint reader telnetd", "AVTECH Room Alert", "Meinberg LANTIME", "OctoPrint"]),
    _sp(_SP, r"philips hue|\bhue (?:bridge|personal wireless lighting)\b|\btasmota\b|\besphome\b|\bshelly\b|\bwled\b|"
             r"\bopenbeken\b|tp-?link (?:smart plug|kasa)|\bkasa smart\b|tapo (?:p|l|h|s)\d{3}|\bwemo\b|"
             r"\bnanoleaf\b|\blifx\b|wiz connected|\bgovee\b|\byeelight\b|\bmeross\b|\bsonoff\b|\bewelink\b|\btuya\b|"
             r"\bbroadlink\b|\bhubitat\b|\bsmartthings\b|\bhomey\b|vera ?(?:edge|plus|secure)|\bezlo\b|\bhomematic\b|"
             r"\braspberrymatic\b|\bccu[23]\b|\bdirigera\b|\btradfri\b|\blutron\b|\bcaseta\b|\bradiora\b|\bhomeworks\b|"
             r"\becobee\b|\bthermostat\b|nest (?:learning|thermostat|protect)|\bmyq\b|\bgogogate\b|\bismartgate\b|"
             r"\broomba\b|\birobot\b|\broborock\b|\bvaletudo\b|\becovacs\b|\bdreame\b|\bsensibo\b|\bwink hub\b|"
             r"\binsteon\b|\bzibase\b|\bweatherlink\b|ambient weather|\becowitt\b|crestron\b.{0,25}(?:cp\d|mc\d|pro\d|"
             r"\d-series|automation|control system|home)|\bcontrol4\b|\bsavant\b|global cache|\bitach\b", "high",
        "smart-home devices/hubs and home-automation controllers (HA/openHAB software is matched earlier as server)",
        ["Philips Hue wireless lighting bridge", "Tasmota", "ESPHome Web Server", "TP-LINK Smart Plug fake_httpd",
         "Belkin Wemo upnpd", "Crestron $1 automation system text ui"], ["ESPHome Dashboard", "Home Assistant"]),
    _sp(_SP, r"^ship 2\.0$", "medium",
        "HTTP Server header of newer TP-Link Tapo/Kasa smart-home firmware (plugs, bulbs, hubs; a Tapo camera also "
        "streams RTSP and is then promoted to camera)", ["SHIP 2.0"], ["SHIP 2.0.1 beta", "Relationship 2.0"]),

    # ───────────── 通用字樣（medium；放在所有品牌／產品規則之後）─────────────
    _sp(_A, r"\baccess point\b|\bwireless ap\b|wireless (?:lan |access )?controller|\bwlc\b|wlan repeater|"
            r"range extender|wi-?fi extender", "medium", "generic AP wording (place after specific products)",
        ["HP ProCurve Access Point 10ag WAP telnetd", "Wireless LAN Controller"]),
    _sp(_S, r"\b(?:managed|smart|web ?smart|poe|l2|l3) switch\b|(?<!video )(?<!kvm )(?<!power )(?<!matrix )\bswitch "
            r"(?:http config|telnetd|httpd|admin)", "medium",
        "generic switch wording", ["Managed Switch", "NetGear GS$1 switch http config"], ["Nintendo Switch"]),
    _sp(_P, r"\bprinter\b|print server|\bmfp\b|\bmultifunction\b|\bipp everywhere\b", "medium",
        "generic printer wording (after the CUPS guard and the brand rules)", ["Generic printer http config"],
        ["CUPS 2.4"]),
    _sp(_C, r"netsurveillance|\bxmeye\b|xiongmai|uc-httpd|\bjaws/1\.0\b|cross web server|\bhipcam\b|\breecam\b|"
            r"\bnetwave\b|\bipcam(?:era)?\b|ip ?camera|network (?:video )?camera|\bwebcam\b|network video recorder|"
            r"\bnvr\b|\bdvr\b|\bonvif\b|\bcctv\b|surveillance", "medium",
        "generic camera/NVR wording, cheap-OEM web servers, ONVIF (after VMS-software guards)",
        ["uc-httpd 1.0.0", "ONVIF 1.0 responder", "Kguard Security DVR", "NETSurveillance WEB"],
        ["Blue Iris", "ZoneMinder Console"]),
    _sp(_R, r"\b(?:broadband|adsl2?\+?|vdsl|dsl|cable|wireless|wi-?fi|soho|vpn|3g|4g|lte|5g) router\b|"
            r"\brouter (?:http config|telnetd|httpd|admin|ftpd|webadmin|sipd|sshd|config)\b|\bcable modem\b", "medium",
        "generic router wording (before generic VoIP: 'router sipd' is a router with FXS)",
        ["Pirelli NetGate VOIP v2 broadband router telnetd", "Thomson TG585 router sipd"]),
    _sp(_V, r"\bvoip\b|\bsip (?:phone|gateway|device|trunk|server)\b|\bip phone\b|\bsipd\b", "medium", "generic VoIP wording",
        ["Generic VoIP phone http config"]),
    _sp(_SP, r"\bups[_ ](?:web|network|management|status|monitor|card|server|httpd)|\bpdu\b|uninterruptible power|"
             r"power ?(?:system|meter|relay|distribution)|energy (?:meter|monitor)|smart plug", "medium",
        "generic power wording", ["UPS_Server httpd", "Eltek Power System ftpd", "YouLess LS110 energy monitor http admin"]),
)

# 依服務推論時的已知陷阱（以資料的形式記下來的說明）。
SERVICE_TRAPS: tuple[str, ...] = (
    "nmap names a service from its port table when no probe matched (XML <service method=\"table\" conf=\"3\">): "
    "9100=jetdirect, 515=printer, 631=ipp, 554=rtsp, 5060=sip, 62078=iphone-sync, 8009=ajp13, 8080=http-proxy, "
    "7000=afs3-fileserver, 5000=upnp, 9999=abyss. Treat a table-guessed name as a PORT signal (PORT_SIGNATURES), "
    "never as product evidence. The agent should capture service@method/@conf and service@devicetype (d/ field).",
    "9100/tcp on servers/firewalls is Prometheus node_exporter far more often than raw printing.",
    "515/tcp (LPD) is opened by routers, NAS and print-server boxes that share a USB printer.",
    "631/tcp (IPP) is CUPS on every Linux/macOS desktop; some printers also report 'CUPS' in Server headers.",
    "RTSP outside 554/8554/10554 (e.g. 8080/8443) is usually a web server misidentified by a probe; RTSP on "
    "5000/7000 is Apple AirPlay (Macs since macOS 12, Apple TV, AirPlay speakers).",
    "8554/tcp is the default of MediaMTX/rtsp-simple-server/go2rtc/Frigate on SERVERS.",
    "8006/tcp is Proxmox VE and also Proxmox Mail Gateway; on non-Debian hosts it is something else.",
    "902/tcp (vmware-authd) is open on Windows/Linux desktops running VMware Workstation, not only ESXi.",
    "3389/tcp is xrdp or GNOME Remote Desktop on Linux; 445/139 are Samba on Linux/NAS and SMB file sharing on macOS.",
    "8009/tcp is Tomcat AJP on servers and Google Cast (castv2, TLS) on Chromecast/Nest/Android TV: same port.",
    "2000/tcp is Cisco SCCP (phones/CUCM) and MikroTik bandwidth-test; 20000/tcp is DNP3 and Usermin.",
    "179/tcp (BGP) is open on Kubernetes nodes running Calico/MetalLB/kube-router and on Linux route servers.",
    "623 + 16992-16995 together = Intel AMT inside a vPro desktop/laptop, not a server BMC.",
    "5900/tcp VNC: BMC iKVM, macOS Screen Sharing, Raspberry Pi, Linux/Windows desktops, KVM-over-IP - no signal.",
    "Embedded web servers (GoAhead, Boa, RomPager, mini_httpd, thttpd, lighttpd, Mongoose, Appweb, Virata-EmWeb) "
    "ship in cameras, routers, UPS cards, printers and BMCs alike: no kind signal on their own.",
    "Vendor UI pages for SOFTWARE look like devices: Synology Surveillance Station/Blue Iris/Frigate say 'NVR', "
    "UniFi Network/Omada Controller say 'AP', CUPS lists printers, PowerChute/PowerPanel say 'UPS'.",
    "nmap tags Hikvision DVR services and Qnap VioStor as 'media device'; camera product rules must win.",
    "Reverse proxies/load balancers forward backend Server headers (IIS, Synology nginx) - the answering IP may "
    "be the proxy.",
)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. 埠的特徵 —— 不看產品字樣，「開著這個埠」本身說明了什麼
#    強度 "strong"：條件成立時可以單獨採用
#    強度 "needs-corroboration"：只能替產品／Recog／OUI／名稱已經指出的類型加分（或與 medium 線索矛盾）
#    條件的詞彙見 PORT_CONDITIONS
# ════════════════════════════════════════════════════════════════════════════════════════════════

PORT_CONDITIONS: dict[str, str] = {
    "": "no extra condition",
    "not_general_os": "skip when the OS (fingerprint/agent/banner) is Windows, macOS, iOS, Linux or BSD",
    "not_desktop_os": "skip when the OS is Windows, macOS or iOS (embedded Linux is fine)",
    "not_guest": "skip when the host is a known VM/container",
    "debian_not_guest": "only when the OS is Debian (not Ubuntu/RHEL/...), not a VM/CT, product not PMG/PBS",
    "no_file_sharing": "skip when NFS/SMB/AFP/iSCSI is also open (NAS and media servers stream RTSP too)",
    "needs_product": "only with a product/extrainfo/title that names a device of this kind",
    "not_router_or_pbx": "skip on routers (SIP ALG/FXS) - but a PBX product still means voip",
    "embedded": "only when nothing shows a general-purpose host (no OpenSSH, distro banner, Samba, database...) "
                "and the OS is not Windows/macOS/iOS",
}


class PortSig(NamedTuple):
    port: int
    proto: str                  # "tcp"｜"udp"
    services: tuple[str, ...]   # nmap 通常回報的服務名稱（常常只是照埠號表猜的）
    kind: str | None
    strength: str               # "strong"｜"needs-corroboration"
    condition: str              # PORT_CONDITIONS 的鍵
    note: str


def _ps(port: int, proto: str, services: Iterable[str], kind: str | None, strength: str, condition: str,
        note: str) -> PortSig:
    return PortSig(port, proto, tuple(services), kind, strength, condition, note)


_STRONG, _CORR = "strong", "needs-corroboration"

PORT_SIGNATURES: tuple[PortSig, ...] = (
    # ── 手機 ──
    _ps(62078, "tcp", ["iphone-sync"], _MO, _STRONG, "",
        "iOS/iPadOS lockdownd (Finder/iTunes Wi-Fi sync). Some tvOS/audioOS builds were also reported to listen - "
        "if AirPlay/RAOP is present too, prefer media"),
    _ps(5555, "tcp", ["freeciv", "adb"], None, _CORR, "",
        "adb over TCP: Android TV boxes/Fire TV (common) or developer phones - Android, kind ambiguous"),
    # ── Windows／一般電腦 ──
    _ps(3389, "tcp", ["ms-wbt-server"], _W, _CORR, "not_general_os",
        "RDP: Windows, but also xrdp and GNOME Remote Desktop (Ubuntu 22.04+) on Linux"),
    _ps(445, "tcp", ["microsoft-ds"], _W, _CORR, "",
        "SMB: Windows, Samba (Linux/NAS), macOS file sharing - use the product ('Samba smbd' => not Windows)"),
    _ps(135, "tcp", ["msrpc"], _W, _CORR, "",
        "RPC endpoint mapper: Windows; Samba AD DCs also listen"),
    _ps(5985, "tcp", ["wsman"], _W, _STRONG, "",
        "WinRM HTTP (Microsoft OMI on Linux - Azure/SCOM agents - also uses 5985/5986; check OS if available)"),
    _ps(5986, "tcp", ["wsmans"], _W, _STRONG, "", "WinRM HTTPS (same OMI caveat)"),
    _ps(5357, "tcp", ["wsdapi"], _W, _CORR, "", "WS-Discovery API (Network Discovery on Windows; some printers)"),
    _ps(16992, "tcp", ["amt-soap-http"], None, _CORR, "",
        "Intel AMT web: the host is a vPro desktop/laptop (general computer), NOT a BMC/specialized device"),
    _ps(16993, "tcp", ["amt-soap-https"], None, _CORR, "", "Intel AMT TLS (see 16992)"),
    _ps(6443, "tcp", ["sun-sr-https"], _SV, _CORR, "", "Kubernetes API server (k8s/k3s nodes are general hosts)"),
    _ps(10250, "tcp", [], _SV, _CORR, "", "kubelet"),
    _ps(2375, "tcp", ["docker"], _SV, _CORR, "", "Docker API (also Synology/QNAP container stations)"),
    _ps(22, "tcp", ["ssh"], None, _CORR, "", "SSH is everywhere; only the banner (distro, Dropbear, vendor) helps"),
    # ── BMC／頻外管理 ──
    _ps(623, "udp", ["asf-rmcp", "ipmi"], _SP, _STRONG, "not_general_os",
        "IPMI/RMCP on a dedicated BMC address. Intel AMT also answers 623/664 on desktops - skip if the same IP "
        "shows a general-purpose OS"),
    _ps(623, "tcp", ["oob-ws-http"], _SP, _CORR, "not_general_os", "IPMI-over-TCP/AMT redirection"),
    _ps(5120, "tcp", [], _SP, _CORR, "", "Supermicro/ATEN BMC virtual media (with 623/5900)"),
    _ps(17988, "tcp", [], _SP, _CORR, "", "HPE iLO virtual media"),
    _ps(5900, "tcp", ["vnc"], None, _CORR, "",
        "VNC: BMC iKVM, macOS Screen Sharing, Raspberry Pi, desktops, KVM-over-IP - no signal alone"),
    # ── 工控／樓宇自動化 ──
    _ps(102, "tcp", ["iso-tsap"], _SP, _STRONG, "", "Siemens S7comm (ISO-TSAP) - PLCs, also some X.400 MTAs (rare)"),
    _ps(502, "tcp", ["mbap", "modbus"], _SP, _STRONG, "not_general_os",
        "Modbus/TCP (SCADA software and gateways on Windows/Linux also serve Modbus)"),
    _ps(44818, "tcp", ["EtherNetIP-2"], _SP, _STRONG, "", "EtherNet/IP explicit messaging (Rockwell/Omron/...)"),
    _ps(2222, "udp", ["EtherNetIP-1"], _SP, _CORR, "", "EtherNet/IP implicit I/O (2222/tcp is often an alt SSH)"),
    _ps(47808, "udp", ["bacnet"], _SP, _STRONG, "not_general_os",
        "BACnet/IP controllers (BMS workstations running BACnet software are Windows)"),
    _ps(20000, "tcp", ["dnp", "dnp3"], _SP, _CORR, "", "DNP3 - but 20000 is also Usermin (Webmin) on Linux"),
    _ps(2404, "tcp", ["iec-104"], _SP, _STRONG, "", "IEC 60870-5-104 RTUs/protection relays"),
    _ps(4840, "tcp", ["opcua-tcp"], _SP, _CORR, "not_general_os", "OPC UA (also SCADA/MES servers)"),
    _ps(1911, "tcp", ["niagara-fox"], _SP, _STRONG, "not_general_os", "Tridium Niagara Fox (JACE; Supervisor is Windows)"),
    _ps(4911, "tcp", ["niagara-fox-tls"], _SP, _STRONG, "not_general_os", "Niagara Fox TLS"),
    _ps(9600, "udp", ["omron-fins"], _SP, _STRONG, "", "OMRON FINS"),
    _ps(1962, "tcp", ["pcworx"], _SP, _STRONG, "", "Phoenix Contact PCWorx"),
    _ps(789, "tcp", ["crimson"], _SP, _STRONG, "", "Red Lion Crimson v3"),
    _ps(18245, "tcp", ["ge-srtp"], _SP, _STRONG, "", "GE SRTP PLCs"),
    _ps(5007, "tcp", ["melsec"], _SP, _CORR, "", "Mitsubishi MELSEC (also 5006/5008)"),
    _ps(34962, "udp", ["profinet-rt"], _SP, _STRONG, "", "PROFINET (34962-34964)"),
    _ps(5094, "tcp", ["hart-ip"], _SP, _STRONG, "", "HART-IP instruments"),
    _ps(3671, "udp", ["knxnet-ip"], _SP, _STRONG, "", "KNXnet/IP routers/interfaces"),
    _ps(1883, "tcp", ["mqtt"], None, _CORR, "",
        "MQTT broker: IoT devices are usually CLIENTS; a listener is a broker (server, HA box, gateway)"),
    _ps(8883, "tcp", ["secure-mqtt"], None, _CORR, "", "MQTT over TLS (same as 1883)"),
    _ps(5683, "udp", ["coap"], _SP, _CORR, "not_general_os", "CoAP (IoT devices; IKEA gateway uses 5684 DTLS)"),
    _ps(4370, "tcp", [], _SP, _STRONG, "", "ZKTeco time-attendance/access-control protocol (also udp)"),
    # ── 智慧家庭／IoT ──
    _ps(9999, "tcp", ["abyss"], _SP, _STRONG, "not_general_os", "TP-Link Kasa local protocol (plugs/bulbs/switches)"),
    _ps(6668, "tcp", ["irc"], _SP, _STRONG, "not_general_os", "Tuya local protocol (6668 is also an IRC port on servers)"),
    _ps(6053, "tcp", [], _SP, _STRONG, "", "ESPHome native API (the ESPHome *dashboard* is 6052, on a server)"),
    _ps(8266, "udp", [], _SP, _CORR, "", "ESP8266 Arduino OTA (3232/udp = ESP32 OTA)"),
    _ps(5353, "udp", ["mdns"], None, _CORR, "", "mDNS: everything (use the advertised service types/model TXT instead)"),
    # ── 印表機 ──
    _ps(9100, "tcp", ["jetdirect"], _P, _CORR, "needs_product",
        "raw printing - but Prometheus node_exporter uses 9100 on servers/firewalls"),
    _ps(515, "tcp", ["printer"], _P, _CORR, "needs_product", "LPD - routers/NAS/print-server boxes too"),
    _ps(631, "tcp", ["ipp"], _P, _CORR, "needs_product", "IPP - CUPS on every Linux/macOS desktop"),
    _ps(9220, "tcp", [], _P, _CORR, "needs_product", "HP printer raw/firmware (also 9280-9290 HP)"),
    # ── 攝影機 ──
    _ps(554, "tcp", ["rtsp"], _C, _CORR, "no_file_sharing",
        "RTSP standard port: cameras/NVRs, but also NAS, media servers, Android TV boxes; not on macOS/Windows/iOS"),
    _ps(8554, "tcp", ["rtsp-alt"], None, _CORR, "",
        "RTSP alt: MediaMTX/go2rtc/Frigate on SERVERS more often than cameras"),
    _ps(37777, "tcp", [], _C, _STRONG, "", "Dahua DVR/NVR/camera proprietary protocol (and OEMs)"),
    _ps(34567, "tcp", [], _C, _STRONG, "", "XiongMai/XMEye 'NETsurveillance' DVR/NVR/camera"),
    _ps(8000, "tcp", ["http-alt"], _C, _CORR, "needs_product",
        "Hikvision SDK/iVMS port - but 8000 is also every dev web server, Splunk web, etc."),
    _ps(3702, "udp", ["ws-discovery"], None, _CORR, "",
        "WS-Discovery: ONVIF cameras, printers and Windows PCs all answer"),
    # ── VoIP ──
    _ps(5060, "udp", ["sip"], _V, _CORR, "not_router_or_pbx",
        "SIP: phones/ATAs/PBX, but also router SIP ALG, FRITZ!Box/ISP gateways with FXS, desktop softphones"),
    _ps(5060, "tcp", ["sip"], _V, _CORR, "not_router_or_pbx", "SIP over TCP (same caveats)"),
    _ps(5061, "tcp", ["sip-tls"], _V, _CORR, "not_router_or_pbx", "SIP over TLS"),
    _ps(2000, "tcp", ["cisco-sccp"], _V, _CORR, "",
        "Cisco SCCP (phones/CUCM) - also MikroTik bandwidth-test (RouterOS)"),
    _ps(5038, "tcp", [], _V, _CORR, "", "Asterisk Manager Interface (PBX on a server: IPAM convention voip)"),
    # ── 儲存設備 ──
    _ps(2049, "tcp", ["nfs"], _ST, _CORR, "not_general_os", "NFS - any Linux/BSD server can export NFS"),
    _ps(3260, "tcp", ["iscsi"], _ST, _CORR, "not_general_os", "iSCSI target - also Linux targetcli/Windows iSCSI Target"),
    _ps(548, "tcp", ["afp"], _ST, _CORR, "not_general_os", "AFP - Time Capsule/NAS; older Macs and netatalk share AFP too"),
    _ps(5000, "tcp", ["upnp"], None, _CORR, "",
        "Synology DSM HTTP default - but also AirPlay (macOS 12+), UPnP, Flask, Docker registry"),
    _ps(5001, "tcp", ["commplex-link"], _ST, _CORR, "needs_product", "Synology DSM HTTPS default"),
    _ps(10000, "tcp", ["snet-sensor-mgmt", "ndmp"], None, _CORR, "", "NDMP on NAS/filers and Webmin on Linux"),
    # ── 虛擬化主機 ──
    _ps(8006, "tcp", ["wpl-analytics"], _H, _STRONG, "debian_not_guest",
        "Proxmox VE web UI - but also Proxmox Mail Gateway (often a CT/VM) and arbitrary services on non-Debian"),
    _ps(8007, "tcp", [], None, _CORR, "", "Proxmox Backup Server (a server application, not a hypervisor)"),
    _ps(902, "tcp", ["vmware-auth"], _H, _CORR, "not_desktop_os",
        "vmware-authd: ESXi, but also every Windows/Linux host running VMware Workstation/Player"),
    _ps(5480, "tcp", [], None, _CORR, "", "VMware VAMI (vCenter appliance = VM)"),
    _ps(2179, "tcp", ["vmrdp"], _H, _CORR, "", "Hyper-V VMConnect (Windows Server with Hyper-V; client Hyper-V too)"),
    _ps(16509, "tcp", ["libvirt"], _H, _CORR, "", "libvirtd TCP (KVM hosts)"),
    _ps(9440, "tcp", [], None, _CORR, "", "Nutanix Prism: served by the CVM (a VM beside the AHV host)"),
    # ── 網通設備 ──
    _ps(8291, "tcp", [], _R, _STRONG, "", "MikroTik Winbox (RouterOS)"),
    _ps(8728, "tcp", [], _R, _STRONG, "", "MikroTik RouterOS API (8729 TLS)"),
    _ps(4786, "tcp", ["smart-install"], _S, _STRONG, "", "Cisco Smart Install client (Catalyst switches)"),
    _ps(161, "udp", ["snmp"], None, _CORR, "", "SNMP: everything; sysDescr/sysObjectID (Recog snmp_*) are the signal"),
    _ps(830, "tcp", ["netconf-ssh"], None, _CORR, "", "NETCONF: routers/switches/firewalls (and Linux netopeer)"),
    _ps(179, "tcp", ["bgp"], _R, _CORR, "",
        "BGP: routers - but also Kubernetes nodes (Calico/MetalLB/kube-router) and Linux route servers"),
    _ps(7547, "tcp", ["cwmp"], _R, _CORR, "", "TR-069 CWMP: ISP CPE (gateways/ONTs; some ATAs and set-top boxes)"),
    _ps(52869, "tcp", [], _R, _CORR, "", "Realtek SDK miniigd UPnP: consumer routers/repeaters/cheap cameras"),
    _ps(541, "tcp", [], _F, _CORR, "", "FortiGate FGFM (FortiManager tunnel)"),
    _ps(256, "tcp", ["fw1-secureremote"], _F, _STRONG, "", "Check Point FW-1 (256-264, 18264 CPD ICA)"),
    _ps(18264, "tcp", [], _F, _STRONG, "", "Check Point ICA/certificate services"),
    _ps(3517, "tcp", ["802-11-iapp"], _A, _STRONG, "embedded",
        "802.11 IAPP (inter-AP roaming), left open by many APs (DrayTek VigorAP, older Cisco/Linksys/Zyxel); on a "
        "general-purpose host it is just a port"),
    _ps(5246, "udp", ["capwap-control"], _A, _CORR, "",
        "CAPWAP control LISTENER = wireless controller (APs are clients); FortiGate also acts as WLC"),
    _ps(10001, "udp", [], None, _CORR, "", "Ubiquiti discovery: UniFi/UISP gear of any kind (AP, switch, gateway, camera)"),
    _ps(500, "udp", ["isakmp"], None, _CORR, "", "IKE: VPN endpoint (firewall, router, or Windows/Linux VPN server)"),
    _ps(1194, "udp", ["openvpn"], None, _CORR, "", "OpenVPN endpoint (same)"),
    _ps(51820, "udp", [], None, _CORR, "", "WireGuard endpoint (same)"),
    # ── 影音 ──
    _ps(8009, "tcp", ["ajp13"], _M, _CORR, "",
        "Google Cast (castv2/TLS; with 8008 http and 8443) - but also Tomcat AJP on servers; the product decides"),
    _ps(8008, "tcp", ["http"], _M, _CORR, "needs_product", "Google Cast 'eureka_info' HTTP (also generic alt-HTTP)"),
    _ps(1400, "tcp", ["cadkey-tablet"], _M, _STRONG, "", "Sonos UPnP control (1443 TLS)"),
    _ps(8060, "tcp", ["aero"], _M, _STRONG, "", "Roku External Control Protocol"),
    _ps(7000, "tcp", ["afs3-fileserver"], _M, _CORR, "not_desktop_os",
        "AirPlay: Apple TV/HomePod/AirPlay speakers/TVs, AND macOS 12+ - skip on macOS/iOS"),
    _ps(3689, "tcp", ["daap"], _M, _CORR, "not_desktop_os", "DAAP (iTunes sharing; NAS iTunes servers too)"),
    _ps(4352, "tcp", ["pjlink"], _M, _STRONG, "", "PJLink projector/display control"),
    _ps(3000, "tcp", ["ppp"], None, _CORR, "", "LG webOS TV SSAP - and every Node.js/Grafana dev server"),
    _ps(8001, "tcp", ["vcom-tunnel"], None, _CORR, "", "Samsung Tizen TV remote API (8002 wss) - common alt port"),
    _ps(9295, "tcp", [], _M, _CORR, "", "PlayStation Remote Play (9295-9304)"),
    _ps(3074, "udp", ["xbox"], _M, _CORR, "", "Xbox Live (PC games also use it)"),
    _ps(32400, "tcp", [], None, _CORR, "", "Plex Media Server (host may be server/NAS/Shield)"),
    _ps(8096, "tcp", [], None, _CORR, "", "Jellyfin/Emby (server applications)"),
    _ps(8123, "tcp", [], _SV, _CORR, "", "Home Assistant (general-purpose host; IPAM convention server)"),
)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. 主機名稱的線索（DHCP option 12／mDNS／DNS PTR）
#    輸入約定：只取「第一段」（`name.split('.')[0]`）、轉小寫、把 '-'、'_' 換成空白 —— 即 normalize_hostname()。
#    比對整個 FQDN 是陷阱：「*.cam.ac.uk」（劍橋大學）與 AWS 的「ip-10-0-0-1.ap-northeast-1.compute.internal」
#    會被讀成攝影機、AP。
#    依序比對，第一個符合的為準。這是最弱的證據：只在沒有更強的證據時用。
# ════════════════════════════════════════════════════════════════════════════════════════════════

class HostnameHint(NamedTuple):
    kind: str | None
    pattern: str
    confidence: str
    note: str
    examples: tuple[str, ...]           # 一定要判成這個類型的主機名稱（原樣）
    counter: tuple[str, ...] = ()       # 一定「不可以」判成這個類型的主機名稱
    # 只有網卡廠牌（normalize_vendor 之後）以這些開頭時才採用：型號字（P105、HS300）在別的網路上可能是教室、
    # 印表機、專案主機（對抗式驗證 2026-10-05）
    vendors: tuple[str, ...] = ()


def _hh(kind: str | None, pattern: str, confidence: str, note: str, examples: Iterable[str],
        counter: Iterable[str] = (), vendors: Iterable[str] = ()) -> HostnameHint:
    return HostnameHint(kind, pattern, confidence, note, tuple(examples), tuple(counter), tuple(vendors))


HOSTNAME_HINTS: tuple[HostnameHint, ...] = (
    # ── Windows 的預設名稱（安裝程式產生）──
    _hh(_W, r"^(?:desktop (?=[a-z]*\d)[a-z0-9]{7}|laptop (?=[a-z]*\d)[a-z0-9]{8}|win (?=[a-z]*\d)[a-z0-9]{11}|"
        r"ec2amaz [a-z0-9]{7}|minint [a-z0-9]{6,7})$",
        "high", "Windows OOBE defaults: DESKTOP-XXXXXXX, LAPTOP-XXXXXXXX, Server WIN-XXXXXXXXXXX, AWS EC2AMAZ-, "
                "WinPE/MDT MININT-",
        ["DESKTOP-4G7P2QK", "LAPTOP-0OLV8C5N", "WIN-3J5KT8VQ0FR", "EC2AMAZ-A1B2C3D", "MININT-8H2K1LP"],
        ["desktop-support", "laptop-cart-12"]),
    # ── BMC／頻外管理的預設名稱 ──
    _hh(_SP, r"^(?:idrac [a-z0-9]{7}|ilo[a-z0-9]{8,12}|xcc [a-z0-9]{4} [a-z0-9]{6,10}|imm2? [a-z0-9]{6,12})$|"
             r"\b(?:idrac|ilo|ipmi|bmc|drac|xcc|imm|cimc|irmc)\b(?! ?server)", "high",
        "iDRAC 'idrac-<service tag>', iLO 'ILO<serial>', Lenovo 'XCC-<type>-<serial>', plus admin suffixes "
        "(srv01-ipmi, node3-bmc). Counter: 'BMC Software' servers (bmc-remedy-01) - medium in practice",
        ["idrac-7XK2Q12", "ILOCZ2345678AB", "XCC-7X06-J30012AB", "srv01-ipmi", "node3-bmc", "esx01-idrac"],
        ["bmcsoft", "ilona-laptop"]),
    _hh(_SP, r"^(?:pikvm|tinypilot|jetkvm|nanokvm|blikvm|glkvm)\b", "high", "KVM-over-IP appliance defaults "
        "(NOT bare 'kvm' - that is usually a KVM hypervisor host)", ["pikvm", "tinypilot", "jetkvm"], ["kvm01"]),
    _hh(_SP, r"^apc[0-9a-f]{6}$|\b(?:ups|pdu)(?: ?\d+)?\b", "medium",
        "APC NMC default 'apcXXXXXX'; 'ups'/'pdu' tokens", ["apc9F12A3", "ups-rack3", "pdu02", "rack1 pdu a"],
        ["backups", "groups-db"]),
    # ── 手機／平板 ──
    _hh(_MO, r"\b(?:iphone|ipad|ipod)\b|^android [0-9a-f]{16}$", "high",
        "iOS default '<Name>s-iPhone'; Android <=7 default 'android-<16 hex>'",
        ["Johns-iPhone", "iPhone", "iPad-Pro", "android-3f2a9c1b7d6e5f40"], ["myiphonesvc"]),
    _hh(_MO, r"\bgalaxy (?!book|watch\b|buds)(?:[asmzfx] ?\d|note|tab|s\d|z ?(?:fold|flip)|xcover)|"
             r"\bsm [agnstxfm]\d{3}[a-z0-9]*\b|\bpixel (?:\d|fold|tablet)|\bredmi\b|\bpoco [a-z]?\d|"
             r"\b(?:mi|xiaomi) \d{1,2}[a-z]?\b|\boneplus\b|\boppo [a-z]|\bvivo [a-z]\d|\brealme\b|\bxperia\b|"
             r"\bmoto [a-z]|\bmotorola (?:edge|one|razr)|\bhuawei (?:p\d|mate|nova|y\d|enjoy)|"
             r"\bhonor (?:magic|x\d|\d{2,3}|play)|\bnokia (?:[gcxt]\d|\d)|\bfairphone\b|\bnothing phone\b|"
             r"\bkindle\b|\bsurface duo\b", "high",
        "Android/other phone & tablet model names used as DHCP host names",
        ["Galaxy-S21-Ultra", "Galaxy-A52", "Galaxy-Tab-S7", "SM-G991B", "Pixel-7", "Redmi-Note-11", "POCO-X3-Pro",
         "OnePlus-9-Pro", "OPPO-A74", "vivo-Y20", "realme-8", "Xperia-1-III", "moto-g-power",
         "HUAWEI_P30_Pro-a1b2c3", "HONOR_Magic5-1234"],
        ["Galaxy-Book3", "galaxy-server", "pixelbook-go", "mi-router"]),
    # ── macOS／筆電／桌機（一般電腦）──
    _hh(_W, r"\bsurface (?:pro|laptop|book|go|studio|hub)\b|\b\w+ pc$", "medium",
        "Surface runs Windows; '<user>-PC' is the Windows Vista/7 default",
        ["Surface-Pro-9", "JOHN-PC", "Marys-PC"], ["pc"]),
    _hh(_SV, r"\b(?:macbook(?: (?:pro|air))?|imac|mac (?:mini|pro|studio)|mac ?book|macmini)\b|"
             r"\b(?:thinkpad|thinkcentre|thinkstation|ideapad|ideacentre|optiplex|latitude [3579]\d{3}|elitebook|"
             r"probook|elitedesk|prodesk|zbook|zenbook|vivobook|matebook|chromebook|galaxy book\w*)\b", "high",
        "macOS defaults ('Johns-MacBook-Pro') and laptop/desktop model families",
        ["Johns-MacBook-Pro", "MacBook-Air-3", "iMac", "Mac-mini", "ThinkPad-X1", "OptiPlex-7090", "Galaxy-Book3"],
        ["imacros-server"]),
    _hh(_SV, r"^(?:raspberrypi|ubuntu|debian|fedora|kali|archlinux|homeassistant|pihole|steamdeck)$", "medium",
        "Linux defaults (Raspberry Pi OS 'raspberrypi', HA OS 'homeassistant'; SteamOS 'steamdeck' is a handheld PC)",
        ["raspberrypi", "homeassistant", "ubuntu"]),
    # ── 印表機 ──
    _hh(_P, r"^(?:br[nw][0-9a-f]{12}|npi[0-9a-f]{6}|hp[0-9a-f]{6}|epson[0-9a-f]{6}|kmbt[0-9a-f]{6}|km[0-9a-f]{6}|"
            r"rnp[0-9a-f]{6,12}|et[0-9a-f]{12}|xrx[0-9a-f]{12}|sec[0-9a-f]{12}|zbr\d{4,}|oki [a-z]{1,3}\d{3,4}\w* "
            r"[0-9a-f]{6})$", "high",
        "factory defaults: Brother BRN/BRW+MAC, HP NPIxxxxxx/HPxxxxxx, EPSONxxxxxx, Konica KMBTxxxxxx, Kyocera "
        "KMxxxxxx, Ricoh RNP+MAC, Lexmark ET+MAC, Xerox XRX+MAC, Samsung SEC+MAC, Zebra ZBR+serial, OKI-model-hex",
        ["BRN30055C123456", "BRW008092A1B2C3", "NPI4B2A1C", "HP3C2A1B", "EPSON6B2C3A", "KMBT3A2B1C", "KM6B3C1A",
         "RNP00267341A2B3", "ET0021B7123456", "XRX0000AA123456", "SEC30CDA7123456", "OKI-C332-5A3B21"],
        ["hp-server-01", "km-gateway"]),
    _hh(_P, r"\b(?:printer|mfp|copier|laserjet|officejet|deskjet|pixma|imagerunner|bizhub|taskalfa|ecosys|"
            r"workcentre|versalink|altalink|phaser|aficio|docucentre|apeosport|lexmark|kyocera|brother|canon|epson)"
            r"\w*", "medium", "printer words and brands (counter: Canon/Epson cameras or projectors)",
        ["printer-2f", "MFP-Accounting", "Canon-MF4410", "LaserJet-M404", "EPSON-ET-2850"], ()),
    # ── 攝影機 ──
    _hh(_C, r"\btapo c\d{3}|\bkc\d{3}\b|\bring(?:stickupcam|doorbell|spotlight|floodlight|indoorcam)\w*|"
            r"\bwyze ?c\w*|\bnest cam|\bdoorbell\b|\b(?:ipcam\w*|ip cam\w*|camera\w*|cam\d+|nvr\d*|dvr\d*|cctv\w*|"
            r"ezviz\w*|reolink\w*|amcrest\w*|hikvision\w*|dahua\w*|imou\w*)\b|\bds (?:2c|2d|7\d)\w*|\bipc h[df]w",
        "medium", "camera words/brands and default names; 'cam' must be a whole token+digit (camel/campus/cam.ac.uk)",
        ["ipcam4", "Tapo_C200_A1B2", "RingStickUpCam-5", "WYZEC1-JZ", "Front-Doorbell", "nvr01", "camera-lobby",
         "DS-2CD2043G2"], ["camel", "campus-gw", "cambridge-01", "scam-filter"]),
    # ── 智慧家庭／IoT ──
    _hh(_SP, r"^(?:esp[_ -]?[0-9a-f]{6}|esp32 [0-9a-f]{6}|esp8266 [0-9a-f]{6}|espressif|wled [0-9a-f]{6}|"
             r"tasmota [0-9a-f]{6}(?: \d{4})?|sonoff \d{4}|openbk\w*|obk\w*)$|\bshelly\w*|\bihoment\b|\bwiz [0-9a-f]{6}\b|"
             r"\byeelink\b|\bphilips hue\b|\bdirigera\b|\btradfri\b|\bnanoleaf\w*|\blifx\w*|\bmyq\w*|\birobot [0-9a-f]+|"
             r"\broomba\w*|\b(?:zhimi|chuangmi|roborock|lumi|dmaker|chunmi|viomi|dreame|deerma|cuco)\b|\becobee\w*|"
             r"\bthermostat\w*|\bnest (?:protect|thermostat|learning)|\bmeross\w*|\bwemo\w*|\bsensibo\w*|\bsmartthings\b|"
             r"\bhubitat\b", "high",
        "IoT firmware defaults: ESP_xxxxxx (ESP8266), espressif (ESP-IDF), esp32-xxxxxx, WLED, Tasmota, Shelly, "
        "Govee 'ihoment_', WiZ 'wiz_xxxxxx', Xiaomi Mi Home models",
        ["ESP_A1B2C3", "espressif", "esp32-A1B2C3", "tasmota-A1B2C3-1234", "shellyplug-s-A1B2C3", "wled-0A1B2C",
         "ihoment_H6159_A1B2", "wiz_a1b2c3", "zhimi-airpurifier-v6_miio123", "iRobot-0A1B2C3D4E5F", "Philips-hue"],
        ["esp-api-server", "wizard"]),
    _hh(_SP, r"\b(?:hs(?:1(?:00|03|05|07|10)|2(?:00|10|20)|300)|kp(?:1(?:00|05|15|25)|2(?:00|25)|303|40[015])|"
             r"kl(?:1(?:10|20|25|30|35)|4(?:00|20|30))|ks2(?:00|05|20|25|30|40)|ep(?:10|25|40)|"
             r"p1(?:00|05|10|15|25)|p300|l5(?:10|30)|l9(?:00|20|30)|h100|kh100|s500d?)\b", "medium",
        "TP-Link Kasa/Tapo plug/bulb/switch model codes the devices use as their DHCP name - only with a TP-Link NIC "
        "(elsewhere P105 is a classroom, a printer, a project host)",
        ["HS300", "KP115", "P100"], ["p1000-server", "hs2024"], vendors=("tplink",)),
    _hh(_SP, r"\btapo (?:p|l|s|h)\d{3}|\bkasa\w*|\bsmart ?plug\w*|\bwlan0$", "medium",
        "Tapo/Kasa brand names, smart-plug words, and the 'wlan0' host name many Tuya/BK7231 gadgets send "
        "('smart-gw' is NOT here: gw usually means the default gateway)",
        ["Tapo_P110_1A2B", "smartplug-garage", "wlan0"], ["smart-gw"]),
    _hh(_SP, r"\bpos ?\d+\b|\boctopi\b|\boctoprint\b", "medium", "POS terminals; OctoPi (3D-printer controller)",
        ["POS01", "pos-3", "octopi"], ["position-svc"]),
    # ── 影音 ──
    _hh(_M, r"\blg ?webos ?tv\b|\blgwebostv\b|\bapple ?tv\b|\bhomepod\w*|\bchromecast\w*|\bgoogle (?:home|nest)\w*|"
            r"\bnest (?:audio|hub|mini)\b|\broku\w*|\bsonos\w*|\bbravia\w*|\bfire ?tv\w*|\bshield (?:android )?tv\b|"
            r"\bshield\b$|\bps[345](?: \d+)?$|\bxbox\w*|\bnintendo\w*|\bsamsung ?tv\b|\bviziotv\b|\bdenon\w*|"
            r"\bmarantz\w*|\bheos\w*|\bsoundtouch\w*|\bbose\w*|\blibreelec\b|\bcoreelec\b|\bosmc\b|\bkodi\b|"
            r"\b(?:living ?room|bedroom|lounge|kitchen) (?:tv|speaker)\b|\btv\b|\bprojector\w*|\bpj ?\d+\b", "medium",
        "TV/streamer/console/speaker defaults ('LGwebOSTV', 'PS5-123', 'XboxOne', 'SonosZP')",
        ["LGwebOSTV", "Apple-TV", "Living-Room-TV", "Chromecast-Ultra", "Google-Home-Mini", "Roku-Ultra", "SonosZP",
         "PS5-123", "XboxOne", "Nintendo-Switch", "BRAVIA-4K", "LibreELEC"], ["tvbs-proxy"]),
    # ── VoIP ──
    _hh(_V, r"^(?:sep|ata)[0-9a-f]{12}$|\byealink\w*|\bsip t\d{2}[a-z]?\b|\bpolycom\w*|\bgrandstream\w*|"
            r"\b(?:gxp|grp|gxv)\d{4}\b|\bht8\d\d\b|\bsnom\w*|\bfanvil\w*|\bobi ?\d{3}\b|\bgigaset\w*", "high",
        "Cisco phones/ATAs default SEP/ATA + MAC; vendor/model names",
        ["SEP001122334455", "ATA0011AABBCCDD", "SIP-T46S", "Yealink-T54W", "Polycom_0004F2123456", "GXP2170",
         "snomD785", "voip-lobby"], ["sepia", "atari-pc"]),
    # ── 儲存設備 ──
    _hh(_V, r"\bvoip\w*|\bsip ?phone\w*|\bip ?phone\b", "medium",
        "generic VoIP words (weaker than the vendor defaults above: 'voip-router-2' also says router)",
        ["voip-gw-1", "sipphone-lobby", "ip-phone-12"]),
    _hh(_ST, r"^(?:nas[0-9a-f]{6}|diskstation|rackstation|ds\d{3,4}(?:plus|j|play|xs\+?)?|truenas|freenas|"
             r"openmediavault|unraid|tower)$|\bnas ?\d*\b|\b(?:synology|qnap|truenas|readynas|terastation|"
             r"linkstation|mycloud|wdmycloud)\w*", "high",
        "QNAP default 'NAS' + 6 hex, Synology 'DiskStation'/'DS920plus', TrueNAS 'truenas', unRAID 'Tower' "
        "(whole name only)", ["NAS4A2B3C", "DiskStation", "DS220plus", "truenas", "Tower", "nas01", "backup-nas"],
        ["towerdefense", "nasa-gw"]),
    # ── 虛擬化主機 ──
    _hh(_H, r"\besxi? ?\d*\b|\bvsphere\d*\b|\bpve(?: ?\d+)?\b(?! (?:backup|bak|mail))|\bproxmox(?: ?\d+)?\b(?! (?:mail|backup))|\bhyper ?v ?\d*\b|"
            r"\bhv ?\d+\b|\bxcp ?ng\w*|\bxenserver\w*|\bnutanix\w*|\bahv ?\d*\b", "medium",
        "hypervisor host naming; virtual machines are excluded by the IPAM's guest rule",
        ["esxi01", "esx-03", "pve2", "proxmox-node1", "hyperv-01", "hv03", "xcp-ng-1"],
        ["proxmox-mail"]),
    # ── 網通設備（企業的命名慣例）──
    _hh(_F, r"\b(?:fw ?\d*|firewall\w*|opnsense\w*|pfsense\w*|fortigate\w*|fgt ?\d+\w*|paloalto\w*|pa ?\d{3,4}|"
            r"sophos\w*|sonicwall\w*|watchguard\w*|firebox\w*|asa ?\d*|checkpoint\w*)\b", "medium",
        "firewall naming", ["fw01", "core-fw-2", "opnsense-backup-02", "FGT60F", "pa-3220"], ["fwd-proxy"]),
    _hh(_S, r"\b(?:sw ?\d+|(?<!nintendo )switch\w*|core ?sw|access ?sw|dist ?sw|usw\w*|catalyst\w*|c9[23]00\w*)\b", "medium",
        "switch naming", ["sw01", "core-sw", "switch-2f", "c9300-48p"], ["Nintendo-Switch", "swagger-api"]),
    _hh(_R, r"\b(?:rtr ?\d*|router\w*|gw ?rtr|edge ?router|mikrotik\w*|routeros|edgerouter\w*|vyos\w*|udm\w*|"
            r"vigor ?\d{3,4}\w*|fritz ?box\w*|openwrt|dd ?wrt)\b", "medium",
        "router naming / product names", ["rtr1", "edge-mikrotik-01", "FritzBox-7590", "OpenWrt", "Vigor2927"]),
    _hh(_A, r"^ap[0-9a-f]{4}(?: [0-9a-f]{4} [0-9a-f]{4})?$|\b(?:wap ?\d*|uap\w*|u[67] (?:lite|lr|pro|mesh|plus|"
            r"enterprise|iw|in wall)|eap ?\d{3}\w*|access ?point\w*|ruckus\w*|aironet\w*|meraki ?mr\w*)\b|"
            r"\bap ?\d+\w*", "medium",
        "Cisco AP default 'APxxxx.xxxx.xxxx', UniFi model names, Omada EAP. WARNING: in Taiwan/Japan 'AP' also "
        "means APPLICATION server (ap01 = app server) - keep this weakest of all",
        ["AP0011.2233.4455", "U6-Lite", "UAP-AC-Pro", "EAP245", "wap-3f", "ap-2f-01"],
        ["ip-10-0-0-1.ap-northeast-1.compute.internal", "apache01"]),
)

# 伺服器角色的字眼否決上面所有設備類的線索（Windows／一般電腦的除外）：叫 "nvr-server"、"camera-archive-01"、
# "ups-api"、"pve-backup-01"、"kodi-db"、"canon-printserver" 的主機，是替那類設備存／提供東西的「伺服器」。
# （server／srv 前面不加 \b，"printserver"、"fileserver" 也會否決。）
HOSTNAME_ROLE_VETO = (r"(?:server|srv|svr)\b|\b(?:api|db|sql|proxy|vm|archive|collector|runner|test|"
                      r"dev|logs?|monitor(?:ing)?|svc|service|app|web|www|portal|exporter|mirror|repo|build|ci|k8s|"
                      r"docker|container|lxc|cloud|relay|agent)\b")
HOSTNAME_VETO_EXEMPT_KINDS = frozenset({"windows", "server"})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. 小型純函式（比對語意以這裡為準；證據的先後順序在 ip_identify／device_identity）
# ════════════════════════════════════════════════════════════════════════════════════════════════

_I = re.I

#: 一般電腦／手機的作業系統家族（app.core.os_fingerprint.normalize_os 的詞彙）：嵌入式設備不會跑這些
DESKTOP_OS = frozenset({"windows", "macos", "ios"})
#: 一般用途的作業系統家族（含 Linux、BSD）
GENERAL_OS = DESKTOP_OS | {"linux", "bsd"}

#: 每段文字最多看這麼多字元：文字來自被掃的主機（banner、網頁標題），比對時間的最壞情況要有上限。
#: 產品字樣與標題都很短；有幾條樣式帶 `(?!.*…)` 這種向後看，長度沒有上限時最壞是二次方
MAX_TEXT = 400
#: 主機名稱的第一段最多 63 個字元（RFC 1035）
_MAX_LABEL = 63


def normalize_vendor(vendor: str | None) -> str:
    """IPAM 的 OUI 正規化：轉小寫、只留 a-z（數字與變音符號都去掉）。"""
    return re.sub(r"[^a-z]", "", (vendor or "")[:200].lower())


_OUI_INDEX: dict[str, OuiHint] = {}
for _h in OUI_SINGLE_PURPOSE:
    for _t in (*_h.tokens, *_h.aliases):
        _OUI_INDEX.setdefault(_t, _h)
OUI_MIXED_TOKENS = frozenset(t for m in OUI_MIXED_DO_NOT_USE for t in m.tokens)
_VIRTUAL_HEX = tuple(p.replace(":", "").lower() for p in OUI_VIRTUAL_NIC_PREFIXES)


def _mac_hex(mac: str | None) -> str:
    return re.sub(r"[^0-9a-f]", "", (mac or "")[:64].lower())


def is_locally_administered(mac: str | None) -> bool:
    """隨機／私人 MAC（iOS／Android／Windows 的私人位址、容器）：OUI 沒有意義。"""
    m = _mac_hex(mac)
    return len(m) >= 2 and bool(int(m[1], 16) & 0x2)


def is_virtual_nic(mac: str | None) -> bool:
    """虛擬網卡的 MAC 前綴（VMware、Hyper-V、Xen、VirtualBox、Proxmox、Nutanix、QEMU、Docker…）。"""
    m = _mac_hex(mac)
    return bool(m) and m.startswith(_VIRTUAL_HEX)


def oui_usable(mac: str | None) -> bool:
    """這個 MAC 的 OUI 能不能拿來推類型。沒有 MAC（只知道廠牌名稱）算可以；本機管理（隨機）的、虛擬網卡的、
    全零的（nmap-mac-prefixes 把 00:00:00 寫成 Xerox）都不行。"""
    m = _mac_hex(mac)
    if not m:
        return True
    return not (is_locally_administered(mac) or is_virtual_nic(mac) or set(m) == {"0"})


def oui_hint(vendor: str | None, mac: str | None = None) -> OuiHint | None:
    """網卡廠牌 → 只做一種東西的廠牌的線索。正規化之後完全相等才算（不做子字串比對）；
    混合廠牌、不認得的廠牌、不可用的 MAC 都回 None。"""
    if not oui_usable(mac):
        return None
    v = normalize_vendor(vendor)
    if not v or v in OUI_MIXED_TOKENS:
        return None
    return _OUI_INDEX.get(v)


def first_alternative(osmatch_name: str | None) -> str:
    """nmap 的名稱常列好幾個候選（「A or B」「A, B, C」）；第一個才對應第一筆 <osclass>。括號內的細節去掉。
    依名稱覆寫的規則只看這一段。"""
    n = re.sub(r"\([^()]{0,200}\)", " ", (osmatch_name or "")[:MAX_TEXT])
    # 只要第一段，分隔符兩側只需一個空白（後面的 strip 會去掉其餘）：`\s+or\s+` 在一長串空白後面
    # 不是 or 時會二次方回溯（CodeQL #45）；現在有長度上限擋著，這樣寫則不靠上限也是線性
    return re.split(r"\sor\s|,\s|;\s", n.strip(), maxsplit=1)[0].strip()


_NMAP_TYPE_LC = {k.lower(): k for k in NMAP_DEVICE_TYPES}


def nmap_kind(device_type: str | None, vendor: str | None = None, osfamily: str | None = None,
              name: str | None = None) -> tuple[str | None, str, str]:
    """一筆 nmap osclass／osmatch（或只有類別的服務 devicetype）→（類型, 信心, 理由）。
    nmap 的類別大小寫不一（WAP、VoIP phone），表裡用原始拼法，這裡不分大小寫查。"""
    raw = (device_type or "").strip()
    t = _NMAP_TYPE_LC.get(raw.lower(), raw)
    v, f, n = (vendor or "")[:200], (osfamily or "")[:200], first_alternative(name)
    for o in NMAP_CLASS_OVERRIDES:
        if o.device_type == "*":
            if t == "general purpose":
                continue
        elif o.device_type != t:
            continue
        if o.vendor and not re.search(o.vendor, v, _I):
            continue
        if o.osfamily and not re.search(o.osfamily, f, _I):
            continue
        if o.name and not re.search(o.name, n, _I):
            continue
        return o.kind, "high", f"override: {o.reason}"
    base = NMAP_DEVICE_TYPES.get(t)
    return (base.kind, base.confidence, base.reason) if base else (None, "medium", "unknown nmap device type")


_RECOG_OVERRIDES_LC = [(o.device.lower(), o) for o in RECOG_OVERRIDES]


def recog_kind(device: str | None, vendor: str | None = None, product: str | None = None,
               description: str | None = None, *, os_family: str | None = None) -> tuple[str | None, str, str]:
    """一筆 Recog 比對結果（hw.device 或 os.device，加上對應的 vendor／product）→（類型, 信心, 理由）。
    `os_family`：最後採用的作業系統家族；帶條件的覆寫（AirPlay 在 macOS 上）據此判斷。"""
    d = (device or "").strip()
    dl = d.lower()
    fields = {"vendor": (vendor or "")[:200], "product": (product or "")[:200],
              "description": (description or "")[:MAX_TEXT]}
    for dev, o in _RECOG_OVERRIDES_LC:
        if dev in ("*", dl) and re.search(o.pattern, fields[o.field], _I):
            if o.condition == "not_desktop_os" and os_family in DESKTOP_OS:
                return None, "medium", f"override not applicable on {os_family}: {o.reason}"
            return o.kind, "high", f"override: {o.reason}"
    base = RECOG_DEVICE_LC.get(dl)
    return (base.kind, base.confidence, base.reason) if base else (None, "medium", "unknown Recog device value")


_SERVICE_RX = [(p, re.compile(p.pattern, _I)) for p in SERVICE_PRODUCT_PATTERNS]


def clean_text(text: str | None) -> str:
    """比對前的整理：HTML 實體還原（標題常帶 &nbsp;）、限制長度。"""
    s = html.unescape((text or "")[:MAX_TEXT * 2]).replace("\xa0", " ")
    return s[:MAX_TEXT]


@lru_cache(maxsize=8192)
def _classify(text: str, os_family: str | None, debian: bool | None, guest: bool) -> int:
    for i, (p, rx) in enumerate(_SERVICE_RX):
        if not rx.search(text):
            continue
        c = p.condition
        if c == "not_desktop_os" and os_family in DESKTOP_OS:
            continue
        if c == "not_general_os" and os_family in GENERAL_OS:
            continue
        if c == "pve" and (guest or debian is False):
            continue
        return i
    return -1


def classify_service_text(text: str | None, *, os_family: str | None = None, debian: bool | None = None,
                          guest: bool = False) -> ServicePattern | None:
    """「一個」文字欄位（product＋version＋extrainfo、或網頁標題、或 Server 標頭）第一個符合的樣式。
    回傳的樣式 kind 是 None ＝排除條件（認得的軟體，說明不了設備）。`os_family` 用 normalize_os 的詞彙；
    `debian`：True 是 Debian、False 是別的發行版、None 是不知道；`guest`：已知是虛擬機或容器。
    同樣的產品字樣在很多台主機上重複出現，結果有快取。"""
    s = clean_text(text)
    if not s.strip():
        return None
    i = _classify(s, os_family, debian, bool(guest))
    return SERVICE_PRODUCT_PATTERNS[i] if i >= 0 else None


def normalize_hostname(hostname: str | None) -> str:
    """主機名稱的第一段，轉小寫，'-'／'_' 換成空白。"""
    h = (hostname or "").strip().lower().split(".")[0][:_MAX_LABEL]
    return re.sub(r"[-_]+", " ", h).strip()


_HOST_RX = [(h, re.compile(h.pattern, _I)) for h in HOSTNAME_HINTS]
_HOST_VETO = re.compile(HOSTNAME_ROLE_VETO, _I)


def hostname_kind(hostname: str | None, nic_vendor: str | None = None) -> HostnameHint | None:
    """主機名稱的線索：只看第一段；伺服器角色的字眼（server、db、api、archive…）否決設備類的線索。
    要求網卡廠牌的線索（型號字）只在廠牌相符時算；名稱同時講出兩種類型（voip-router-2）→ 不猜。"""
    n = normalize_hostname(hostname)
    if not n:
        return None
    v = normalize_vendor(nic_vendor)
    hits = [h for h, rx in _HOST_RX if rx.search(n) and (not h.vendors or any(v.startswith(t) for t in h.vendors))]
    if not hits:
        return None
    if len({h.kind for h in hits if h.kind is not None}) > 1:
        # 信心高的（廠牌預設名稱、BMC 的 idrac-／ilo-）優先；一樣高還是兩種類型 → 不猜
        rank = {"high": 2, "medium": 1, "low": 0}
        top = max(rank.get(h.confidence, 0) for h in hits)
        hits = [h for h in hits if rank.get(h.confidence, 0) == top]
        if len({h.kind for h in hits if h.kind is not None}) > 1:
            return None
    hit = hits[0]
    if hit.kind not in HOSTNAME_VETO_EXEMPT_KINDS and _HOST_VETO.search(n):
        return None
    return hit


_PORT_INDEX: dict[tuple[int, str], list[PortSig]] = {}
for _p in PORT_SIGNATURES:
    _PORT_INDEX.setdefault((_p.port, _p.proto), []).append(_p)


def port_signatures(port: int, proto: str = "tcp") -> list[PortSig]:
    """這個埠（與協定）的特徵；沒有就是空清單。"""
    try:
        key = (int(port), (proto or "tcp").lower())
    except (TypeError, ValueError):
        return []
    return list(_PORT_INDEX.get(key, []))
