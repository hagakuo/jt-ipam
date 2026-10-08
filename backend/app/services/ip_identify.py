"""IP 詳細頁「探測」的結果摘要：由掃描代理回報的證據推出「這是什麼主機」。

探測本身在掃描代理上跑（agent/jt_ipam_agent.py 的 `_job_run_identify`）：服務版本、OS 指紋、
banner／TLS 憑證等唯讀資訊，加上反解、NetBIOS、mDNS 名稱。這裡只做**確定性的推論**
（規則表），每個結論都附上依據，畫面上看得到為什麼這樣判斷 —— 不交給 LLM 猜。

設備類型代碼（前端翻譯）：server／windows／router／switch／firewall／wireless_ap／printer／
camera／voip／hypervisor／storage／media／mobile／specialized／unknown。

有安裝 Recog 指紋庫（選用，services/recog.py）時，另外拿 banner、網頁標題、憑證、SMB 回的
OS 字串去比對：認得出 nmap 認不出的設備（預設憑證、管理介面標題）與更精確的 OS（OpenSSH 註解裡的
發行版）。Recog 的結論一樣列在依據裡。

對應表（nmap 的類別、Recog 的設備值、網卡廠牌、產品字樣、埠的特徵）在 services/device_kind_knowledge.py；
這裡決定證據的先後（2026-10-05 起）：
  1. 服務自己講的話：每個埠的產品字樣、網頁標題、Server 標頭逐欄比對，以及 Recog 比中的設備
  2. nmap 服務偵測附的設備類別（devicetype，代理 1.17.2 起回報）
  3. 開著的埠（PVE、BMC、儲存、印表機、攝影機、VoIP、iOS、Windows，與廠牌專屬協定的埠）
  4. TCP/IP 指紋的類別（要夠準、前幾名不矛盾、廠牌跟網卡對得上）
  5. 只做一種東西的網卡廠牌（完全相等才算）
IPAM 自己知道的事實（裝置記錄、LibreNMS、電腦上的代理、虛擬化平台、主機名稱）在 device_identity.resolve_kind。
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, NamedTuple

from app.services import device_kind_knowledge as kk

if TYPE_CHECKING:
    from app.services.recog import Matcher

# 服務特徵 → 設備類型（比 OS 指紋可靠：服務是實際回應的內容）。依序比對，第一個命中為準。
# 每條規則看（這個埠, 整台的背景）：單一個埠常常不夠 —— NAS 也會開 RTSP、Linux 的 Samba 也會開 445。
# ⚠️ 這終究是推測（畫面上會標明可能不準），規則要「寧可說不知道，也不要自信地說錯」。
# 產品字樣（Synology、OPNsense、Hikvision…）的比對在 device_kind_knowledge.SERVICE_PRODUCT_PATTERNS，
# 下面的 _PORT_RULES 只看埠號與背景。
# Proxmox 的郵件閘道（PMG）與備份伺服器（PBS）也叫 Proxmox，PMG 的管理頁同樣在 8006
_NOT_PVE = re.compile(r"mail gateway|backup server", re.I)
# Proxmox VE 一定是 Debian：SSH 標頭寫著別的發行版 → 8006 是別的服務（gpu-node-01：NVIDIA DGX 的 Ubuntu）
_NOT_DEBIAN_DISTRO = re.compile(r"\b(?:ubuntu|centos|red ?hat|rhel|fedora|rocky|almalinux|suse|alpine|arch ?linux|"
                                r"raspbian|gentoo)\b", re.I)
_DEBIAN = re.compile(r"\bdebian\b|\+deb\d", re.I)
# BMC（伺服器的頻外管理）：主機板廠牌的網卡＋Dropbear＋iKVM 的 VNC（這些廠牌的伺服器網卡與 BMC 共用 OUI，
# 單看廠牌分不出來，要三個一起成立）
_BMC_VENDORS = ("supermicro", "asrockrack", "quanta", "gigabyte", "tyan", "inventec", "wiwynn")
# RTSP 的標準埠：攝影機幾乎都在這些；別的埠上的「rtsp」常是 nmap 把網頁誤認（keycloak 的 8080／8443）
_RTSP_PORTS = (554, 8554, 10554)
# Intel AMT（vPro 電腦內建）的網頁埠：同一台有這些時，623 是 AMT 不是伺服器的 BMC
_AMT_PORTS = (16992, 16993, 16994, 16995)

_LINUX_DISTRO = re.compile(r"\b(?:ubuntu|debian|centos|red ?hat|rhel|fedora|rocky|almalinux|suse|alpine|"
                           r"arch ?linux|raspbian|gentoo)\b", re.I)
_FILE_SHARING = ("nfs", "iscsi", "afp", "netbios-ssn", "microsoft-ds")
_FILE_SHARING_PORTS = (139, 445, 2049, 3260, 548)

#: 一般電腦／手機的作業系統家族：攝影機、印表機這類嵌入式設備不會跑這些
DESKTOP_FAMILIES = kk.DESKTOP_OS
#: 一般用途的作業系統家族（含 Linux、BSD）：埠號推測的「印表機」在這些上面多半是別的服務
GENERAL_FAMILIES = kk.GENERAL_OS
#: 「一般主機」的兩個類型：與其他類型並存不算矛盾
_GENERIC = frozenset({"server", "windows"})
#: 嵌入式設備：nmap 服務的類別（不夠具體的證據）在 Windows／macOS／iOS 上不採用這些
_EMBEDDED = frozenset({"printer", "camera", "switch", "wireless_ap", "voip", "media"})
#: 同一階段有好幾個候選（不同埠講出不同類型）、信心又相同時的順序：角色明確、不會跟別的類型並存的在前
#: （NAS 上的影音服務、路由器上的 AP 功能、Windows 上的虛擬化）
_KIND_RANK = {k: i for i, k in enumerate((
    "hypervisor", "specialized", "firewall", "router", "switch", "wireless_ap", "storage", "printer", "camera",
    "voip", "media", "mobile", "windows", "server"))}
_CONF_RANK = {"high": 0, "medium": 1}


def _text(p: dict[str, Any]) -> str:
    return f"{p.get('product') or ''} {p.get('extrainfo') or ''}"


def _is_samba(p: dict[str, Any]) -> bool:
    return "samba" in _text(p).lower()


#: 只有嵌入式設備會用的軟體：同一台有這些就不是一般主機（OpenWrt、BMC、AP、印表機、攝影機…）
_EMBEDDED_SOFTWARE = re.compile(r"busybox|dropbear|goahead|\bboa\b|mini_httpd|micro_httpd|uhttpd|thttpd|rompager|"
                                r"allegro|virata|emweb|\blwip\b|embedded web server", re.I)
#: 一般主機才會跑的服務（要真的比中，不是照埠號表猜的）
_SERVER_SERVICES = frozenset({"mysql", "postgresql", "redis", "mongodb", "mongod", "ms-sql-s", "oracle-tns",
                              "elasticsearch", "memcache", "amqp", "zabbix-agent", "nrpe", "docker", "kubernetes"})


def _general_host_evidence(ports: list[dict[str, Any]], os_name: str | None) -> bool:
    """看得到「這是一般用途的主機」的正面證據嗎。TCP/IP 指紋的「general purpose」只代表 Linux／BSD 核心，
    路由器、AP、IoT 閘道也都是（對抗式驗證 2026-10-05：198.51.100.53／.130、VigorAP903 被判成伺服器）。
    OpenSSH 算（RHEL 系的 banner 不帶發行版）、遠端桌面算，但同一台有 BusyBox／Dropbear 這類嵌入式軟體就不算。"""
    texts = [f"{p.get('product') or ''} {p.get('version') or ''} {p.get('extrainfo') or ''}" for p in ports]
    if any(_EMBEDDED_SOFTWARE.search(t) for t in texts):
        return False
    if os_name and _LINUX_DISTRO.search(os_name):
        return True
    for p, t in zip(ports, texts, strict=True):
        low = t.lower()
        if "openssh" in low or "xrdp" in low or "samba" in low or _LINUX_DISTRO.search(t):
            return True
        # 遠端桌面：不是 Windows 的堆疊上是 xrdp／GNOME 遠端登入，嵌入式設備不會開
        if _confirmed_service(p) in _SERVER_SERVICES or p.get("port") == 3389:
            return True
    return False


_DEBIAN_RELEASE = re.compile(r"\bdeb(\d{1,2})u\d+\b")


def _distro_from_banners(ports: list[dict[str, Any]]) -> str | None:
    """服務版本字串講出的發行版（OpenSSH 的「Debian 5+deb11u3」→ Debian 11）：TCP/IP 指紋只給得出
    「Linux 2.6.32」這種核心範圍時拿來顯示。"""
    for p in ports:
        t = f"{p.get('product') or ''} {p.get('version') or ''} {p.get('extrainfo') or ''}"
        m = _DEBIAN_RELEASE.search(t)
        if m and "debian" in t.lower():
            return f"Debian Linux {m.group(1)}"
    for p in ports:
        t = f"{p.get('product') or ''} {p.get('version') or ''} {p.get('extrainfo') or ''}"
        m = _LINUX_DISTRO.search(t)
        if m:
            name = {"red hat": "Red Hat", "redhat": "Red Hat", "rhel": "Red Hat", "almalinux": "AlmaLinux",
                    "suse": "SUSE"}.get(m.group(0).lower(), m.group(0).title())
            return f"{name} Linux"
    return None


def _table_guess(p: dict[str, Any]) -> bool:
    """nmap 沒有任何探針比中、只是照埠號表寫出服務名稱（XML 的 <service method="table">）：這個名稱只代表
    「開著這個埠」，等同沒有認出服務。代理 1.17.2 起才回報 method；舊代理沒有這個欄位 ＝ 照舊當成比中。"""
    return str(p.get("method") or "").lower() == "table"


def _confirmed_service(p: dict[str, Any]) -> str:
    """確認過的服務名稱：照埠號表猜的不算（例如 445 的 microsoft-ds? 在 Linux 的 Samba 上也是這樣）。"""
    return "" if _table_guess(p) else str(p.get("service") or "")


def _port_condition_ok(cond: str, c: dict[str, Any]) -> bool:
    """埠的特徵（PORT_SIGNATURES）的條件。needs_product 這類要靠產品字樣的，單憑埠號不成立。"""
    if cond == "":
        return True
    if cond == "not_general_os":
        return not c["general_os"]
    if cond == "not_desktop_os":
        return not c["desktop_os"]
    if cond == "not_guest":
        return not c["guest"]
    if cond == "no_file_sharing":
        return not c["file_sharing"]
    if cond == "embedded":
        return not c["general_host"] and not c["desktop_os"]
    return False


def _oui_disagrees(kind: str, c: dict[str, Any]) -> bool:
    """只做一種東西的網卡廠牌講的是另一種類型（一般主機之間不算矛盾）。"""
    h = c["oui"]
    return h is not None and h.kind != kind and not {h.kind, kind} <= _GENERIC


# 埠的特徵裡已經由下面較細的規則處理的：PVE 要 Debian、623 要排除 Intel AMT、iOS 的 62078、WinRM
_SIG_HANDLED = frozenset({(8006, "tcp"), (623, "udp"), (62078, "tcp"), (5985, "tcp"), (5986, "tcp")})


def _strong_sig(kind: str) -> Any:
    """「開著這個埠就足以判斷」的特徵（PORT_SIGNATURES 的 strong，多是廠牌專屬協定：MikroTik 的 8291、Dahua 的
    37777、Siemens S7 的 102、Sonos 的 1400…）。網卡是只做別種東西的廠牌時不採信 —— 同一個埠號別家也會用
    （ATOM Cam 攝影機也開 Kasa 插座的 9999）。"""
    sigs = {(s.port, s.proto): s for s in kk.PORT_SIGNATURES
            if s.kind == kind and s.strength == "strong" and (s.port, s.proto) not in _SIG_HANDLED}

    def rule(p: dict[str, Any], c: dict[str, Any]) -> bool:
        s = sigs.get((p.get("port"), str(p.get("proto") or "tcp").lower()))
        return s is not None and _port_condition_ok(s.condition, c) and not _oui_disagrees(kind, c)
    return rule


_PORT_RULES: list[tuple[str, Any]] = [
    # Proxmox VE 網頁介面在 8006；版本偵測常只認得 tcpwrapped，所以只有埠號也算 —— 但虛擬機／容器不算
    # （pmg-01 是 PVE 上的容器，跑 Proxmox Mail Gateway，管理頁也在 8006，以前判成虛擬化主機）
    # Proxmox Mail Gateway（同時收信：25／26）與 Datacenter Manager（8443）的管理頁也在 8006 附近，只認得埠號時不算
    ("hypervisor", lambda p, c: p.get("port") == 8006 and not c["guest"] and not c["not_debian"]
                                and not c["pve_conflict"] and not _NOT_PVE.search(_text(p))),
    # BMC：IPMI 的 623；同一台開著 Intel AMT 的網頁（16992～16995）或作業系統是 Windows／macOS → 是 vPro 電腦的
    # AMT，不是伺服器的 BMC。或主機板廠牌的網卡＋Dropbear（BMC 的 SSH）＋iKVM 的 VNC
    ("specialized", lambda p, c: ((p.get("port") == 623 or p.get("service") in ("asf-rmcp", "ipmi"))
                                  and not c["amt"] and not c["desktop_os"])
                                 or (c["bmc_vendor"] and "dropbear" in _text(p).lower() and c["has_vnc"])),
    ("firewall", _strong_sig("firewall")),
    ("router", _strong_sig("router")),
    ("switch", _strong_sig("switch")),
    ("wireless_ap", _strong_sig("wireless_ap")),
    # NAS：主力做 NAS 的廠牌＋檔案分享、或 iSCSI／NFS／AFP 這種儲存服務（產品字樣在前一階段就比過了）
    # 一般作業系統上只有 NFS／iSCSI／AFP 的埠，是一台順便分享檔案的主機，不是儲存設備（samba-dc-01：Debian 上的 Samba
    # 網域控制站開了 NFS）；NAS 要有產品字樣或 NAS 廠牌
    ("storage", lambda p, c: (c["nas_vendor"] and (p.get("service") in _FILE_SHARING
                                                   or p.get("port") in _FILE_SHARING_PORTS))
                             or ((p.get("service") in ("iscsi", "nfs", "afp") or p.get("port") in (3260, 2049, 548))
                                 and not c["general_os"])),
    # IPP 本身不代表印表機：Linux 的 CUPS 列印服務也開 631/ipp（實測 Ubuntu 開發機被判成印表機）
    # 9100 只有埠號（nmap 照埠號表寫 jetdirect、沒認出產品）時，在一般作業系統上多半是 Prometheus 的
    # node_exporter（OPNsense、Linux 伺服器都常開），不算印表機；認出產品、或指紋不是一般作業系統才算
    # 515（LPD）同理：路由器、NAS 分享 USB 印表機都會開（VigorAP903、Synology RT1900ac 被判成印表機）
    # 631 只是照埠號表猜的 ipp（沒有探針比中）跟沒認出產品的 9100 一樣看待
    ("printer", lambda p, c: ((p.get("service") in ("jetdirect", "printer") or p.get("port") in (9100, 515)
                               or (_table_guess(p) and p.get("port") == 631))
                              and (bool(p.get("product")) or not (c["general_os"] or c["network_os"])))
                             or (_confirmed_service(p) == "ipp" and "cups" not in str(p.get("product") or "").lower())),
    # 只有 RTSP 時：有檔案分享的不算（NAS、媒體伺服器都會開 RTSP）；作業系統是一般電腦／手機的也不算 ——
    # macOS 的 AirPlay 接收器就在 5000／7000 用 RTSP（2026-10-05 正式環境的 MacBook 被判成攝影機）
    ("camera", lambda p, c: ((p.get("service") == "rtsp" and (p.get("port") in _RTSP_PORTS or not c["general_os"]))
                             or p.get("port") == 554) and not c["file_sharing"] and not c["desktop_os"]),
    ("camera", _strong_sig("camera")),
    # 工控（S7 的 102、EtherNet/IP、BACnet、Modbus…）、門禁打卡機、智慧插座的區網協定
    ("specialized", _strong_sig("specialized")),
    ("media", _strong_sig("media")),
    ("voip", lambda p, c: p.get("service") in ("sip", "sip-tls") or p.get("port") in (5060, 5061)),
    # iOS 的 lockdownd（iTunes／Finder 同步）：只有 Apple 的行動裝置會聽 62078 —— Apple TV／HomePod 也會，
    # 它們同時是 AirPlay 接收器（7000）；Mac 有 AirPlay 但不開 62078
    ("media", lambda p, c: (p.get("port") == 62078 or p.get("service") == "iphone-sync") and c["airplay"]),
    ("mobile", lambda p, c: (p.get("port") == 62078 or p.get("service") == "iphone-sync") and not c["airplay"]),
    # 445／139 在 Linux 上是 Samba，3389 在 Linux 上是 xrdp，都不是 Windows；作業系統確定不是 Windows 時整條不套
    #（ws-ud24 是 Ubuntu，裝了 xrdp → 以前判成 Windows 主機）。msrpc／microsoft-ds 要真的比中服務才算：
    # 照埠號表猜的只代表 135／445 開著（Samba 也是）。5985／5986 是 WinRM
    ("windows", lambda p, c: not c["non_windows_os"] and "xrdp" not in _text(p).lower()
                             and (p.get("service") == "ms-wbt-server" or _confirmed_service(p) == "msrpc"
                                  or p.get("port") in (3389, 5985, 5986)
                                  or (_confirmed_service(p) == "microsoft-ds" and not _is_samba(p)))),
    # 最後：服務自己講出是一般 Linux（xrdp、Samba、版本字串裡的發行版名稱）→ 一般主機（前面的具體角色都沒中時才用）
    ("server", lambda p, c: "xrdp" in _text(p).lower() or _is_samba(p)
                            or _LINUX_DISTRO.search(f"{p.get('product') or ''} {p.get('version') or ''} "
                                                    f"{p.get('extrainfo') or ''}")),
]

#: 指紋的「廠牌」其實是作業系統的作者，不是硬體廠牌（ESXi 的指紋寫 VMware，硬體是 Dell、HPE…）
_OS_AUTHORS = ("linux", "freebsd", "openbsd", "netbsd", "microsoft", "openwrt", "vmware")
#: 產品全是網通設備的混合廠牌（AP、交換器、路由器都做）：指紋只說得出「OpenWrt／Linux 的 WAP」時，網卡是這些、
#: 或是 device_kind_knowledge 裡主力做 AP／路由器／交換器的廠牌就採信。以前是子字串比對，"aruba" 在 manuf 裡
#: 根本不存在（Aruba 的 OUI 登記在 HPE 名下）、Meraki 也做攝影機，都拿掉了
_NETWORK_VENDOR_TOKENS = frozenset({"ubiquiti", "ubiquitiinc", "routerboardc", "routerboardcom", "mikrotik"})
#: 網卡 OUI 名稱與指紋廠牌寫法不同的常見對照（OUI 名稱已去掉空白、截成 12 字元）
_VENDOR_ALIASES = {"hp": ("hewlett", "hpe", "aruba"), "dlink": ("dlink",), "tplink": ("tplink", "tp-link"),
                   "cisco": ("cisco",), "ubiquiti": ("ubiquiti",), "netgear": ("netgear",)}


def _norm_vendor(v: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (v or "").lower())


def _vendors_agree(fp_vendor: str | None, nic_vendor: str | None) -> bool:
    """指紋說的廠牌與網卡 OUI 廠牌是不是同一家。任一邊不知道 → 不能說不一致（照舊採信）。"""
    a, b = _norm_vendor(fp_vendor), _norm_vendor(nic_vendor)
    if not a or not b:
        return True
    if a in _OS_AUTHORS:
        return False            # 指紋只說得出作業系統（OpenWrt／Linux），說不出是哪家的硬體
    if a[:5] in b or b[:5] in a:
        return True
    return any(x in b for x in _VENDOR_ALIASES.get(a, ()))


def _network_vendor(nic_vendor: str | None, mac: str | None) -> bool:
    if not kk.oui_usable(mac):
        return False
    h = kk.oui_hint(nic_vendor, mac)
    return kk.normalize_vendor(nic_vendor) in _NETWORK_VENDOR_TOKENS or (
        h is not None and h.kind in ("wireless_ap", "router", "switch"))


def _ports_contradict(kind: str, ports: list[dict[str, Any]], c: dict[str, Any]) -> bool:
    """開著的埠講出另一種設備（一般主機不算）：medium 的網卡廠牌線索要「沒有矛盾的證據」才用
    （Canon 也做網路攝影機：開著 Google Cast 的 8009 就不猜印表機）。
    廠牌專屬協定的埠（strong）不算矛盾：跟網卡廠牌不一致時，在前面就因為廠牌對不上而不採信了。"""
    for p in ports:
        for s in kk.port_signatures(p.get("port") or 0, str(p.get("proto") or "tcp")):
            if (s.strength != "strong" and s.kind and s.kind != kind and s.kind not in _GENERIC
                    and _port_condition_ok(s.condition, c)):
                return True
    return False


class _Cand(NamedTuple):
    """一個類型的候選：同一階段裡依（信心, 來源, 類型順序, 埠的位置）挑一個。"""

    kind: str
    conf: str
    source: int                 # 0＝服務自己講的產品字樣、1＝Recog
    port: int
    evidence: str | None


def _pick(cands: list[_Cand]) -> _Cand | None:
    if not cands:
        return None
    return min(cands, key=lambda x: (_CONF_RANK.get(x.conf, 1), x.source, _KIND_RANK.get(x.kind, 99), x.port))


def _kind_allowed(kind: str, c: dict[str, Any], *, specific: bool) -> bool:
    """證據講的類型在這台的背景下說得通嗎。
    - 攝影機：同一台有檔案分享（NFS／SMB／AFP／iSCSI）時不算 —— NAS、媒體伺服器也會開 RTSP，nmap 還常把
      NAS 的 RTSP 認成某款攝影機（2026-09-29 Synology）
    - 不夠具體的證據（nmap 服務偵測附的設備類別）：作業系統是 Windows／macOS／iOS 時不會是嵌入式設備
      （macOS 的 AirPlay 接收器在 nmap 的服務類別是 media device）
    - Windows：作業系統確定是 Linux／BSD／macOS 時不算 —— Samba AD DC 的 135 在 nmap 寫「Microsoft Windows RPC」、
      反向代理會把後端 IIS 的 Server 標頭轉出來（2026-10-05 samba-dc-01／samba-dc-02 被判成 Windows）"""
    if kind == "camera" and c["file_sharing"]:
        return False
    if kind == "windows" and c["non_windows_os"]:
        return False
    return specific or not (kind in _EMBEDDED and c["desktop_os"])


_NO_TITLE = ("Site doesn't have a title", "Did not follow redirect")
_MAX_SCRIPT_TEXT = 4000


def _text_fields(p: dict[str, Any], recog_app: str | None) -> list[tuple[str, str]]:
    """一個埠可以拿來比對產品樣式的文字欄位（欄位名稱, 文字）。每個欄位分開比對：一個欄位裡的排除條件
    （例如 Plex Media Server）不可以蓋掉另一個欄位講出的產品（Synology DiskStation）。
    「Did not follow redirect to https://printer…」這種是 nmap 的訊息不是標題，裡面的網址不可以當成產品。"""
    out: list[tuple[str, str]] = []
    prod = " ".join(str(x) for x in (p.get("product"), p.get("version"), p.get("extrainfo")) if x).strip()
    if prod:
        out.append(("product", prod))
    scripts = p.get("scripts") or {}
    title = _first_line(str(scripts.get("http-title") or "")[:_MAX_SCRIPT_TEXT])
    if title and not title.startswith(_NO_TITLE):
        out.append(("title", _unescape(title)))
    for line in str(scripts.get("http-server-header") or "")[:_MAX_SCRIPT_TEXT].splitlines():
        if line.strip():
            out.append(("server", _unescape(line.strip())))
    if recog_app:
        out.append(("recog", recog_app))
    return out

_MIN_OS_ACCURACY = 85
#: 第一名是設備類、但通用作業系統的猜測只差這麼多以內 → 分不出來，改用通用作業系統那筆
#: （nmap 常把新版 Linux 核心認成 HP P2000 G3 NAS，兩者只差 0~1 個百分點）
_AMBIGUOUS_GAP = 2


def _open_ports(nmap: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in (nmap.get("ports") or []) if isinstance(p, dict)
            and (p.get("state") or "open") == "open"]


def _service_line(p: dict[str, Any]) -> str:
    parts = [f"{p.get('port')}/{p.get('proto') or 'tcp'}", p.get("service") or "?"]
    prod = " ".join(x for x in (p.get("product"), p.get("version")) if x)
    if prod:
        parts.append(prod)
    return " ".join(str(x) for x in parts)


_MAX_CERT_NAMES = 3


def _cert_names(p: dict[str, Any]) -> list[str]:
    """TLS 憑證上的主機名稱：只看 Subject 與 SAN（Issuer 的 CN 是簽發機構，例如 Let's Encrypt 的
    「YR2」），略過萬用名稱（*.example.net 說明不了這是哪一台），每張憑證最多取幾個 ——
    一張多網域憑證可能列上幾十個名稱。"""
    out = (p.get("scripts") or {}).get("ssl-cert") or ""
    found: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Subject:"):
            found += re.findall(r"commonName=([^/\s,]+)", line)
        elif line.startswith("Subject Alternative Name:"):
            found += re.findall(r"DNS:([^\s,]+)", line)
    names: list[str] = []
    for n in found:
        if _FQDN_RE.match(n) and n not in names:
            names.append(n)
    return names[:_MAX_CERT_NAMES]


# 憑證上的名稱要長得像網域名稱才算主機名稱：實測 7070 埠的憑證 CN 是「AnyDesk Client」
# （軟體自簽的憑證，CN 放的是軟體名稱），被當成主機名稱「AnyDesk」。萬用名稱（*.）也不算。
_FQDN_RE = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def _cert_subject_cn(p: dict[str, Any]) -> str | None:
    out = (p.get("scripts") or {}).get("ssl-cert") or ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Subject:"):
            m = re.search(r"commonName=([^/,]+)", line)
            return m.group(1).strip() if m else None
    return None


def _applications(ports: list[dict[str, Any]], recog_apps: dict[str, str] | None = None) -> list[str]:
    """這台跑了哪些軟體：nmap 認出來的產品＋版本；nmap 認不出、Recog 認得的用 Recog 的；
    都認不出、但 TLS 憑證的 CN 不是主機名稱時，CN 通常就是軟體名稱（例如 AnyDesk 的自簽憑證
    「AnyDesk Client」）。同一個軟體只列一次。"""
    apps: list[str] = []
    for p in ports:
        prod = " ".join(x for x in (p.get("product"), p.get("version")) if x).strip()
        if not prod and recog_apps:
            prod = recog_apps.get(f"{p.get('port')}/{p.get('proto') or 'tcp'}", "")
        if not prod:
            cn = _cert_subject_cn(p)
            if cn and not _FQDN_RE.match(cn) and not cn.startswith("*"):
                # 去掉結尾的 Client／Server／Service（不用 `\s+…$`：一長串空白會回溯到平方時間）
                words = cn.split()
                if len(words) > 1 and words[-1] in ("Client", "Server", "Service"):
                    words = words[:-1]
                prod = " ".join(words)
        if prod and prod not in apps:
            apps.append(prod)
    return apps


# ───────────────────────── Recog 指紋比對 ─────────────────────────

# Recog 的 hw.device／os.device → 設備類型：device_kind_knowledge.RECOG_DEVICE（Recog 全部 117 個值逐一整理，
# 籠統的 Device／Appliance／Security Appliance 這類對到 None，交給其他規則，不硬猜）
_RECOG_MIN_CERTAINTY = 0.5        # 低於這個（例如 0.0＝「assert nothing」）的欄位一律不用
_RECOG_STRONG_OS = 0.75           # OS 到這個把握度才蓋過 nmap 的 OS 指紋
_MAX_RECOG_EVIDENCE = 6

_NMAP_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})|\\\\")
# telnet 協商位元組：WILL/WONT/DO/DONT＋選項、子協商 SB … SE、其他單一指令。
# 子協商限長（CodeQL #39）：以前寫 `.*?`，每個沒結束的 SB 都掃到結尾＝二次方（40 KB 要十秒）；
# 子協商內容裡的 IAC 會寫成 \xff\xff，要允許
_TELNET_IAC = re.compile(rb"\xff[\xfb-\xfe].|\xff\xfa(?:[^\xff]|\xff\xff){0,256}\xff\xf0|\xff[\xf0-\xfa]", re.S)
#: smb-os-discovery 的「OS: …」那一行（只取整行，括號另外拆：CodeQL #40）
_SMB_OS_LINE = re.compile(r"^[ \t]*OS: ([^\n]+)$", re.M)
# nmap ssl-cert 的欄位名稱 → RFC 4514 的簡寫（Recog 的憑證範例是 CN=…,OU=…,O=…,L=…,ST=…,C=… 的順序）
_DN_ORDER = (("emailAddress", "emailAddress"), ("serialNumber", "SERIALNUMBER"), ("commonName", "CN"),
             ("organizationalUnitName", "OU"), ("organizationName", "O"), ("localityName", "L"),
             ("stateOrProvinceName", "ST"), ("countryName", "C"))


def _unescape(text: str, *, telnet: bool = False) -> str:
    """nmap 腳本輸出把不可列印的位元組寫成 \\xHH：還原後以 UTF-8 解（中文標題才讀得出來）。"""
    raw = bytearray()
    pos = 0
    for m in _NMAP_ESC.finditer(text):
        raw += text[pos:m.start()].encode("utf-8", errors="replace")
        raw += bytes([int(m.group(1), 16)]) if m.group(1) else b"\\"
        pos = m.end()
    raw += text[pos:].encode("utf-8", errors="replace")
    data = bytes(raw)
    if telnet:
        data = _TELNET_IAC.sub(b"", data)
    return data.decode("utf-8", errors="replace")


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")


def _dn(fields: dict[str, Any]) -> str:
    """{commonName: …, organizationName: …} → 「CN=…,O=…」（值裡的逗號要跳脫）。"""
    parts = []
    for long_name, short in _DN_ORDER:
        v = fields.get(long_name)
        if isinstance(v, str) and v:
            parts.append(f"{short}={v.replace(',', chr(92) + ',')}")
    return ",".join(parts)


def _dn_from_text(line: str) -> str:
    """舊版代理只回文字：「commonName=x/organizationName=y/countryName=US」。"""
    fields: dict[str, str] = {}
    for part in line.split("/"):
        k, sep, v = part.partition("=")
        if sep:
            fields[k.strip()] = v.strip()
    return _dn(fields)


def _banner_observation(p: dict[str, Any], banner: str) -> tuple[str, str] | None:
    svc = str(p.get("service") or "").lower()
    port = p.get("port")
    line = _first_line(_unescape(banner))
    if line.startswith("SSH-") or svc == "ssh":
        return "ssh.banner", re.sub(r"^SSH-[\d.]+-", "", line)
    if svc == "ftp" or port == 21:
        return "ftp.banner", re.sub(r"^220[- ]", "", line)
    if svc in ("smtp", "submission") or port in (25, 587):
        return "smtp.banner", re.sub(r"^220[- ]", "", line)
    if svc == "pop3" or port == 110:
        return "pop3.banner", re.sub(r"^\+OK\s*", "", line)
    if svc == "imap" or port == 143:
        return "imap4.banner", re.sub(r"^\* OK\s*(?:\[[^\]]{0,400}\]\s*)?", "", line)
    if svc == "telnet" or port == 23:
        return "telnet_banners", _unescape(banner, telnet=True).strip()
    return None


def recog_observations(nmap: dict[str, Any]) -> list[tuple[str, str | None, str]]:
    """探測結果裡可以拿去比對 Recog 的文字 → [(指紋庫, 埠, 文字)]。"""
    obs: list[tuple[str, str | None, str]] = []
    for p in _open_ports(nmap):
        where = f"{p.get('port')}/{p.get('proto') or 'tcp'}"
        scripts = p.get("scripts") or {}
        data = p.get("script_data") or {}
        if scripts.get("banner"):
            b = _banner_observation(p, str(scripts["banner"]))
            if b and b[1]:
                obs.append((b[0], where, b[1]))
        for line in str(scripts.get("http-server-header") or "").splitlines():
            if line.strip():
                obs.append(("http_header.server", where, _unescape(line.strip())))
        title = _first_line(str(scripts.get("http-title") or ""))
        if title and not title.startswith(("Site doesn't have a title", "Did not follow redirect")):
            obs.append(("html_title", where, _unescape(title)))
        cert = data.get("ssl-cert") if isinstance(data.get("ssl-cert"), dict) else None
        text = str(scripts.get("ssl-cert") or "")
        for part, label in (("subject", "Subject:"), ("issuer", "Issuer:")):
            if cert and isinstance(cert.get(part), dict):
                dn = _dn(cert[part])
            else:
                line = next((ln.strip()[len(label):].strip() for ln in text.splitlines()
                             if ln.strip().startswith(label)), "")
                dn = _dn_from_text(line) if line else ""
            if dn:
                obs.append((f"x509.{part}", where, dn))
    # smb-os-discovery 是主機層腳本：「OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)」＝ native OS (LAN manager)
    smb = str((nmap.get("host_scripts") or {}).get("smb-os-discovery") or "")
    # 以前一條正規表示式同時拆括號（`(.+?)(?: \((.+)\))?\s*$`）：遇到「OS: a ( ( ( …」是二次方。
    # 現在先取整行、再用字串操作拆：第一個「 (」之前是 native OS，結尾的括號內是 LAN manager
    m = _SMB_OS_LINE.search(smb)
    rest = m.group(1).strip() if m else ""
    if rest:
        i = rest.find(" (", 1)
        if i != -1 and rest.endswith(")") and len(rest) - i > 3:
            obs.append(("smb.native_os", None, rest[:i]))
            obs.append(("smb.native_lm", None, rest[i + 2:-1]))
        else:
            obs.append(("smb.native_os", None, rest))
    return obs


def _certainty(match: dict[str, Any], ns: str) -> float:
    raw = match["params"].get(f"{ns}.certainty") or match.get("certainty")
    try:
        return float(raw) if raw is not None else 1.0
    except ValueError:
        return 1.0


def recog_matches(nmap: dict[str, Any], matcher: Matcher) -> list[dict[str, Any]]:
    """每段文字比對一次；比中了但 Recog 自己說「不下結論」（certainty 0）的也留著，只是不採用。"""
    out = []
    for key, where, text in recog_observations(nmap):
        m = matcher.match(key, text)
        if m:
            out.append({**m, "port": where, "input": text[:200]})
    return out


def _os_from_params(pr: dict[str, str]) -> str | None:
    product, vendor = pr.get("os.product"), pr.get("os.vendor")
    name = product or pr.get("os.family")
    if not name:
        return None
    if vendor and vendor.lower() not in name.lower():
        name = f"{vendor} {name}"
    for extra in (pr.get("os.edition"), pr.get("os.version")):
        if extra and extra.lower() not in name.lower():
            name = f"{name} {extra}"
    return name


def _service_name(pr: dict[str, str]) -> str | None:
    product = pr.get("service.product")
    if not product:
        return None
    family = pr.get("service.family")
    name = f"{family} {product}" if family and family.lower() not in product.lower() else product
    return f"{name} {pr['service.version']}" if pr.get("service.version") else name


def _recog_conclusions(matches: list[dict[str, Any]], matcher: Matcher,
                       known_ports: set[str]) -> dict[str, Any]:
    """比對結果 → 設備的候選、OS（附把握度）、硬體廠牌、型號、每個埠的軟體。偏好度高的指紋庫先看。

    `known_ports`：nmap 已經認出產品的埠 —— 這些埠的軟體用 nmap 的，Recog 的就不算貢獻
    （不然依據裡會塞滿「nginx with version info」這種對結論沒有幫助的條目）。
    設備（hw.device／os.device）只收集成候選、依偏好度排好：對應成哪個類型要等作業系統決定之後才知道
    （Recog 的 AirPlay 指紋在 macOS 上不算影音設備），由 summarize 挑。"""
    ranked = sorted(matches, key=lambda m: -matcher.preference(m["db"]))
    out: dict[str, Any] = {"devices": [], "os": None, "vendor": None, "model": None, "apps": {}, "used": [],
                           "default_cert_ports": set(), "ranked": ranked}
    for m in ranked:
        pr = m["params"]
        used = False
        hw_ok = _certainty(m, "hw") >= _RECOG_MIN_CERTAINTY
        os_ok = _certainty(m, "os") >= _RECOG_MIN_CERTAINTY
        # 比中的是設備出廠的預設憑證（Synology 的 CN=synology.com 這種）：上面的名稱是廠商的，不是這台的
        if m["db"] == "x509.subject" and m.get("port") and (
                (hw_ok and any(k.startswith("hw.") for k in pr)) or (os_ok and any(k.startswith("os.") for k in pr))):
            out["default_cert_ports"].add(m["port"])
        for ns, ok in (("hw", hw_ok), ("os", os_ok)):
            if ok and pr.get(f"{ns}.device"):
                out["devices"].append((pr[f"{ns}.device"], pr.get(f"{ns}.vendor"),
                                       pr.get(f"{ns}.product") or pr.get(f"{ns}.family"), m.get("description"), m))
        if os_ok:
            name = _os_from_params(pr)
            cert = _certainty(m, "os")
            if name and (out["os"] is None or cert > out["os"][1]):
                out["os"] = (name, cert, m)
                used = True
        if hw_ok and out["vendor"] is None and pr.get("hw.vendor"):
            out["vendor"] = pr["hw.vendor"]
            used = True
        if hw_ok and out["model"] is None and (pr.get("hw.product") or pr.get("hw.family")):
            out["model"] = pr.get("hw.product") or pr.get("hw.family")
            used = True
        if (_certainty(m, "service") >= _RECOG_MIN_CERTAINTY and m.get("port")
                and m["port"] not in known_ports and m["port"] not in out["apps"]):
            svc = _service_name(pr)
            if svc:
                out["apps"][m["port"]] = svc
                used = True
        if used:
            out["used"].append(m)
    return out


def _recog_evidence(m: dict[str, Any]) -> str:
    where = f"{m['port']} " if m.get("port") else ""
    return f"recog:{m['description'] or m['db']} ({where}{m['db']})"


# ─────────────────── 已經抓到、以前沒顯示的欄位（2026-10-07） ───────────────────

# 值用貪婪的 [^\n]* 再 strip：值後面接 [ \t]*$ 的寫法遇到一長串空白會二次方回溯
_KV_LINE = re.compile(r"^[ \t|_]*([A-Za-z][A-Za-z0-9 _-]{0,40}?):[ \t]*(\S[^\n]*)", re.M)
_HOSTKEY_LINE = re.compile(r"^[ \t|_]*(\d{3,5})[ \t]+((?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}|SHA256:\S+)[ \t]+\(([\w-]{1,30})\)",
                           re.M)
_WIN_BUILD = re.compile(r"^\d{1,2}\.\d{1,2}\.(\d{3,6})$")
_MAX_CERTS = 10


def _kv(text: str | None) -> dict[str, str]:
    """nmap 腳本的「欄位: 值」文字 → dict（rdp-ntlm-info、smb-os-discovery、ssl-cert 的文字輸出都是這種）。
    值結尾的 `\x00`（nmap 把 NUL 寫成這樣，NetBIOS 名稱常帶）去掉。"""
    out: dict[str, str] = {}
    for k, v in _KV_LINE.findall(text or ""):
        v = v.replace("\\x00", "").replace("\x00", "").strip()
        if v and k.strip() not in out:
            out[k.strip()] = v
    return out


def _windows_identity(ports: list[dict[str, Any]], nmap: dict[str, Any]) -> dict[str, Any] | None:
    """rdp-ntlm-info（3389）與 smb-os-discovery（主機層）講出的 Windows 電腦名稱、網域、工作群組、版本。
    沒加入網域的電腦，NTLM 回的「網域」就是電腦名稱自己 —— 那不是網域，不列。"""
    rdp = next((str((p.get("scripts") or {}).get("rdp-ntlm-info")) for p in ports
                if (p.get("scripts") or {}).get("rdp-ntlm-info")), None)
    smb = (nmap.get("host_scripts") or {}).get("smb-os-discovery")
    if not rdp and not smb:
        return None
    r, m = _kv(rdp), _kv(smb)
    computer = r.get("NetBIOS_Computer_Name") or m.get("NetBIOS computer name") or m.get("Computer name")
    domain = r.get("NetBIOS_Domain_Name")
    dns_domain = r.get("DNS_Domain_Name") or m.get("Domain name")
    fqdn = r.get("DNS_Computer_Name") or m.get("FQDN")
    def same(v: str | None) -> bool:
        return bool(v and computer and v.lower() == computer.lower())
    out = {
        "computer": computer,
        "domain": None if same(domain) else domain,
        "dns_domain": None if same(dns_domain) or not (dns_domain and "." in dns_domain) else dns_domain,
        "fqdn": fqdn if fqdn and "." in fqdn else None,
        "workgroup": m.get("Workgroup"),
        "product_version": r.get("Product_Version"),
    }
    return out if any(out.values()) else None


def _windows_os(nmap: dict[str, Any], win: dict[str, Any] | None) -> tuple[str, str] | None:
    """OS 指紋與 Recog 都沒結論時，SMB 與 RDP 自己講的作業系統 →（OS, 依據）。

    Samba 會自稱「Windows 6.1」，不採信；RDP 只給核心版本號（10.0.26100），分不出用戶端或伺服器版，照實寫 build。"""
    smb = str((nmap.get("host_scripts") or {}).get("smb-os-discovery") or "")
    m = _SMB_OS_LINE.search(smb)
    if m and "samba" not in smb.lower():
        name = m.group(1).split("(", 1)[0].strip()
        if name.lower().startswith("windows"):
            return name[:80], f"smb-os:{name[:80]}"
    ver = (win or {}).get("product_version") or ""
    b = _WIN_BUILD.match(ver)
    if b:
        return f"Windows (build {b.group(1)})", f"rdp:{ver}"
    return None


def _dn_display(fields: dict[str, Any]) -> str:
    return ", ".join(f"{short}={fields[long]}" for long, short in _DN_ORDER
                     if isinstance(fields.get(long), str) and fields.get(long))


def _dn_display_text(line: str) -> str:
    fields: dict[str, str] = {}
    for part in line.split("/"):
        k, sep, v = part.partition("=")
        if sep:
            fields[k.strip()] = v.strip()
    return _dn_display(fields)


def _hex(v: str | None) -> str | None:
    h = re.sub(r"[^0-9a-fA-F]", "", v or "").lower()
    return h or None


def _certs(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """每個 TLS 埠的憑證：主體、簽發者、有效期間、指紋、金鑰、SAN。新代理（1.17.4）給結構化欄位；
    舊代理只有文字（600 字內），能讀多少算多少。"""
    out = []
    for p in ports:
        data = ((p.get("script_data") or {}).get("ssl-cert")) or {}
        text = str((p.get("scripts") or {}).get("ssl-cert") or "")
        if not data and not text:
            continue
        kv = _kv(text)
        subject = _dn_display(data["subject"]) if data.get("subject") else _dn_display_text(kv.get("Subject", ""))
        issuer = _dn_display(data["issuer"]) if data.get("issuer") else _dn_display_text(kv.get("Issuer", ""))
        key_type = data.get("key_type") or kv.get("Public Key type")
        key_bits = data.get("key_bits") or kv.get("Public Key bits")
        san = data.get("san")
        if san is None and kv.get("Subject Alternative Name"):
            san = [x.strip() for x in kv["Subject Alternative Name"].split(",") if x.strip()][:20]
        out.append({
            "port": _port_key(p),
            "subject": subject or None,
            "issuer": issuer or None,
            "self_signed": bool(subject) and subject == issuer,
            "not_before": data.get("not_before") or kv.get("Not valid before"),
            "not_after": data.get("not_after") or kv.get("Not valid after"),
            "sha256": data.get("sha256") or _hex(kv.get("SHA-256")),
            "sha1": data.get("sha1") or _hex(kv.get("SHA-1")),
            "key": " ".join(str(x) for x in (key_type, key_bits) if x) or None,
            "san": san or [],
        })
    return out[:_MAX_CERTS]


def _ssh_keys(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SSH 主機金鑰。新代理給 SHA256 指紋（跟 `ssh-keygen -lf` 一樣）；舊代理只有 nmap 預設的 MD5 文字。"""
    out = []
    for p in ports:
        data = (p.get("script_data") or {}).get("ssh-hostkey")
        if data:
            out += [{"port": _port_key(p), "type": k.get("type"), "bits": k.get("bits"), "fingerprint": k.get("sha256")}
                    for k in data if isinstance(k, dict)]
            continue
        for bits, fp, typ in _HOSTKEY_LINE.findall(str((p.get("scripts") or {}).get("ssh-hostkey") or "")):
            out.append({"port": _port_key(p), "type": typ, "bits": int(bits),
                        "fingerprint": fp if fp.startswith("SHA256:") else f"MD5:{fp.lower()}"})
    return out[:16]


def _scan_error(nmap: dict[str, Any]) -> str | None:
    """nmap 本身失敗（不是主機沒回應）：例外、逾時、結束碼非零、輸出裡沒有這台、單台時限到了被丟掉。"""
    if not bool(nmap.get("available", bool(nmap))):
        return None
    if nmap.get("error"):
        return str(nmap["error"])[:600]
    stderr = str(nmap.get("stderr") or "").strip()
    if nmap.get("exit") not in (None, 0):
        return f"exit {nmap.get('exit')}" + (f": {stderr[-500:]}" if stderr else "")
    if nmap.get("host_found") is False:
        return stderr[-500:] or "no host in nmap output"
    if nmap.get("timedout"):
        return "host timeout"
    return None


def _responded(result: dict[str, Any]) -> bool:
    """主機到底有沒有回應：-Pn 時 nmap 一律把主機當成「在線」，不能看它的狀態欄；
    要看實際的證據 —— 開著或關著的埠、區網內的 MAC 回應、OS 指紋、主機自己回的 NetBIOS／mDNS 名稱。
    反解是 DNS 回的，不算。"""
    nmap = result.get("nmap") or {}
    names_in = result.get("names") or {}
    os_list = [o for o in (nmap.get("os") or []) if isinstance(o, dict)]
    return bool(_open_ports(nmap) or int(nmap.get("closed") or 0) or nmap.get("mac") or os_list
                or names_in.get("netbios") or names_in.get("mdns"))


def probe_state(result: dict[str, Any] | None) -> str:
    """ok／no_response（真的沒回應）／scan_failed（nmap 自己失敗）／unavailable（代理沒有 nmap）。"""
    result = result or {}
    nmap = result.get("nmap") or {}
    if not bool(nmap.get("available", bool(nmap))):
        return "unavailable"
    if _responded(result):
        return "ok"
    return "scan_failed" if _scan_error(nmap) else "no_response"


def summarize(result: dict[str, Any] | None, *, mac_vendor: str | None = None,
              recog: Matcher | None = None, virtual_guest: bool | str | None = False,
              mac: str | None = None) -> dict[str, Any]:
    """代理回報的探測結果 → 摘要。`mac_vendor` 是 jt-ipam 依 IP 記錄的 MAC 查到的 OUI 廠商；
    `recog` 是已安裝的 Recog 指紋庫（沒安裝就是 None，摘要照常，只是少了這一層）；
    `virtual_guest`：已由虛擬化整合確認是虛擬機或容器 —— 虛擬化讓 TCP/IP 指紋失準，不拿它的類別判斷；
    `mac`：查出 `mac_vendor` 的那個 MAC。本機管理（隨機）的、虛擬網卡的 MAC，廠牌不拿來推類型。
    沒給時用 nmap 回報的 MAC（只在 `mac_vendor` 也沒給、廠牌是 nmap 查的時候）。"""
    result = result or {}
    nmap = result.get("nmap") or {}
    names_in = result.get("names") or {}
    ports = _open_ports(nmap)
    evidence: list[str] = []
    # 判斷的理由（畫面列出來：為什麼作業系統是「—」、為什麼不採信指紋…）：{code, params}，前端翻譯
    notes: list[dict[str, Any]] = []
    win = _windows_identity(ports, nmap)

    rc = (_recog_conclusions(recog_matches(nmap, recog), recog,
                             {f"{p.get('port')}/{p.get('proto') or 'tcp'}" for p in ports if p.get("product")})
          if recog else None)

    os_name = None
    os_list = [o for o in (nmap.get("os") or []) if isinstance(o, dict)]
    top = os_list[0] if os_list else None
    if top and str(top.get("type") or "").lower() not in ("", "general purpose"):
        gp = next((o for o in os_list if str(o.get("type") or "").lower() == "general purpose"), None)
        if gp and int(top.get("accuracy") or 0) - int(gp.get("accuracy") or 0) <= _AMBIGUOUS_GAP:
            top = gp
    # 沒有一般作業系統可退，而前幾名（差距 _AMBIGUOUS_GAP 以內）的類別互相矛盾 → 指紋分不出來：
    # 192.0.2.185（網卡是 Dyson）前四名都是 90%：交換器、影音設備、影音設備、手機，以前寫成「HP 交換器」
    fp_ambiguous = False
    if top is not None and str(top.get("type") or "").lower() not in ("", "general purpose"):
        near = [o for o in os_list
                if int(top.get("accuracy") or 0) - int(o.get("accuracy") or 0) <= _AMBIGUOUS_GAP]
        fp_ambiguous = len({str(o.get("type") or "").lower() for o in near}) > 1
    # 設備類的指紋（不是一般用途的作業系統）名稱其實是某個產品，廠牌跟網卡對不上時不是作業系統
    #（CyberPower UPS、TP-Link 插座都寫成「Philips Hue Bridge」，對抗式驗證 2026-10-05）
    fp_device_mismatch = bool(top) and str(top.get("type") or "").lower() not in ("", "general purpose") \
        and _norm_vendor(top.get("vendor")) not in _OS_AUTHORS \
        and not _vendors_agree(top.get("vendor"), mac_vendor or nmap.get("mac_vendor"))
    from app.core.os_fingerprint import normalize_os as _family
    # TCP/IP 堆疊本身是哪一家的作業系統（一般用途的指紋才算）。banner 可能來自容器、WSL、轉送的埠，
    # 堆疊不會：Windows 桌機用 Docker Desktop 發布 Ubuntu 容器，SSH 寫 Ubuntu、堆疊照樣是 Windows
    stack_fam = None
    if top and int(top.get("accuracy") or 0) >= _MIN_OS_ACCURACY and not fp_ambiguous and not fp_device_mismatch \
            and str(top.get("type") or "").lower() == "general purpose":
        stack_fam = _family(top.get("name"))
    if top and int(top.get("accuracy") or 0) >= _MIN_OS_ACCURACY and not fp_ambiguous:
        if not fp_device_mismatch:
            os_name = top.get("name")
        else:
            notes.append({"code": "fp_device_mismatch",
                          "params": {"fp": str(top.get("name") or ""),
                                     "nic": str(mac_vendor or nmap.get("mac_vendor") or "—")}})
        evidence.append(f"os:{top.get('name')} ({top.get('accuracy')}%)")
    elif top and fp_ambiguous:
        notes.append({"code": "os_ambiguous", "params": {}})
    elif top:
        notes.append({"code": "os_low_accuracy",
                      "params": {"acc": int(top.get("accuracy") or 0), "min": _MIN_OS_ACCURACY}})
    # Recog 的 OS 來自服務自己講的話（OpenSSH 的註解、SMB 回的 OS 名稱），夠有把握時比 TCP/IP 指紋精確；
    # 把握度低的（例如「IIS 10 大概是 Windows」）只在 nmap 沒結論時才用
    # nmap 的指紋被推翻了沒有：Recog 有把握地講出另一個 OS 時，指紋的類別與廠牌也不再採信
    #（2026-10-02 PVE 的 LXC 容器：指紋說 HP NAS，OpenSSH 說 Ubuntu → 以前 OS 寫 Ubuntu、類型卻寫儲存設備）
    fingerprint_overruled = False
    if rc and rc["os"]:
        rname, rcert, _m = rc["os"]
        if (rcert >= _RECOG_STRONG_OS or os_name is None) and not (stack_fam == "windows"
                                                                   and _family(rname) != "windows"):
            fingerprint_overruled = bool(top and os_name and rcert >= _RECOG_STRONG_OS and os_name != rname)
            os_name = rname
    trust_fingerprint = top is not None and not fingerprint_overruled and not virtual_guest and not fp_ambiguous
    if fingerprint_overruled and top:
        notes.append({"code": "recog_overruled", "params": {"fp": str(top.get("name") or ""), "os": str(os_name or "")}})
    if virtual_guest and top:
        notes.append({"code": "guest_fp_ignored", "params": {}})
    nic_vendor = mac_vendor or nmap.get("mac_vendor") or None
    # 廠牌是從哪個 MAC 查的：呼叫端給的（IP 記錄上的），或廠牌本身就是 nmap 查的那個 MAC
    oui_mac = mac if mac is not None else (None if mac_vendor else nmap.get("mac"))
    oui = kk.oui_hint(nic_vendor, oui_mac)

    # 指紋與 Recog 都沒結論：SMB／RDP 自己講的 Windows 版本（以前這兩段資料都沒用上，探測頁的作業系統是「—」，
    # IP 頁卻有）
    if os_name is None:
        wos = _windows_os(nmap, win)
        if wos:
            os_name = wos[0]
            evidence.append(wos[1])
    # 指紋只給得出核心範圍（Linux 2.6.32）時，服務版本字串講得出發行版就顯示發行版（堆疊是 Windows 時不用：
    # 那個 banner 多半是容器的）
    if stack_fam != "windows" and (os_name is None or re.match(r"linux \d", os_name, re.I)):
        distro = _distro_from_banners(ports)
        if distro:
            os_name = distro
    fam_now = _family(os_name) if os_name else None
    banner_text = " ".join([os_name or "", *(f"{p.get('product') or ''} {p.get('version') or ''}" for p in ports)])
    not_debian = bool(_NOT_DEBIAN_DISTRO.search(banner_text))
    ctx: dict[str, Any] = {
        "file_sharing": any(p.get("service") in _FILE_SHARING or p.get("port") in (2049, 3260, 548)
                            for p in ports),
        # 作業系統是一般電腦／手機（不是嵌入式設備）：單憑 RTSP 不能說是攝影機
        "desktop_os": fam_now in DESKTOP_FAMILIES,
        "os_family": fam_now,
        # 主力做 NAS 的網卡廠牌（完全相等才算；以前的子字串比對對不到 Drobo 的「DataRobotics」）。Buffalo 也做
        # 路由器，但這條還要同一台開著檔案分享
        "nas_vendor": (oui is not None and oui.kind == "storage")
                      or (kk.oui_usable(oui_mac) and kk.normalize_vendor(nic_vendor) == "buffalo"),
        "oui": oui,
        "guest": virtual_guest,
        "general_os": fam_now in GENERAL_FAMILIES,
        # 作業系統確定不是 Windows：先看 TCP/IP 堆疊，沒有堆疊指紋才看 banner 推出的
        "non_windows_os": (stack_fam in GENERAL_FAMILIES - {"windows"}) if stack_fam
                          else fam_now in GENERAL_FAMILIES - {"windows"},
        "general_host": (stack_fam in ("windows", "macos")) or _general_host_evidence(ports, os_name),
        "airplay": any(p.get("port") == 7000 or re.search(r"airtunes|airplay", _text(p), re.I) for p in ports),
        "pve_conflict": any((p.get("port") in (25, 26) and str(p.get("service") or "").startswith("smtp"))
                            or p.get("port") == 8443 for p in ports),
        "network_os": fam_now == "network",
        "not_debian": not_debian,
        # Proxmox VE 只裝在 Debian 上：True ＝看得到 Debian、False ＝看得到別的發行版、None ＝不知道
        "debian": False if not_debian else (True if _DEBIAN.search(banner_text) else None),
        "bmc_vendor": any(v in _norm_vendor(nic_vendor) for v in _BMC_VENDORS),
        "has_vnc": any(p.get("service") == "vnc" or p.get("port") == 5900 for p in ports),
        "amt": any(p.get("port") in _AMT_PORTS for p in ports),
    }
    device_type = "unknown"

    # ① 服務自己講的話：每個埠的每個文字欄位分開比對產品樣式，加上 Recog 比中的設備（特定產品的預設憑證、
    # 管理介面標題、banner），比「開了哪個埠」具體。不同埠講出不同類型時，信心高的先、產品字樣先於 Recog、
    # 再依類型順序。排除條件（node_exporter、CUPS、Plex、錄影軟體…）比中的埠，不再拿來當埠號的證據
    guarded: set[int] = set()
    cands: list[_Cand] = []
    recog_apps = rc["apps"] if rc else {}
    for i, p in enumerate(ports):
        for field, text in _text_fields(p, recog_apps.get(_port_key(p))):
            sp = kk.classify_service_text(text, os_family=fam_now, debian=ctx["debian"], guest=bool(virtual_guest))
            if sp is None:
                continue
            if sp.kind is None:
                if field == "product":
                    guarded.add(i)
                continue
            if _kind_allowed(sp.kind, ctx, specific=True):
                where = "" if field == "product" else f" ({field}: {text[:80]})"
                cands.append(_Cand(sp.kind, sp.confidence, 0, i, f"service:{_service_line(p)}{where}"))
    recog_dev = None
    for dev, dvendor, dproduct, ddesc, dm in (rc["devices"] if rc else []):
        kind, conf, _why = kk.recog_kind(dev, dvendor, dproduct, ddesc, os_family=fam_now)
        if kind and _kind_allowed(kind, ctx, specific=True):
            cands.append(_Cand(kind, conf, 1, 0, None))
            recog_dev = dm
            break
    best = _pick(cands)
    if best is not None:
        device_type = best.kind
        if best.evidence:
            evidence.append(best.evidence)
        # 智慧家庭／專用設備同時串流 RTSP（554）＝攝影機（Tapo 的插座與攝影機網頁標頭一樣是 SHIP 2.0）
        rtsp = next((p for p in ports if p.get("port") == 554), None)
        if device_type == "specialized" and rtsp is not None and not ctx["file_sharing"]:
            device_type = "camera"
            evidence.append(f"service:{_service_line(rtsp)}")
        elif rc is not None and recog_dev is not None and not any(u is recog_dev for u in rc["used"]):
            # Recog 的設備決定了類型：依據裡要列出它（依偏好度的順序）
            keep = [*rc["used"], recog_dev]
            rc["used"] = [m for m in rc["ranked"] if any(m is u for u in keep)]

    # ② nmap 服務偵測附的設備類別（nmap-service-probes 的 d/ 欄位，代理 1.17.2 起回報）：只有探針真的比中才有。
    # 那個埠的產品是排除條件時不用（motion、ZoneMinder 這類軟體在 nmap 標成 webcam）
    if device_type == "unknown":
        dcands = []
        for i, p in enumerate(ports):
            dt = str(p.get("devicetype") or "").strip()[:40]
            if not dt or _table_guess(p) or i in guarded:
                continue
            name = " ".join(str(x) for x in (p.get("product"), p.get("extrainfo")) if x)
            kind, conf, _why = kk.nmap_kind(dt, name=name)
            if kind and _kind_allowed(kind, ctx, specific=False):
                dcands.append(_Cand(kind, conf, 0, i, f"service:{_service_line(p)} (devicetype: {dt})"))
        dbest = _pick(dcands)
        if dbest is not None:
            device_type = dbest.kind
            evidence.append(dbest.evidence or "")

    # ③ 開著的埠
    if device_type == "unknown":
        for code, rule in _PORT_RULES:
            hit = next((p for i, p in enumerate(ports) if (code in _GENERIC or i not in guarded) and rule(p, ctx)),
                       None)
            if hit:
                device_type = code
                evidence.append(f"service:{_service_line(hit)}")
                break

    # ④ TCP/IP 指紋的類別（nmap 的 device type 對照 device_kind_knowledge.NMAP_DEVICE_TYPES 與覆寫規則：
    # Windows → windows、iOS／Android → mobile、ESXi／PVE → hypervisor、lwIP／VxWorks 這類嵌入式核心不當成伺服器）
    if device_type == "unknown" and trust_fingerprint and top and top.get("type"):
        mapped, _conf, _why = kk.nmap_kind(str(top["type"]), top.get("vendor"), top.get("family"), top.get("name"))
        # 指紋的類別只是「這個 TCP/IP 指紋常見於哪種機器」：說的廠牌跟網卡廠牌對不上就不採信
        # （atomcam-01 是 ATOMtech 的攝影機，指紋是 Linux 2.4 的 OpenWrt → 以前判成無線 AP）
        # 一般主機、虛擬化主機與手機例外：作業系統本身就說明是什麼（Android 的指紋寫 Google，手機卻是 Samsung、
        # 小米…；Windows 的指紋寫 Microsoft、ESXi 的寫 VMware，網卡是 Intel、Broadcom）
        # 專用設備例外：前幾名一致都是嵌入式（lwIP 之類）時，「是一台嵌入式設備」本身就成立，不看廠牌
        # 網通例外：指紋只說得出「Linux 的 WAP」、但網卡是主力做 AP／網通的廠牌 → 採信（ap-hall-01：Ubiquiti）
        net_ok = (mapped in ("wireless_ap", "router", "switch") and _norm_vendor(top.get("vendor")) in _OS_AUTHORS
                  and _network_vendor(nic_vendor, oui_mac))
        if mapped and mapped not in ("server", "windows", "hypervisor", "mobile", "specialized") and not net_ok \
                and not _vendors_agree(top.get("vendor"), nic_vendor):
            mapped = None
        # 「general purpose」的 Linux／BSD 只是核心：沒有一般主機的正面證據時，路由器、AP、IoT 閘道也長這樣
        if mapped == "server" and _family(top.get("name")) in ("linux", "bsd") and not ctx["general_host"]:
            mapped = None
        if mapped and int(top.get("accuracy") or 0) >= _MIN_OS_ACCURACY:
            device_type = mapped
            evidence.append(f"osclass:{top['type']}")
    if device_type == "unknown" and fingerprint_overruled and os_name:
        # 服務自己講出的是一般作業系統（Ubuntu、Windows…）：那就是一台一般主機
        from app.core.os_fingerprint import normalize_os
        fam = normalize_os(os_name)
        if fam in ("linux", "windows", "bsd", "macos"):
            device_type = "windows" if fam == "windows" else "server"
            evidence.append(f"recog-os:{os_name}")
    # 手機：iPhone 與 Mac 的 TCP/IP 指紋幾乎一樣（前面會選到「一般用途」的 macOS）；服務已經說明是手機時，
    # 作業系統改取候選裡寫著 iOS／Android 的那個（192.0.2.166 的 iPhone 曾寫成 macOS）
    if device_type == "mobile":
        mob = next((o for o in os_list if re.search(r"\bios\b|android", f"{o.get('name')} {o.get('family')}", re.I)),
                   None)
        if mob is not None and int(mob.get("accuracy") or 0) >= _MIN_OS_ACCURACY:
            os_name = mob.get("name")
            evidence = [f"os:{mob.get('name')} ({mob.get('accuracy')}%)" if e.startswith("os:") else e
                        for e in evidence]
    # ⑤ 只做一種東西的網卡廠牌：證據最弱，什麼都看不出來時才用。廠牌名稱要完全相等（以前是子字串比對：
    # "sonos" 對到超音波儀器的 SonoSite、"arlo" 對到 Carlo Gavazzi、"dahua" 只對得到秤的製造商）。
    # medium 的廠牌（Canon 也做攝影機、Espressif 也有攝影機模組）要沒有開著的埠講出別種設備才用
    if device_type == "unknown" and not virtual_guest and oui is not None:
        if oui.confidence == "high" or not _ports_contradict(oui.kind, ports, ctx):
            device_type = oui.kind
            evidence.append(f"oui-kind:{nic_vendor}")
    if device_type == "unknown" and virtual_guest:
        # 虛擬機／容器沒有任何服務講出特定角色：Windows 的話標 Windows；LXC 容器一定是 Linux → 一般主機。
        # KVM 虛擬機不知道（同一個網段裡就有防火牆、Windows 的虛擬機），停在「不明」（對抗式驗證 2026-10-05）
        from app.core.os_fingerprint import normalize_os
        if os_name and normalize_os(os_name) == "windows":
            device_type = "windows"
            evidence.append("virt:guest")
        elif virtual_guest is True or virtual_guest == "ct":
            device_type = "server"
            evidence.append("virt:ct")

    # 設備廠牌與網卡廠牌分開：網卡的 OUI 不等於設備的品牌（Mac 接 CalDigit 擴充座，以前寫「廠牌 CalDigit」）。
    # 設備廠牌只採服務自己講的（Recog）或可信的指紋；指紋的「廠牌」若是作業系統作者（FreeBSD、Linux）不算
    fp_vendor = (top or {}).get("vendor") if trust_fingerprint else None
    if fp_vendor and _norm_vendor(fp_vendor) in _OS_AUTHORS:
        fp_vendor = None
    vendor = (rc["vendor"] if rc else None) or fp_vendor or None
    if mac_vendor:
        evidence.append(f"oui:{mac_vendor}")
    if rc:
        evidence += [_recog_evidence(m) for m in rc["used"][:_MAX_RECOG_EVIDENCE]]

    # 名稱與來源：反解、NetBIOS、mDNS、nmap、Windows 自己講的（RDP／SMB）、憑證。同一個名稱好幾個來源都列
    skip_certs = rc["default_cert_ports"] if rc else set()
    rdp_said = any((p.get("scripts") or {}).get("rdp-ntlm-info") for p in ports)
    win_src = "rdp" if rdp_said else "smb"
    sourced: list[tuple[Any, str]] = [
        (names_in.get("rdns"), "rdns"), (names_in.get("netbios"), "netbios"), (names_in.get("mdns"), "mdns"),
        *((h, "nmap") for h in (nmap.get("hostnames") or [])),
        ((win or {}).get("fqdn"), win_src), ((win or {}).get("computer"), win_src),
        *((c, "cert") for p in ports if f"{p.get('port')}/{p.get('proto') or 'tcp'}" not in skip_certs
          for c in _cert_names(p)),
    ]
    name_sources: list[dict[str, Any]] = []
    for n, src in sourced:
        if not n:
            continue
        hit = next((x for x in name_sources if x["name"] == str(n)), None)
        if hit is None:
            name_sources.append({"name": str(n), "sources": [src]})
        elif src not in hit["sources"]:
            hit["sources"].append(src)
    names = [x["name"] for x in name_sources]

    # 主機到底有沒有回應：-Pn 時 nmap 一律把主機當成「在線」，不能看它的狀態欄；
    # 要看實際的證據 —— 開著或關著的埠、區網內的 MAC 回應、OS 指紋、主機自己回的 NetBIOS／mDNS 名稱。
    # 反解是 DNS 回的，不算。全部沒有＝探測時沒有回應（多半是關機、離線，或防火牆擋掉所有探測）
    # nmap 自己失敗（結束碼非零、輸出裡沒有這台、逾時）不是「主機沒回應」：以前一律顯示成沒回應
    nmap_ok = bool(nmap.get("available", bool(nmap)))
    scan_error = _scan_error(nmap)
    no_response = nmap_ok and not _responded(result) and scan_error is None
    if no_response:
        device_type = "no_response"

    if nmap.get("os_scan") is False:
        notes.append({"code": "no_os_scan", "params": {}})
    guessed = [_port_key(p) for p in ports if _table_guess(p)]
    if guessed:
        notes.append({"code": "port_table_guess", "params": {"ports": ", ".join(guessed[:12])}})
    seen_mac = nmap.get("mac") or None
    shown_mac = mac if mac is not None else seen_mac
    if mac and seen_mac and str(mac).lower() != str(seen_mac).lower():
        notes.append({"code": "mac_differs", "params": {"seen": str(seen_mac)}})
    if shown_mac and kk.is_locally_administered(str(shown_mac)):
        notes.append({"code": "mac_random", "params": {}})

    return {
        "device_type": device_type,
        "no_response": no_response,
        "os": os_name,
        "vendor": vendor,
        "nic_vendor": nic_vendor,
        "model": rc["model"] if rc else None,
        "names": names,
        "applications": _applications(ports, rc["apps"] if rc else None),
        "services": [_service_line(p) for p in ports],
        "evidence": evidence,
        "nmap_available": bool(nmap.get("available", bool(nmap))),
        # 用了哪一版 Recog 指紋庫（沒裝是 None，畫面上會提示判斷較有限）
        "recog": recog.release if recog else None,
        "scan_failed": scan_error is not None,
        "scan_error": scan_error,
        "name_sources": name_sources,
        "windows": win,
        "certs": _certs(ports),
        "ssh_keys": _ssh_keys(ports),
        # 舊代理（1.17.4 以前）沒有過濾數：None ＝不知道，不寫 0
        "port_counts": ({"open": len(ports), "closed": int(nmap.get("closed") or 0),
                         "filtered": int(nmap["filtered"]) if nmap.get("filtered") is not None else None}
                        if (nmap_ok and scan_error is None) or ports else None),
        "distance": nmap.get("distance"),
        "uptime_seconds": (nmap.get("uptime") or {}).get("seconds") if isinstance(nmap.get("uptime"), dict) else None,
        "elapsed": result.get("elapsed"),
        "os_scan": nmap.get("os_scan"),
        # 顯示的 MAC 跟算網卡廠牌用的是同一個；這次 nmap 看到的另外列（不同時 notes 有 mac_differs）
        "mac": shown_mac,
        "mac_seen": seen_mac,
        "notes": notes,
    }


def _port_key(p: dict[str, Any]) -> str:
    return f"{p.get('port')}/{p.get('proto') or 'tcp'}"


def _port_product(p: dict[str, Any]) -> str:
    return " ".join(x for x in (p.get("product"), p.get("version")) if x).strip()


def changes_between(previous: dict[str, Any] | None, current: dict[str, Any] | None,
                    prev_summary: dict[str, Any] | None = None,
                    cur_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """兩次探測之間的差異：新開、關掉、產品／版本變了的服務，以及 MAC、作業系統、設備類型、名稱、
    SSH 主機金鑰、TLS 憑證的變化（金鑰或憑證變了可能代表重灌、換機或被冒充）。

    其中一次沒回應或 nmap 失敗時不比連接埠（`baseline`／`current` 說明原因）：以前上一次沒回應，
    這次所有埠都被列成「新開」。摘要沒傳就自己算（不含 Recog 與 IPAM 的對照）。"""
    previous, current = previous or {}, current or {}
    before_state, after_state = probe_state(previous), probe_state(current)
    out: dict[str, Any] = {
        "opened": [], "closed": [], "changed": [],
        "baseline": None if before_state == "ok" else before_state,
        "current": None if after_state == "ok" else after_state,
        "fields": [], "names_added": [], "names_removed": [], "ssh_keys": [], "certs": [],
    }
    if before_state != "ok" or after_state != "ok":
        return out
    before = {_port_key(p): p for p in _open_ports(previous.get("nmap") or {})}
    after = {_port_key(p): p for p in _open_ports(current.get("nmap") or {})}
    for k in after:
        if k in before:
            a, b = _port_product(before[k]), _port_product(after[k])
            if a != b and a and b:
                out["changed"].append({"port": k, "before": a, "after": b})
    out["opened"] = [k for k in after if k not in before]
    out["closed"] = [k for k in before if k not in after]

    ps = prev_summary if prev_summary is not None else summarize(previous)
    cs = cur_summary if cur_summary is not None else summarize(current)
    # 兩邊都有值、而且不同才算（指紋時有時無，一邊是「—」不算變化）
    for field, key in (("mac", "mac_seen"), ("os", "os"), ("device_type", "device_type")):
        va, vb = ps.get(key), cs.get(key)
        if not va or not vb or va == "unknown" or vb == "unknown":
            continue
        if (str(va).lower() != str(vb).lower()) if field == "mac" else va != vb:
            out["fields"].append({"field": field, "before": va, "after": vb})
    pn, cn = list(ps.get("names") or []), list(cs.get("names") or [])
    out["names_added"] = [n for n in cn if n not in pn]
    out["names_removed"] = [n for n in pn if n not in cn]
    # 金鑰：同一個埠、同一種演算法的指紋不同。舊代理是 MD5、新代理是 SHA256，格式不同不算變化
    pk = {(k["port"], k.get("type")): k.get("fingerprint") for k in ps.get("ssh_keys") or []}
    for k in cs.get("ssh_keys") or []:
        old = pk.get((k["port"], k.get("type")))
        new = k.get("fingerprint")
        if old and new and old != new and old.split(":", 1)[0] == new.split(":", 1)[0]:
            out["ssh_keys"].append({"port": k["port"], "type": k.get("type"), "before": old, "after": new})
    pc = {c["port"]: c for c in ps.get("certs") or []}
    for c in cs.get("certs") or []:
        o = pc.get(c["port"])
        if not o:
            continue
        algo = "sha256" if o.get("sha256") and c.get("sha256") else ("sha1" if o.get("sha1") and c.get("sha1") else None)
        if algo and o[algo] != c[algo]:
            out["certs"].append({"port": c["port"], "before": {algo: o[algo], "not_after": o.get("not_after")},
                                 "after": {algo: c[algo], "not_after": c.get("not_after")}})
    return out
