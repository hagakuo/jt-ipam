"""OS 指紋正規化：把雜亂的原始 OS 字串（nmap -O / TTL / SNMP sysDescr）對應成
固定的「家族 key」，前端再依 key 配 SVG icon，顯示才一致美觀。

前後端共用同一份家族 key（前端 osIcons.ts）。比不到一律回 "unknown"。
"""

from __future__ import annotations

# 家族 key → 雙語 label（icon 在前端 osIcons.ts 依 key 對應）
OS_FAMILIES: dict[str, dict[str, str]] = {
    "windows": {"label_en": "Windows", "label_zh": "Windows", "label_ja": "Windows"},
    "linux": {"label_en": "Linux", "label_zh": "Linux", "label_ja": "Linux"},
    "macos": {"label_en": "macOS", "label_zh": "macOS", "label_ja": "macOS"},
    "bsd": {"label_en": "BSD / firewall", "label_zh": "BSD / 防火牆", "label_ja": "BSD / ファイアウォール"},
    "ios": {"label_en": "iOS", "label_zh": "iOS", "label_ja": "iOS"},
    "android": {"label_en": "Android", "label_zh": "Android", "label_ja": "Android"},
    "network": {"label_en": "Network device", "label_zh": "網路裝置", "label_ja": "ネットワーク機器"},
    "printer": {"label_en": "Printer", "label_zh": "印表機", "label_ja": "プリンター"},
    "storage": {"label_en": "NAS / storage", "label_zh": "NAS / 儲存", "label_ja": "NAS / ストレージ"},
    "hypervisor": {"label_en": "Hypervisor", "label_zh": "虛擬化平台", "label_ja": "仮想化基盤"},
    "unknown": {"label_en": "Unknown", "label_zh": "未知", "label_ja": "不明"},
}

# 比對順序很重要：較精準/較窄的關鍵字放前面（如 pfSense/OPNsense 要先於泛 BSD；
# ESXi 要先於泛 Linux）。每組 = (family, [關鍵字…])，關鍵字比對小寫子字串。
_RULES: list[tuple[str, list[str]]] = [
    ("hypervisor", ["esxi", "vmware", "proxmox", "hyper-v", "xenserver", "vsphere"]),
    ("storage", ["synology", "qnap", "truenas", "freenas", "netapp", "diskstation", "unraid"]),
    ("bsd", ["pfsense", "opnsense", "freebsd", "openbsd", "netbsd", "bsd"]),
    ("network", ["cisco", "mikrotik", "routeros", "junos", "juniper", "fortinet", "fortigate",
                 "palo alto", "panos", "pan-os",
                 "ubiquiti", "edgeos", "aruba", "ios-xe", "ios xe", "switch", "router",
                 "huawei", "zyxel", "tp-link", "draytek", "h3c"]),
    ("printer", ["jetdirect", "printer", "laserjet", "officejet", "brother", "kyocera", "epson"]),
    ("macos", ["mac os", "macos", "os x", "darwin"]),
    ("ios", ["iphone", "ipad", "ios "]),
    ("android", ["android"]),
    ("windows", ["windows", "microsoft", "win32", "winnt"]),
    ("linux", ["linux", "ubuntu", "debian", "centos", "red hat", "redhat", "fedora",
               "rocky", "alma", "suse", "openwrt", "raspbian", "android-x86"]),
]


def wazuh_os_display(name: str | None, platform: str | None, version: str | None) -> str | None:
    """Wazuh 代理的作業系統要怎麼顯示：有產品名稱（os.name）就用它。

    沒有時退回「平台 版本」；Windows 的核心版本號在 Windows 11 仍是 10.0，build 22000 以上才是 11，
    只看「windows 10.0.26200」會被當成 Windows 10 —— 這種情況補上「Windows 11」。
    """
    if name and name.strip():
        return name.strip()[:160]
    if not platform:
        return None
    ver = (version or "").strip()
    if platform.strip().lower() == "windows" and ver.startswith("10.0."):
        try:
            build = int(ver.split(".")[2])
        except (IndexError, ValueError):
            build = 0
        if build >= 22000:
            return f"Windows 11 {ver}"
    return f"{platform}{' ' + ver if ver else ''}"


def normalize_os(raw: str | None) -> str:
    """原始 OS 字串 → 家族 key。比不到回 'unknown'。"""
    if not raw:
        return "unknown"
    s = raw.strip().lower()
    if not s:
        return "unknown"
    for family, kws in _RULES:
        if any(kw in s for kw in kws):
            return family
    return "unknown"


def family_from_ttl(ttl: int | None) -> str | None:
    """純 TTL 粗略推測（無 nmap 時的後備）：64→linux 系、128→windows、255→network。
    僅當其他探測都拿不到 OS 字串時才用，回 None 表示不猜。"""
    if ttl is None:
        return None
    # 容忍經過數個 hop 的衰減
    if 0 < ttl <= 64:
        return "linux"
    if 64 < ttl <= 128:
        return "windows"
    if 128 < ttl <= 255:
        return "network"
    return None


def families_for_api() -> list[dict[str, str]]:
    return [{"key": k, **v} for k, v in OS_FAMILIES.items()]
