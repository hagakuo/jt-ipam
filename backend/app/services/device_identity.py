"""掃描代理定期偵測的判讀結果寫回 IP 記錄（2026-10-01，Recog 的其他用途 ①）。

代理 1.14.0 起，定期 OS 偵測連同 nmap 的結構化結果（服務 banner、網頁標題、伺服器標頭、憑證）
一起回報；這裡用 IP 探測同一套判讀（`ip_identify.summarize`，含 Recog 指紋庫）推出 OS、設備類型
與廠牌型號。以前只有代理在本機從 nmap 文字推的一行 OS（NAS 常被判成攝影機、OS 只給
「Linux 4.15-5.8」）。

OS 家族或設備類型**從一個確定的值變成另一個**時寫一筆 IP 異動記錄（os_changed／kind_changed）：
同一個位址突然從印表機變成 Linux 主機，可能是 IP 被別台機器拿去用了 —— 異常偵測據此提出來。
從「不知道」變成知道不算變更。判讀不出來（unknown）時保留上一次的結果，不會清掉。

IP「探測」（使用者手動按的，掃前 1000 個埠＋服務版本）完成時也寫回這裡（source="identify"）。
定期偵測只有 TCP/IP 指紋的「一般主機」結論時，不會把具體的類型蓋回去（見 apply_summary）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress

#: 會寫進 IP 記錄的設備類型（ip_identify 的 device_type；unknown／no_response 不寫）
KINDS = frozenset({"router", "switch", "firewall", "wireless_ap", "printer", "camera", "voip",
                   "storage", "hypervisor", "media", "specialized", "server", "windows", "mobile"})
#: 「一般主機」：沒有任何服務講出特定角色時的結論
GENERIC_KINDS = frozenset({"server", "windows"})
#: 夠具體、可以推翻既有判讀的證據：服務（開了哪個服務）、Recog 比中的產品、服務自己講出的 OS、
#: 虛擬化整合確認是 VM／容器。其餘（TCP/IP 指紋的 os／osclass、網卡廠商 oui）都只是推測
_STRONG_EVIDENCE = ("service:", "recog:", "recog-os:", "virt:")


def _has_strong_evidence(summary: dict[str, Any]) -> bool:
    return any(str(e).startswith(_STRONG_EVIDENCE) for e in (summary.get("evidence") or []))


# ── 依證據強弱決定類型（2026-10-05 對正式環境 192.0.2.0/24 全段探測比對後重寫）────────────────────
# 埠號與 TCP/IP 指紋只是推測；IPAM 自己知道的事實更可靠，依序：
#   1. 裝置記錄的類型（人工或匯入設定；籠統的 server／other 不算）
#   2. LibreNMS 的分類（它用 SNMP 問設備自己是什麼）
#   3. 電腦上的代理（Wazuh／RustDesk／OCS）：裝得了代理＝一般電腦，作業系統以代理回報為準
#   4. 虛擬化整合：虛擬機／容器不會是交換器、AP、印表機、攝影機、實體虛擬化主機
#   5. 探測／定期偵測的結論
# 事實要新鮮：代理太久沒回報、虛擬機網卡的 MAC 跟這個 IP 現在的不同，都可能是 DHCP 位址上一任主人的
#（192.0.2.166 的 iPhone 被當成 vm-lab-02 虛擬機、Windows 主機）。

FACT_FRESH = timedelta(days=7)
#: 一般電腦（裝了代理、或是虛擬機）不會是這些
_EMBEDDED_KINDS = frozenset({"printer", "camera", "switch", "wireless_ap", "voip", "media", "mobile"})
#: 虛擬機／容器另外不會是實體虛擬化主機
_NOT_FOR_GUESTS = _EMBEDDED_KINDS | {"hypervisor"}
_DEVICE_TYPE_KIND = {"firewall": "firewall", "router": "router", "switch": "switch", "ap": "wireless_ap",
                     "storage": "storage", "ipmi": "specialized", "pdu": "specialized", "ups": "specialized"}
_LNMS_TYPE_KIND = {"firewall": "firewall", "wireless": "wireless_ap", "printer": "printer", "storage": "storage",
                   "power": "specialized", "environment": "specialized"}
# LibreNMS 的 network 分類不分路由器與交換器，看 os
_LNMS_ROUTER_OS = frozenset({"routeros", "openwrt", "edgeos", "vyos", "iosxr", "ddwrt", "asuswrt",
                             "fortigate", "junos-router"})
_LNMS_SWITCH_OS = frozenset({"dlink", "mellanox", "onyx", "procurve", "arubaos-cx", "arubaos", "ciscosb",
                             "edgeswitch", "netgear", "zyxelos", "zynos", "comware", "nxos", "dnos", "dell-os10",
                             "cumulus", "ruckus-icx", "fs-switch", "unifi-switch", "unifiswitch", "tplink-switch",
                             "cisco-sb", "hpe-ilo-switch", "aos-switch"})
_LNMS_HYPERVISOR_OS = frozenset({"proxmox", "vmware", "esxi", "vmware-esxi", "hyperv", "xcp-ng", "xenserver"})


@dataclass
class Facts:
    """IPAM 對這個 IP 已知的事實（ipam_facts 查出來；只放新鮮的）。"""

    device_type: str | None = None      # 裝置記錄的 type
    lnms_type: str | None = None        # LibreNMS 的 type（network／firewall／server…）
    lnms_os: str | None = None          # LibreNMS 的 os（opnsense、dlink、proxmox…）
    lnms_hw: str | None = None          # LibreNMS 的 hardware（VigorAP903、RT1900ac、DS918+…）
    agent_family: str | None = None     # 代理回報的作業系統家族（windows／linux／macos／android…）
    agent_source: str | None = None     # wazuh／rustdesk／ocs
    guest: bool = False                 # 虛擬機或容器（虛擬化整合 IP 與 MAC 都對得上，或 Proxmox 指派的 MAC）
    guest_kind: str | None = None       # "ct"（LXC 容器，一定是 Linux）／"vm"（可能是防火牆、Windows…）
    pve_node: bool = False              # 主機名稱就是虛擬化整合回報的 PVE 節點
    vrrp_owner: str | None = None       # VRRP／CARP 虛擬位址所屬那組設備的類型（同網段有防火牆＝firewall）
    hostname: str | None = None         # IP 記錄的主機名稱（弱線索：只在沒有更強的證據時用）
    mac: str | None = None              # IP 記錄的 MAC（VRRP／CARP 虛擬 MAC）
    nic_vendor: str | None = None       # 這個 MAC 的 OUI 廠牌（主機名稱裡的型號字要廠牌相符才採用）


# LibreNMS 的硬體型號比它的分類可靠：VigorAP903 的分類是 network（裝置記錄匯入時寫成 router），
# Synology 的路由器（SRM）被當成 dsm／storage（198.51.100.0/24 比對，2026-10-05）
_LNMS_HW_AP = re.compile(r"vigorap|\buap\b|unifi ?ap|\bu6-|\bu7-|nanohd|\beap\d|\bwap\d|access ?point", re.I)
_LNMS_HW_ROUTER = re.compile(r"^(?:rt|mr|wrx)\d", re.I)
# DrayTek 的路由器、AP、交換器在 LibreNMS 都是 os=draytek，只能看型號
_LNMS_HW_SWITCH = re.compile(r"vigor ?switch", re.I)
_LNMS_HW_DRAYTEK_ROUTER = re.compile(r"^vigor ?\d{3,4}", re.I)


def _lnms_hw_kind(f: Facts) -> str | None:
    hw = (f.lnms_hw or "").strip()
    # 虛擬機／容器在 LibreNMS 的硬體型號是宿主的（LXC 寫成 Supermicro Super Server）或 QEMU 的，說明不了它
    if not hw or f.guest:
        return None
    if _LNMS_HW_AP.search(hw):
        return "wireless_ap"
    if _LNMS_HW_SWITCH.search(hw):
        return "switch"
    os_ = (f.lnms_os or "").lower()
    if os_ == "dsm" and _LNMS_HW_ROUTER.search(hw):
        return "router"
    if os_ == "draytek" and _LNMS_HW_DRAYTEK_ROUTER.search(hw):
        return "router"
    return None


def _lnms_kind(f: Facts) -> str | None:
    hk = _lnms_hw_kind(f)
    if hk:
        return hk
    t, os_ = (f.lnms_type or "").lower(), (f.lnms_os or "").lower()
    # LibreNMS 沒有真的用 SNMP 認出這台（type 空白）時不查表：198.51.100.195 的 TP-Link 智慧插座 os 卻寫 tplink
    if not t:
        return None
    # 先查完整的作業系統對照表（lnms_os_kinds：LibreNMS 全部 815 個定義逐一整理過），沒有的才看 type
    from app.services.lnms_os_kinds import LNMS_OS_KIND, LNMS_OS_NEEDS_NODE_CHECK
    if os_ in LNMS_OS_NEEDS_NODE_CHECK:
        # proxmox／nutanix：只看核心字串或由控制 VM 回答，容器、PMG、PDM 也會中 → 要主機名稱就是節點才算
        return "hypervisor" if f.pve_node and not f.guest else None
    known = LNMS_OS_KIND.get(os_)
    if known:
        return None if (known == "hypervisor" and f.guest) else known
    if t in _LNMS_TYPE_KIND:
        return _LNMS_TYPE_KIND[t]
    if t == "network":
        if os_ in _LNMS_ROUTER_OS:
            return "router"
        if os_ in _LNMS_SWITCH_OS:
            return "switch"
        return None
    # LibreNMS 的 proxmox 只是看核心字串的「-pve」：LXC 容器、Proxmox Mail Gateway／Datacenter Manager 都會
    # 被認成 proxmox（對抗式驗證 2026-10-05）→ 只有主機名稱就是 PVE 節點時才算；其餘交給代理、虛擬化的事實
    if os_ == "proxmox":
        return "hypervisor" if f.pve_node and not f.guest else None
    if os_ in _LNMS_HYPERVISOR_OS:
        return None if f.guest else "hypervisor"
    if os_ == "windows":
        return "windows"
    return None


# 主機名稱的線索（證據最弱：只在探測說不出具體角色、也沒有代理／裝置記錄／LibreNMS 時用，依據會寫 hostname:）。
# 家用網段裡很多設備什麼服務都沒開，只剩 DHCP 給的名稱（198.51.100.0/24：Galaxy-A53-5G、HS300、ipcam4…）。
# 對照表在 device_kind_knowledge.HOSTNAME_HINTS：只看第一段（整個 FQDN 會把 *.cam.ac.uk 讀成攝影機），
# 伺服器角色的字眼否決設備類（nvr-server、camera-archive 是存錄影的伺服器），Windows 的預設名稱
# （DESKTOP-XXXXXXX、LAPTOP-、WIN-）是 Windows
#: 已知是 Windows／macOS／iOS 的主機，名稱不可以把它改成這些（嵌入式設備不會跑一般電腦的作業系統）
_NOT_FOR_DESKTOP = frozenset({"printer", "camera", "switch", "wireless_ap", "voip", "media"})


def _hostname_kind(hostname: str | None, nic_vendor: str | None = None) -> str | None:
    from app.services.device_kind_knowledge import hostname_kind
    hint = hostname_kind(hostname, nic_vendor)
    return hint.kind if hint is not None else None


def resolve_kind(scan_kind: str | None, f: Facts, *, os_family: str | None = None) -> tuple[str | None, str | None]:
    """（類型, 依據）。依據 None＝沿用探測的結論。`os_family`：探測判讀出的作業系統家族（normalize_os 的詞彙），
    只用來判斷主機名稱的線索跟作業系統矛盾不矛盾。"""
    hk = _lnms_hw_kind(f)
    if hk:
        return hk, f"librenms:{f.lnms_hw}"
    dk = _DEVICE_TYPE_KIND.get((f.device_type or "").lower())
    if dk:
        return dk, f"device:{f.device_type}"
    lk = _lnms_kind(f)
    # LibreNMS 說是一般主機（server／windows）時：等同「一般電腦」，探測認出的角色（虛擬化主機、儲存、防火牆…）保留，
    # 硬體類（印表機、攝影機…）不採信 → 交給下面的代理／一般電腦規則
    if lk and lk not in GENERIC_KINDS:
        # PVE 節點是虛擬化整合回報的（LibreNMS 的 proxmox 只是看核心字串）：依據寫那個事實
        if lk == "hypervisor" and f.pve_node:
            return lk, "virt:pve-node"
        return lk, f"librenms:{f.lnms_os or f.lnms_type}"
    if lk in GENERIC_KINDS:
        if scan_kind in KINDS and scan_kind not in GENERIC_KINDS and scan_kind not in _EMBEDDED_KINDS:
            return scan_kind, None
        if not f.agent_family:
            return lk, f"librenms:{f.lnms_os or f.lnms_type}"
    # VRRP／CARP 的虛擬 MAC（00:00:5e:00:01:xx IPv4、00:00:5e:00:02:xx IPv6）＝備援路由器／防火牆的虛擬位址
    # CARP（OPNsense／pfSense）、keepalived 也用同一段 MAC → 類型跟著同網段的那組設備：有防火牆就是防火牆
    if (f.mac or "").lower().startswith(("00:00:5e:00:01:", "00:00:5e:00:02:")):
        return f.vrrp_owner or "router", "mac:vrrp"
    kind = scan_kind if scan_kind in KINDS else None
    fam = f.agent_family
    general = bool(fam) or f.guest or (f.lnms_type or "").lower() in ("server", "workstation")
    reason = None
    if f.guest and kind in _NOT_FOR_GUESTS:
        kind, reason = None, f"virt:{f.guest_kind or 'guest'}"
    if fam in ("android", "ios"):
        return "mobile", f"{f.agent_source}:{fam}"
    if general and kind in _EMBEDDED_KINDS:
        kind, reason = None, f"{f.agent_source or 'virt'}:{fam or f.guest_kind or 'general'}"
    if fam and fam != "windows" and kind == "windows":
        kind, reason = None, f"{f.agent_source}:{fam}"
    if kind is None or kind in GENERIC_KINDS:
        if fam == "windows":
            return "windows", f"{f.agent_source}:windows"
        if fam in ("linux", "bsd", "macos"):
            return "server", f"{f.agent_source}:{fam}"
        # 主機名稱的線索：探測只看到一般主機（或什麼都沒看到）時才用
        hk = _hostname_kind(f.hostname, f.nic_vendor)
        from app.services.ip_identify import DESKTOP_FAMILIES
        # 已經知道是 Windows（或作業系統是 macOS／iOS）：名稱不可以把它改成嵌入式設備，也不可以把 Windows 改成
        # 「一般主機」（printer-2f 這種名稱的位址換成一台 Windows 電腦，是「設備換了」，要照實記下來）
        if hk and (scan_kind == "windows" or os_family in DESKTOP_FAMILIES) and (
                hk in _NOT_FOR_DESKTOP or (scan_kind == "windows" and (hk in GENERIC_KINDS or hk == "mobile"))):
            hk = None
        # Windows 的預設名稱跟作業系統是 Linux／BSD／macOS 矛盾：不採用
        if hk == "windows" and os_family in ("linux", "bsd", "macos", "ios", "android"):
            hk = None
        # 虛擬機／容器不會是硬體類（名稱叫 camera-archive 的虛擬機是存錄影的伺服器）
        if hk and not (f.guest and hk in _NOT_FOR_GUESTS):
            return hk, f"hostname:{f.hostname}"
        # 沒有任何角色可說：LXC 容器一定是 Linux → 一般主機；KVM 虛擬機不知道（可能是防火牆、Windows）
        if kind is None and (f.guest_kind == "ct" or (f.lnms_type or "").lower() in ("server", "workstation")):
            return "server", reason or (f"virt:{f.guest_kind}" if f.guest_kind == "ct" else f"librenms:{f.lnms_type}")
    return kind, reason


async def ipam_facts(session: AsyncSession, ipa: IPAddress) -> Facts:
    """查 IPAM 對這個 IP 已知的事實（每次最多幾個走索引的小查詢）。"""
    from sqlalchemy import func, or_, select, text

    from app.core.os_fingerprint import normalize_os
    from app.services.fw_lookup import virtual_guest_kind

    now = datetime.now(UTC)
    ip_text = str(ipa.ip).split("/")[0]
    f = Facts()
    if ipa.device_id is not None:
        f.device_type = (await session.execute(text("SELECT type FROM devices WHERE id = :d"),
                                               {"d": ipa.device_id})).scalar_one_or_none()
    from app.models.librenms import LibreNMSDevice
    conds = [LibreNMSDevice.primary_ip == ip_text]
    if ipa.device_id is not None:
        conds.append(LibreNMSDevice.jt_ipam_device_id == ipa.device_id)
    row = (await session.execute(select(LibreNMSDevice.type, LibreNMSDevice.os, LibreNMSDevice.last_seen_at,
                                        LibreNMSDevice.hardware)
                                 .where(or_(*conds)).limit(1))).first()
    if row is not None and (row[2] is None or row[2] >= now - FACT_FRESH * 4):
        f.lnms_type, f.lnms_os, f.lnms_hw = row[0], row[1], row[3]
    # 代理：Wazuh → RustDesk → OCS，第一個新鮮的為準
    from app.models.wazuh import WazuhAgent
    w = (await session.execute(select(WazuhAgent.os_platform, WazuhAgent.last_keep_alive)
                               .where(WazuhAgent.jt_ipam_address_id == ipa.id)
                               .order_by(WazuhAgent.last_keep_alive.desc().nulls_last()).limit(1))).first()
    candidates: list[tuple[str, str | None]] = []
    if w is not None and w[1] is not None and w[1] >= now - FACT_FRESH:
        candidates.append(("wazuh", w[0]))
    from app.models.rustdesk import RustDeskPeer
    r = (await session.execute(select(RustDeskPeer.os_name, RustDeskPeer.last_online_at)
                               .where(RustDeskPeer.address_id == ipa.id, RustDeskPeer.match_status == "matched")
                               .order_by(RustDeskPeer.last_online_at.desc().nulls_last()).limit(1))).first()
    if r is not None and r[0] and r[1] is not None and r[1] >= now - FACT_FRESH:
        candidates.append(("rustdesk", r[0]))
    if ipa.os_ocs and ipa.last_seen_ocs is not None and ipa.last_seen_ocs >= now - FACT_FRESH:
        candidates.append(("ocs", ipa.os_ocs))
    for src, os_text in candidates:
        fam = normalize_os(os_text) if os_text else "unknown"
        if fam != "unknown":
            f.agent_family, f.agent_source = fam, src
            break
    f.guest_kind = await virtual_guest_kind(session, ip_text, str(ipa.mac) if ipa.mac else None)
    f.guest = f.guest_kind is not None
    f.hostname = ipa.hostname
    f.mac = str(ipa.mac) if ipa.mac else None
    if ipa.mac:
        from app.services.oui import vendor_for_mac
        f.nic_vendor = await vendor_for_mac(session, ipa.mac)
    short = (ipa.hostname or "").split(".")[0].strip().lower()
    if short and not f.guest:
        from app.models.virt import VirtualMachine
        f.pve_node = (await session.execute(select(VirtualMachine.id).where(
            func.lower(VirtualMachine.node) == short).limit(1))).first() is not None
    if f.mac and f.mac.lower().startswith(("00:00:5e:00:01:", "00:00:5e:00:02:")):
        fw = (await session.execute(select(IPAddress.id).where(
            IPAddress.subnet_id == ipa.subnet_id, IPAddress.device_kind == "firewall",
            IPAddress.id != ipa.id).limit(1))).first()
        f.vrrp_owner = "firewall" if fw is not None else None
    return f


def model_text(summary: dict[str, Any]) -> str | None:
    vendor = (summary.get("vendor") or "").strip()
    model = (summary.get("model") or "").strip()
    if model and vendor and model.lower().startswith(vendor.lower()):
        vendor = ""
    text = " ".join(x for x in (vendor, model) if x)
    return text[:120] or None


async def apply_summary(session: AsyncSession, ipa: IPAddress, summary: dict[str, Any], *,
                        fallback_os: str | None = None, source: str = "scanner") -> None:
    """把一次判讀結果寫進 IP 記錄。`fallback_os`：判讀沒有 OS 時用代理自己推的那行（舊行為）。"""
    from app.core.os_fingerprint import normalize_os
    from app.services.ip_history import log_change

    os_text = summary.get("os") or fallback_os
    os_family_changed = False
    if os_text:
        new_family = normalize_os(os_text)
        old_family = ipa.os_family
        ipa.os_guess = str(os_text)[:160]
        ipa.os_family = new_family
        if old_family and new_family and old_family != new_family:
            os_family_changed = True
            await log_change(session, ip=ipa, event_type="os_changed", field="os_family",
                             old=old_family, new=new_family, source=source,
                             note=str(os_text)[:200])

    kind = summary.get("device_type")
    facts = await ipam_facts(session, ipa)
    resolved, reason = resolve_kind(kind, facts, os_family=normalize_os(os_text) if os_text else None)
    explicit_unknown = (source == "identify" and kind == "unknown" and not summary.get("no_response"))
    if reason is not None:
        summary = {**summary, "evidence": [reason, *(summary.get("evidence") or [])]}
        kind = resolved
    elif resolved is not None:
        kind = resolved
    # 定期偵測只有 TCP/IP 指紋說「一般主機」、OS 家族也沒變時，不推翻既有的具體類型（攝影機、印表機…）：
    # 定期偵測沒開「連接埠」探測時以前只看幾個埠，看不到攝影機的 554，只剩「Linux」的指紋 —— 因此把手動
    # 探測判斷正確的攝影機改回「伺服器」，還記一筆「類型突變」（2026-10-04 正式環境）。
    # OS 家族變了（印表機的位址變成 Windows）本身就是換了一台機器的訊號，照樣改
    # 但指紋說的是 macOS／Windows／iOS 時不擋：嵌入式設備不會跑這些，舊的具體類型多半是誤判
    # （2026-10-05 Mac 的 AirPlay 用 RTSP，被判成攝影機；規則修好後要能靠定期偵測改回來）
    from app.services.ip_identify import DESKTOP_FAMILIES
    desktop = bool(os_text) and normalize_os(os_text) in DESKTOP_FAMILIES
    if (source == "scanner" and kind in GENERIC_KINDS and ipa.device_kind in KINDS
            and ipa.device_kind not in GENERIC_KINDS and not os_family_changed
            and not desktop and reason is None and not _has_strong_evidence(summary)):
        kind = None
    # 手動探測（最完整的一次）說不出是什麼、IPAM 也沒有事實可依 → 舊的推測不留（多半是舊規則或上一任主人的）
    if explicit_unknown and kind == "unknown" and ipa.device_kind is not None:
        old_kind = ipa.device_kind
        ipa.device_kind, ipa.device_model = None, None
        ipa.device_identified_at = datetime.now(UTC)
        await log_change(session, ip=ipa, event_type="kind_changed", field="device_kind",
                         old=old_kind, new=None, source=source, note="identify: unknown")
    if kind in KINDS:
        old_kind = ipa.device_kind
        ipa.device_kind = kind
        # 同一類型、這次沒帶型號 → 保留原型號（定期偵測常常沒有）；類型換了 → 舊型號屬於上一次的判讀，
        # 不可沿用（PVE 的 LXC 從「儲存設備 · HP」改判成伺服器時，留著 HP 就變成「伺服器 · HP」）
        new_model = model_text(summary)
        # 以前型號欄放的是網卡的 OUI（IP 頁「攝影機 · CalDigit」）：新判讀沒有設備廠牌時，跟網卡廠牌一樣的舊值清掉
        nic = (summary.get("nic_vendor") or "").strip().lower()
        stale = bool(nic) and (ipa.device_model or "").strip().lower() == nic
        ipa.device_model = new_model if (new_model or old_kind != kind or stale) else ipa.device_model
        ipa.device_identified_at = datetime.now(UTC)
        if old_kind and old_kind != kind:
            evidence = ", ".join((summary.get("evidence") or [])[:3])
            await log_change(session, ip=ipa, event_type="kind_changed", field="device_kind",
                             old=old_kind, new=kind, source=source, note=evidence[:200] or None)
