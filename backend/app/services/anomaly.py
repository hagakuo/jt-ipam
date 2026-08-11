"""異常偵測（規格書 §6.9）。

偵測規則：
- IP 衝突：同 IP 在短時間（1h）內 ARP 看到不同 MAC
- MAC 變動：同 MAC 在多個 switch+port 跳動（1h 內）
- 失聯 IP：IPAM 有 IP 紀錄但 ARP/FDB 從未看過超過 N 天
- 未授權設備：ARP 出現的 IP 但 IPAM 沒有
- **非法 DHCP 伺服器**：掃描代理在網段上收到 DHCPOFFER，但該位址沒有被標記為 DHCP
  伺服器。這是少數「一出現幾乎必定有事」的異常 —— 多半是有人插了台家用路由器，或某台
  虛擬機誤開了 DHCP，會把租約發給不該拿的機器。

每次偵測結果寫站內通知 + Webhook 事件 + audit。
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.librenms import ARPEntry, FDBEntry, LibreNMSDevice
from app.models.user import User
from app.services.notification import deliver_event, push_notification
from app.services.oui import mac_prefix, vendor_map


@dataclass
class AnomalyReport:
    ip_conflicts: list[dict[str, Any]] = field(default_factory=list)
    mac_drifts: list[dict[str, Any]] = field(default_factory=list)
    ghost_ips: list[dict[str, Any]] = field(default_factory=list)
    unauthorized_ips: list[dict[str, Any]] = field(default_factory=list)
    rogue_dhcp: list[dict[str, Any]] = field(default_factory=list)
    external_exposure: list[dict[str, Any]] = field(default_factory=list)
    dangling_dns: list[dict[str, Any]] = field(default_factory=list)
    duplicate_ip_records: list[dict[str, Any]] = field(default_factory=list)
    suspicious_changes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_conflicts": self.ip_conflicts,
            "mac_drifts": self.mac_drifts,
            "ghost_ips": self.ghost_ips,
            "unauthorized_ips": self.unauthorized_ips,
            "rogue_dhcp": self.rogue_dhcp,
            "external_exposure": self.external_exposure,
            "dangling_dns": self.dangling_dns,
            "duplicate_ip_records": self.duplicate_ip_records,
            "suspicious_changes": self.suspicious_changes,
            "total": (
                len(self.ip_conflicts) + len(self.mac_drifts)
                + len(self.ghost_ips) + len(self.unauthorized_ips)
                + len(self.rogue_dhcp) + len(self.external_exposure)
                + len(self.dangling_dns) + len(self.duplicate_ip_records)
                + len(self.suspicious_changes)
            ),
        }


def _is_locally_administered(mac: str) -> bool:
    """第一個位元組的 bit 1 為 1 ＝ 本地管理位址（不是廠商燒錄的全球唯一位址）。

    為什麼要標出來：虛擬機、容器、以及手機的 MAC 隨機化隱私功能都會用這類位址，
    它們沒有 OUI 登記所以查不到廠商。同一個 IP 上出現這種位址，多半是同一台裝置換了
    位址（重新連線、遷移、故障接手），而不是兩台機器搶同一個 IP —— 不標示的話，
    這些會混在真正的衝突裡讓整張表看起來像雜訊。
    """
    try:
        first = int(mac.replace(":", "").replace("-", "")[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b10)


async def detect_ip_conflicts(
    session: AsyncSession, *, window: timedelta = timedelta(hours=1),
) -> list[dict[str, Any]]:
    """ARP 中同一 IP 在短時間內看到 ≥2 個 MAC。"""
    cutoff = datetime.now(UTC) - window
    rows = (
        await session.execute(
            select(ARPEntry.ip, ARPEntry.mac, func.count(), func.max(ARPEntry.last_seen_at))
            .where(ARPEntry.last_seen_at >= cutoff)
            .group_by(ARPEntry.ip, ARPEntry.mac)
        )
    ).all()
    # asyncpg 把 INET/MACADDR 回成物件不是字串（已知地雷 #10）——
    # 在這裡就轉成字串，否則呼叫端拿去比對或塞進別的查詢會失敗。
    by_ip: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for ip, mac, _cnt, last in rows:
        by_ip[str(ip)].append((str(mac), last))

    conflicts = {ip: pairs for ip, pairs in by_ip.items() if len({m for m, _ in pairs}) >= 2}

    # 帶上 OUI 廠商：兩個裸 MAC 位址擺在一起看不出是誰在打架，
    # 「Dell vs Apple」才讓人知道該去找哪一台。一次批次查完，不要逐筆查。
    vendors = await vendor_map(
        session, [m for pairs in conflicts.values() for m, _ in pairs],
    )

    out: list[dict[str, Any]] = []
    for ip, pairs in conflicts.items():
        out.append({
            "ip": ip,
            "macs": [
                {
                    "mac": m,
                    # vendor_map 的 key 是正規化後的 6 碼前綴，不是完整 MAC
                    "vendor": vendors.get(mac_prefix(m) or ""),
                    "local": _is_locally_administered(m),
                    "last_seen_at": dt.isoformat(),
                }
                for m, dt in sorted(pairs, key=lambda x: x[1], reverse=True)
            ],
        })
    return out


async def detect_mac_drifts(
    session: AsyncSession, *, window: timedelta = timedelta(hours=1),
) -> list[dict[str, Any]]:
    """同一 MAC 出現在 ≥2 個 (device, port) 組合（1h 內）。"""
    cutoff = datetime.now(UTC) - window
    rows = (
        await session.execute(
            select(FDBEntry.mac, FDBEntry.device_id, FDBEntry.port_name,
                   func.max(FDBEntry.last_seen_at))
            .where(FDBEntry.last_seen_at >= cutoff)
            .group_by(FDBEntry.mac, FDBEntry.device_id, FDBEntry.port_name)
        )
    ).all()
    by_mac: dict[str, list[tuple[str | None, str | None, datetime]]] = defaultdict(list)
    for mac, did, port, last in rows:
        by_mac[mac].append((str(did) if did else None, port, last))

    # device_id 是 librenms_devices.id → 解析成交換器友善名（sysname / hostname）供前端顯示
    dev_ids = {d for locs in by_mac.values() for d, _, _ in locs if d}
    name_by_id: dict[str, str] = {}
    if dev_ids:
        drows = (
            await session.execute(
                select(LibreNMSDevice.id, LibreNMSDevice.sysname, LibreNMSDevice.hostname)
                .where(LibreNMSDevice.id.in_([uuid.UUID(x) for x in dev_ids]))
            )
        ).all()
        for did, sysname, hostname in drows:
            name_by_id[str(did)] = sysname or hostname or str(did)[:8]

    # 每個有變動的 MAC → 對應的 IP / 主機名稱（先查 IPAddress.mac，補 ARP 表）
    drift_macs = {mac for mac, locs in by_mac.items() if len({(d, p) for d, p, _ in locs}) >= 2}
    ips_by_mac: dict[str, list[dict[str, str | None]]] = defaultdict(list)
    if drift_macs:
        seen_pair: set[tuple[str, str]] = set()
        iarows = (await session.execute(
            select(IPAddress.mac, IPAddress.ip, IPAddress.hostname).where(IPAddress.mac.in_(drift_macs))
        )).all()
        for m, ip, hn in iarows:
            key = (str(m), str(ip))
            if str(m) in drift_macs and key not in seen_pair:
                seen_pair.add(key)
                ips_by_mac[str(m)].append({"ip": str(ip).split("/")[0], "hostname": hn})
        arows = (await session.execute(
            select(ARPEntry.mac, ARPEntry.ip).where(ARPEntry.mac.in_(drift_macs))
        )).all()
        for m, ip in arows:
            key = (str(m), str(ip))
            if str(m) in drift_macs and key not in seen_pair:
                seen_pair.add(key)
                ips_by_mac[str(m)].append({"ip": str(ip).split("/")[0], "hostname": None})

    out: list[dict[str, Any]] = []
    for mac, locs in by_mac.items():
        unique = {(d, p) for d, p, _ in locs}
        if len(unique) < 2:
            continue
        out.append({
            "mac": mac,
            "ips": ips_by_mac.get(mac, []),
            "locations": [
                {
                    "device_id": d,
                    "device_name": name_by_id.get(d) if d else None,
                    "port": p,
                    "last_seen_at": dt.isoformat(),
                }
                for d, p, dt in sorted(locs, key=lambda x: x[2], reverse=True)
            ],
        })
    return out


async def _anomaly_subnet_ids(session: AsyncSession) -> set[Any]:
    """有開啟異常偵測的子網路 ID。"""
    from app.models.subnet import Subnet
    return {
        r[0] for r in (await session.execute(
            select(Subnet.id).where(Subnet.anomaly_enabled.is_(True))
        )).all()
    }


async def detect_ghost_ips(
    session: AsyncSession, *, days: int = 30,
) -> list[dict[str, Any]]:
    """IPAM 有的 IP，但 ARP 從未看過或上次看到 > days 天前。

    只看有開啟異常偵測的子網路 —— 訪客／實驗網段本來就常常一堆位址沒人在用，
    報出來只會把真正該處理的埋掉。
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    subnet_ids = await _anomaly_subnet_ids(session)
    if not subnet_ids:
        return []
    # 取所有有寫進 IPAM 但其實沒 last_seen_scanner / last_seen_librenms 的
    rows = (
        await session.execute(
            select(IPAddress)
            .where(
                IPAddress.subnet_id.in_(subnet_ids),
                (
                    (IPAddress.last_seen_scanner.is_(None))
                    | (IPAddress.last_seen_scanner < cutoff)
                )
                & (
                    (IPAddress.last_seen_librenms.is_(None))
                    | (IPAddress.last_seen_librenms < cutoff)
                ),
            )
            .limit(500)
        )
    ).scalars().all()
    return [
        {
            "ip_address_id": str(r.id),
            "ip": str(r.ip).split("/")[0],
            "hostname": r.hostname,
            "last_seen_scanner": r.last_seen_scanner.isoformat() if r.last_seen_scanner else None,
            "last_seen_librenms": r.last_seen_librenms.isoformat() if r.last_seen_librenms else None,
        }
        for r in rows
    ]


def _is_noise_address(ip: str) -> bool:
    """這個位址天生就不該被當成「未授權裝置」。

    最大宗是 **169.254.x.x**（DHCP 拿不到位址時自己指派的 link-local）—— 那是「這台
    機器沒拿到 IP」的徵狀，不是有人偷接東西。實測一台正式站台的未授權清單 53 筆全是
    這個，真正該看的東西整個被埋掉。

    另外排除多點傳送／保留位址與網段的網路位址、廣播位址：它們不對應到任何一台機器。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True          # 解析不出來的字串一律不報
    return bool(
        addr.is_link_local or addr.is_multicast or addr.is_loopback
        or addr.is_unspecified or addr.is_reserved
    )


async def _anomaly_networks(session: AsyncSession) -> list[Any]:
    """有開啟異常偵測的子網路（網段物件）。"""
    from app.models.subnet import Subnet
    rows = (await session.execute(
        select(Subnet.cidr).where(Subnet.anomaly_enabled.is_(True))
    )).all()
    nets = []
    for (cidr,) in rows:
        try:
            nets.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            continue
    return nets


async def detect_unauthorized_ips(session: AsyncSession) -> list[dict[str, Any]]:
    """ARP 看到但 IPAM 沒紀錄的 IP。

    只看**有開啟異常偵測的子網路**範圍內的位址。落在所有子網路之外的位址，本來就不是
    這套 IPAM 在管的東西，報出來只會製造雜訊。
    """
    arp_ips_rows = (
        await session.execute(
            select(ARPEntry.ip).group_by(ARPEntry.ip).limit(2000)
        )
    ).all()
    arp_ips = {str(r[0]) for r in arp_ips_rows}
    if not arp_ips:
        return []

    ipam_ips_rows = (
        await session.execute(select(IPAddress.ip))
    ).all()
    ipam_ips = {str(r[0]).split("/")[0] for r in ipam_ips_rows}

    nets = await _anomaly_networks(session)

    def _in_scope(ip: str) -> bool:
        if _is_noise_address(ip):
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # 網段的網路位址／廣播位址不對應到機器（/31、/32 例外，那兩種沒有這個概念）
        for net in nets:
            if addr in net:
                if net.prefixlen < 31 and addr in (net.network_address, net.broadcast_address):
                    return False
                return True
        return False

    unauthorized = sorted(ip for ip in (arp_ips - ipam_ips) if _in_scope(ip))
    return [{"ip": ip} for ip in unauthorized[:200]]


async def detect_rogue_dhcp(
    session: AsyncSession, *, within_days: int = 7,
) -> list[dict[str, Any]]:
    """在網段上回應 DHCP、但沒有被標記為 DHCP 伺服器的主機。

    合法與否是**查詢時**才比對的：把它存成欄位的話，管理員事後把某台標記為合法，
    舊記錄仍然會寫著非法。

    `via_relay` 的回應不算 —— 經由中繼轉送過來的伺服器本來就不在這個網段上，
    拿本網段的標記去判它會是必然的誤報。
    """
    from app.models.dhcp_sighting import DHCPSighting
    from app.models.subnet import Subnet

    cutoff = datetime.now(UTC) - timedelta(days=within_days)
    rows = (await session.execute(
        select(DHCPSighting, Subnet.cidr)
        .join(Subnet, Subnet.id == DHCPSighting.subnet_id)
        .where(DHCPSighting.last_seen_at >= cutoff,
               DHCPSighting.via_relay.is_(False))
        .order_by(DHCPSighting.last_seen_at.desc())
        .limit(200)
    )).all()
    if not rows:
        return []

    # ── 這個位址是不是「已知合法」的 DHCP 伺服器。
    #
    # 人工標記**維持逐子網路比對**：重疊網段（多單位共用 192.168.1.0/24）下，
    # 同一個 IP 字串在不同網段是不同機器，只比對字串等於把別人的授權套到自己頭上。
    marked = {
        (r[0], str(r[1]))
        for r in (await session.execute(
            select(IPAddress.subnet_id, IPAddress.ip)
            .where(IPAddress.is_dhcp_server.is_(True))
        )).all()
    }

    # 整合中的防火牆是另一回事：那是**我們自己在管的設備**，租約、規則、NAT 都是
    # 我們同步進來的，還要人來勾一個框說「它是 DHCP 伺服器」並不合理。
    #
    # 這條之所以可以跨網段成立、而人工標記不行，差別在證據強度：「我們管理這台防火牆」
    # 是確定的事實；「別的網段有人勾過同一個 IP 字串」不是（實機：一台服務多個網段的
    # 路由器，在別的網段被看到時會變成永遠消不掉的誤報）。
    integrated: set[str] = set()
    from urllib.parse import urlparse

    from app.models.firewall import OPNsenseFirewall
    _fw_models = [OPNsenseFirewall]
    try:
        from app.models.pfsense import PfSenseFirewall
        _fw_models.append(PfSenseFirewall)
    except Exception:
        pass
    try:
        from app.models.fortigate import FortiGateFirewall
        _fw_models.append(FortiGateFirewall)
    except Exception:
        pass
    for model in _fw_models:
        for (url,) in (await session.execute(select(model.api_url))).all():
            host = (urlparse(str(url)).hostname or "").strip()
            if host:
                integrated.add(host)

    out: list[dict[str, Any]] = []
    for sighting, cidr in rows:
        server_ip = str(sighting.server_ip)
        if (sighting.subnet_id, server_ip) in marked or server_ip in integrated:
            continue
        mac = str(sighting.server_mac) if sighting.server_mac else None
        out.append({
            "subnet_id": str(sighting.subnet_id),
            "subnet_cidr": str(cidr),
            "server_ip": server_ip,
            "mac": mac,
            "vendor": None,          # 下面統一補（一次查完 OUI，避免逐筆打 DB）
            "offered_ip": str(sighting.offered_ip) if sighting.offered_ip else None,
            "router": str(sighting.router) if sighting.router else None,
            "first_seen_at": sighting.first_seen_at,
            "last_seen_at": sighting.last_seen_at,
        })

    macs = [o["mac"] for o in out if o["mac"]]
    if macs:
        vendors = await vendor_map(session, macs)
        for o in out:
            if o["mac"]:
                o["vendor"] = vendors.get(mac_prefix(o["mac"]))
    return out




async def detect_external_exposure(session: AsyncSession) -> list[dict[str, Any]]:
    """對外曝險：哪些內部主機被開到外面，而且狀態不對。

    **只讀 jt-ipam 已同步進來的資料表**（`nat_translations`、`opnsense_rules`、
    `dns_records`、`ip_addresses`…），不會連到防火牆或任何設備 —— 這是異常偵測，
    每輪都要跑，不能依賴外部服務通不通。

    這裡全部是算得出來的事實，所以放異常偵測而不是 AI 巡檢：可以直接講「這台對外開著」，
    不必加「可能」。

    曝險來源有兩種，都取自同步結果：
      NAT     ── `nat_translations` 裡未停用、且目標指到某個 IP 的規則
      防火牆規則 ── WAN 介面上 action=pass、direction=in 且目的地是某個內部 IP 的規則

    每個位址只報一次，取最嚴重的一種：
      exposed_archived    子網路已歸檔，門卻還開著 —— 退役沒退乾淨
      exposed_offline     主機已離線，門還開著
      exposed_unmonitored 對外開放，但 Wazuh／LibreNMS 都沒看著它
    另外獨立一種（與上面互斥的另一份清單）：
      dns_to_offline      DNS 還指著這個位址，主機卻已離線

    **不用 owner 當判準**：實機上 360 個 IP 只有 1 個填了 owner，拿它當訊號會把幾乎每一台
    對外主機都標成問題。owner 只當附註帶出去，讓看的人知道找誰。
    """
    import ipaddress as _ipaddr

    from app.models.dns import DNSRecord
    from app.models.firewall_rule import OPNsenseRule
    from app.models.nat import NATTranslation
    from app.models.subnet import Subnet
    from app.models.wazuh import WazuhAgent

    # ── 1. NAT（已同步的表）
    exposures: dict[Any, dict[str, Any]] = {}   # ip_id → {ports, rules}

    def _note(ip_id: Any, port_label: str | None, rule: dict[str, Any]) -> None:
        e = exposures.setdefault(ip_id, {"ports": [], "rules": []})
        if port_label and port_label not in e["ports"]:
            e["ports"].append(port_label)
        e["rules"].append(rule)

    nat_rows = (await session.execute(
        select(NATTranslation).where(
            NATTranslation.disabled.is_(False),
            NATTranslation.dst_ip_id.is_not(None),
        )
    )).scalars().all()
    for nat in nat_rows:
        proto = (nat.protocol or "any").lower()
        _note(nat.dst_ip_id,
              f"{proto}/{nat.dst_port}" if nat.dst_port else proto,
              {"source": "nat", "name": nat.name, "type": nat.type,
               "interface": nat.src_interface})

    # ── 2. 防火牆規則（已同步的表）：WAN 介面上放行進來、且目的地就是某台內部主機
    #     目的地可能是別名（如 allowlist_taiwan）→ 只在解析得出 IP 時才算
    fw_rows = (await session.execute(
        select(OPNsenseRule).where(
            OPNsenseRule.enabled.is_(True),
            func.lower(OPNsenseRule.action) == "pass",
        )
    )).scalars().all()
    wanted: dict[str, list[OPNsenseRule]] = {}
    for r in fw_rows:
        iface = (r.interface or "").upper()
        if "WAN" not in iface:      # 只看對外介面；LAN→LAN 的放行不是曝險
            continue
        if (r.direction or "in").lower() != "in":
            continue
        dest = (r.destination_net or "").strip()
        try:
            _ipaddr.ip_address(dest)
        except ValueError:
            continue                # 別名或網段 → 指不到單一主機，略過
        wanted.setdefault(dest, []).append(r)
    if wanted:
        for ip_id, host in (await session.execute(
            select(IPAddress.id, func.host(IPAddress.ip))
            .where(func.host(IPAddress.ip).in_(list(wanted)))
        )).all():
            for r in wanted.get(str(host), []):
                proto = (r.protocol or "any").lower()
                _note(ip_id,
                      f"{proto}/{r.destination_port}" if r.destination_port else proto,
                      {"source": "firewall_rule", "name": r.description,
                       "type": "pass", "interface": r.interface})

    out: list[dict[str, Any]] = []
    if exposures:
        rows = (await session.execute(
            select(IPAddress, Subnet)
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .where(IPAddress.id.in_(list(exposures)))
        )).all()
        ip_ids = [ipa.id for ipa, _ in rows]
        # 失聯的 agent 不算「有監控」—— 它沒有在看任何東西，而且它登記的 IP 可能早被回收
        from app.services.wazuh import agent_represents_ip
        ip_by_id = {ipa.id: ipa for ipa, _ in rows}
        monitored: set[Any] = {
            wa.jt_ipam_address_id
            for wa in (await session.execute(
                select(WazuhAgent).where(WazuhAgent.jt_ipam_address_id.in_(ip_ids))
            )).scalars().all()
            if wa.jt_ipam_address_id
            and agent_represents_ip(wa, ip_by_id.get(wa.jt_ipam_address_id))
        }
        dev_ids = [ipa.device_id for ipa, _ in rows if ipa.device_id]
        if dev_ids:
            ln = {
                r[0] for r in (await session.execute(
                    select(LibreNMSDevice.jt_ipam_device_id)
                    .where(LibreNMSDevice.jt_ipam_device_id.in_(dev_ids))
                )).all() if r[0]
            }
            monitored |= {ipa.id for ipa, _ in rows if ipa.device_id in ln}

        for ipa, subnet in rows:
            if subnet.archived_at is not None:
                kind = "exposed_archived"
            elif ipa.effective_status == "offline":
                kind = "exposed_offline"
            elif ipa.id not in monitored:
                kind = "exposed_unmonitored"
            else:
                continue    # 對外開放、活著、也有人看著 → 正常，不報
            e = exposures[ipa.id]
            out.append({
                "kind": kind,
                "ip_address_id": str(ipa.id),
                "ip": str(ipa.ip),
                "hostname": ipa.hostname,
                "owner": ipa.owner,
                "effective_status": ipa.effective_status,
                "subnet": str(subnet.cidr),
                "monitored": ipa.id in monitored,
                "ports": e["ports"],
                "rules": e["rules"],
                "names": [],
            })

    # ── 3. DNS 還指著，主機卻已離線（同樣只讀已同步的 dns_records）
    #     用實際 IP 值比對，不靠 ipam_address_id —— 實機上那個欄位 121 筆全是空的
    dns_rows = (await session.execute(
        select(DNSRecord.name, DNSRecord.value, IPAddress.id, IPAddress.hostname,
               IPAddress.owner, Subnet.cidr)
        .join(IPAddress, func.host(IPAddress.ip) == DNSRecord.value)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(
            func.upper(DNSRecord.type).in_(("A", "AAAA")),
            IPAddress.effective_status == "offline",
        )
    )).all()
    # 每一筆都給同一組欄位（ports / rules / monitored 也要有），前端才不必為了
    # 少數幾種 kind 特別判斷 —— 少一個鍵就會是一個 undefined 錯誤
    by_ip: dict[Any, dict[str, Any]] = {}
    for name, value, ip_id, host, owner, cidr in dns_rows:
        rec = by_ip.setdefault(ip_id, {
            "kind": "dns_to_offline",
            "ip_address_id": str(ip_id),
            "ip": str(value),
            "hostname": host,
            "owner": owner,
            "effective_status": "offline",
            "subnet": str(cidr),
            "monitored": False,
            "ports": [],
            "rules": [],
            "names": [],
        })
        if name not in rec["names"]:
            rec["names"].append(name)
    out.extend(by_ip.values())
    return out




async def detect_dangling_dns(session: AsyncSession) -> list[dict[str, Any]]:
    """DNS 還解析得到，但指向的位址在 IPAM 裡根本不存在。

    對外網域時這是**子網域接管**的前置條件：名字還在、位址已經沒人管，誰拿到那個位址
    就等於拿到那個名字。內部網域則多半是退役沒清乾淨。

    只看 A／AAAA —— CNAME 的值是名字不是位址，拿去跟 IP 比對必定「找不到」，
    全收會把每一筆 CNAME 都報成懸空。

    （「DNS 指向已離線主機」是另一條，在對外曝險裡：那是位址存在但機器不在；
    這裡是位址根本沒登記。）
    """
    from app.models.dns import DNSRecord, DNSServer, DNSZone

    rows = (await session.execute(
        select(DNSRecord.name, DNSRecord.value, DNSRecord.type,
               DNSZone.name.label("zone"), DNSServer.name.label("server"))
        .join(DNSZone, DNSRecord.zone_id == DNSZone.id)
        .join(DNSServer, DNSZone.server_id == DNSServer.id)
        .where(func.upper(DNSRecord.type).in_(("A", "AAAA")))
    )).all()
    if not rows:
        return []
    known = {
        str(h) for (h,) in (await session.execute(
            select(func.host(IPAddress.ip))
        )).all()
    }
    out: list[dict[str, Any]] = []
    for name, value, rtype, zone, server in rows:
        v = str(value or "").strip()
        if not v or v in known:
            continue
        out.append({"name": name, "value": v, "type": rtype,
                    "zone": zone, "server": server})
    return out


async def detect_duplicate_ip_records(session: AsyncSession) -> list[dict[str, Any]]:
    """同一個位址在**互相包含**的子網路裡各有一筆紀錄。

    只挑「一個網段包含另一個」的情形。兩個單位各自登記一模一樣的 CIDR 是刻意支援的
    多租戶用法（同一個私網位址在不同單位是不同機器），把那個也報出來，多單位環境會被
    自己的正常設定洗版。

    為什麼要報：整合同步只會標到其中一筆，另一筆的存活狀態與主機名稱會永遠停在舊值 ——
    實機上就這樣讓一台正常運作的機器在畫面上顯示離線、可用率 0%。
    """
    import ipaddress as _ipaddr

    from app.models.subnet import Subnet

    rows = (await session.execute(
        select(IPAddress.id, func.host(IPAddress.ip), IPAddress.hostname,
               IPAddress.effective_status, Subnet.cidr)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
    )).all()
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for ip_id, host, hostname, status, cidr in rows:
        by_ip.setdefault(str(host), []).append({
            "ip_address_id": str(ip_id), "hostname": hostname,
            "effective_status": status, "subnet": str(cidr),
        })

    out: list[dict[str, Any]] = []
    for ip, recs in by_ip.items():
        if len(recs) < 2:
            continue
        nets = []
        for r in recs:
            try:
                nets.append(_ipaddr.ip_network(r["subnet"], strict=False))
            except ValueError:
                nets.append(None)
        contained = any(
            a is not None and b is not None and a != b and (a.subnet_of(b) or b.subnet_of(a))
            for i, a in enumerate(nets) for b in nets[i + 1:]
        )
        if contained:
            out.append({"ip": ip, "records": recs})
    return out




# 變更行為分析的門檻。刻意保守 —— 會誤報的規則會訓練人忽略整個清單。
CHANGE_WINDOW_HOURS = 24
BULK_DELETE_MIN = 20          # 單一帳號在窗內刪除幾筆算異常
LOGIN_FAIL_MIN = 8            # 同一來源 IP 幾次登入失敗算異常
# 只要發生就該被看見的物件類型（不需要「量大」）
PRIVILEGE_OBJECTS = ("permission", "user", "group", "api_token", "system_settings")


async def detect_suspicious_changes(session: AsyncSession) -> list[dict[str, Any]]:
    """從稽核記錄找出值得看一眼的操作。

    稽核記錄平常沒有人會翻，但裡面藏著出事後才會回頭找的線索。三條規則：
    大量刪除、集中的登入失敗、權限與憑證的變更。

    刻意**不做**「非上班時段的變更」：那需要可靠的時區與工時設定，猜錯會把正常的白天
    工作標成可疑。一條會誤報的規則比沒有規則更糟。
    """
    from app.models.audit import AuditLog
    from app.models.user import User as _User

    since = datetime.now(UTC) - timedelta(hours=CHANGE_WINDOW_HOURS)
    out: list[dict[str, Any]] = []

    names = dict((await session.execute(select(_User.id, _User.username))).all())

    # 1) 同一帳號短時間內大量刪除
    for actor, cnt, first, last in (await session.execute(
        select(AuditLog.actor_user_id, func.count(), func.min(AuditLog.ts), func.max(AuditLog.ts))
        # 只看「有帳號」的刪除：沒有 actor 的是系統同步刪掉重建（實機上一次 967 筆），
        # 那是例行作業。把它算進來，清單第一名永遠是同步，真正的人為誤刪反而被埋掉。
        .where(AuditLog.ts >= since, AuditLog.action == "delete",
               AuditLog.actor_user_id.is_not(None))
        .group_by(AuditLog.actor_user_id)
        .having(func.count() >= BULK_DELETE_MIN)
    )).all():
        out.append({
            "kind": "bulk_delete", "actor": names.get(actor) or str(actor or "?"),
            "count": int(cnt), "first_at": first, "last_at": last,
        })

    # 2) 同一來源 IP 反覆登入失敗
    for ip, cnt, last in (await session.execute(
        select(AuditLog.actor_ip, func.count(), func.max(AuditLog.ts))
        .where(AuditLog.ts >= since, AuditLog.action == "login_failed")
        .group_by(AuditLog.actor_ip)
        .having(func.count() >= LOGIN_FAIL_MIN)
    )).all():
        out.append({
            "kind": "login_failures", "actor_ip": str(ip) if ip else None,
            "count": int(cnt), "last_at": last,
        })

    # 3) 權限／帳號／憑證的變更 —— 發生就要看見
    for otype, action, actor, cnt, last in (await session.execute(
        select(AuditLog.object_type, AuditLog.action, AuditLog.actor_user_id,
               func.count(), func.max(AuditLog.ts))
        .where(AuditLog.ts >= since,
               AuditLog.object_type.in_(PRIVILEGE_OBJECTS),
               AuditLog.action.in_(("create", "update", "delete")))
        .group_by(AuditLog.object_type, AuditLog.action, AuditLog.actor_user_id)
    )).all():
        out.append({
            "kind": "privilege_change", "object_type": otype, "action": action,
            "actor": names.get(actor) or str(actor or "?"),
            "count": int(cnt), "last_at": last,
        })

    return out


async def run_detection(
    session: AsyncSession, *, notify_admins: bool = True,
) -> AnomalyReport:
    """一次跑所有偵測規則；命中時發通知 + webhook event。"""
    report = AnomalyReport(
        ip_conflicts=await detect_ip_conflicts(session),
        mac_drifts=await detect_mac_drifts(session),
        ghost_ips=await detect_ghost_ips(session),
        unauthorized_ips=await detect_unauthorized_ips(session),
        rogue_dhcp=await detect_rogue_dhcp(session),
        external_exposure=await detect_external_exposure(session),
        dangling_dns=await detect_dangling_dns(session),
        duplicate_ip_records=await detect_duplicate_ip_records(session),
        suspicious_changes=await detect_suspicious_changes(session),
    )

    if notify_admins:
        from app.services.notification import email_users
        from app.services.system_config import get_notification_matrix
        ch = (await get_notification_matrix(session)).get(
            "anomaly.detected", {"in_app": True, "email": False})
        admins = (
            await session.execute(
                select(User).where(User.is_admin.is_(True), User.is_active.is_(True))
            )
        ).scalars().all()

        if ch.get("in_app") or ch.get("email"):
            for category, tkey, items in (
                ("IP 衝突", "notif.anom_ip_conflict", report.ip_conflicts),
                ("MAC 變動", "notif.anom_mac_drift", report.mac_drifts),
                ("失聯 IP", "notif.anom_ghost", report.ghost_ips),
                ("未授權 IP", "notif.anom_unauthorized", report.unauthorized_ips),
                ("非法 DHCP 伺服器", "notif.anom_rogue_dhcp", report.rogue_dhcp),
                ("對外曝險", "notif.anom_exposure", report.external_exposure),
                ("懸空 DNS", "notif.anom_dangling_dns", report.dangling_dns),
                ("重複的 IP 紀錄", "notif.anom_dup_ip", report.duplicate_ip_records),
                ("可疑的變更", "notif.anom_changes", report.suspicious_changes),
            ):
                if not items:
                    continue
                title = f"{category}：新增 {len(items)} 筆"
                if ch.get("in_app"):
                    for admin in admins:
                        await push_notification(
                            session, user_id=admin.id, severity="warning", title=title,
                            body="詳見「異常偵測」頁面。", link="/anomalies", object_type="anomaly",
                            title_key=tkey, body_key="notif.anom_body", params={"count": len(items)},
                        )
                if ch.get("email"):
                    await email_users(session, [a.email for a in admins],
                                      f"[jt-ipam] {title}", "詳見「異常偵測」頁面。")
                from app.services.notify_channels import broadcast_channels
                await broadcast_channels(session, subject=title, text="詳見「異常偵測」頁面。")
        await deliver_event(session, event="anomaly.detected", payload=report.to_dict())

    await session.commit()
    return report
