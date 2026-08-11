"""調查模式：把一個位址散落在各處的線索收成一份檔案。

查一台機器現在要在六個頁面之間跳。這幾天追「macOS 掛到 Linux VM」與「ping 得到卻顯示
離線」兩個問題，都是這樣一頁一頁翻出來的 —— IP 詳細資料、Wazuh、DNS、NAT、ARP、
異動記錄。人做得到，但慢，而且很容易漏掉關鍵的那一項。

**這裡只收事實**，不做推論。要不要請模型解讀是呼叫端的事，兩者刻意分開：檔案本身可以
單獨使用，而模型的敘述永遠標示為推測（延續異常偵測與 AI 巡檢那條線）。

權限依專案的三類資料分層：
- 位址本身是逐物件資料 → 看不到那個子網路，就連「這個位址存在」都不揭露
- NAT／防火牆／DNS 是全域基礎設施 → 只有具全域讀取權限者才附上那幾段
  （**降級而不是整個擋掉** —— 部門帳號對自己的機器仍該查得到基本狀況）
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.subnet import Subnet
from app.models.user import User
from app.services.permission import visible_ids

MAX_ROWS = 20          # 每一段最多列幾筆（檔案是給人讀的，不是傾印資料庫）
CHANGE_DAYS = 90


def _dt(v: Any) -> str | None:
    return v.isoformat() if isinstance(v, datetime) else None


async def _global_read(session: AsyncSession, user: User) -> bool:
    if getattr(user, "is_admin", False):
        return True
    for ot in ("subnet", "device", "customer", "section", "rack", "location"):
        if await visible_ids(session, user=user, object_type=ot) is None:
            return True
    return False


async def collect_dossier(
    session: AsyncSession, *, user: User, ip: str,
) -> dict[str, Any]:
    """收集某個位址的完整線索。只回事實。"""
    vis = await visible_ids(session, user=user, object_type="subnet")
    rows = (await session.execute(
        select(IPAddress, Subnet)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(func.host(IPAddress.ip) == ip)
    )).all()
    if vis is not None:
        rows = [(a, s) for a, s in rows if a.subnet_id in vis]
    if not rows:
        # 看不到就當作不存在 —— 回「無權限」等於確認了這個位址存在
        return {"found": False, "ip": ip}

    ipa, subnet = rows[0]
    gread = await _global_read(session, user)
    out: dict[str, Any] = {
        "found": True, "ip": ip, "global_read": gread,
        "address": {
            "ip_address_id": str(ipa.id), "hostname": ipa.hostname,
            "state": ipa.state, "effective_status": ipa.effective_status,
            "mac": str(ipa.mac) if ipa.mac else None,
            "owner": ipa.owner, "description": ipa.description,
            "subnet": str(subnet.cidr), "subnet_description": subnet.description,
            "discovery_source": ipa.discovery_source,
            "in_dhcp_lease": bool(ipa.in_dhcp_lease),
            "dhcp_reserved": bool(getattr(ipa, "dhcp_reserved", False)),
            "last_seen_scanner": _dt(ipa.last_seen_scanner),
            "last_seen_librenms": _dt(ipa.last_seen_librenms),
            "switch_port": ipa.switch_port,
        },
        # 重疊網段下同一位址的其他紀錄。挑一筆正是這幾天連續修掉的那類 bug，
        # 調查用的檔案更不該重蹈覆轍 —— 全部列出來，讓人看見有幾筆。
        "other_records": [
            {"ip_address_id": str(a.id), "subnet": str(s.cidr),
             "hostname": a.hostname, "effective_status": a.effective_status}
            for a, s in rows[1:]
        ],
        "hostname_sources": [], "os_candidates": {}, "monitoring": {},
        "arp": [], "dns": [], "nat": [], "firewall_rules": [], "changes": [],
    }

    # ── 主機名稱各來源分別回報了什麼（名稱對不上多半是張冠李戴的第一個徵兆）
    try:
        from app.models.ip_hostname import IPHostnameObservation
        out["hostname_sources"] = [
            {"source": o.source, "hostname": o.hostname, "seen_at": _dt(o.observed_at)}
            for o in (await session.execute(
                select(IPHostnameObservation)
                .where(IPHostnameObservation.ip_id == ipa.id)
            )).scalars().all()
        ]
    except Exception:
        pass

    try:
        from app.services.os_precedence import _candidates
        out["os_candidates"] = await _candidates(session, ipa)
    except Exception:
        pass

    # ── 監控涵蓋：誰在看這台
    from app.models.wazuh import WazuhAgent
    from app.services.wazuh import agent_represents_ip
    wa = (await session.execute(
        select(WazuhAgent).where(WazuhAgent.jt_ipam_address_id == ipa.id).limit(1)
    )).scalars().first()
    if wa is not None:
        out["monitoring"]["wazuh"] = {
            "agent_id": wa.agent_id, "name": wa.name, "status": wa.status,
            "os": wa.os_platform, "last_keep_alive": _dt(wa.last_keep_alive),
            "sca_score": wa.sca_score, "sca_policy": wa.sca_policy,
            # 失聯 agent 的登記可能是舊的（DHCP 位址被回收給別台）
            "still_represents_this_ip": agent_represents_ip(wa, ipa),
        }
    if ipa.device_id:
        from app.models.librenms import LibreNMSDevice
        ln = (await session.execute(
            select(LibreNMSDevice).where(
                LibreNMSDevice.jt_ipam_device_id == ipa.device_id).limit(1)
        )).scalars().first()
        if ln is not None:
            out["monitoring"]["librenms"] = {
                "hostname": ln.hostname, "os": ln.os, "status": ln.status,
                "hardware": ln.hardware,
            }

    # ── ARP：這個位址在網路上被哪些 MAC 用過（換過 MAC 常代表換了機器）
    from app.models.librenms import ARPEntry
    out["arp"] = [
        {"mac": str(m), "last_seen_at": _dt(t)}
        for m, t in (await session.execute(
            select(ARPEntry.mac, ARPEntry.last_seen_at)
            .where(ARPEntry.ip == ip)
            .order_by(ARPEntry.last_seen_at.desc()).limit(MAX_ROWS)
        )).all()
    ]

    # ── 異動記錄：這個位址最近被改過什麼
    try:
        from app.models.ip_change_log import IPChangeLog
        out["changes"] = [
            {"event": c.event_type, "field": c.field,
             "old": c.old_value, "new": c.new_value,
             "at": _dt(c.created_at), "source": c.source}
            for c in (await session.execute(
                select(IPChangeLog)
                .where(IPChangeLog.ip_id == ipa.id,
                       IPChangeLog.created_at >= datetime.now(UTC) - timedelta(days=CHANGE_DAYS))
                .order_by(IPChangeLog.created_at.desc()).limit(MAX_ROWS)
            )).scalars().all()
        ]
    except Exception:
        pass

    if not gread:
        return out         # 全域基礎設施那幾段到此為止

    # ── DNS：哪些名字指到這裡
    from app.models.dns import DNSRecord
    out["dns"] = [
        {"name": n, "type": t, "value": v}
        for n, t, v in (await session.execute(
            select(DNSRecord.name, DNSRecord.type, DNSRecord.value)
            .where(DNSRecord.value == ip).limit(MAX_ROWS)
        )).all()
    ]

    # ── NAT：對外開了什麼
    from app.models.nat import NATTranslation
    out["nat"] = [
        {"name": n.name, "type": n.type, "protocol": n.protocol,
         "port": n.dst_port, "interface": n.src_interface, "disabled": n.disabled}
        for n in (await session.execute(
            select(NATTranslation).where(NATTranslation.dst_ip_id == ipa.id).limit(MAX_ROWS)
        )).scalars().all()
    ]

    # ── 防火牆規則：目的地就是這個位址的
    from app.models.firewall_rule import OPNsenseRule
    out["firewall_rules"] = [
        {"action": r.action, "interface": r.interface, "direction": r.direction,
         "protocol": r.protocol, "source": r.source_net, "port": r.destination_port,
         "description": r.description, "enabled": r.enabled}
        for r in (await session.execute(
            select(OPNsenseRule).where(OPNsenseRule.destination_net == ip).limit(MAX_ROWS)
        )).scalars().all()
    ]
    return out


def infer_role_hints(dossier: dict[str, Any]) -> list[str]:
    """從事實裡算出「這台在扮演什麼角色」的訊號。

    由來（實機）：一台反向代理有 20 筆 A 記錄指向它，AI 判讀把這件事說成「DNS 記錄與
    主機名稱來源顯著矛盾」。那不是模型的錯 —— 送過去的只是一串域名，沒有任何訊號說明
    多個域名指向同一個位址對反向代理是常態，而提示詞又特別要求它「指出矛盾」。

    這裡只描述**觀察到的樣態**，不下「安全 / 不安全」「設定錯誤」這類判斷 ——
    那取決於這台本來該做什麼，而那件事只有人知道。
    """
    hints: list[str] = []

    names = {str(r.get("name") or "").strip().lower()
             for r in (dossier.get("dns") or []) if r.get("name")}
    if len(names) >= 5:
        hints.append(
            f"{len(names)} distinct DNS names resolve to this address. Many names on one"
            " address is the normal shape of a reverse proxy, load balancer or shared"
            " web host — do not report it as a contradiction on its own."
        )

    nat_ports = sorted({str(n.get("port")) for n in (dossier.get("nat") or []) if n.get("port")})
    web = [p for p in nat_ports if p in ("80", "443", "8080", "8443")]
    if web:
        hints.append(
            f"Ports {', '.join(web)} are forwarded to this address from outside, which is"
            " what a public web entry point looks like."
        )
    other = [p for p in nat_ports if p not in web]
    if other:
        hints.append(f"Also forwarded from outside: ports {', '.join(other)}.")

    macs = {str(a.get("mac")) for a in (dossier.get("arp") or []) if a.get("mac")}
    if len(macs) > 2:
        hints.append(
            f"{len(macs)} different MAC addresses have used this address over time. That is"
            " expected in a DHCP range and unexpected for a statically assigned server —"
            " which of the two this is, the record should say."
        )
    return hints
