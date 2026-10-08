"""裝置類型的自動判斷：工作站／伺服器（使用者 2026-10-06）。

由來：一台 Windows 11 筆電（laptop-07）在 IP 頁是「Windows 主機」，點進裝置卻是「其他」。裝置類型只在建立時
決定一次，之後沒有任何同步會再看它。

規則（一體適用所有裝置，不針對某台）：
- 只碰「類型是 other 而且沒人定過（type_source 是 NULL）」或「上次就是自動判斷（type_source='auto'）」的裝置；
  人工、匯入或整合明確給過的類型一律不動。
- 證據來自這台裝置的 IP：代理回報的作業系統（Wazuh、RustDesk、OCS）最可靠；都沒有才看掃描代理的 nmap 猜測；
  作業系統分不出來才看 OCS 的機殼類型。
- 作業系統：Windows 用戶端版（XP～11）、macOS → 工作站；Windows Server → 伺服器；Linux 分不出用途 → 不判斷。
- 代理之間說法矛盾（一個說伺服器版、一個說用戶端版）→ 不判斷，維持原狀。
- 筆電與桌機不分：沒有 OCS 時沒有任何來源分得出來，機殼類型在裝置頁的 OCS 卡片上看得到。
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sqlin import in_values

AUTO = "auto"
_WIN_CLIENT = re.compile(r"\bwindows\s*(?:xp|vista|7|8(?:\.1)?|10|11)\b", re.I)
_MAC = re.compile(r"\bmac\s?os\b|\bos\s?x\b|\bdarwin\b", re.I)
# 代理多久沒回報就不算數（DHCP 位址會換人用，失聯代理的舊作業系統不可以貼到別台身上）
AGENT_FRESH = timedelta(days=30)
_CHASSIS_WORKSTATION = ("notebook", "laptop", "portable", "sub notebook", "convertible", "detachable",
                        "tablet", "hand held", "desktop", "low profile desktop", "mini pc", "all in one",
                        "space-saving", "lunch box", "stick pc")
_CHASSIS_SERVER = ("rack mount chassis", "blade", "multi-system chassis", "main server chassis", "blade enclosure")


def classify_os(os_str: str | None) -> str | None:
    """作業系統字串 → 'workstation'／'server'／None（分不出來）。"""
    s = (os_str or "").strip()
    if not s:
        return None
    low = s.lower()
    if "windows" in low:
        server, client = "server" in low, bool(_WIN_CLIENT.search(s))
        if server and client:
            return None          # nmap 常給「Windows 10 / Server 2016」這種二選一 → 分不出來
        if server:
            return "server"
        return "workstation" if client else None
    if _MAC.search(s):
        return "workstation"
    return None


def classify_chassis(chassis: str | None) -> str | None:
    c = (chassis or "").strip().lower()
    if not c:
        return None
    if any(k == c or k in c for k in _CHASSIS_SERVER):
        return "server"
    if any(k == c or k in c for k in _CHASSIS_WORKSTATION):
        return "workstation"
    return None


def decide(agent_os: list[str], scanner_os: list[str], chassis: list[str]) -> str | None:
    """把一台裝置的證據合起來判斷。每一層都要意見一致才算數，矛盾就不猜。"""
    for layer in (agent_os, scanner_os):
        votes = {v for v in (classify_os(x) for x in layer) if v}
        if len(votes) == 1:
            return votes.pop()
        if len(votes) > 1:
            return None
    votes = {v for v in (classify_chassis(x) for x in chassis) if v}
    return votes.pop() if len(votes) == 1 else None


async def _evidence(session: AsyncSession, device_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, list[str]]]:
    from app.core.os_fingerprint import wazuh_os_display
    from app.models.address import IPAddress
    from app.models.rustdesk import RustDeskPeer
    from app.models.wazuh import WazuhAgent

    ev: dict[uuid.UUID, dict[str, list[str]]] = defaultdict(lambda: {"agent": [], "scanner": [], "chassis": []})
    ip_dev: dict[uuid.UUID, uuid.UUID] = {}
    for ip_id, dev_id, os_ocs, os_guess, hw in (await session.execute(
            select(IPAddress.id, IPAddress.device_id, IPAddress.os_ocs, IPAddress.os_guess, IPAddress.ocs_hw)
            .where(in_values(IPAddress.device_id, device_ids)))).all():
        ip_dev[ip_id] = dev_id
        e = ev[dev_id]
        if os_ocs:
            e["agent"].append(os_ocs)
        if os_guess:
            e["scanner"].append(os_guess)
        ch = ((hw or {}).get("system") or {}).get("chassis") if isinstance(hw, dict) else None
        if ch:
            e["chassis"].append(str(ch))
    if not ip_dev:
        return ev
    ip_ids = list(ip_dev)
    fresh = datetime.now(UTC) - AGENT_FRESH
    for addr_id, name, plat, ver in (await session.execute(
            select(WazuhAgent.jt_ipam_address_id, WazuhAgent.os_name, WazuhAgent.os_platform, WazuhAgent.os_version)
            .where(in_values(WazuhAgent.jt_ipam_address_id, ip_ids), WazuhAgent.last_keep_alive >= fresh))).all():
        shown = wazuh_os_display(name, plat, ver)
        if shown:
            ev[ip_dev[addr_id]]["agent"].append(shown)
    for addr_id, os_name in (await session.execute(
            select(RustDeskPeer.address_id, RustDeskPeer.os_name)
            .where(in_values(RustDeskPeer.address_id, ip_ids), RustDeskPeer.match_status == "matched",
                   RustDeskPeer.os_name.is_not(None),
                   or_(RustDeskPeer.last_online_at.is_(None), RustDeskPeer.last_online_at >= fresh)))).all():
        from app.services.rustdesk import os_display
        ev[ip_dev[addr_id]]["agent"].append(os_display(os_name) or os_name)
    return ev


async def refresh_auto_types(session: AsyncSession, device_ids: list[uuid.UUID] | None = None,
                             *, batch: int = 2000) -> int:
    """重新判斷可以自動決定類型的裝置；回傳改了幾台。不 commit（呼叫端決定）。"""
    from app.models.device import Device

    eligible = or_(and_(Device.type == "other", Device.type_source.is_(None)), Device.type_source == AUTO)
    stmt = select(Device.id, Device.type).where(eligible)
    if device_ids is not None:
        if not device_ids:
            return 0
        stmt = stmt.where(in_values(Device.id, device_ids))
    rows: list[Any] = list((await session.execute(stmt)).all())
    changed = 0
    for i in range(0, len(rows), batch):
        chunk = rows[i:i + batch]
        ev = await _evidence(session, [r[0] for r in chunk])
        for dev_id, cur in chunk:
            e = ev.get(dev_id)
            if not e:
                continue
            new = decide(e["agent"], e["scanner"], e["chassis"])
            if new and new != cur:
                await session.execute(update(Device).where(Device.id == dev_id, eligible)
                                      .values(type=new, type_source=AUTO))
                changed += 1
    return changed
