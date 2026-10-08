"""OS 來源優先序。

OS 資訊有三個來源，各自存在不同地方：
  - scanner  : 掃描代理 nmap 偵測 → ip_addresses.os_guess
  - librenms : LibreNMS 裝置 → devices.os（IP 經 device_id 關聯）
  - wazuh    : Wazuh 代理 → wazuh_agents.os_name（沒有才用 os_platform / os_version）（以 IP 對映）
  - ocs      : OCS 代理 → ip_addresses.os_ocs
  - rustdesk : RustDesk 客戶端心跳 → rustdesk_peers.os_name（已對應到這筆 IP 的）

依設定的順序取第一個有值的來源當作此 IP 的「有效 OS」。compute-on-read：不另存欄位，
由 `effective_os()` 即時彙整（OS 不常變，且免 migration / sync hook）。

排序與快取的共通機制在 `services/precedence.py`；來源性質登記在 `services/evidence.py`。
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.os_fingerprint import normalize_os
from app.services.precedence import Precedence

OS_KEY = "os_precedence"
OS_SOURCES: list[str] = ["scanner", "librenms", "wazuh", "ocs", "rustdesk"]
# rustdesk 排最後（使用者 2026-10-06）：既有站台存的順序裡沒有它，Precedence 會依預設次序補在最後
DEFAULT_ORDER: list[str] = ["librenms", "wazuh", "ocs", "scanner", "rustdesk"]

# OS 沒有「停用個別來源」的需求，protected 留空即可（沒有 manual 這個來源）
_P = Precedence(key=OS_KEY, sources=tuple(OS_SOURCES),
                default_order=tuple(DEFAULT_ORDER), protected=frozenset())


def _bust() -> None:
    _P.bust()


async def get_order(session: AsyncSession) -> list[str]:
    return await _P.get_order(session)


async def set_order(
    session: AsyncSession, *, order: list[str], updated_by_user_id: uuid.UUID | None = None,
) -> list[str]:
    clean, _ = await _P.save(session, order=order, updated_by_user_id=updated_by_user_id)
    return clean


async def _candidates(session: AsyncSession, ip: Any) -> dict[str, str]:
    """彙整此 IP 各來源的原始 OS 字串（有值才放）。"""
    out: dict[str, str] = {}
    if ip.os_guess:
        out["scanner"] = ip.os_guess
    # OCS 代理回報的 OS（獨立欄位，排在 scanner 之上 → 蓋過 nmap 指紋猜測）
    if getattr(ip, "os_ocs", None):
        out["ocs"] = ip.os_ocs
    if ip.device_id:
        from app.models.device import Device
        dev = await session.get(Device, ip.device_id)
        if dev is not None and getattr(dev, "os", None):
            ver = getattr(dev, "version", None)
            out["librenms"] = f"{dev.os}{' ' + ver if ver else ''}"
    # Wazuh 代理以 IP 對映
    from app.models.wazuh import WazuhAgent
    from app.services.wazuh import agent_represents_ip

    # 只比對 IP 不夠：DHCP 位址會被回收，失聯 agent 的舊登記會把別台機器的 OS 貼過來。
    # 同一個 IP 可能有好幾個 agent（舊的失聯、新的連著）：以前 .limit(1) 任意取一個，
    # 取到舊的就被判不代表 → 連著的那個反而沒用上。改成在「還代表這個 IP」的裡面挑，
    # 連著的優先、再來是最近回報的
    agents = [a for a in (await session.execute(
        select(WazuhAgent).where(WazuhAgent.ip == str(ip.ip)).limit(20)
    )).scalars().all() if agent_represents_ip(a, ip)]
    agents.sort(key=lambda a: ((a.status or "").lower() == "active",
                               a.last_keep_alive.timestamp() if a.last_keep_alive else 0.0),
                reverse=True)
    wa = agents[0] if agents else None
    if wa is not None:
        from app.core.os_fingerprint import wazuh_os_display
        shown = wazuh_os_display(wa.os_name, wa.os_platform, wa.os_version)
        if shown:
            out["wazuh"] = shown
    # RustDesk 客戶端回報的作業系統（只用已對應到這筆 IP 的裝置；預設排最後）
    from app.models.rustdesk import RustDeskPeer
    rd_os = (await session.execute(
        select(RustDeskPeer.os_name).where(RustDeskPeer.address_id == ip.id, RustDeskPeer.match_status == "matched",
                                           RustDeskPeer.os_name.is_not(None))
        .order_by(RustDeskPeer.online.desc(), RustDeskPeer.last_online_at.desc().nulls_last()).limit(1)
    )).scalar_one_or_none()
    if rd_os:
        from app.services.rustdesk import os_display
        out["rustdesk"] = os_display(rd_os) or rd_os
    return out


async def effective_os(session: AsyncSession, ip: Any) -> dict[str, Any]:
    """依優先序回傳此 IP 的有效 OS：{os_guess, os_family, os_source}（皆可能為 None）。"""
    cand = await _candidates(session, ip)
    if not cand:
        return {"os_guess": None, "os_family": None, "os_source": None}
    order, disabled = await _P.load(session)
    src, raw = _P.pick(dict(cand), order, disabled)
    if not raw:
        return {"os_guess": None, "os_family": None, "os_source": None}
    return {"os_guess": raw, "os_family": normalize_os(raw), "os_source": src}
