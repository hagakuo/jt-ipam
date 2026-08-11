"""DHCP 固定分配的共用寫入層。

每個 DHCP 來源（OPNsense / pfSense / Windows DHCP / FortiGate）自己去把資料抓回來、
整理成 `Reservation`，寫入一律走這裡的 `replace_reservations()`：

- 鏡像同步：只清掉「這個來源自己」的列（`source_type` + `source_id`），不動別人的
- 一併重算 `ip_addresses.dhcp_reserved`，清單頁才不必為了一個布林值去 join

**為什麼要有這個共用層**：`dhcp_reserved` 是跨來源的衍生旗標。如果每個整合各自維護，
只要有一個忘記在刪除時清旗標，畫面就會顯示一個已經不存在的固定分配 —— 而且不會有任何
錯誤訊息。集中在一處算，就沒有「有些整合有做、有些沒有」的空間。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.dhcp import DHCPReservation


@dataclass
class Reservation:
    """一筆固定分配。`ip` 是必要的 —— 沒有 IP 的靜態對映只是「認得這張網卡」，不是保留位址。"""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    description: str | None = None


def _clean_mac(v: Any) -> str | None:
    s = str(v or "").strip().lower().replace("-", ":")
    return s[:32] if s and ":" in s else None


async def replace_reservations(
    session: AsyncSession,
    *,
    source_type: str,
    source_id: uuid.UUID,
    source_name: str | None,
    engine: str,
    rows: list[Reservation],
) -> int:
    """以這個來源的最新結果取代它先前寫入的固定分配，並重算 `dhcp_reserved`。"""
    now = datetime.now(UTC)
    await session.execute(delete(DHCPReservation).where(
        DHCPReservation.source_type == source_type,
        DHCPReservation.source_id == source_id,
    ))

    kept: list[Reservation] = []
    seen: set[tuple[str, str | None]] = set()
    for r in rows:
        ip = str(r.ip or "").strip()
        if not ip:
            continue                      # 沒有 IP 就不是「保留位址」
        mac = _clean_mac(r.mac)
        if (ip, mac) in seen:             # 同一台 DHCP 上重複列（多介面設定常見）
            continue
        seen.add((ip, mac))
        kept.append(Reservation(ip=ip, mac=mac, hostname=r.hostname,
                                description=r.description))

    # 對映到既有 IP 物件（只比對、不新建 —— 與 lease/ARP 同步一致）
    ip_map: dict[str, Any] = {}
    if kept:
        for aid, host in (await session.execute(
            select(IPAddress.id, func.host(IPAddress.ip))
            .where(func.host(IPAddress.ip).in_([r.ip for r in kept]))
        )).all():
            ip_map.setdefault(str(host), aid)

    for r in kept:
        session.add(DHCPReservation(
            source_type=source_type, source_id=source_id, source_name=source_name,
            ip=r.ip, mac=r.mac, hostname=(r.hostname or None),
            description=(r.description or None), source=engine,
            ip_address_id=ip_map.get(r.ip), synced_at=now,
        ))

    await _recompute_flags(session)
    return len(kept)


async def _recompute_flags(session: AsyncSession) -> None:
    """整批重算 `ip_addresses.dhcp_reserved`。

    整批重算而不是逐筆加減：某台 DHCP 移除一筆固定分配時，逐筆做很容易漏掉清除，
    畫面就會一直顯示一個已經不存在的固定分配。
    """
    await session.flush()
    reserved = select(DHCPReservation.ip_address_id).where(
        DHCPReservation.ip_address_id.is_not(None))
    await session.execute(
        update(IPAddress)
        .where(IPAddress.dhcp_reserved.is_(True), IPAddress.id.not_in(reserved))
        .values(dhcp_reserved=False)
    )
    await session.execute(
        update(IPAddress)
        .where(IPAddress.dhcp_reserved.is_(False), IPAddress.id.in_(reserved))
        .values(dhcp_reserved=True)
    )
