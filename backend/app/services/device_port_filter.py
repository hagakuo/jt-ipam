"""裝置連接埠匯入的偽介面過濾與自我修復（手動匯入與 LibreNMS 排程同步共用）。

Windows 端點的偽介面：LibreNMS 從 ifIndex 產生的 ethernet_N / wireless_N / ppp_N（NDIS
輕量過濾器、WAN Miniport、通道等），MAC 多半複製自實體卡或全零，對 IPAM 佈線毫無意義。實體
交換器與 Linux 的埠名不會長這樣（GigabitEthernet0/1、eth0、ens18、bond0），故不受影響。
名稱樣式清單可在系統設定調整（見 system_config.DEFAULT_PORT_IGNORE_PATTERNS）；ifType 這幾
種本質非實體埠的型別則一律排除。

以前只有手動匯入（physical.import_device_ports）有過濾，排程同步（librenms.sync_device_ports）
沒有 → 手動清完，下一輪同步又加回來（2026-09-26 稽核）。
"""
from __future__ import annotations

import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sqlin import in_values
from app.services.system_config import DEFAULT_PORT_IGNORE_PATTERNS, get_device_port_filter

PSEUDO_IFTYPES = {"ppp", "tunnel", "softwareloopback"}
_DEFAULT_PSEUDO_RES = [re.compile(p, re.IGNORECASE) for p in DEFAULT_PORT_IGNORE_PATTERNS]


def is_pseudo_iface(name: str, iftype: str | None = None,
                    patterns: list[re.Pattern[str]] | None = None) -> bool:
    """判斷是否為應略過的偽/虛擬介面。patterns 省略時用內建預設（供純函式測試）。"""
    n = (name or "").strip()
    for rx in (patterns if patterns is not None else _DEFAULT_PSEUDO_RES):
        if rx.match(n):
            return True
    return bool(iftype and iftype.strip().lower() in PSEUDO_IFTYPES)


async def load_patterns(session: AsyncSession) -> list[re.Pattern[str]] | None:
    """系統設定的過濾樣式；總開關關閉時回 None（＝完全不過濾也不清除）。"""
    cfg = await get_device_port_filter(session)
    if not cfg["filter_pseudo"]:
        return None
    return [re.compile(p, re.IGNORECASE) for p in cfg["ignore_patterns"]]


async def prune_pseudo_ports(session: AsyncSession, device_id: uuid.UUID,
                             patterns: list[re.Pattern[str]]) -> int:
    """清掉先前被拉進來的偽介面。只刪未接線、未做穿透對應的（手動建立或已納入佈線的不動）。"""
    from app.models.physical import CableTermination, DevicePort

    ports = [p for p in (await session.execute(
        select(DevicePort).where(DevicePort.device_id == device_id))).scalars().all()
        if p.peer_port_id is None and is_pseudo_iface(p.name, None, patterns)]
    if not ports:
        return 0
    # 一台 Windows 主機可以累積上萬個偽網卡（issue #47：三萬多個 → 超過 IN 的參數上限）
    pids = [p.id for p in ports]
    peered = set((await session.execute(
        select(DevicePort.peer_port_id).where(in_values(DevicePort.peer_port_id, pids)))).scalars().all())
    cabled = set((await session.execute(
        select(CableTermination.object_id).where(in_values(CableTermination.object_id, pids)))).scalars().all())
    pruned = 0
    for p in ports:
        if p.id in peered or p.id in cabled:
            continue
        await session.delete(p)
        pruned += 1
    return pruned
