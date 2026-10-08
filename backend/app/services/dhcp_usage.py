"""DHCP 集區的使用率。

「已用」＝**範圍內已經存在的 IP 記錄**，而不是只算有租約的。使用者關心的是
「還有多少位址可以發出去」：有人把固定 IP 設在集區的範圍裡（常見的設定失誤）
一樣吃掉可用量，而且那正是應該被看見的事。
"""
from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.dhcp import DHCPPoolRange


def _range_size(start: str, end: str) -> int:
    """範圍內的位址數。算不出來（起 > 迄、不是位址、家族不同）回 0。

    回 0 而不是丟例外：這些值是從外部設備同步回來的，壞掉的一筆不該讓整輪告警中斷。
    """
    try:
        a = ipaddress.ip_address(str(start))
        b = ipaddress.ip_address(str(end))
    except ValueError:
        return 0
    if a.version != b.version or int(b) < int(a):
        return 0
    return int(b) - int(a) + 1


async def pool_usage(session: AsyncSession) -> list[tuple[Any, int, int]]:
    """回傳每個集區的 (集區, 已用, 總數)。"""
    from app.services.ip_ranges import manual_dhcp_pools
    # 手動定義的 DHCP 集區（子網路內的位址範圍，issue #40）欄位與 DHCPPoolRange 同名，一起算
    pools: list[Any] = [*(await session.execute(select(DHCPPoolRange))).scalars().all(),
                        *await manual_dhcp_pools(session)]
    if not pools:
        return []
    rows = (await session.execute(select(IPAddress.ip))).all()
    addrs: list[int] = []
    for (ip_val,) in rows:
        try:
            addrs.append(int(ipaddress.ip_address(str(ip_val).split("/")[0])))
        except ValueError:
            continue

    out: list[tuple[Any, int, int]] = []
    for pool in pools:
        size = _range_size(pool.start_ip, pool.end_ip)
        if size == 0:
            out.append((pool, 0, 0))
            continue
        lo = int(ipaddress.ip_address(str(pool.start_ip)))
        hi = int(ipaddress.ip_address(str(pool.end_ip)))
        used = sum(1 for a in addrs if lo <= a <= hi)
        out.append((pool, used, size))
    return out
