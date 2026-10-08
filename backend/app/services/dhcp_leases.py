"""「有 DHCP 租約」的逐來源目擊與衍生旗標（2026-09-26）。

`ip_addresses.in_dhcp_lease` 以前是六個 DHCP 來源（OPNsense／pfSense／FortiGate／Palo Alto／
MikroTik／Windows DHCP）共用的一個布林，清除各寫各的：
- 沒設「關聯子網路」→ 永遠不清：租約早就沒了，畫面仍顯示「DHCP」
- Palo Alto 從來不清
- 有設範圍時以子網路整批清 → 別的來源還發著的租約也被清掉，下一輪又被設回來

改成比照固定分配（services/dhcp_reservations.py）：每個來源的每一台實例各記各的
（`dhcp_lease_sightings`），旗標＝還有任何一列。用法（每個同步一輪一次）：

    run = LeaseRun(session, source_type="opnsense", source_id=fw.id)
    run.saw(ipa)                              # 這個位址目前有租約
    out = await run.finish(complete=本輪是否完整讀到租約清單)

只有 complete=True 時才清掉這台本輪沒看到的；完整讀取卻回 0 筆、之前卻有一堆 → 不清，
out["breaker"] 說明原因（多半是權限或 API 問題，不是租約全部到期）。
來源停用、刪掉或一直失敗：超過 MAX_AGE 沒再回報的列由任何一輪同步清掉 —— 不能永遠算數。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sqlin import in_values
from app.models.address import IPAddress
from app.models.dhcp import DHCPLeaseSighting

#: 遷移前就是 True、不知道是哪個來源設的旗標
LEGACY = "legacy"
LEGACY_ID = uuid.UUID(int=0)
#: 舊旗標等這麼久沒人認領才清（每個來源都有機會同步幾輪）
LEGACY_GRACE = timedelta(hours=24)
#: 任何來源超過這麼久沒再回報的租約不再算數（停用、刪除、長期同步失敗）
MAX_AGE = timedelta(days=7)
#: 完整讀取卻回 0 筆、而這台原本有這麼多筆以上 → 不清
EMPTY_GUARD = 5


class LeaseRun:
    """一台 DHCP 來源的一輪租約同步。見模組說明。"""

    def __init__(self, session: AsyncSession, *, source_type: str, source_id: uuid.UUID) -> None:
        self.session = session
        self.source_type = source_type
        self.source_id = source_id
        self.run_at = datetime.now(UTC)
        self._seen: set[uuid.UUID] = set()

    def saw(self, ipa: IPAddress) -> None:
        self._seen.add(ipa.id)
        ipa.in_dhcp_lease = True      # 同一輪後面的邏輯（與畫面）立刻看得到

    async def finish(self, *, complete: bool) -> dict[str, Any]:
        s = self.session
        await s.flush()
        # 整批 upsert（以前每個租約各一次：大型 DHCP 一輪十萬筆＝十萬次查詢）；一次 5,000 列
        rows = [{"ip_address_id": ip_id, "source_type": self.source_type, "source_id": self.source_id,
                 "first_seen_at": self.run_at, "last_seen_at": self.run_at} for ip_id in self._seen]
        ins = pg_insert(DHCPLeaseSighting)
        upsert = ins.on_conflict_do_update(
            constraint="uq_dhcp_lease_sightings_ip_source",
            set_={"last_seen_at": ins.excluded.last_seen_at},
        )
        for i in range(0, len(rows), 10000):
            await s.execute(upsert, rows[i:i + 10000])
        mine = (DHCPLeaseSighting.source_type == self.source_type) & (
            DHCPLeaseSighting.source_id == self.source_id)
        # 認領：真實來源看到了的位址，舊旗標那一列就不需要了
        if self._seen:
            await s.execute(delete(DHCPLeaseSighting).where(
                DHCPLeaseSighting.source_type == LEGACY,
                in_values(DHCPLeaseSighting.ip_address_id, self._seen)))

        removed, breaker = 0, None
        if complete:
            stale = select(DHCPLeaseSighting.id).where(mine, DHCPLeaseSighting.last_seen_at < self.run_at)
            doomed = (await s.execute(select(func.count()).select_from(stale.subquery()))).scalar_one()
            if doomed and not self._seen and doomed >= EMPTY_GUARD:
                breaker = f"empty lease list would clear {doomed}"
            elif doomed:
                removed = (await s.execute(delete(DHCPLeaseSighting).where(
                    mine, DHCPLeaseSighting.last_seen_at < self.run_at))).rowcount or 0
            # 舊旗標：寬限期過了、仍沒有任何來源認領
            await s.execute(delete(DHCPLeaseSighting).where(
                DHCPLeaseSighting.source_type == LEGACY,
                DHCPLeaseSighting.last_seen_at < self.run_at - LEGACY_GRACE))
        # 任何來源太久沒再回報的（不論本輪是否完整：那些列跟這台無關）
        await s.execute(delete(DHCPLeaseSighting).where(
            DHCPLeaseSighting.source_type != LEGACY,
            DHCPLeaseSighting.last_seen_at < self.run_at - MAX_AGE))
        await recompute_flags(s)
        return {"seen": len(self._seen), "removed": removed, "breaker": breaker}


async def recompute_flags(session: AsyncSession) -> None:
    """整批重算 `ip_addresses.in_dhcp_lease`（比照 dhcp_reservations._recompute_flags）。

    整批而不是逐筆加減：逐筆做很容易漏掉清除，畫面就一直顯示一個早就不存在的租約。
    """
    await session.flush()
    leased = select(DHCPLeaseSighting.ip_address_id)
    await session.execute(
        update(IPAddress)
        .where(IPAddress.in_dhcp_lease.is_(True), IPAddress.id.not_in(leased))
        .values(in_dhcp_lease=False))
    await session.execute(
        update(IPAddress)
        .where(IPAddress.in_dhcp_lease.is_(False), IPAddress.id.in_(leased))
        .values(in_dhcp_lease=True))


async def forget_source(session: AsyncSession, *, source_type: str, source_id: uuid.UUID) -> None:
    """刪除／停用一台 DHCP 來源時：它回報的租約全部收回並重算旗標。"""
    await session.execute(delete(DHCPLeaseSighting).where(
        DHCPLeaseSighting.source_type == source_type, DHCPLeaseSighting.source_id == source_id))
    await recompute_flags(session)
