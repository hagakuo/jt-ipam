"""上下線翻轉的異動記錄要寫對來源（GitHub #49）。

全站上線重算在 2026-09 改成每輪都跑、不再依附 LibreNMS，但寫異動記錄時還寫死
`source="librenms"`：沒有設定 LibreNMS 的站台，「失聯」事件的來源與操作者都顯示 librenms。

- 失聯：是系統判定「採信的證據都過期了」→ `system`，不是任何一個整合說的
- 上線：記實際讓它上線的那個來源（`arp:opnsense` 這類逐來源鍵記廠牌）
- 只靠 LibreNMS 的 ARP 撐著（`online (arp)`）：`last_seen_arp` 只有 LibreNMS 會寫 → `librenms`
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import librenms as lnms
from sqlalchemy import select

NOW = datetime.now(UTC)


async def _recompute(db, sources=("scanner", "librenms", "arp", "arp:opnsense")):
    async def _cfg(_s):
        return {"sources": list(sources), "minutes": 30}
    with patch("app.services.system_config.get_liveness_config", _cfg):
        await lnms.recompute_effective_status(db)
    await db.commit()


async def _flip_source(db, ip_id) -> tuple[str, str]:
    row = (await db.execute(select(IPChangeLog).where(
        IPChangeLog.ip_id == ip_id, IPChangeLog.field == "effective_status"))).scalars().one()
    return row.event_type, row.source


async def test_flips_record_the_real_source(db_session) -> None:
    sec = Section(name=f"fs-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    stale = NOW - timedelta(hours=3)
    gone = IPAddress(subnet_id=sub.id, ip="198.51.100.11", effective_status="online (scanner)",
                     last_seen_scanner=stale)
    by_fw = IPAddress(subnet_id=sub.id, ip="198.51.100.12", effective_status="offline",
                      arp_seen={"arp:opnsense": NOW.isoformat()})
    by_scan = IPAddress(subnet_id=sub.id, ip="198.51.100.13", effective_status="offline",
                        last_seen_scanner=NOW)
    by_arp = IPAddress(subnet_id=sub.id, ip="198.51.100.14", effective_status="offline",
                       mac="00:00:5e:00:53:14", last_seen_arp=NOW)
    db_session.add_all([gone, by_fw, by_scan, by_arp])
    await db_session.commit()

    await _recompute(db_session)

    assert await _flip_source(db_session, gone.id) == ("offline", "system")
    assert await _flip_source(db_session, by_fw.id) == ("online", "opnsense")
    assert await _flip_source(db_session, by_scan.id) == ("online", "scanner")
    assert await _flip_source(db_session, by_arp.id) == ("online", "librenms")
