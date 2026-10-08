"""全站上線狀態重算在超大規模下（2026-09-30 大量資料測試）。

`recompute_effective_status` 每 5 分鐘跑一次。逐日觀測以前是把**每個 IP** 塞進同一個
INSERT（每個 IP 5 個參數）：超過約 6,500 個 IP 就超過 asyncpg 的 32767 參數上限，整個重算失敗
—— 上線狀態從此不再更新，而且每一輪都重來一次（14.5 萬個 IP：跑 291 秒、10.7 萬次查詢後失敗）。
另外每個「有 MAC、沒有 ARP 起點」的 IP 各查一次 ARP 表，每次上下線翻轉各查一次異動記錄。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.ip_liveness import IPLivenessDay
from app.models.librenms import ARPEntry, LibreNMSDevice, LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import librenms as lnms
from sqlalchemy import event, func, select


async def _recompute(db, sources=("scanner", "librenms", "arp:opnsense")):
    async def _cfg(_s):
        return {"sources": list(sources), "minutes": 30}
    with patch("app.services.system_config.get_liveness_config", _cfg):
        return await lnms.recompute_effective_status(db)


async def _counted(db, fn):
    n = {"q": 0}
    conn = await db.connection()

    def _c(*_a, **_k):
        n["q"] += 1
    event.listen(conn.sync_connection, "before_cursor_execute", _c)
    try:
        out = await fn()
        await db.commit()
    finally:
        event.remove(conn.sync_connection, "before_cursor_execute", _c)
    return out, n["q"]


async def test_more_ips_than_the_parameter_limit_allows(db_session) -> None:
    db_session.autoflush = False
    sec = Section(name=f"lv-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="10.92.0.0/16")
    db_session.add(sn)
    await db_session.flush()
    now = datetime.now(UTC)
    n = 8_000                                                  # 8,000 × 5 參數 > 32767
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.92.{i // 256}.{i % 256}",
         "last_seen_scanner": now - timedelta(minutes=5) if i % 2 else now - timedelta(days=3),
         "effective_status": "online (scanner)"} for i in range(1, n + 1)])
    await db_session.commit()

    first, q1 = await _counted(db_session, lambda: _recompute(db_session))
    assert first == n // 2                                     # 偶數那一半過期了 → 離線
    days = (await db_session.execute(select(func.count()).select_from(IPLivenessDay))).scalar_one()
    assert days == n
    flips = (await db_session.execute(select(func.count()).select_from(IPChangeLog).where(
        IPChangeLog.event_type == "offline"))).scalar_one()
    assert flips == n // 2
    assert q1 < 40, f"第一輪查了 {q1} 次"

    second, q2 = await _counted(db_session, lambda: _recompute(db_session))
    assert second == 0
    assert q2 < 15, f"什麼都沒變的一輪查了 {q2} 次"
    down = (await db_session.execute(select(IPAddress.effective_status).where(
        IPAddress.ip == "10.92.0.2"))).scalar_one()
    assert down == "offline"


async def test_legacy_arp_start_is_filled_without_a_query_per_ip(db_session) -> None:
    """有 MAC、從沒對應過 ARP 的舊資料：補一次起點（行為不變，只是不再逐筆查）。"""
    db_session.autoflush = False
    sec = Section(name=f"lv-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="10.93.0.0/24")
    db_session.add(sn)
    inst = LibreNMSInstance(name=f"l-{uuid.uuid4().hex[:6]}", api_url="https://l.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    dev = LibreNMSDevice(instance_id=inst.id, legacy_device_id=1, hostname="r1")
    db_session.add(dev)
    await db_session.flush()
    seen = datetime.now(UTC) - timedelta(hours=2)
    for i in range(1, 51):
        db_session.add(IPAddress(subnet_id=sn.id, ip=f"10.93.0.{i}", mac=f"00:00:5e:00:53:{i:02x}"))
        db_session.add(ARPEntry(instance_id=inst.id, device_id=dev.id, ip=f"10.93.0.{i}",
                                mac=f"00:00:5e:00:53:{i:02x}", last_seen_at=seen))
    await db_session.commit()
    _out, q = await _counted(db_session, lambda: _recompute(db_session, ("scanner", "librenms", "arp")))
    assert q < 20, f"補 ARP 起點查了 {q} 次（50 個 IP）"
    got = (await db_session.execute(select(IPAddress.last_seen_arp, IPAddress.effective_status).where(
        IPAddress.ip == "10.93.0.7"))).one()
    assert abs((got[0] - seen).total_seconds()) < 1
    assert got[1] == "offline"                                 # ARP 兩小時前 → 過期
