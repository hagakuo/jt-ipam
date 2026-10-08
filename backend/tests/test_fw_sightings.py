"""防火牆整合共用的整批寫入（services/fw_sightings.py）。

以前五家各自逐筆 `_stamp_ip_seen`：一筆約 4 次查詢，一台 5 萬筆 ARP＋5 萬筆租約的防火牆一輪
三四十萬次（2026-09-30 大量資料測試）。這裡守兩件事：查詢次數不隨筆數成長，規則與原本相同。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.librenms import ARPEntry
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.dhcp_leases import LeaseRun
from app.services.fw_sightings import SightingBatch
from app.services.hostname_reports import HostnameRun
from sqlalchemy import event, func, select


async def _subnet(db, cidr="10.80.0.0/16"):
    sec = Section(name=f"fw-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sn = Subnet(section_id=sec.id, cidr=cidr)
    db.add(sn)
    await db.flush()
    return sn


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


def _mac(i: int) -> str:
    return f"00:00:5e:00:{i // 256:02x}:{i % 256:02x}"


async def test_thousands_of_arp_rows_take_a_handful_of_queries(db_session) -> None:
    db_session.autoflush = False
    sn = await _subnet(db_session)
    n = 2_000
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.80.{i // 256}.{i % 256}"} for i in range(n)])
    await db_session.commit()
    now = datetime.now(UTC)

    async def run():
        b = SightingBatch(db_session, source="opnsense")
        for i in range(n):
            b.add(f"10.80.{i // 256}.{i % 256}", evidence="arp:opnsense", mac=_mac(i), seen_at=now)
        return await b.flush()

    first, q1 = await _counted(db_session, run)
    second, q2 = await _counted(db_session, run)
    assert first == [(True, True)] * n
    assert second == [(True, True)] * n
    assert q1 < 30, f"第一輪 {q1} 次（{n} 筆，每筆都補 MAC）"
    assert q2 < 15, f"什麼都沒變的一輪 {q2} 次（{n} 筆）"
    ip = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "10.80.0.9"))).scalar_one()
    assert str(ip.mac) == _mac(9)
    assert ip.mac_source == "opnsense"
    assert "arp:opnsense" in (ip.arp_seen or {})
    logs = (await db_session.execute(select(func.count()).select_from(IPChangeLog).where(
        IPChangeLog.field == "mac"))).scalar_one()
    assert logs == n                                           # 只有第一輪補 MAC 時寫
    obs = (await db_session.execute(select(func.count()).select_from(ARPEntry).where(
        ARPEntry.source == "arp:opnsense"))).scalar_one()
    assert obs == n                                            # IP 衝突偵測的觀測（再看到只推時間）


async def test_unique_only_scope_and_bad_input(db_session) -> None:
    """重疊網段（同一個位址在兩個子網路）不寫；給了範圍就只在範圍內找；不是位址的略過。"""
    a = await _subnet(db_session, "192.0.2.0/24")
    b = await _subnet(db_session, "192.0.2.0/24")
    db_session.add_all([IPAddress(subnet_id=a.id, ip="192.0.2.5"), IPAddress(subnet_id=b.id, ip="192.0.2.5")])
    await db_session.commit()
    batch = SightingBatch(db_session, source="pfsense")
    for ip in ("192.0.2.5", "not-an-ip", "", "198.51.100.1"):
        batch.add(ip, evidence="arp:pfsense", mac="00:00:5e:00:53:01")
    assert await batch.flush() == [(False, False)] * 4
    scoped = SightingBatch(db_session, source="pfsense", subnet_ids=[a.id])
    scoped.add("192.0.2.5/24", evidence="arp:pfsense", mac="00:00:5e:00:53:01")
    assert await scoped.flush() == [(True, True)]


async def test_auto_create_only_where_the_subnet_is_unique(db_session) -> None:
    from app.services.ip_autocreate import addable_subnets

    sn = await _subnet(db_session, "203.0.113.0/24")
    await db_session.commit()
    batch = SightingBatch(db_session, source="opnsense", create_in=await addable_subnets(db_session, None))
    batch.add("203.0.113.40", evidence="lease:opnsense", mac="00:00:5e:00:53:40")
    batch.add("203.0.113.40", evidence="arp:opnsense", mac="00:00:5e:00:53:40")   # 同一批再看到
    batch.add("198.51.100.40", evidence="lease:opnsense")                          # 沒有可建的子網路
    assert await batch.flush() == [(True, False), (True, False), (False, False)]
    await db_session.commit()
    rows = (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == sn.id))).scalars().all()
    assert [(str(r.ip).split("/")[0], r.discovery_source) for r in rows] == [("203.0.113.40", "opnsense")]


async def test_static_arp_is_not_evidence_of_being_online(db_session) -> None:
    sn = await _subnet(db_session, "198.51.100.0/24")
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.7"))
    await db_session.commit()
    batch = SightingBatch(db_session, source="paloalto")
    batch.add("198.51.100.7", evidence="arp:paloalto", mac="00:00:5e:00:53:07", permanent=True)
    assert await batch.flush() == [(True, True)]
    await db_session.commit()
    ip = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "198.51.100.7"))).scalar_one()
    assert "arp:paloalto" not in (ip.arp_seen or {})
    assert (await db_session.execute(select(func.count()).select_from(ARPEntry))).scalar_one() == 0
    assert str(ip.mac) == "00:00:5e:00:53:07"                  # MAC 照樣依優先序採用


async def test_leases_and_hostnames(db_session) -> None:
    sn = await _subnet(db_session, "198.51.100.0/24")
    db_session.add_all([IPAddress(subnet_id=sn.id, ip="198.51.100.8"), IPAddress(subnet_id=sn.id, ip="198.51.100.9")])
    await db_session.commit()
    fw_id = uuid.uuid4()
    lease_run = LeaseRun(db_session, source_type="mikrotik", source_id=fw_id)
    hn_run = HostnameRun(db_session, source="mikrotik", origin=f"mikrotik:{fw_id}", peers=1)
    batch = SightingBatch(db_session, source="mikrotik", lease_run=lease_run, hn_run=hn_run)
    batch.add("198.51.100.8", evidence="lease:mikrotik", hostname="printer-2f",
              seen_at=datetime.now(UTC) - timedelta(minutes=1))
    batch.add("198.51.100.9", evidence="lease:mikrotik")
    assert await batch.flush() == [(True, True), (True, True)]
    await hn_run.finish(complete=True)
    await lease_run.finish(complete=True)
    await db_session.commit()
    got = dict((await db_session.execute(select(func.host(IPAddress.ip), IPAddress.hostname).where(
        IPAddress.in_dhcp_lease.is_(True)))).all())
    assert got == {"198.51.100.8": "printer-2f", "198.51.100.9": None}


async def test_two_macs_for_one_ip_in_a_batch_do_not_flip(db_session) -> None:
    """同一批裡同一個 IP 有兩個 MAC（ARP 是新的那台、租約還是上一台）：以前依序套用，每一輪都換兩次。"""
    db_session.autoflush = False
    sn = await _subnet(db_session)
    ip = IPAddress(subnet_id=sn.id, ip="10.80.9.9", mac=_mac(2), mac_source="opnsense")
    db_session.add(ip)
    await db_session.commit()
    for _ in range(2):
        b = SightingBatch(db_session, source="opnsense", subnet_ids=[sn.id])
        b.add("10.80.9.9", evidence="arp:opnsense", mac=_mac(1))
        b.add("10.80.9.9", evidence=None, mac=_mac(2))
        await b.flush()
        await db_session.commit()
        await db_session.refresh(ip)
        assert str(ip.mac) == _mac(2)      # 每一輪都要檢查：異動記錄會把「改過去又改回來」合併掉，只看記錄看不出來
    n = (await db_session.execute(select(func.count()).select_from(IPChangeLog)
                                  .where(IPChangeLog.ip_id == ip.id, IPChangeLog.field == "mac"))).scalar()
    assert n == 0
