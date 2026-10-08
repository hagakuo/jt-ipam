"""DNS 拉取在超大規模下（2026-09-30 大量資料測試）。

以前套用主機名稱時每個位址各查一次 IP、一次其他來源的名稱：一個 10 萬筆 A 記錄的 zone
一輪 20 萬次查詢。同時守「唯一才算」：重疊網段又沒設範圍時不可以任意挑一筆。
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.dns import DNSServer
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.dns.base import DNSRecordOp
from sqlalchemy import event, select

from tests.test_dns_sync_pull import _patch

N = 400


async def test_pull_does_not_query_per_record(db_session, monkeypatch) -> None:
    from app.services import dns_sync

    db_session.autoflush = False
    sec = Section(name=f"d-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="10.95.0.0/16")
    db_session.add(sn)
    await db_session.flush()
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.95.{i // 256}.{i % 256}"} for i in range(N)])
    server = DNSServer(name=f"pdns-{uuid.uuid4().hex[:6]}", type="powerdns")
    db_session.add(server)
    await db_session.commit()
    _patch(monkeypatch, [DNSRecordOp(name=f"host-{i}", type="A", value=f"10.95.{i // 256}.{i % 256}")
                         for i in range(N)])
    counts = []
    for _ in range(2):
        n = {"q": 0}
        conn = await db_session.connection()

        def _c(*_a, _n=n, **_k):
            _n["q"] += 1
        event.listen(conn.sync_connection, "before_cursor_execute", _c)
        try:
            await dns_sync.pull_server(db_session, server)
            await db_session.commit()
        finally:
            event.remove(conn.sync_connection, "before_cursor_execute", _c)
        counts.append(n["q"])
    assert counts[1] < 40, f"第二輪查了 {counts[1]} 次（{N} 筆 A 記錄）"
    assert counts[0] < 60, f"第一輪查了 {counts[0]} 次（{N} 筆 A 記錄）"
    ip = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "10.95.0.7"))).scalar_one()
    assert ip.hostname == "host-7"


async def test_overlapping_address_without_scope_is_not_guessed(db_session, monkeypatch) -> None:
    from app.services import dns_sync

    sec = Section(name=f"d-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    a = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
    b = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
    db_session.add_all([a, b])
    await db_session.flush()
    db_session.add_all([IPAddress(subnet_id=a.id, ip="192.0.2.9"), IPAddress(subnet_id=b.id, ip="192.0.2.9")])
    server = DNSServer(name=f"pdns-{uuid.uuid4().hex[:6]}", type="powerdns")
    db_session.add(server)
    await db_session.commit()
    _patch(monkeypatch, [DNSRecordOp(name="whose", type="A", value="192.0.2.9")])
    await dns_sync.pull_server(db_session, server)
    await db_session.commit()
    names = (await db_session.execute(select(IPAddress.hostname).where(IPAddress.ip == "192.0.2.9"))).scalars().all()
    assert names == [None, None], "兩個單位都有這個位址 → 不可以任意挑一筆掛名稱"
