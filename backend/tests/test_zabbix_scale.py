"""Zabbix 同步在超大規模下（2026-09-30 大量資料測試）。

以前每台主機各比對一次 IP、各查一次鏡像列：一萬台主機一輪兩萬次查詢。
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.zabbix import ZabbixHost, ZabbixInstance
from app.services import zabbix as zbx
from sqlalchemy import event, func, select

N = 300


async def test_host_sync_does_not_query_per_host(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    sec = Section(name=f"z-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="10.90.0.0/16")
    db_session.add(sn)
    await db_session.flush()
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.90.{i // 256}.{i % 256}"} for i in range(N)])
    inst = ZabbixInstance(name=f"zbx-{uuid.uuid4().hex[:6]}", api_url="https://zbx.example")
    db_session.add(inst)
    await db_session.commit()
    hosts = [{"hostid": str(1000 + i), "host": f"h{i}", "name": f"host-{i}", "status": "0",
              "maintenance_status": "0", "tags": [], "inventory": [], "hostgroups": [{"name": "Linux"}],
              "interfaces": [{"ip": f"10.90.{i // 256}.{i % 256}", "dns": "", "useip": "1", "type": "1",
                              "main": "1", "available": "1"}]} for i in range(N)]
    hosts.append(dict(hosts[0]))                                     # 同一台主機回了兩次

    async def fake_rpc(_inst, method, params, *, auth=None, timeout=30.0):
        return "7.0.0" if method == "apiinfo.version" else hosts

    async def fake_token(_inst, *, major=None):
        return "tok"
    monkeypatch.setattr(zbx, "_rpc", fake_rpc)
    monkeypatch.setattr(zbx, "_auth_token", fake_token)

    counts = []
    for _ in range(2):
        n = {"q": 0}
        conn = await db_session.connection()

        def _c(*_a, _n=n, **_k):
            _n["q"] += 1
        event.listen(conn.sync_connection, "before_cursor_execute", _c)
        try:
            out = await zbx.sync_instance(db_session, inst)
            await db_session.commit()
        finally:
            event.remove(conn.sync_connection, "before_cursor_execute", _c)
        counts.append(n["q"])
        assert out["linked"] == N
    assert counts[1] < 30, f"第二輪查了 {counts[1]} 次（{N} 台）"
    assert counts[0] < 50, f"第一輪查了 {counts[0]} 次（{N} 台）"
    total = (await db_session.execute(select(func.count()).select_from(ZabbixHost))).scalar_one()
    assert total == N
    ip = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "10.90.0.7"))).scalar_one()
    assert ip.hostname == "host-7"
    assert ip.last_seen_zabbix is not None
