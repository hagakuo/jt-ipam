"""整合看到一個 IP、要對到 IPAM 既有的哪一筆：重疊網段下不可以任意挑（2026-09-26 稽核）。

以前各整合一律 `.limit(1)`：同一個 IP 在兩個單位的子網路都有、整合又沒設關聯子網路時，
主機名稱／MAC／上線證據／租約旗標會掛到**任意一筆** —— 常常是別的單位名下的那筆。
建立新 IP 早就有「落點不唯一就不建」的規則（ip_autocreate），比對既有的卻沒有。
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.ip_autocreate import match_existing
from sqlalchemy import func, select


async def _two_units(db):
    out = []
    for _ in range(2):
        sec = Section(name=f"unit-{uuid.uuid4().hex[:6]}")
        db.add(sec)
        await db.flush()
        sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
        db.add(sub)
        await db.flush()
        ip = IPAddress(subnet_id=sub.id, ip="192.0.2.10")
        db.add(ip)
        await db.flush()
        out.append((sub, ip))
    return out


async def test_unique_match(db_session) -> None:
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.4")
    db_session.add(ip)
    await db_session.flush()
    assert await match_existing(db_session, "198.51.100.4") == (ip, False)
    assert await match_existing(db_session, "198.51.100.5") == (None, False)


async def test_overlap_without_scope_is_ambiguous_and_scope_settles_it(db_session) -> None:
    (sub_a, ip_a), (_sub_b, _ip_b) = await _two_units(db_session)
    assert await match_existing(db_session, "192.0.2.10") == (None, True)
    assert await match_existing(db_session, "192.0.2.10", [sub_a.id]) == (ip_a, False)


async def test_a_firewall_without_scope_does_not_write_to_either_unit(db_session) -> None:
    """OPNsense 租約：兩個單位都有 192.0.2.10、防火牆沒設關聯子網路 → 兩筆都不動、也不新建。"""
    from app.services.fw_sightings import SightingBatch

    (_a, ip_a), (_b, ip_b) = await _two_units(db_session)
    before = (await db_session.execute(select(func.count()).select_from(IPAddress))).scalar_one()
    batch = SightingBatch(db_session, source="opnsense", create_in=[])
    batch.add("192.0.2.10", evidence="lease:opnsense", hostname="someones-pc", mac="00:00:5e:00:53:10")
    [(ok, _existed)] = await batch.flush()
    assert ok is False
    after = (await db_session.execute(select(func.count()).select_from(IPAddress))).scalar_one()
    assert after == before
    for ip in (ip_a, ip_b):
        await db_session.refresh(ip)
        assert not ip.arp_seen
        assert ip.mac is None
