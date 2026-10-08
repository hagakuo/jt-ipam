"""子網路偵測到 DHCP 發放範圍時，「位址範圍（集區）」自動加上對應的範圍（2026-09-27 使用者要求）。

以前子網路詳細資料上方寫著「DHCP 發放範圍 198.51.100.150 — 198.51.100.200（firewall-a · KEA）」，
下面的位址範圍卻是「還沒有定義範圍」，要自己再建一次。自動建立的範圍跟著上游走：出現就建、
改了就換、上游不再回報（或整合刪掉）就移除；手動建立的範圍一律不動。
"""
from __future__ import annotations

import uuid

from app.models.dhcp import DHCPPoolRange
from app.models.ip_range import IPRange
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import ip_ranges
from sqlalchemy import select

FW = uuid.UUID("00000000-0000-0000-0000-0000000000f1")


async def _subnet(db, cidr="198.51.100.0/24") -> Subnet:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr)
    db.add(sub)
    await db.flush()
    return sub


def _pool(start="198.51.100.150", end="198.51.100.200", **kw) -> DHCPPoolRange:
    base = {"source_type": "opnsense", "source_id": FW, "source_name": "firewall-a",
            "subnet_cidr": "198.51.100.0/24", "start_ip": start, "end_ip": end, "family": 4,
            "source": "kea"}
    base.update(kw)
    return DHCPPoolRange(**base)


async def _ranges(db, sub) -> list[IPRange]:
    return list((await db.execute(select(IPRange).where(IPRange.subnet_id == sub.id)
                                  .order_by(IPRange.start_ip))).scalars().all())


async def test_a_detected_dhcp_range_becomes_a_pool_range(db_session) -> None:
    sub = await _subnet(db_session)
    db_session.add(_pool())
    await db_session.flush()
    out = await ip_ranges.sync_auto_dhcp_ranges(db_session)
    rows = await _ranges(db_session, sub)
    assert [(str(r.start_ip), str(r.end_ip), r.purpose) for r in rows] == [
        ("198.51.100.150", "198.51.100.200", "dhcp")]
    assert rows[0].source_origin == f"opnsense:{FW}"
    assert "firewall-a" in (rows[0].name or "")
    assert out["created"] == 1
    # 再跑一次不重複建
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    assert len(await _ranges(db_session, sub)) == 1


async def test_it_follows_the_upstream_change_and_removal(db_session) -> None:
    sub = await _subnet(db_session)
    pool = _pool()
    db_session.add(pool)
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    pool.end_ip = "198.51.100.220"
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    rows = await _ranges(db_session, sub)
    assert [(str(r.start_ip), str(r.end_ip)) for r in rows] == [("198.51.100.150", "198.51.100.220")]
    await db_session.delete(pool)
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    assert await _ranges(db_session, sub) == []


async def test_manual_ranges_are_never_touched_and_block_overlaps(db_session) -> None:
    """手動建好的範圍跟偵測到的重疊：不自動建（手動的已經涵蓋），也不動手動的那一筆。"""
    sub = await _subnet(db_session)
    db_session.add(IPRange(subnet_id=sub.id, start_ip="198.51.100.140", end_ip="198.51.100.180",
                           purpose="dhcp", name="my pool"))
    db_session.add(IPRange(subnet_id=sub.id, start_ip="198.51.100.10", end_ip="198.51.100.20",
                           purpose="reserved", name="printers"))
    db_session.add(_pool())
    await db_session.flush()
    out = await ip_ranges.sync_auto_dhcp_ranges(db_session)
    names = [r.name for r in await _ranges(db_session, sub)]
    assert names == ["printers", "my pool"]
    assert out["skipped_overlap"] == 1


async def test_an_ambiguous_subnet_is_not_guessed(db_session) -> None:
    """兩個單位都有 198.51.100.0/24：不知道是哪一個的，不建。"""
    a = await _subnet(db_session)
    b = await _subnet(db_session)
    db_session.add(_pool())
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    assert await _ranges(db_session, a) == []
    assert await _ranges(db_session, b) == []


async def test_the_most_specific_subnet_wins(db_session) -> None:
    outer = await _subnet(db_session, "198.51.0.0/16")
    inner = await _subnet(db_session, "198.51.100.0/24")
    db_session.add(_pool())
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    assert len(await _ranges(db_session, inner)) == 1
    assert await _ranges(db_session, outer) == []


async def test_auto_ranges_are_not_counted_twice_as_manual_pools(db_session) -> None:
    """DHCP 集區使用率、「在 DHCP 範圍內」已經算了上游的範圍：自動建的不可以再當成手動集區算一次。"""
    await _subnet(db_session)
    db_session.add(_pool())
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    assert await ip_ranges.manual_dhcp_pools(db_session) == []


async def test_auto_ranges_cannot_be_edited_or_deleted_by_hand(client, auth_headers, db_session) -> None:
    """同步管理的範圍：改了下一輪會被蓋回去、刪了會再建 —— 直接擋，講清楚要改上游。"""
    sub = await _subnet(db_session)
    db_session.add(_pool())
    await db_session.flush()
    await ip_ranges.sync_auto_dhcp_ranges(db_session)
    await db_session.commit()
    rid = (await _ranges(db_session, sub))[0].id

    r = await client.get(f"/api/v1/subnets/{sub.id}/ranges", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()[0]["auto"] is True
    assert "firewall-a" in r.json()[0]["source_label"]

    r = await client.patch(f"/api/v1/subnets/{sub.id}/ranges/{rid}", headers=auth_headers,
                           json={"name": "x"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "range_auto_managed"
    r = await client.delete(f"/api/v1/subnets/{sub.id}/ranges/{rid}", headers=auth_headers)
    assert r.status_code == 409, r.text
