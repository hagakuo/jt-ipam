"""兩條規則式偵測：懸空 DNS、重疊網段的重複紀錄。

**懸空 DNS**：A 記錄指向 IPAM 裡根本不存在的位址。對外網域時是子網域接管的前置條件 ——
名字還解析得到、但指向的位址已經沒人管，被別人拿到那個位址就等於拿到那個名字。
（「DNS 指向已離線主機」是另一回事，已在對外曝險裡；這裡講的是**位址根本不存在**。）

**重疊網段的重複紀錄**：同一個 IP 字串在多個互相重疊的子網路裡各有一筆。多單位共用
私網位址是刻意支援的，但同一個單位、而且一個網段包含另一個時，多半是誤建 —— 整合同步
只會標到其中一筆，另一筆的存活狀態會永遠停在舊值（實機上就這樣讓一台機器顯示離線 0%）。

兩條都是**算得出來的事實**，所以放異常偵測而不是 AI 巡檢。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.address import IPAddress
from app.models.dns import DNSRecord, DNSServer, DNSZone
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.anomaly import detect_dangling_dns, detect_duplicate_ip_records


async def _zone(db_session):
    srv = DNSServer(name=f"dns-{uuid.uuid4().hex[:6]}", type="bind9")
    db_session.add(srv)
    await db_session.flush()
    z = DNSZone(server_id=srv.id, name=f"z{uuid.uuid4().hex[:6]}.test", type="forward")
    db_session.add(z)
    await db_session.flush()
    return z


async def _subnet(db_session, cidr, **kw):
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr=cidr, **kw)
    db_session.add(sn)
    await db_session.flush()
    return sn


@pytest.mark.anyio
async def test_dangling_dns_record_is_reported(db_session):
    z = await _zone(db_session)
    db_session.add(DNSRecord(zone_id=z.id, name="ghost.example.test", type="A",
                             value="198.51.100.240", ttl=300))
    await db_session.commit()

    out = await detect_dangling_dns(db_session)
    hits = [x for x in out if x["value"] == "198.51.100.240"]
    assert hits, "指向 IPAM 裡不存在的位址 → 要報"
    assert hits[0]["name"] == "ghost.example.test"


@pytest.mark.anyio
async def test_record_pointing_at_a_known_address_is_fine(db_session):
    """位址在 IPAM 裡就不是懸空 —— 那台是不是活著是另一條規則的事。"""
    sn = await _subnet(db_session, "198.51.100.0/24")
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.241"))
    z = await _zone(db_session)
    db_session.add(DNSRecord(zone_id=z.id, name="ok.example.test", type="A",
                             value="198.51.100.241", ttl=300))
    await db_session.commit()

    out = await detect_dangling_dns(db_session)
    assert not [x for x in out if x["value"] == "198.51.100.241"]


@pytest.mark.anyio
async def test_cname_is_not_treated_as_dangling(db_session):
    """只看 A／AAAA。CNAME 的值是名字不是位址，拿去比對 IP 一定「找不到」。"""
    z = await _zone(db_session)
    db_session.add(DNSRecord(zone_id=z.id, name="alias.example.test", type="CNAME",
                             value="target.example.test", ttl=300))
    await db_session.commit()

    out = await detect_dangling_dns(db_session)
    assert not [x for x in out if x["name"] == "alias.example.test"]


@pytest.mark.anyio
async def test_duplicate_record_in_overlapping_subnets(db_session):
    """一個網段包含另一個、同一位址各有一筆 → 報出來讓人清掉。"""
    wide = await _subnet(db_session, "198.51.100.0/24")
    narrow = await _subnet(db_session, "198.51.100.32/28")
    for sn in (wide, narrow):
        db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.36", hostname="dup"))
    await db_session.commit()

    out = await detect_duplicate_ip_records(db_session)
    hits = [x for x in out if x["ip"] == "198.51.100.36"]
    assert hits
    assert len(hits[0]["records"]) == 2
    cidrs = {r["subnet"] for r in hits[0]["records"]}
    assert cidrs == {"198.51.100.0/24", "198.51.100.32/28"}


@pytest.mark.anyio
async def test_same_cidr_twice_is_not_reported(db_session):
    """兩個單位各自登記一模一樣的 CIDR 是刻意支援的多租戶用法，不是錯誤。

    只有「一個網段包含另一個」才幾乎必定是誤建 —— 少了這個條件，多單位環境會被自己的
    正常設定洗版。
    """
    a = await _subnet(db_session, "198.51.100.0/24")
    b = await _subnet(db_session, "198.51.100.0/24")
    for sn in (a, b):
        db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.50"))
    await db_session.commit()

    out = await detect_duplicate_ip_records(db_session)
    assert not [x for x in out if x["ip"] == "198.51.100.50"]
