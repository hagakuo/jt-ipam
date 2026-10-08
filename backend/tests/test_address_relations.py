"""位址關係鏈端點：（location → rack →）device → ip → subnet → section；
缺的環節省略；無權限的子網路看不到。

方向跟裝置頁、儀表板一致：**實體在左、邏輯在右**。以前 IP 頁剛好是反的
（區段 → … → 機房），同一台機器在兩頁左右顛倒（使用者回報）。"""

from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.device import Device
from app.models.section import Section
from app.models.subnet import Subnet


async def _mk(session, *, with_device: bool):
    sec = Section(name="ar-sec")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr="10.7.0.0/24", description="ar-subnet")
    session.add(sub)
    await session.flush()
    dev_id = None
    if with_device:
        dev = Device(name="ar-dev", type="server")
        session.add(dev)
        await session.flush()
        dev_id = dev.id
    addr = IPAddress(subnet_id=sub.id, ip="10.7.0.30", device_id=dev_id, hostname="host-a")
    session.add(addr)
    await session.flush()
    return sec, sub, addr


async def test_chain_up_to_device(client, db_session, auth_headers):
    sec, sub, addr = await _mk(db_session, with_device=True)
    await db_session.commit()

    r = await client.get(f"/api/v1/addresses/{addr.id}/relations", headers=auth_headers)
    assert r.status_code == 200, r.text
    chain = r.json()["chain"]
    assert [c["type"] for c in chain] == ["device", "ip", "subnet", "section"]
    by = {c["type"]: c for c in chain}
    assert by["section"]["id"] == str(sec.id)
    assert by["subnet"]["label"] == "10.7.0.0/24"
    assert by["ip"]["label"] == "10.7.0.30"
    assert by["ip"]["sub"] == "host-a"


async def test_chain_without_device_stops_at_ip(client, db_session, auth_headers):
    sec, sub, addr = await _mk(db_session, with_device=False)
    await db_session.commit()

    r = await client.get(f"/api/v1/addresses/{addr.id}/relations", headers=auth_headers)
    chain = r.json()["chain"]
    assert [c["type"] for c in chain] == ["ip", "subnet", "section"]


async def test_relations_404_for_unknown_address(client, db_session, auth_headers):
    r = await client.get(f"/api/v1/addresses/{uuid.uuid4()}/relations", headers=auth_headers)
    assert r.status_code == 404


async def test_ip_page_and_device_page_run_the_same_direction(client, db_session, auth_headers):
    """同一台機器（機房 → 機櫃 → 裝置 → IP → 子網路 → 區段），IP 頁與裝置頁的關係圖
    要一模一樣的順序 —— 兩頁講的是同一件事。"""
    from app.models.location import Location, Rack

    sec, sub, addr = await _mk(db_session, with_device=True)
    loc = Location(name="ar-room")
    db_session.add(loc)
    await db_session.flush()
    rack = Rack(name="ar-rack", location_id=loc.id, u_height=42)
    db_session.add(rack)
    await db_session.flush()
    dev = await db_session.get(Device, addr.device_id)
    dev.rack_id, dev.location_id, dev.primary_ip_id = rack.id, loc.id, addr.id
    await db_session.commit()

    ip_chain = (await client.get(f"/api/v1/addresses/{addr.id}/relations",
                                 headers=auth_headers)).json()["chain"]
    dev_chain = (await client.get(f"/api/v1/devices/{dev.id}/relations",
                                  headers=auth_headers)).json()["chain"]
    want = ["location", "rack", "device", "ip", "subnet", "section"]
    assert [c["type"] for c in dev_chain] == want
    assert [c["type"] for c in ip_chain] == want, "IP 頁的關係圖方向要跟裝置頁一致"
    assert [c["id"] for c in ip_chain] == [c["id"] for c in dev_chain]
