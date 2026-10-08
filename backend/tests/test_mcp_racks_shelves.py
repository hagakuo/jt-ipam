"""AI／MCP 看到的機櫃資料要跟上層架那一套（非標準機架、逐層、一層多台）。

`list_racks` 原本只講 U：層架會被說成「9U」，而且「還能放幾台」是按**整列**算的 ——
一層放了一台半寬的裝置，整層就被當成滿了，明明旁邊還有位置。數字每個都是真的，
只是算在錯的集合上。
"""
from __future__ import annotations

import pytest

from app.mcp.tools import list_racks
from app.models.device import Device
from app.models.location import Location, Rack


@pytest.mark.anyio
async def test_shelf_is_reported_in_levels_not_u(db_session, admin_user) -> None:
    loc = Location(name="mcp-shelf-room")
    db_session.add(loc)
    await db_session.flush()
    rack = Rack(name="MCP-IVAR", location_id=loc.id, kind="wood_shelf", u_height=3,
                level_heights=[210, 140, 110], board_mm=18, floor_mm=10)
    db_session.add(rack)
    await db_session.flush()

    out = await list_racks(db_session, user=admin_user)
    r = next(x for x in out["racks"] if x["name"] == "MCP-IVAR")
    assert r["kind"] == "wood_shelf"
    assert r["uses_levels"] is True
    assert r["rows_label"] == "level"
    # 木層架最上面那片板的**上面**也放得下 → 可放的位置比層數多一層
    assert r["open_top"] is True
    assert r["placeable_rows"] == 4
    assert r["level_heights_mm"] == [210, 140, 110]


@pytest.mark.anyio
async def test_half_occupied_level_still_has_room(db_session, admin_user) -> None:
    loc = Location(name="mcp-shelf-room2")
    db_session.add(loc)
    await db_session.flush()
    rack = Rack(name="MCP-SHELF2", location_id=loc.id, kind="shelf", u_height=2)
    db_session.add(rack)
    await db_session.flush()
    # 第 1 層只放了左半邊
    db_session.add(Device(name="mcp-halfdev", type="server", rack_id=rack.id,
                          u_position=1, u_size=1, rack_slot=0, rack_slot_span=30,
                          rack_vslot=0, rack_vslot_span=60))
    await db_session.flush()

    out = await list_racks(db_session, user=admin_user)
    r = next(x for x in out["racks"] if x["name"] == "MCP-SHELF2")
    d = next(x for x in r["devices"] if x["name"] == "mcp-halfdev")
    # 橫向與層內上下位置都要看得到，否則模型答不出「放得下嗎、放哪裡」
    assert d["rack_slot"] == 0 and d["rack_slot_span"] == 30
    assert d["rack_vslot"] == 0 and d["rack_vslot_span"] == 60
    # 第 1 層還有一半是空的 —— 不能當成整層滿了
    space = {x["row"]: x for x in r["rows_with_space"]}
    assert 1 in space, r["rows_with_space"]
    assert space[1]["free_fraction"] == pytest.approx(0.5)


@pytest.mark.anyio
async def test_device_tools_expose_the_in_row_position(db_session, admin_user) -> None:
    """`list_devices` / `get_device` 只回 u_position/u_size 的話，同一層並排或疊放的
    兩台在 AI 眼中是同一個位置 —— 問「它放在哪」只能答到「第 2 層」。"""
    from app.mcp.tools import get_device, list_devices

    loc = Location(name="mcp-shelf-room3")
    db_session.add(loc)
    await db_session.flush()
    rack = Rack(name="MCP-SHELF3", location_id=loc.id, kind="wire_shelf", u_height=4)
    db_session.add(rack)
    await db_session.flush()
    dev = Device(name="mcp-rightdev", type="server", rack_id=rack.id,
                 u_position=2, u_size=1, rack_slot=30, rack_slot_span=30,
                 rack_vslot=30, rack_vslot_span=30)
    db_session.add(dev)
    await db_session.flush()

    lst = await list_devices(db_session, user=admin_user, rack_id=str(rack.id))
    d = next(x for x in lst["devices"] if x["name"] == "mcp-rightdev")
    assert (d["rack_slot"], d["rack_slot_span"]) == (30, 30)
    assert (d["rack_vslot"], d["rack_vslot_span"]) == (30, 30)

    one = await get_device(db_session, user=admin_user, device_id=str(dev.id))
    assert (one["rack_slot"], one["rack_slot_span"]) == (30, 30)
    assert (one["rack_vslot"], one["rack_vslot_span"]) == (30, 30)
    # 機架型態要跟著出來，否則層架會被講成 U
    assert one["rack"]["kind"] == "wire_shelf"
    assert one["rack"]["uses_levels"] is True
