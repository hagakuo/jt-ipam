"""機櫃插入／刪除一層 + 裝置整批移位。

由來：機櫃建錯（例如最下面多算了一層）時只能一台一台搬，很費工。這裡一次搞定。
重點在三件事：**不自動刪別人的資料**、**預覽與實際執行同一段程式**、**可以復原**。
"""

from __future__ import annotations

import pytest
from app.services.rack_levels import LevelOpError, apply_level_op, plan_level_op


async def _rack(session, **kw):  # type: ignore[no-untyped-def]
    from app.models.location import Rack
    r = Rack(name=kw.pop("name", "R"), u_height=kw.pop("u_height", 6), **kw)
    session.add(r)
    await session.flush()
    return r


async def _dev(session, rack, pos, size=1, name="d"):  # type: ignore[no-untyped-def]
    from app.models.device import Device
    d = Device(name=name, type="server", rack_id=rack.id, u_position=pos, u_size=size)
    session.add(d)
    await session.flush()
    return d


@pytest.mark.anyio
async def test_removing_a_level_shifts_everything_above_it_down(db_session) -> None:
    rk = await _rack(db_session, u_height=6)
    low = await _dev(db_session, rk, 1, name="low")
    high = await _dev(db_session, rk, 5, name="high")
    await apply_level_op(db_session, rack_id=rk.id, op="remove", at=3)
    await db_session.refresh(low); await db_session.refresh(high); await db_session.refresh(rk)
    assert low.u_position == 1, "被刪那層以下的不該動"
    assert high.u_position == 4, "上面的要往下掉一層"
    assert rk.u_height == 5


@pytest.mark.anyio
async def test_inserting_a_level_shifts_everything_above_it_up(db_session) -> None:
    rk = await _rack(db_session, u_height=6)
    low = await _dev(db_session, rk, 1, name="low")
    high = await _dev(db_session, rk, 3, name="high")
    await apply_level_op(db_session, rack_id=rk.id, op="insert", at=3)
    await db_session.refresh(low); await db_session.refresh(high); await db_session.refresh(rk)
    assert low.u_position == 1
    assert high.u_position == 4
    assert rk.u_height == 7


@pytest.mark.anyio
async def test_a_level_with_a_device_on_it_is_refused_not_silently_emptied(db_session) -> None:
    """要刪的那層上還有東西 → 擋下來並說是誰。**絕不自動刪掉別人的裝置。**"""
    rk = await _rack(db_session, u_height=4)
    keep = await _dev(db_session, rk, 2, name="keep-me")
    plan = await plan_level_op(db_session, rack_id=rk.id, op="remove", at=2)
    assert [b["name"] for b in plan.blockers] == ["keep-me"]
    with pytest.raises(LevelOpError) as e:
        await apply_level_op(db_session, rack_id=rk.id, op="remove", at=2)
    assert e.value.code == "rack_level_blocked"
    await db_session.refresh(keep); await db_session.refresh(rk)
    assert keep.u_position == 2 and rk.u_height == 4, "擋下來就要什麼都沒變"


@pytest.mark.anyio
async def test_a_device_spanning_the_level_is_refused_rather_than_guessed(db_session) -> None:
    """跨越該層的裝置：該縮短還是該整台移沒有唯一正解 —— 與其猜不如問。"""
    rk = await _rack(db_session, u_height=6)
    await _dev(db_session, rk, 2, size=3, name="tall")     # 佔第 2~4 層
    plan = await plan_level_op(db_session, rack_id=rk.id, op="remove", at=3)
    assert plan.blockers and plan.blockers[0]["reason"] == "spans"


@pytest.mark.anyio
async def test_dry_run_changes_nothing(db_session) -> None:
    """預覽用的就是實際要做的那段程式，但不可以寫入。"""
    rk = await _rack(db_session, u_height=5)
    d = await _dev(db_session, rk, 4, name="x")
    plan = await plan_level_op(db_session, rack_id=rk.id, op="remove", at=2)
    assert plan.moves == [{"device_id": str(d.id), "name": "x", "u_size": 1,
                           "from": 4, "to": 3}]
    await db_session.refresh(d); await db_session.refresh(rk)
    assert d.u_position == 4 and rk.u_height == 5


@pytest.mark.anyio
async def test_the_operation_can_be_undone_exactly(db_session) -> None:
    """回應帶的 undo 照送回來就會還原 —— 插入與刪除互為反操作，不必在伺服器存狀態。"""
    rk = await _rack(db_session, u_height=5, kind="wood_shelf",
                     level_heights=[100, 200, 300, 400, 500])
    d = await _dev(db_session, rk, 5, name="top")
    plan = await apply_level_op(db_session, rack_id=rk.id, op="remove", at=2)
    await db_session.refresh(rk)
    assert rk.u_height == 4 and rk.level_heights == [100, 300, 400, 500]

    u = plan.undo
    assert u == {"op": "insert", "at": 2, "height_mm": 200}
    await apply_level_op(db_session, rack_id=rk.id, op=u["op"], at=u["at"],
                         height_mm=u["height_mm"])
    await db_session.refresh(rk); await db_session.refresh(d)
    assert rk.u_height == 5, "層數要回來"
    assert rk.level_heights == [100, 200, 300, 400, 500], "被刪那層的高度也要回來"
    assert d.u_position == 5, "裝置要回到原位"


@pytest.mark.anyio
async def test_cannot_remove_the_only_level(db_session) -> None:
    rk = await _rack(db_session, u_height=1)
    with pytest.raises(LevelOpError) as e:
        await plan_level_op(db_session, rack_id=rk.id, op="remove", at=1)
    assert e.value.code == "rack_level_last_one"
