"""IP 詳情頁 uptime 長條圖的資料重建。

我們沒有逐時取樣，只有 `ip_change_log` 的狀態轉換，所以每日狀態是「重建」出來的。
最容易出錯也最要緊的是：**沒有資料的日子不能被當成正常**，而 uptime 百分比的
分母只能算有資料的天數 —— 否則數字會說謊。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints.addresses import get_address_uptime
from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet


async def _mk_ip(session, admin_user):
    sec = Section(name=f"upt-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    sub = Subnet(cidr="10.90.0.0/24", section_id=sec.id)
    session.add(sub)
    await session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="10.90.0.5")
    session.add(ipa)
    await session.flush()
    return ipa


def _ev(ipa, when, new):
    return IPChangeLog(
        ip_id=ipa.id, subnet_id=ipa.subnet_id, ip_text="10.90.0.5",
        event_type="update", field="effective_status",
        old_value=None, new_value=new, created_at=when, source="system",
    )


@pytest.mark.anyio
async def test_no_source_is_all_unknown_not_up(db_session, admin_user) -> None:
    """沒有存活來源的 IP（約 68%）→ 整條 unknown，絕不可粉飾成 up。"""
    ipa = await _mk_ip(db_session, admin_user)
    await db_session.commit()

    out = await get_address_uptime(ipa.id, admin_user, db_session, days=30)
    assert out["has_source"] is False
    assert {i["status"] for i in out["items"]} == {"unknown"}
    # 完全沒資料 → 不能回 0% 也不能回 100%
    assert out["uptime_pct"] is None
    assert out["known_days"] == 0


@pytest.mark.anyio
async def test_state_persists_between_transitions(db_session, admin_user) -> None:
    """轉換式重建：狀態要延續到下一筆轉換，不是只有轉換當天才有狀態。"""
    ipa = await _mk_ip(db_session, admin_user)
    now = datetime.now(UTC)
    db_session.add(_ev(ipa, now - timedelta(days=9), "online (scanner)"))
    db_session.add(_ev(ipa, now - timedelta(days=4), "offline"))
    db_session.add(_ev(ipa, now - timedelta(days=3), "online (librenms)"))
    await db_session.commit()

    out = await get_address_uptime(ipa.id, admin_user, db_session, days=10)
    by_date = {i["date"]: i["status"] for i in out["items"]}
    d = (now - timedelta(days=7)).date().isoformat()
    assert by_date[d] == "up", "轉換之間的日子沒有延續狀態"
    assert by_date[(now - timedelta(days=4)).date().isoformat()] == "down"
    # 有中斷的當天算 down（即使當天稍後又復線）
    assert by_date[(now - timedelta(days=3)).date().isoformat()] == "down"
    assert by_date[(now - timedelta(days=1)).date().isoformat()] == "up"


@pytest.mark.anyio
async def test_days_before_first_transition_are_unknown(db_session, admin_user) -> None:
    """資料起點之前一律 unknown —— 塗綠等於謊稱那段期間正常。"""
    ipa = await _mk_ip(db_session, admin_user)
    now = datetime.now(UTC)
    db_session.add(_ev(ipa, now - timedelta(days=2), "online (scanner)"))
    await db_session.commit()

    out = await get_address_uptime(ipa.id, admin_user, db_session, days=30)
    by_date = {i["date"]: i["status"] for i in out["items"]}
    assert by_date[(now - timedelta(days=20)).date().isoformat()] == "unknown"
    assert by_date[(now - timedelta(days=1)).date().isoformat()] == "up"


@pytest.mark.anyio
async def test_uptime_pct_denominator_excludes_unknown(db_session, admin_user) -> None:
    """只監測 3 天且全綠 → 100%，不是「3/30 = 10%」也不是被灰稀釋的數字。"""
    ipa = await _mk_ip(db_session, admin_user)
    now = datetime.now(UTC)
    db_session.add(_ev(ipa, now - timedelta(days=2), "online (scanner)"))
    await db_session.commit()

    out = await get_address_uptime(ipa.id, admin_user, db_session, days=30)
    assert out["known_days"] == 3          # 今天 + 前兩天
    assert out["down_days"] == 0
    assert out["uptime_pct"] == 100.0


@pytest.mark.anyio
async def test_online_prefix_matching(db_session, admin_user) -> None:
    """effective_status 是小寫帶來源後綴；用固定字串比對正是 v0.4.196 的儀表板誤判。"""
    ipa = await _mk_ip(db_session, admin_user)
    now = datetime.now(UTC)
    db_session.add(_ev(ipa, now - timedelta(days=1), "online (librenms)"))
    await db_session.commit()

    out = await get_address_uptime(ipa.id, admin_user, db_session, days=3)
    assert out["items"][-1]["status"] == "up", "帶來源後綴的 online 沒被認出來"


@pytest.mark.anyio
async def test_device_uptime_merges_all_its_ips(db_session, admin_user) -> None:
    """裝置有多個 IP：當天任一 IP 曾中斷 → 該日標中斷（浮現問題，不掩蓋）。"""
    from app.api.v1.endpoints.devices import get_device_uptime
    from app.models.device import Device

    dev = Device(name=f"upt-dev-{uuid.uuid4().hex[:6]}", type="server")
    db_session.add(dev)
    await db_session.flush()

    sec = Section(name=f"upt-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(cidr="10.91.0.0/24", section_id=sec.id)
    db_session.add(sub)
    await db_session.flush()

    now = datetime.now(UTC)
    ips = []
    for n in (1, 2):
        ipa = IPAddress(subnet_id=sub.id, ip=f"10.91.0.{n}", device_id=dev.id)
        db_session.add(ipa)
        await db_session.flush()
        ips.append(ipa)
        db_session.add(IPChangeLog(
            ip_id=ipa.id, subnet_id=sub.id, ip_text=f"10.91.0.{n}",
            event_type="update", field="effective_status", old_value=None,
            new_value="online (scanner)", created_at=now - timedelta(days=5), source="system",
        ))
    # 只有第二個 IP 在第 2 天前中斷過
    db_session.add(IPChangeLog(
        ip_id=ips[1].id, subnet_id=sub.id, ip_text="10.91.0.2",
        event_type="update", field="effective_status", old_value=None,
        new_value="offline", created_at=now - timedelta(days=2), source="system",
    ))
    await db_session.commit()

    out = await get_device_uptime(dev.id, db_session, days=7)
    by_date = {i["date"]: i["status"] for i in out["items"]}
    assert by_date[(now - timedelta(days=4)).date().isoformat()] == "up"
    assert by_date[(now - timedelta(days=2)).date().isoformat()] == "down", (
        "其中一個 IP 中斷卻沒反映在裝置上"
    )
    assert out["has_source"] is True


@pytest.mark.anyio
async def test_device_without_ips_is_all_unknown(db_session, admin_user) -> None:
    """沒有 IP 的裝置 → 整條灰，不可畫成正常。"""
    from app.api.v1.endpoints.devices import get_device_uptime
    from app.models.device import Device

    dev = Device(name=f"upt-noip-{uuid.uuid4().hex[:6]}", type="server")
    db_session.add(dev)
    await db_session.commit()

    out = await get_device_uptime(dev.id, db_session, days=14)
    assert {i["status"] for i in out["items"]} == {"unknown"}
    assert out["uptime_pct"] is None
    assert out["has_source"] is False
