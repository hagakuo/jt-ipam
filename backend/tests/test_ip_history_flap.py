"""異動記錄：翻動摺疊與「總數＋篩選」。

實機事故：兩個 Wazuh 代理登記同一個 IP，每輪同步互相覆寫主機名稱，
十天內單一 IP 洗出 620 筆 hostname_changed，把真正有意義的人為編輯完全埋掉
（最嚴重的一筆 IP 累積 1,838 筆，且 100% 是同一種事件）。
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.ip_history import log_change


async def _ip(session):
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    session.add(sub)
    await session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.9", state="used")
    session.add(ipa)
    await session.flush()
    return ipa


async def _count(session, ip_id) -> int:
    return int(await session.scalar(
        select(func.count()).select_from(IPChangeLog).where(IPChangeLog.ip_id == ip_id)) or 0)


@pytest.mark.anyio
async def test_exact_reversal_is_collapsed(db_session) -> None:
    """A→B 後緊接著 B→A：淨效果是零，兩筆都不該留下。"""
    ipa = await _ip(db_session)
    await log_change(db_session, ip=ipa, event_type="hostname_changed", field="hostname",
                     old="a", new="b", source="wazuh")
    await db_session.flush()
    assert await _count(db_session, ipa.id) == 1

    await log_change(db_session, ip=ipa, event_type="hostname_changed", field="hostname",
                     old="b", new="a", source="wazuh")
    await db_session.flush()
    assert await _count(db_session, ipa.id) == 0, "來回翻動仍被記錄 → 清單會被洗版"


@pytest.mark.anyio
async def test_real_progression_is_kept(db_session) -> None:
    """A→B→C 不是翻動，一筆都不能少。"""
    ipa = await _ip(db_session)
    for old, new in (("a", "b"), ("b", "c")):
        await log_change(db_session, ip=ipa, event_type="hostname_changed", field="hostname",
                         old=old, new=new, source="librenms")
        await db_session.flush()
    assert await _count(db_session, ipa.id) == 2, "正常的連續變更被誤刪"


@pytest.mark.anyio
async def test_different_field_not_collapsed(db_session) -> None:
    """不同欄位的反向值互不相干，不可互相抵銷。"""
    ipa = await _ip(db_session)
    await log_change(db_session, ip=ipa, event_type="edited", field="hostname",
                     old="a", new="b", source="manual")
    await db_session.flush()
    await log_change(db_session, ip=ipa, event_type="edited", field="owner",
                     old="b", new="a", source="manual")
    await db_session.flush()
    assert await _count(db_session, ipa.id) == 2


@pytest.mark.anyio
async def test_history_endpoint_returns_total_and_facets(client, auth_headers, db_session) -> None:
    """端點要回總數與篩選選項 —— 只回一頁陣列，使用者無從得知還有多少。"""
    ipa = await _ip(db_session)
    for i in range(7):
        await log_change(db_session, ip=ipa, event_type="hostname_changed", field="hostname",
                         old=f"h{i}", new=f"h{i + 1}", source="wazuh")
        await db_session.flush()
    await log_change(db_session, ip=ipa, event_type="edited", field="owner",
                     old=None, new="ops", source="manual")
    await db_session.commit()

    r = await client.get(f"/api/v1/addresses/{ipa.id}/history?limit=3", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 8, "total 應為總數而非本頁筆數"
    assert body["returned"] == 3
    assert {f["value"] for f in body["event_types"]} == {"hostname_changed", "edited"}
    assert {f["value"] for f in body["sources"]} == {"wazuh", "manual"}

    r2 = await client.get(f"/api/v1/addresses/{ipa.id}/history?event_type=edited",
                          headers=auth_headers)
    b2 = r2.json()
    assert b2["total"] == 1
    # 選項母體不隨篩選縮減，否則選了之後就換不回去
    assert {f["value"] for f in b2["event_types"]} == {"hostname_changed", "edited"}
