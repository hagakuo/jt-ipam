"""同一個 MAC 不可以每次同步都被當成「變更」。

實機症狀：IP 異動記錄 24 小時內出現 990 筆「MAC 變更」，每一筆的舊值都是空的，
而且同一個 IP 一天記 90 次、新值卻**始終是同一個 MAC**。

根因是本專案的老坑（已知地雷 #10）的變形：asyncpg 把 MACADDR 欄位回成**物件**，
字串化後帶冒號（`bc:24:11:6a:58:ef`），而傳進來的值是正規化過的 `bc24116a58ef`。
兩者永遠不相等 → 每輪都判定「變了」。

比對前兩邊都要正規化。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.arp_precedence import consider_mac


async def _ip(db_session, mac: str | None):
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sn)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sn.id, ip="198.51.100.30", mac=mac,
                    mac_source="librenms" if mac else None)
    db_session.add(ipa)
    await db_session.flush()
    return ipa


@pytest.mark.anyio
async def test_same_mac_in_colon_form_is_not_a_change(db_session):
    """資料庫存冒號式、來源給無分隔式 —— 那是同一個 MAC。"""
    ipa = await _ip(db_session, "bc:24:11:6a:58:ef")
    await db_session.refresh(ipa)      # 讓 mac 變成 asyncpg 回來的型別，與實機一致
    assert await consider_mac(db_session, ip=ipa, mac="bc24116a58ef",
                              source="librenms") is False


@pytest.mark.anyio
async def test_same_mac_with_dashes_is_not_a_change(db_session):
    ipa = await _ip(db_session, "bc:24:11:6a:58:ef")
    await db_session.refresh(ipa)
    assert await consider_mac(db_session, ip=ipa, mac="BC-24-11-6A-58-EF",
                              source="librenms") is False


@pytest.mark.anyio
async def test_a_genuinely_different_mac_is_a_change(db_session):
    """真的換了網卡還是要偵測得到 —— 修掉誤報不能把真正的變更也一起蓋掉。"""
    ipa = await _ip(db_session, "bc:24:11:6a:58:ef")
    await db_session.refresh(ipa)
    assert await consider_mac(db_session, ip=ipa, mac="00:11:22:33:44:55",
                              source="librenms") is True
    assert str(ipa.mac).replace(":", "").lower() == "001122334455"


@pytest.mark.anyio
async def test_first_time_still_fills_it_in(db_session):
    ipa = await _ip(db_session, None)
    assert await consider_mac(db_session, ip=ipa, mac="bc24116a58ef",
                              source="librenms") is True
