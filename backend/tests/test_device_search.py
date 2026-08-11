"""裝置清單的伺服器端搜尋。

客戶回報（v0.5.137）：新增的裝置在「裝置」清單看不到，用名字搜也搜不到，但從機櫃點進去
卻看得到、也能編輯。原因不是資料沒建立，是三件事疊在一起：

1. 清單只載入第一頁（前 200 筆），依名稱排序
2. 畫面上的搜尋框是**前端**過濾，只比對已經載入的那 200 筆
3. 機櫃那條路徑用 rack_id 查，結果集很小，所以看得到

於是裝置數量超過一頁的站台，新增的裝置只要名稱排在後面，就會「看不到也搜不到」。
"""

from __future__ import annotations

import uuid

import pytest
from app.models.device import Device
from httpx import AsyncClient


@pytest.fixture
async def many_devices(db_session):
    tag = uuid.uuid4().hex[:6]
    # 名稱刻意讓目標裝置排在最後
    for i in range(5):
        db_session.add(Device(name=f"aaa-{tag}-{i:03d}", type="server"))
    target = Device(name=f"zzz-{tag}-target", type="server", serial=f"SN-{tag}")
    db_session.add(target)
    await db_session.commit()
    return tag, target


async def test_search_finds_a_device_outside_the_first_page(
    client: AsyncClient, auth_headers, many_devices,
):
    tag, target = many_devices
    # 只看第一頁、每頁 2 筆 → 目標一定不在裡面
    r = await client.get("/api/v1/devices", params={"page_size": 2}, headers=auth_headers)
    assert r.status_code == 200
    assert target.name not in [d["name"] for d in r.json()["items"]]

    # 但用搜尋就要找得到 —— 這正是客戶回報的情境
    r = await client.get("/api/v1/devices", params={"q": f"zzz-{tag}"}, headers=auth_headers)
    assert r.status_code == 200
    names = [d["name"] for d in r.json()["items"]]
    assert target.name in names
    # 而且要真的有在篩：不比對這一點的話，「q 被忽略、整份回傳」也會通過
    assert not [n for n in names if n.startswith(f"aaa-{tag}")]


async def test_search_is_case_insensitive_and_partial(
    client: AsyncClient, auth_headers, many_devices,
):
    tag, target = many_devices
    r = await client.get("/api/v1/devices", params={"q": f"ZZZ-{tag.upper()}"}, headers=auth_headers)
    names = [d["name"] for d in r.json()["items"]]
    assert target.name in names
    assert not [n for n in names if n.startswith(f"aaa-{tag}")]


async def test_search_also_matches_serial(client: AsyncClient, auth_headers, many_devices):
    tag, target = many_devices
    r = await client.get("/api/v1/devices", params={"q": f"SN-{tag}"}, headers=auth_headers)
    names = [d["name"] for d in r.json()["items"]]
    assert target.name in names
    assert not [n for n in names if n.startswith(f"aaa-{tag}")]


async def test_search_total_reflects_the_filter(client: AsyncClient, auth_headers, many_devices):
    """total 要跟著搜尋縮放，否則分頁會顯示成「共 N 筆」但只有幾筆。"""
    tag, _ = many_devices
    r = await client.get("/api/v1/devices", params={"q": f"zzz-{tag}"}, headers=auth_headers)
    assert r.json()["total"] == 1


@pytest.mark.anyio
async def test_devices_past_the_first_page_are_reachable(client: AsyncClient, auth_headers, db_session):
    """跨過「第一頁」的邊界：第 201 台之後的裝置要拿得到，total 也要是真的總數。

    這條要撐到 200 筆以上才驗得到 —— 資料少於一頁時，只抓第一頁的壞版本一樣會通過，
    客戶站台正是有 272 台才踩出來的。
    """
    tag = uuid.uuid4().hex[:6]
    # 墊到超過一頁，並讓目標排在最後（依名稱排序）
    for i in range(205):
        db_session.add(Device(name=f"aaa-{tag}-{i:04d}", type="server"))
    db_session.add(Device(name=f"zzz-{tag}-last", type="server"))
    await db_session.commit()

    r = await client.get("/api/v1/devices", params={"page_size": 200, "page": 1},
                         headers=auth_headers)
    assert r.status_code == 200
    first = r.json()
    assert len(first["items"]) == 200
    assert first["total"] >= 206, "total 要回真正的總數，不是這一頁的筆數"
    assert f"zzz-{tag}-last" not in [d["name"] for d in first["items"]], (
        "前提：目標本來就不在第一頁 —— 不成立的話這條測試什麼都沒驗到"
    )

    # 前端就是靠這個往下翻。翻得到，清單才會完整。
    seen: list[str] = [d["name"] for d in first["items"]]
    page = 2
    while len(seen) < first["total"] and page <= 60:
        rr = await client.get("/api/v1/devices", params={"page_size": 200, "page": page},
                              headers=auth_headers)
        items = rr.json()["items"]
        if not items:
            break
        seen.extend(d["name"] for d in items)
        page += 1
    assert f"zzz-{tag}-last" in seen
    assert len(seen) == first["total"]
