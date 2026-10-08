"""IP 異動記錄要能依區段／子網路／單位篩選。

由來（2026-09-04 使用者要求）：這一頁是全站所有 IP 的變更歷史，實務上的問題永遠是
「**這個單位**這週有什麼變動」或「**這個網段**有什麼變動」，而不是「全站有什麼變動」。

單位那條的重點在**繼承**：子網路自己沒設單位時要沿用所屬區段的。只比對
`subnets.customer_id` 會漏掉一整批「只在區段層指定單位」的站台 —— 而且是安靜地漏，
畫面上只會少幾列，不會有任何錯誤。
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.models.address import IPAddress
from app.models.customer import Customer
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet


async def _seed(session: Any) -> dict[str, Any]:
    cust_a = Customer(name=f"unit-a-{uuid.uuid4().hex[:6]}")
    cust_b = Customer(name=f"unit-b-{uuid.uuid4().hex[:6]}")
    session.add_all([cust_a, cust_b])
    await session.flush()

    # 區段層設單位；底下兩個子網路：一個自己沒設（要繼承）、一個自己設成別家（要覆寫）
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}", customer_id=cust_a.id)
    sec_other = Section(name=f"sec2-{uuid.uuid4().hex[:6]}")
    session.add_all([sec, sec_other])
    await session.flush()

    inherit = Subnet(section_id=sec.id, cidr="198.51.100.0/24")           # 繼承 cust_a
    override = Subnet(section_id=sec.id, cidr="203.0.113.0/24",
                      customer_id=cust_b.id)                              # 覆寫成 cust_b
    elsewhere = Subnet(section_id=sec_other.id, cidr="192.0.2.0/24")      # 另一個區段
    session.add_all([inherit, override, elsewhere])
    await session.flush()

    rows = []
    for sub, ip in ((inherit, "198.51.100.5"), (override, "203.0.113.5"), (elsewhere, "192.0.2.5")):
        ipa = IPAddress(subnet_id=sub.id, ip=ip)
        session.add(ipa)
        await session.flush()
        log = IPChangeLog(ip_id=ipa.id, subnet_id=sub.id, ip_text=ip,
                          event_type="edited", field="hostname",
                          old_value="a", new_value="b", source="manual")
        session.add(log)
        rows.append(ip)
    await session.commit()
    return {"section": sec, "cust_a": cust_a, "cust_b": cust_b,
            "inherit": inherit, "override": override, "elsewhere": elsewhere}


@pytest.mark.anyio
async def test_filter_by_section(client: Any, auth_headers: Any, db_session: Any) -> None:
    d = await _seed(db_session)
    r = await client.get("/api/v1/ip-changes",
                         params={"section_id": str(d["section"].id)}, headers=auth_headers)
    assert r.status_code == 200, r.text
    ips = {i["ip_text"] for i in r.json()["items"]}
    assert ips == {"198.51.100.5", "203.0.113.5"}, ips


@pytest.mark.anyio
async def test_filter_by_subnet(client: Any, auth_headers: Any, db_session: Any) -> None:
    d = await _seed(db_session)
    r = await client.get("/api/v1/ip-changes",
                         params={"subnet_id": str(d["inherit"].id)}, headers=auth_headers)
    assert {i["ip_text"] for i in r.json()["items"]} == {"198.51.100.5"}


@pytest.mark.anyio
async def test_customer_filter_follows_section_inheritance(
    client: Any, auth_headers: Any, db_session: Any,
) -> None:
    """單位 A 設在**區段**上：沒有自己設單位的子網路要算進來，設成別家的不算。"""
    d = await _seed(db_session)
    r = await client.get("/api/v1/ip-changes",
                         params={"customer_id": str(d["cust_a"].id)}, headers=auth_headers)
    ips = {i["ip_text"] for i in r.json()["items"]}
    assert ips == {"198.51.100.5"}, f"繼承或覆寫算錯了：{ips}"


@pytest.mark.anyio
async def test_customer_filter_respects_subnet_override(
    client: Any, auth_headers: Any, db_session: Any,
) -> None:
    d = await _seed(db_session)
    r = await client.get("/api/v1/ip-changes",
                         params={"customer_id": str(d["cust_b"].id)}, headers=auth_headers)
    assert {i["ip_text"] for i in r.json()["items"]} == {"203.0.113.5"}


@pytest.mark.anyio
async def test_filters_combine_as_and(client: Any, auth_headers: Any, db_session: Any) -> None:
    """區段 + 單位同時指定時是交集；沒有交集就該回空的，而不是忽略其中一個。"""
    d = await _seed(db_session)
    r = await client.get("/api/v1/ip-changes", headers=auth_headers, params={
        "section_id": str(d["section"].id), "customer_id": str(d["cust_b"].id)})
    assert {i["ip_text"] for i in r.json()["items"]} == {"203.0.113.5"}

    r = await client.get("/api/v1/ip-changes", headers=auth_headers, params={
        "subnet_id": str(d["elsewhere"].id), "customer_id": str(d["cust_a"].id)})
    assert r.json()["items"] == []
