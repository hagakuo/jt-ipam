"""系統診斷的「資料統計」（使用者 2026-10-06，比照 LibreNMS 的統計頁）：各類資料各有幾筆。

只在本機計算，只有管理員看得到；不回傳、不蒐集。
"""

from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet


async def _stats(client, headers) -> dict[str, dict]:
    r = await client.get("/api/v1/system/doctor/stats", headers=headers)
    assert r.status_code == 200, r.text
    return {i["key"]: i for g in r.json()["groups"] for i in g["items"]}


async def test_every_item_is_a_number(client, auth_headers) -> None:
    items = await _stats(client, auth_headers)
    assert {"subnets", "ipv4", "ipv6", "devices", "audit_logs", "firewall_rules"} <= set(items)
    for k, v in items.items():
        assert isinstance(v["count"], int) and v["count"] >= 0, (k, v)
        assert v["approx"] is False, k          # 小資料庫不會逾時


async def test_counts_follow_the_data_and_split_ipv4_ipv6(client, auth_headers, db_session) -> None:
    before = await _stats(client, auth_headers)
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    s4 = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    s6 = Subnet(section_id=sec.id, cidr="2001:db8:77::/64")
    db_session.add_all([s4, s6])
    await db_session.flush()
    db_session.add_all([IPAddress(subnet_id=s4.id, ip="198.51.100.7"),
                        IPAddress(subnet_id=s4.id, ip="198.51.100.8"),
                        IPAddress(subnet_id=s6.id, ip="2001:db8:77::7")])
    await db_session.commit()
    after = await _stats(client, auth_headers)
    assert after["subnets"]["count"] == before["subnets"]["count"] + 2
    assert after["ipv4"]["count"] == before["ipv4"]["count"] + 2
    assert after["ipv6"]["count"] == before["ipv6"]["count"] + 1


async def test_only_admins(client, db_session) -> None:
    from tests.test_rbac_enforcement import _nonadmin_token
    _u, token = await _nonadmin_token(db_session)
    await db_session.commit()
    r = await client.get("/api/v1/system/doctor/stats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
