"""子網路內的位址範圍（集區）—— GitHub issue #40。

回報者要在 jt-ipam 定義內部網路的 DHCP 集區：一個 /24 裡的 .181～.250，這段沒辦法用一個 CIDR 表示，
只能拆成 /32、/31、/29、/26、/30、/32 六個「子網路」。子網路是一個 L3 網路（有遮罩、閘道、廣播），
那段位址不是網路、是那個 /24 裡面的一段集區 —— 所以子網路維持 CIDR，範圍是子網路裡的
另一種物件（NetBox 的 IP Ranges 也是這樣）。

用途是「DHCP 集區」的範圍，要跟整合同步回來的 DHCP 範圍一起用：清單上的「在 DHCP 範圍內」、
DHCP 集區的使用率、AI 工具「這個 IP 在不在 DHCP 集區」都要算進去。
"""
from __future__ import annotations

import pytest

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet


async def _subnet(session, cidr="198.51.100.0/24"):
    sec = Section(name=f"rng-{cidr}")
    session.add(sec)
    await session.flush()
    sn = Subnet(section_id=sec.id, cidr=cidr, description="lan")
    session.add(sn)
    await session.flush()
    return sn


# ── 驗證 ─────────────────────────────────────────────────────────────────

@pytest.mark.anyio
@pytest.mark.parametrize(("start", "end", "code"), [
    ("198.51.100.181", "198.51.100.250", None),
    ("198.51.100.250", "198.51.100.181", "range_start_after_end"),
    ("198.51.100.200", "198.51.101.10", "range_outside_subnet"),
    ("198.51.100.10", "2001:db8::1", "range_family_mismatch"),
    ("198.51.100.x", "198.51.100.20", "range_invalid_address"),
])
async def test_validation(db_session, start, end, code) -> None:
    from app.core.ui_error import UiError
    from app.services.ip_ranges import validate_range
    sn = await _subnet(db_session)
    if code is None:
        await validate_range(db_session, sn, start, end)
        return
    with pytest.raises(UiError) as ei:
        await validate_range(db_session, sn, start, end)
    assert ei.value.code == code


@pytest.mark.anyio
async def test_ranges_in_one_subnet_do_not_overlap(db_session) -> None:
    from app.core.ui_error import UiError
    from app.models.ip_range import IPRange
    from app.services.ip_ranges import validate_range
    sn = await _subnet(db_session)
    first = IPRange(subnet_id=sn.id, start_ip="198.51.100.181", end_ip="198.51.100.250",
                    purpose="dhcp", name="DHCP 集區")
    db_session.add(first)
    await db_session.flush()
    with pytest.raises(UiError) as ei:
        await validate_range(db_session, sn, "198.51.100.240", "198.51.100.254")
    assert ei.value.code == "range_overlap"
    assert ei.value.params["other"] == "DHCP 集區"
    # 改自己那一筆不算重疊
    await validate_range(db_session, sn, "198.51.100.181", "198.51.100.249", exclude_id=first.id)
    # 緊鄰不算重疊
    await validate_range(db_session, sn, "198.51.100.251", "198.51.100.254")


# ── API ─────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_crud_is_audited_and_reports_usage(client, auth_headers, db_session) -> None:
    from sqlalchemy import select

    from app.models.audit import AuditLog
    sn = await _subnet(db_session)
    for ip in ("198.51.100.181", "198.51.100.182", "198.51.100.10"):
        db_session.add(IPAddress(subnet_id=sn.id, ip=ip))
    await db_session.commit()

    base = f"/api/v1/subnets/{sn.id}/ranges"
    r = await client.post(base, headers=auth_headers, json={
        "start_ip": "198.51.100.181", "end_ip": "198.51.100.250", "purpose": "dhcp",
        "name": "DHCP 集區", "description": "辦公室"})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]

    rows = (await client.get(base, headers=auth_headers)).json()
    assert len(rows) == 1
    row = rows[0]
    assert (row["size"], row["used"]) == (70, 2), "181～250 共 70 個，其中 2 個已有記錄"
    assert row["first_free"] == "198.51.100.183"

    r = await client.patch(f"{base}/{rid}", headers=auth_headers, json={"end_ip": "198.51.100.200"})
    assert r.status_code == 200, r.text
    assert r.json()["end_ip"] == "198.51.100.200"

    r = await client.post(base, headers=auth_headers, json={
        "start_ip": "198.51.100.190", "end_ip": "198.51.100.210", "purpose": "reserved"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "range_overlap"

    assert (await client.delete(f"{base}/{rid}", headers=auth_headers)).status_code == 204
    acts = (await db_session.execute(select(AuditLog.action).where(
        AuditLog.object_type == "ip_range"))).scalars().all()
    assert sorted(acts) == ["create", "delete", "update"]


@pytest.mark.anyio
async def test_a_user_who_cannot_see_the_subnet_cannot_see_or_add_ranges(client, db_session) -> None:
    from app.models.user import User
    from app.services.auth import issue_access_token
    sn = await _subnet(db_session)
    u = User(username="rng-viewer", email="rng@example.invalid", password_hash="x", is_active=True)
    db_session.add(u)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    base = f"/api/v1/subnets/{sn.id}/ranges"
    assert (await client.get(base, headers=h)).status_code in (403, 404)
    r = await client.post(base, headers=h, json={"start_ip": "198.51.100.1", "end_ip": "198.51.100.9",
                                                 "purpose": "reserved"})
    assert r.status_code in (403, 404)


@pytest.mark.anyio
async def test_deleting_the_subnet_removes_its_ranges(db_session) -> None:
    from sqlalchemy import func, select

    from app.models.ip_range import IPRange
    sn = await _subnet(db_session)
    db_session.add(IPRange(subnet_id=sn.id, start_ip="198.51.100.1", end_ip="198.51.100.9",
                           purpose="reserved"))
    await db_session.commit()
    await db_session.delete(sn)
    await db_session.commit()
    assert await db_session.scalar(select(func.count()).select_from(IPRange)) == 0


# ── 跟既有的 DHCP 範圍一起用 ────────────────────────────────────────────

@pytest.mark.anyio
async def test_manual_dhcp_range_marks_ips_and_counts_in_pool_usage(client, auth_headers, db_session) -> None:
    from app.models.ip_range import IPRange
    from app.services.dhcp_usage import pool_usage
    sn = await _subnet(db_session)
    db_session.add_all([
        IPRange(subnet_id=sn.id, start_ip="198.51.100.181", end_ip="198.51.100.250",
                purpose="dhcp", name="DHCP 集區"),
        IPRange(subnet_id=sn.id, start_ip="198.51.100.2", end_ip="198.51.100.9", purpose="reserved"),
        IPAddress(subnet_id=sn.id, ip="198.51.100.200"),
        IPAddress(subnet_id=sn.id, ip="198.51.100.5"),
    ])
    await db_session.commit()

    r = await client.get(f"/api/v1/addresses?subnet_id={sn.id}", headers=auth_headers)
    flags = {x["ip"].split("/")[0]: x.get("in_dhcp_range") for x in r.json()["items"]}
    assert flags["198.51.100.200"] is True, "手動定義的 DHCP 集區也要標「在 DHCP 範圍內」"
    assert flags["198.51.100.5"] is False, "保留範圍不是 DHCP 集區"

    usage = await pool_usage(db_session)
    mine = [(u, t) for p, u, t in usage if str(getattr(p, "start_ip", "")) == "198.51.100.181"]
    assert mine == [(1, 70)], "DHCP 集區的使用率要算進手動定義的"
