"""非管理員帳號的可見範圍在超大規模下（2026-09-30 大量資料測試）。

`visible_ids()` 把「這個帳號看得到的物件」展開成 id 集合，清單端點再用 `.in_(集合)` 過濾。
管理員不經過這條路，所以之前的全面掃描（用管理員）完全沒測到：一個被授權整個單位的部門帳號，
看得到的裝置超過 32767 台（或 IP 超過 32767 個）時，每個參數都是一個 IN 項目 → 超過 asyncpg 的
參數上限 → 500。實測 2 萬台裝置時裝置清單要 1.2 秒（管理員 0.2 秒）。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.address import IPAddress
from app.models.customer import Customer
from app.models.device import Device
from app.models.location import Location, Rack
from app.models.permission import Permission
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.user import User
from app.services import permission as perm

PADDING = 40_000


@pytest.fixture
async def dept(db_session, monkeypatch):
    """被授權一個區段、一個地點、一個客戶的部門帳號；可見範圍另外灌 4 萬個（不存在的）id。"""
    from app.core.security import hash_password
    from app.services.auth import issue_access_token

    cust = Customer(name=f"c-{uuid.uuid4().hex[:6]}")
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    loc = Location(name=f"l-{uuid.uuid4().hex[:6]}")
    db_session.add_all([cust, sec, loc])
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    rack = Rack(name="r1", location_id=loc.id)
    db_session.add_all([sn, rack])
    await db_session.flush()
    db_session.add_all([IPAddress(subnet_id=sn.id, ip="198.51.100.9", hostname="vis-host"),
                        Device(name="vis-dev", location_id=loc.id, rack_id=rack.id)])
    u = User(username=f"d-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local",
             display_name="D", password_hash=hash_password("TestPassword2026!"),
             auth_provider="local", is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.flush()
    for otype, oid in (("section", sec.id), ("location", loc.id), ("customer", cust.id)):
        db_session.add(Permission(object_type=otype, object_id=oid, principal_type="user",
                                  principal_id=u.id, level="read"))
    await db_session.commit()

    orig = perm._resolve_visible

    async def padded(session, object_type, granted):
        real = await orig(session, object_type, granted)
        return real | {uuid.uuid4() for _ in range(PADDING)}
    monkeypatch.setattr(perm, "_resolve_visible", padded)
    return {"Authorization": f"Bearer {issue_access_token(u)}"}


@pytest.mark.parametrize(("path", "expect"), [
    ("/api/v1/sections", "s-"),
    ("/api/v1/subnets", "198.51.100.0"),
    ("/api/v1/addresses", "198.51.100.9"),
    ("/api/v1/devices", "vis-dev"),
    ("/api/v1/locations", "l-"),
    ("/api/v1/racks", "r1"),
    ("/api/v1/customers", "c-"),
    ("/api/v1/ip-changes", None),
    ("/api/v1/dashboard/overview", None),
    ("/api/v1/addresses/ssh/targets", None),
    ("/api/v1/addresses/connections/targets", None),
    ("/api/v1/search?q=vis", None),
])
async def test_list_endpoints_with_more_visible_ids_than_the_parameter_limit(client, dept, path, expect) -> None:
    r = await client.get(path, headers=dept)
    assert r.status_code == 200, f"{path}: {r.status_code} {r.text[:300]}"
    if expect:
        assert expect in r.text, f"{path} 沒有回傳看得到的那一筆"


async def test_ai_tools_with_more_visible_ids_than_the_parameter_limit(db_session, dept) -> None:
    """AI 對話的工具走同一套可見範圍（mcp/tools.py）：每個不需要參數的唯讀工具都跑一次。"""
    from app.core.ui_error import UiError
    from app.mcp.tools import TOOLS, IPAMToolError
    from sqlalchemy import select

    user = (await db_session.execute(select(User).where(User.username.like("d-%")))).scalars().first()
    mutating = {"update_ip", "create_subnet", "create_device", "approve_ip_request",
                "reject_ip_request", "allocate_ip"}
    ran = []
    for name, spec in TOOLS.items():
        if name in mutating or (spec.get("parameters") or {}).get("required"):
            continue
        try:
            await TOOLS[name]["fn"](db_session, user=user)
        except (IPAMToolError, UiError):
            pass                                 # 工具自己回的錯誤（缺參數、找不到）不是這裡要抓的
        except Exception as exc:  # noqa: BLE001
            await db_session.rollback()
            raise AssertionError(f"{name}: {type(exc).__name__}: {str(exc)[:200]}") from exc
        ran.append(name)
    assert len(ran) > 30
