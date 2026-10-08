"""get_ip_history（IP 鑑識）：證據要齊、不可越權。

對抗式重點：
- **受限帳號查未登錄 IP 不可以撈到 ARP／MAC** —— ARP 是全域資料，若不經
  「看得到這個 IP」的門檻，查歷史就成了繞過 RBAC 讀 MAC 對應的側門。
- 換過 MAC 的 IP 要能從時間軸看出來（鑑識的核心問題就是「這個 IP 換過人嗎」）。
- 無效輸入直接拒絕，days 夾在合理範圍。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.mcp.tools import IPAMToolError, get_ip_history
from app.models.address import IPAddress
from app.models.librenms import ARPEntry
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.user import User


async def _mk_user(db_session, *, admin: bool) -> User:
    u = User(username=f"u-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:6]}@x",
             password_hash="x", is_admin=admin, is_active=True)
    db_session.add(u)
    await db_session.flush()
    return u


async def _mk_ip(db_session, ip: str):
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip=ip, state="used", hostname="host-a")
    db_session.add(ipa)
    await db_session.flush()
    return ipa


@pytest.mark.anyio
async def test_rejects_invalid_ip(db_session) -> None:
    admin = await _mk_user(db_session, admin=True)
    with pytest.raises(IPAMToolError):
        await get_ip_history(db_session, user=admin, ip="not-an-ip")


@pytest.mark.anyio
async def test_mac_change_is_visible_in_the_timeline(db_session) -> None:
    """同一個 IP 出現過兩個 MAC → 兩筆 arp 事件都要在，換機器／偽冒才查得出來。"""
    admin = await _mk_user(db_session, admin=True)
    await _mk_ip(db_session, "198.51.100.7")
    now = datetime.now(UTC)
    for mac in ("00:00:5e:00:53:01", "00:00:5e:00:53:02"):
        db_session.add(ARPEntry(ip="198.51.100.7", mac=mac, last_seen_at=now))
    await db_session.flush()

    r = await get_ip_history(db_session, user=admin, ip="198.51.100.7")
    macs = {e.get("mac") for e in r["events"] if e["kind"] == "arp"}
    assert macs == {"00:00:5e:00:53:01", "00:00:5e:00:53:02"}
    assert r["registered"] is True and r["current"]["hostname"] == "host-a"


@pytest.mark.anyio
async def test_limited_user_cannot_harvest_arp_via_unregistered_ip(db_session) -> None:
    """受限帳號（有部分可見範圍）查一個它看不到的 IP → 不可以拿到 ARP/MAC。

    ARP 是全域資料；沒有這道門，查歷史就是繞過 RBAC 讀 MAC 對應的側門。
    """
    from app.models.permission import Permission

    limited = await _mk_user(db_session, admin=False)
    # 給他另一個無關子網路的讀取權 → visible_ids 回「限定集合」而非全部
    other = await _mk_ip(db_session, "198.51.100.99")
    db_session.add(Permission(object_type="subnet", object_id=other.subnet_id,
                              principal_type="user", principal_id=limited.id,
                              level="read"))
    # 目標 IP：只有 ARP 證據、未登錄（或登錄在他看不到的子網路）
    db_session.add(ARPEntry(ip="203.0.113.50", mac="00:00:5e:00:53:aa",
                            last_seen_at=datetime.now(UTC)))
    await db_session.flush()

    r = await get_ip_history(db_session, user=limited, ip="203.0.113.50")
    assert all(e["kind"] != "arp" for e in r["events"]), \
        "受限帳號透過未登錄 IP 撈到了 ARP —— RBAC 側門"
    assert r["registered"] is False


@pytest.mark.anyio
async def test_days_is_clamped(db_session) -> None:
    admin = await _mk_user(db_session, admin=True)
    r = await get_ip_history(db_session, user=admin, ip="198.51.100.1", days=99999)
    assert r["days"] == 365
