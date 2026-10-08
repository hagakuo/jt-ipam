"""IP 釋放後的冷卻期。

守的是一件很具體的事：**釋放掉的位址不可以馬上被重新配發**。外面還有 DNS 快取、
防火牆規則、ACL、憑證 SAN 指著它，立刻配給別台機器會造成最難查的那種故障
（新機器收到不屬於它的流量，而 IPAM 上看起來一切正常）。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.address import IPAddress
from app.models.ip_cooldown import IPCooldown
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import ip_lifecycle
from app.services.subnet import find_free_addresses


async def _subnet(session, cidr: str = "198.51.100.0/29") -> Subnet:
    sec = Section(name=f"cd-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr)
    session.add(sub)
    await session.flush()
    return sub


async def _ip(session, sub: Subnet, addr: str, hostname: str = "old-host") -> IPAddress:
    ipa = IPAddress(subnet_id=sub.id, ip=addr, hostname=hostname, state="active")
    session.add(ipa)
    await session.flush()
    return ipa


@pytest.mark.anyio
async def test_released_address_is_not_offered_again(db_session) -> None:
    """核心保證：剛釋放的位址不會出現在「可用位址」裡。"""
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.1")
    await ip_lifecycle.start_cooldown(db_session, ip=ipa, reason="test")
    await db_session.delete(ipa)
    await db_session.flush()

    free = await find_free_addresses(db_session, sub, count=6)
    assert "198.51.100.1" not in free, "剛釋放的位址又被配出去了"
    assert "198.51.100.2" in free


@pytest.mark.anyio
async def test_cooldown_record_survives_deleting_the_ip(db_session) -> None:
    """紀錄必須撐過刪除 —— 實務上「釋放」就是把那筆 IP 刪掉。"""
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.2", hostname="app01")
    await ip_lifecycle.start_cooldown(db_session, ip=ipa, reason="deleted")
    await db_session.delete(ipa)
    await db_session.flush()

    row = await ip_lifecycle.cooldown_for(db_session, subnet_id=sub.id, ip="198.51.100.2")
    assert row is not None
    # 冷卻期間有人問「這位址剛剛是誰」，要答得出來
    assert row.previous_hostname == "app01"


@pytest.mark.anyio
async def test_expired_cooldown_releases_the_address(db_session) -> None:
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.3")
    row = await ip_lifecycle.start_cooldown(db_session, ip=ipa)
    assert row is not None
    row.until = datetime.now(UTC) - timedelta(seconds=1)     # 已過期
    await db_session.delete(ipa)
    await db_session.flush()

    assert await ip_lifecycle.cooldown_for(
        db_session, subnet_id=sub.id, ip="198.51.100.3") is None
    assert "198.51.100.3" in await find_free_addresses(db_session, sub, count=6)


@pytest.mark.anyio
async def test_clearing_keeps_the_record_for_audit(db_session) -> None:
    """提前解除是管理員的權利，但不可以無痕 —— 誰、何時、為什麼都要留著。"""
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.4")
    await ip_lifecycle.start_cooldown(db_session, ip=ipa)
    await db_session.delete(ipa)
    await db_session.flush()

    cleared = await ip_lifecycle.clear_cooldown(
        db_session, subnet_id=sub.id, ip="198.51.100.4", reason="專案急用")
    assert cleared is not None
    assert cleared.cleared_at is not None
    assert cleared.cleared_reason == "專案急用"
    # 解除後可以配發，但紀錄還在
    assert "198.51.100.4" in await find_free_addresses(db_session, sub, count=6)
    rows = (await db_session.execute(
        select(IPCooldown).where(IPCooldown.subnet_id == sub.id))).scalars().all()
    assert len(rows) == 1


@pytest.mark.anyio
async def test_cooldown_can_be_disabled(db_session) -> None:
    """設成 0 天＝停用：不留紀錄，行為與從前一致。"""
    sub = await _subnet(db_session)
    await ip_lifecycle.set_cooldown_days(db_session, days=0)
    ipa = await _ip(db_session, sub, "198.51.100.5")
    assert await ip_lifecycle.start_cooldown(db_session, ip=ipa) is None
    await db_session.delete(ipa)
    await db_session.flush()
    assert "198.51.100.5" in await find_free_addresses(db_session, sub, count=6)


@pytest.mark.anyio
async def test_releasing_twice_extends_instead_of_exploding(db_session) -> None:
    """同一個位址重複釋放不該撞唯一鍵 —— 呼叫端不必先查有沒有。"""
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.6", hostname="first")
    await ip_lifecycle.start_cooldown(db_session, ip=ipa, reason="one")
    ipa.hostname = "second"
    row = await ip_lifecycle.start_cooldown(db_session, ip=ipa, reason="two")
    assert row is not None
    assert row.previous_hostname == "second"
    rows = (await db_session.execute(
        select(IPCooldown).where(IPCooldown.subnet_id == sub.id))).scalars().all()
    assert len(rows) == 1


@pytest.mark.anyio
async def test_purge_keeps_recently_expired(db_session) -> None:
    """剛過期那幾天正是有人會問「上一手是誰」的時候，不要馬上刪。"""
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.1")
    row = await ip_lifecycle.start_cooldown(db_session, ip=ipa)
    assert row is not None
    row.until = datetime.now(UTC) - timedelta(days=10)
    await db_session.flush()

    assert await ip_lifecycle.purge_expired(db_session, keep_days=90) == 0
    assert await ip_lifecycle.purge_expired(db_session, keep_days=5) == 1


# ─────────────── 批次刪除與單筆刪除同一套（2026-09-28 發現） ───────────────
# 批次刪除以前只寫稽核就刪：沒有進冷卻期、IP 異動記錄也沒有「已刪除」—— 同一件事兩條路徑
# 行為不同。實機：一筆 IP 被批次刪掉後，位址馬上就能配給別台，異動記錄裡也查不到刪除。

async def test_bulk_delete_starts_the_cooldown_and_logs_the_deletion(
        client, auth_headers, db_session) -> None:
    from app.models.ip_change_log import IPChangeLog
    sub = await _subnet(db_session)
    a = await _ip(db_session, sub, "198.51.100.2", hostname="host-a")
    b = await _ip(db_session, sub, "198.51.100.3", hostname="host-b")
    await db_session.commit()
    ids = [str(a.id), str(b.id)]
    sub_id = sub.id

    r = await client.post("/api/v1/addresses/bulk-delete", headers=auth_headers, json={"ids": ids})
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] == 2

    db_session.expire_all()
    cds = (await db_session.execute(select(IPCooldown).where(IPCooldown.subnet_id == sub_id))).scalars().all()
    assert sorted(str(c.ip).split("/")[0] for c in cds) == ["198.51.100.2", "198.51.100.3"]
    assert {c.previous_hostname for c in cds} == {"host-a", "host-b"}
    logs = (await db_session.execute(select(IPChangeLog).where(
        IPChangeLog.subnet_id == sub_id, IPChangeLog.event_type == "deleted"))).scalars().all()
    assert sorted(str(x.ip_text).split("/")[0] for x in logs) == ["198.51.100.2", "198.51.100.3"]


async def test_single_delete_still_does_the_same(client, auth_headers, db_session) -> None:
    from app.models.ip_change_log import IPChangeLog
    sub = await _subnet(db_session)
    a = await _ip(db_session, sub, "198.51.100.4", hostname="host-c")
    await db_session.commit()
    aid, sub_id = a.id, sub.id
    r = await client.delete(f"/api/v1/addresses/{aid}", headers=auth_headers)
    assert r.status_code == 204, r.text
    db_session.expire_all()
    assert (await db_session.execute(select(IPCooldown).where(IPCooldown.subnet_id == sub_id))).scalars().first()
    assert (await db_session.execute(select(IPChangeLog).where(
        IPChangeLog.subnet_id == sub_id, IPChangeLog.event_type == "deleted"))).scalars().first()
