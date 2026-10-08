"""IP 生命週期：釋放與冷卻期。

## 為什麼要有冷卻期

一個 IP 被釋放的當下，外面還有一堆東西指著它 —— DNS 記錄與各級快取、防火牆規則、
ACL、憑證 SAN、監控設定、寫死在腳本裡的位址。這些不會跟著一起消失。

馬上把它配給別台機器，症狀會是最難查的那一種：新機器收到不屬於它的流量、或被舊規則
擋掉，而 IPAM 上看起來一切正常。實機上剛好有現成例子 —— DNS 上有個名字
到今天仍指著一個早就換手的位址。

所以預設釋放後 30 天內不重新配發。**這是預設，不是強制**：管理員可以提前解除，
但要留下誰、何時、為什麼（審計）。

## 為什麼紀錄不放在 ip_addresses

因為實務上「釋放」最常見的做法就是把那筆 IP 刪掉。紀錄放在原表會跟著消失，
冷卻期就形同虛設 —— 這種「看起來有做、其實沒生效」的設計比沒有更糟。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.ip_cooldown import IPCooldown
from app.models.system_setting import SystemSetting

COOLDOWN_KEY = "ip_cooldown"
DEFAULT_DAYS = 30


async def get_cooldown_days(session: AsyncSession) -> int:
    """冷卻天數；0＝停用。"""
    row = await session.get(SystemSetting, COOLDOWN_KEY)
    val = row.value if row and isinstance(row.value, dict) else {}
    try:
        days = int(val.get("days", DEFAULT_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_DAYS
    return max(0, min(3650, days))


async def set_cooldown_days(
    session: AsyncSession, *, days: int, updated_by_user_id: uuid.UUID | None = None,
) -> int:
    from sqlalchemy.orm.attributes import flag_modified

    clean = max(0, min(3650, int(days)))
    row = await session.get(SystemSetting, COOLDOWN_KEY)
    if row is None:
        row = SystemSetting(key=COOLDOWN_KEY, value={}, updated_by=updated_by_user_id)
        session.add(row)
    row.value = {"days": clean}
    row.updated_by = updated_by_user_id
    flag_modified(row, "value")
    return clean


def _ip_text(value: Any) -> str:
    """asyncpg 把 INET 回成物件，不是字串 —— 比對前一律轉字串並去掉首碼長度。"""
    return str(value).split("/", 1)[0]


async def start_cooldown(
    session: AsyncSession, *, ip: IPAddress, actor_user_id: uuid.UUID | None = None,
    reason: str | None = None,
) -> IPCooldown | None:
    """把這個 IP 送進冷卻期。天數設為 0（停用）時回 None，不留紀錄。

    同一個 (subnet, ip) 已在冷卻中 → 延長並更新身分資訊，而不是新增一筆
    （唯一鍵擋著，重複釋放不該炸掉呼叫端）。
    """
    days = await get_cooldown_days(session)
    if days <= 0:
        return None
    now = datetime.now(UTC)
    text_ip = _ip_text(ip.ip)
    existing = (await session.execute(
        select(IPCooldown).where(
            IPCooldown.subnet_id == ip.subnet_id,
            IPCooldown.ip == text_ip,
        ).limit(1)
    )).scalars().first()
    row = existing or IPCooldown(subnet_id=ip.subnet_id, ip=text_ip)
    row.released_at = now
    row.until = now + timedelta(days=days)
    row.previous_hostname = ip.hostname
    row.previous_mac = str(ip.mac) if ip.mac else None
    row.reason = reason
    row.released_by = actor_user_id
    row.cleared_at = None
    row.cleared_by = None
    row.cleared_reason = None
    if existing is None:
        session.add(row)
    await session.flush()
    return row


async def active_cooldowns(
    session: AsyncSession, subnet_id: uuid.UUID,
) -> dict[str, IPCooldown]:
    """該子網路目前仍在冷卻中的位址：{ip 字串: 紀錄}。"""
    now = datetime.now(UTC)
    rows = (await session.execute(
        select(IPCooldown).where(
            IPCooldown.subnet_id == subnet_id,
            IPCooldown.cleared_at.is_(None),
            IPCooldown.until > now,
        )
    )).scalars().all()
    return {_ip_text(r.ip): r for r in rows}


async def cooldown_for(
    session: AsyncSession, *, subnet_id: uuid.UUID, ip: str,
) -> IPCooldown | None:
    """這個位址現在是否在冷卻中；不是則回 None。"""
    now = datetime.now(UTC)
    return (await session.execute(
        select(IPCooldown).where(
            IPCooldown.subnet_id == subnet_id,
            IPCooldown.ip == _ip_text(ip),
            IPCooldown.cleared_at.is_(None),
            IPCooldown.until > now,
        ).limit(1)
    )).scalars().first()


async def clear_cooldown(
    session: AsyncSession, *, subnet_id: uuid.UUID, ip: str,
    actor_user_id: uuid.UUID | None = None, reason: str | None = None,
) -> IPCooldown | None:
    """管理員提前解除。**不刪紀錄** —— 留下誰、何時、為什麼，事後查得到。"""
    row = await cooldown_for(session, subnet_id=subnet_id, ip=ip)
    if row is None:
        return None
    row.cleared_at = datetime.now(UTC)
    row.cleared_by = actor_user_id
    row.cleared_reason = reason
    await session.flush()
    return row


async def purge_expired(session: AsyncSession, *, keep_days: int = 90) -> int:
    """清掉早就過期的冷卻紀錄（只增不刪的話會無限累積）。

    刻意在到期後多留一段時間：冷卻期剛過的那幾天，正是有人會問
    「這個位址上一手是誰」的時候。
    """
    from sqlalchemy import delete

    cutoff = datetime.now(UTC) - timedelta(days=max(0, keep_days))
    result = await session.execute(
        delete(IPCooldown).where(IPCooldown.until < cutoff)
    )
    return int(result.rowcount or 0)
