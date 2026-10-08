"""IP 衝突偵測的依據：各來源「看到哪個 MAC 在用這個 IP」—— GitHub issue #41。

## 為什麼有這個檔案

IP 衝突偵測（anomaly.detect_ip_conflicts）只讀 `arp_entries`，而那張表原本**只有
LibreNMS 同步會寫**。掃描代理、防火牆 ARP 表看到的 IP／MAC 只拿去更新 IP 記錄上的 MAC
（依來源優先序）與異動記錄 —— 沒接 LibreNMS 的站台，偵測器永遠沒有資料。回報者的網路
兩台 VM 搶同一個固定 IP，異動記錄五天記了 205 次 MAC 來回切換，偵測卻一次都沒報。

## 三條規則

1. **不管來源優先序**：IP 記錄上顯示哪個 MAC 由優先序決定，但被擋下來的那個 MAC 正是衝突
   的另一方 —— 觀測一律留下來。
2. **只收「有機器在用」的證據**：掃描代理的鄰居表、防火牆 ARP 表的動態項目。DHCP 租約只是
   「曾經發給誰」、靜態 ARP 是設定值、VPN 是連線狀態，拿來判衝突會把換網卡、租約重發報成衝突。
3. **帶子網路**：重疊網段（兩個單位各有一個 10.9.0.5）不可以互相判成衝突。觀測掛在 IP 記錄
   所屬的子網路上；IPAM 裡沒有這筆 IP 就不收（那是「未授權 IP」偵測的事）。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.librenms import ARPEntry

#: 觀測保留多久。偵測只看最近 1 小時、MAC 頻繁更換看 7 天；多留一些給調查時對照。
KEEP_DAYS = 30
#: ARP 表的未完成項目（全 0）與廣播位址不是任何一台機器
_PLACEHOLDER = frozenset({"000000000000", "ffffffffffff"})
#: 部分唯一索引的條件（與 migration 0152、model 一致）
_OBSERVED = text("device_id IS NULL AND subnet_id IS NOT NULL")


def normalize(value: object) -> str | None:
    """MAC 正規化成 `aa:bb:cc:dd:ee:ff`；不是一個真的位址就回 None。"""
    hexs = "".join(c for c in str(value or "").lower() if c in "0123456789abcdef")
    if len(hexs) != 12 or hexs in _PLACEHOLDER:
        return None
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


async def record_arp_observation(
    session: AsyncSession, *, ip: Any, mac: object, source: str,
    seen_at: datetime | None = None,
) -> bool:
    """記下「`source` 在 `seen_at` 看到 `mac` 在用這個 IP」。回傳是否有記。

    `ip` 是 IPAddress（要它的位址與子網路）。同一組 IP／MAC／來源／子網路只一筆，
    再看到只把時間往後推（不會倒退 —— 防火牆給的觀測時間可能比上一輪的還舊）。
    """
    m = normalize(mac)
    subnet_id = getattr(ip, "subnet_id", None)
    if m is None or subnet_id is None or not source:
        return False
    when = (seen_at or datetime.now(UTC)).astimezone(UTC)
    stmt = insert(ARPEntry).values(
        ip=str(ip.ip).split("/")[0], mac=m, source=source[:16], subnet_id=subnet_id,
        first_seen_at=when, last_seen_at=when,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["ip", "mac", "source", "subnet_id"], index_where=_OBSERVED,
        set_={"last_seen_at": func.greatest(ARPEntry.last_seen_at, stmt.excluded.last_seen_at)},
    )
    await session.execute(stmt)
    return True


async def record_firewall_arp(
    session: AsyncSession, *, ip: Any, evidence: str, mac: object,
    seen_at: datetime | None = None, permanent: bool = False,
) -> bool:
    """防火牆整合共用：只有 ARP 表的動態項目算數（`arp:<廠牌>`，見檔頭規則 2）。"""
    if permanent or not evidence.startswith("arp:"):
        return False
    return await record_arp_observation(session, ip=ip, mac=mac, source=evidence,
                                        seen_at=seen_at)


async def prune(session: AsyncSession, *, keep_days: int = KEEP_DAYS) -> int:
    """刪掉太舊的觀測（只動掃描代理／防火牆的；LibreNMS 的由它自己的同步管）。"""
    cutoff = datetime.now(UTC) - timedelta(days=keep_days)
    res = await session.execute(
        delete(ARPEntry).where(_OBSERVED, ARPEntry.last_seen_at < cutoff))
    return int(res.rowcount or 0)


async def coverage(session: AsyncSession, *, window: timedelta) -> dict[str, Any]:
    """偵測窗內有多少筆觀測、各來自哪裡 —— 讓「沒有資料」與「看過了、沒有衝突」分得開。"""
    cutoff = datetime.now(UTC) - window
    rows = (await session.execute(
        select(ARPEntry.source, func.count())
        .where(ARPEntry.last_seen_at >= cutoff).group_by(ARPEntry.source)
    )).all()
    by_source = {str(src): int(n) for src, n in rows}
    return {
        "window_minutes": int(window.total_seconds() // 60),
        "observations": sum(by_source.values()),
        "by_source": by_source,
    }
