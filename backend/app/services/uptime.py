"""由 `effective_status` 的轉換記錄重建每日存活狀態（status page 式長條圖用）。

我們沒有逐時取樣，只有 `ip_change_log` 裡的**狀態轉換**。重建方式：某段期間的狀態
＝上一筆轉換的 `new_value`，一直持續到下一筆轉換；第一筆轉換之前＝未知。

三個不可妥協的規則（弄錯的話圖會說謊）：
1. **沒有資料的日子是 `unknown`，不是 `up`。** 沒有存活來源（掃描代理／LibreNMS）的
   IP 永遠不會產生轉換 → 整條灰。那是有意義的訊號（「這個 IP 沒在被監測」）。
2. **`uptime_pct` 的分母只算有資料的天數。** 只監測 3 天且全綠的 IP 應該是 100%，
   不是被 87 天灰稀釋後的數字，也不是把灰當中斷算出來的低分。
3. **判斷上線要用 `startswith("online")`** —— `effective_status` 是小寫且帶來源後綴
   （`online (scanner)` / `online (librenms)`）。拿固定字串比對正是 v0.4.196 修過的
   儀表板誤判（上線數從 153 被誤算成 63）。
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog


def status_is_up(value: str | None) -> bool | None:
    """`online*` → True、`offline*` → False、其餘（unknown / 空）→ None。"""
    if not value:
        return None
    v = value.strip().lower()
    if v.startswith("online"):
        return True
    if v.startswith("offline"):
        return False
    return None


async def uptime_for_ips(
    session: AsyncSession, ip_ids: list[uuid.UUID], *, days: int = 90,
) -> dict[str, Any]:
    """重建這些 IP 合起來的每日狀態。

    多個 IP（裝置有多個位址）時：**當天任一 IP 曾中斷就標中斷**。與單一 IP 的
    每日規則一致（一天內只要出現過 offline 就算中斷），且傾向浮現問題而非掩蓋。

    ⚠️ **「沒有轉換記錄」不等於「沒在監測」。** 一個從加入以來都沒斷過的 IP
    根本不會產生任何轉換 —— 只看 `ip_change_log` 會把它誤判成整條灰的「未監測」，
    但它其實一直是上線的。所以還要看 IP 目前的 `effective_status` 與 `last_seen_*`：
    有存活來源、且該段期間內沒有任何轉換 → 用目前狀態回填（沒斷過才會沒有轉換）。
    回填起點取 `max(視窗起點, IP 建立時間)`，加入 IPAM 之前仍然是未知。
    """
    today = datetime.now(UTC).date()
    start_day = today - timedelta(days=days - 1)
    start_dt = datetime.combine(start_day, datetime.min.time(), tzinfo=UTC)

    rows: list[tuple[uuid.UUID | None, datetime, str | None]] = []
    if ip_ids:
        rows = list((await session.execute(
            select(IPChangeLog.ip_id, IPChangeLog.created_at, IPChangeLog.new_value)
            .where(
                IPChangeLog.ip_id.in_(ip_ids),
                IPChangeLog.field == "effective_status",
            )
            .order_by(IPChangeLog.created_at)
        )).all())

    # 目前狀態 / 存活來源 / 建立時間 —— 用來處理「一直沒斷過所以沒有轉換」的 IP
    cur_rows: dict[uuid.UUID, tuple[str | None, bool, datetime]] = {}
    if ip_ids:
        for i, st, seen_s, seen_l, created in (await session.execute(
            select(
                IPAddress.id, IPAddress.effective_status,
                IPAddress.last_seen_scanner, IPAddress.last_seen_librenms,
                IPAddress.created_at,
            ).where(IPAddress.id.in_(ip_ids))
        )).all():
            cur_rows[i] = (st, bool(seen_s or seen_l), created)

    # 每個 IP 各自跑一條時間線，最後再逐日合併
    per_ip_days: list[dict[date, dict[str, bool]]] = []
    monitored = False
    for ip_id in ip_ids:
        evs = [(ts, nv) for (i, ts, nv) in rows if i == ip_id]
        state: bool | None = None
        for ts, nv in evs:
            if ts < start_dt:
                state = status_is_up(nv)
            else:
                break
        by_day: dict[date, list[str | None]] = {}
        for ts, nv in evs:
            if ts >= start_dt:
                by_day.setdefault(ts.date(), []).append(nv)

        cur_status, has_live_source, created_at = cur_rows.get(ip_id, (None, False, start_dt))
        if has_live_source:
            monitored = True
        # 整段視窗都沒有轉換、但確實有存活來源 → 用目前狀態回填。
        # 沒斷過才會沒有轉換，所以「現在是什麼狀態」就是這整段的狀態。
        backfill_from: date | None = None
        if not evs and has_live_source and status_is_up(cur_status) is not None:
            state = status_is_up(cur_status)
            backfill_from = max(start_day, created_at.date())

        flags: dict[date, dict[str, bool]] = {}
        cur = state
        for i in range(days):
            d = start_day + timedelta(days=i)
            # 回填情形下，加入 IPAM 之前仍然是未知
            if backfill_from is not None and d < backfill_from:
                flags[d] = {"up": False, "down": False}
                continue
            up = cur is True
            down = cur is False
            for nv in by_day.get(d, []):
                cur = status_is_up(nv)
                if cur is True:
                    up = True
                elif cur is False:
                    down = True
            flags[d] = {"up": up, "down": down}
        per_ip_days.append(flags)

    items: list[dict[str, str]] = []
    known = down_days = 0
    for i in range(days):
        d = start_day + timedelta(days=i)
        any_down = any(f[d]["down"] for f in per_ip_days)
        any_up = any(f[d]["up"] for f in per_ip_days)
        # 「整天全掛」與「當天有斷有通」要分開：連續一個月的離線若全部畫成
        # 「曾中斷」，看起來會像 30 次短暫中斷，而不是一次持續的離線。
        if any_down and any_up:
            st = "partial"
            known += 1
            down_days += 1
        elif any_down:
            st = "down"
            known += 1
            down_days += 1
        elif any_up:
            st = "up"
            known += 1
        else:
            st = "unknown"
        items.append({"date": d.isoformat(), "status": st})

    return {
        "days": days,
        "items": items,
        # 分母只算有資料的天數；完全沒資料回 None，前端顯示「尚無資料」而不是 0%／100%
        "uptime_pct": (round((known - down_days) / known * 100, 3) if known else None),
        "known_days": known,
        "down_days": down_days,
        # 有轉換記錄、或目前就有存活來源（掃描代理／LibreNMS），都算「有在監測」
        "has_source": bool(rows) or monitored,
    }


async def uptime_batch(
    session: AsyncSession, ip_ids: list[uuid.UUID], *, days: int = 90,
) -> list[dict[str, Any]]:
    """一次算多個 IP，**每個 IP 各一條**（儀表板區塊用）。

    與 `uptime_for_ips` 的差別：那支是把多個 IP 合併成一條（裝置的多個位址算同一台
    機器）；這支是每個 IP 獨立一條。

    刻意只打兩次 DB（轉換記錄一次、目前狀態一次）再在記憶體裡分組 —— 30 個 IP
    各自呼叫 `uptime_for_ips` 會變成 60 次查詢。
    """
    if not ip_ids:
        return []

    today = datetime.now(UTC).date()
    start_day = today - timedelta(days=days - 1)
    start_dt = datetime.combine(start_day, datetime.min.time(), tzinfo=UTC)

    ev_rows = list((await session.execute(
        select(IPChangeLog.ip_id, IPChangeLog.created_at, IPChangeLog.new_value)
        .where(IPChangeLog.ip_id.in_(ip_ids), IPChangeLog.field == "effective_status")
        .order_by(IPChangeLog.created_at)
    )).all())
    by_ip: dict[uuid.UUID, list[tuple[datetime, str | None]]] = {}
    for i, ts, nv in ev_rows:
        if i is not None:
            by_ip.setdefault(i, []).append((ts, nv))

    meta: dict[uuid.UUID, tuple[str, str | None, str | None, bool, datetime]] = {}
    for i, ipv, host, st, seen_s, seen_l, created in (await session.execute(
        select(
            IPAddress.id, IPAddress.ip, IPAddress.hostname, IPAddress.effective_status,
            IPAddress.last_seen_scanner, IPAddress.last_seen_librenms, IPAddress.created_at,
        ).where(IPAddress.id.in_(ip_ids))
    )).all():
        meta[i] = (str(ipv).split("/")[0], host, st, bool(seen_s or seen_l), created)

    out: list[dict[str, Any]] = []
    for ip_id in ip_ids:                      # 依使用者排的順序回，不用 DB 順序
        if ip_id not in meta:
            continue
        ip_text, hostname, cur_status, has_live_source, created_at = meta[ip_id]
        evs = by_ip.get(ip_id, [])

        state: bool | None = None
        for ts, nv in evs:
            if ts < start_dt:
                state = status_is_up(nv)
            else:
                break
        day_events: dict[date, list[str | None]] = {}
        for ts, nv in evs:
            if ts >= start_dt:
                day_events.setdefault(ts.date(), []).append(nv)

        # 與 uptime_for_ips 相同：沒有轉換不代表沒在監測（從沒斷過就不會有轉換）
        backfill_from: date | None = None
        if not evs and has_live_source and status_is_up(cur_status) is not None:
            state = status_is_up(cur_status)
            backfill_from = max(start_day, created_at.date())

        items: list[dict[str, str]] = []
        known = down_days = 0
        cur = state
        for n in range(days):
            d = start_day + timedelta(days=n)
            if backfill_from is not None and d < backfill_from:
                items.append({"date": d.isoformat(), "status": "unknown"})
                continue
            up = cur is True
            down = cur is False
            for nv in day_events.get(d, []):
                cur = status_is_up(nv)
                if cur is True:
                    up = True
                elif cur is False:
                    down = True
            if up and down:
                st2 = "partial"
                known += 1
                down_days += 1
            elif down:
                st2 = "down"
                known += 1
                down_days += 1
            elif up:
                st2 = "up"
                known += 1
            else:
                st2 = "unknown"
            items.append({"date": d.isoformat(), "status": st2})

        out.append({
            "ip_id": str(ip_id),
            "ip": ip_text,
            "hostname": hostname,
            "days": days,
            "items": items,
            "uptime_pct": (round((known - down_days) / known * 100, 3) if known else None),
            "known_days": known,
            "down_days": down_days,
            "has_source": bool(evs) or has_live_source,
        })
    return out
