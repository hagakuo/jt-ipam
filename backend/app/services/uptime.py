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

    # 每個 IP 各自跑一條時間線，最後再逐日合併
    per_ip_days: list[dict[date, dict[str, bool]]] = []
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

        flags: dict[date, dict[str, bool]] = {}
        cur = state
        for i in range(days):
            d = start_day + timedelta(days=i)
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
        if any_down:
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
        "has_source": bool(rows),
    }
