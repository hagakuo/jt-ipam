"""掃描代理的負載：記錄每一輪、評估負載、太重時通知管理員並給出具體建議。

使用者要求（2026-09-28）：一台代理能扛多少子網路／位址要靠量測，不是猜；太長要通知，
而且通知要能直接照著做。

「太長」分兩種，因為後果不同：
- **上線偵測一輪超過週期**（ratio ≥ 0.9）→ 上線狀態會延遲、可能誤報失聯。要處理。
- **背景重量探測一直消化不完**（待辦連續幾輪沒有變少）→ OS／名稱資料變舊。可以慢慢處理。
另外，子網路比代理的單輪上限大（被截斷）也要講：後面的位址永遠不會被掃到。

**不自動搬子網路**：子網路要由同一個二層網段的代理掃才拿得到 ARP／MAC、NetBIOS。
系統不知道哪台代理跟哪個網段在同一層，自動搬移會讓資料默默變差，而且不會報錯。
所以這裡只產生建議，由管理員在負載面板上套用。
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_agent import ScanAgent
from app.models.scan_agent_cycle import ScanAgentCycle

BUSY_RATIO = 0.5
OVERLOAD_RATIO = 0.9
TARGET_RATIO = 0.7            # 建議搬走子網路時，要降到多少以下
SLOW_FACTOR = 3.0             # 每個位址的耗時比中位數慢幾倍算「特別慢」
SLOW_MIN_MS = 20.0            # 太快的就算差幾倍也不用講
LAG_CYCLES = 6                # 背景待辦連續幾輪沒有變少算消化不完
LAG_MIN_BACKLOG = 50
ALERT_THRESHOLD = 3           # 連續幾輪才通知
RETENTION = timedelta(days=7)
EVENT = "agent.overloaded"


def _per_host_ms(s: dict[str, Any]) -> float | None:
    hosts = int(s.get("hosts") or 0)
    if hosts <= 0:
        return None
    return float(s.get("duration_s") or 0) * 1000 / hosts


def evaluate(cycle: dict[str, Any] | None, history: list[dict[str, Any]] | None = None, *,
             online_minutes: int = 30) -> dict[str, Any]:
    """一輪的統計（＋最近幾輪）→ 負載評估與建議。建議用代碼＋參數，前端翻譯。

    `online_minutes` 是上線判定門檻：分段輪替的大子網路掃完一遍的時間超過它，主機會在
    兩次被掃到之間被判成離線。"""
    cycle = cycle or {}
    interval = max(int(cycle.get("interval_s") or 0), 1)
    duration = float(cycle.get("duration_s") or 0)
    ratio = round(duration / interval, 3)
    level = "overloaded" if ratio >= OVERLOAD_RATIO else "busy" if ratio >= BUSY_RATIO else "ok"
    subnets = [s for s in (cycle.get("subnets") or []) if isinstance(s, dict)]
    backlog = int(cycle.get("heavy_backlog") or 0)
    suggestions: list[dict[str, Any]] = []

    # 上線偵測跑不完：挑最慢的子網路搬走，直到剩下的降到 TARGET_RATIO 以下
    if level == "overloaded" and len(subnets) > 1:
        remaining = duration
        move: list[str] = []
        for s in sorted(subnets, key=lambda x: -float(x.get("duration_s") or 0)):
            if remaining / interval <= TARGET_RATIO:
                break
            move.append(str(s.get("cidr")))
            remaining -= float(s.get("duration_s") or 0)
        if move and len(move) < len(subnets):
            suggestions.append({"code": "move_subnets", "params": {
                "subnets": move, "target": int(TARGET_RATIO * 100)}})
    elif level == "overloaded":
        suggestions.append({"code": "raise_interval", "params": {
            "interval": interval, "suggested": int(duration / TARGET_RATIO) + 1}})

    # 某個子網路每個位址特別慢：多半是跨 WAN 或被防火牆擋（ping 等逾時）
    rates = [(s, _per_host_ms(s)) for s in subnets]
    known = [r for _, r in rates if r is not None]
    if len(known) >= 2:
        med = statistics.median(known)
        for s, r in rates:
            if r is not None and r >= SLOW_MIN_MS and med > 0 and r >= med * SLOW_FACTOR:
                suggestions.append({"code": "slow_subnet", "params": {
                    "cidr": str(s.get("cidr")), "per_host_ms": round(r, 1), "median_ms": round(med, 1)}})

    # 被截斷的子網路：後面的位址永遠不會被掃到
    truncated = [str(s.get("cidr")) for s in subnets if s.get("truncated")]
    for s in subnets:
        if s.get("truncated"):
            suggestions.append({"code": "split_large", "params": {
                "cidr": str(s.get("cidr")), "total": int(s.get("total_hosts") or 0),
                "scanned": int(s.get("hosts") or 0)}})

    # 分段輪替的大子網路（代理 1.11.0 起）：掃完一遍要幾分鐘？超過上線門檻就會在兩次掃描之間被判成離線
    coverage_gap: list[str] = []
    for s in subnets:
        rounds = int(s.get("rounds") or 1)
        if rounds > 1:
            minutes = round(rounds * interval / 60)
            suggestions.append({"code": "rotating_large", "params": {
                "cidr": str(s.get("cidr")), "total": int(s.get("total_hosts") or 0), "rounds": rounds,
                "minutes": minutes, "threshold": online_minutes}})
            if minutes > online_minutes:
                coverage_gap.append(str(s.get("cidr")))

    # 背景重量探測消化不完：待辦連續 LAG_CYCLES 輪都不少於 LAG_MIN_BACKLOG，而且沒有變少
    hist = [int(h.get("heavy_backlog") or 0) for h in (history or [])][-LAG_CYCLES:]
    lagging = (len(hist) >= LAG_CYCLES and min(hist) >= LAG_MIN_BACKLOG and hist[-1] >= hist[0])
    if lagging:
        suggestions.append({"code": "heavy_interval", "params": {"backlog": backlog}})

    return {
        "ratio": ratio, "level": level, "duration_s": duration, "interval_s": interval,
        "heavy_backlog": backlog, "heavy_lagging": lagging, "truncated": truncated,
        "coverage_gap": coverage_gap,
        "subnets": [{**s, "per_host_ms": round(r, 1) if r is not None else None} for s, r in rates],
        "suggestions": suggestions,
    }


def summary(agent: ScanAgent) -> dict[str, Any] | None:
    """清單用：只看最近一輪（不查歷史）。"""
    if not agent.last_cycle:
        return None
    ev = evaluate(agent.last_cycle)
    return {"ratio": ev["ratio"], "level": ev["level"], "duration_s": ev["duration_s"],
            "interval_s": ev["interval_s"], "heavy_backlog": ev["heavy_backlog"],
            "truncated": len(ev["truncated"]), "coverage_gap": len(ev["coverage_gap"]),
            "at": agent.last_cycle.get("at")}


async def recent(session: AsyncSession, agent_id: Any, limit: int = 300) -> list[ScanAgentCycle]:
    rows = (await session.execute(
        select(ScanAgentCycle).where(ScanAgentCycle.agent_id == agent_id)
        .order_by(ScanAgentCycle.at.desc()).limit(limit))).scalars().all()
    return list(reversed(rows))


async def record(session: AsyncSession, agent: ScanAgent, cycle: dict[str, Any], now: datetime) -> dict[str, Any]:
    """記下這一輪、清掉 7 天前的、評估負載，必要時通知管理員（開始與恢復各一次）。"""
    subnets = [s for s in (cycle.get("subnets") or []) if isinstance(s, dict)]
    session.add(ScanAgentCycle(
        agent_id=agent.id, at=now,
        duration_s=float(cycle.get("duration_s") or 0),
        interval_s=int(cycle.get("interval_s") or 0),
        heavy_backlog=int(cycle.get("heavy_backlog") or 0),
        hosts=sum(int(s.get("hosts") or 0) for s in subnets),
        alive=sum(int(s.get("alive") or 0) for s in subnets)))
    await session.execute(delete(ScanAgentCycle).where(
        ScanAgentCycle.agent_id == agent.id, ScanAgentCycle.at < now - RETENTION))
    await session.flush()

    hist = [{"heavy_backlog": r.heavy_backlog} for r in await recent(session, agent.id, LAG_CYCLES)]
    from app.services.system_config import get_liveness_config
    online = int((await get_liveness_config(session))["minutes"])
    ev = evaluate(cycle, hist, online_minutes=online)
    failing = (ev["level"] == "overloaded" or ev["heavy_lagging"] or bool(ev["truncated"])
               or bool(ev["coverage_gap"]))
    await _alert(session, agent, ev, failing)
    return ev


def _reasons(ev: dict[str, Any]) -> list[str]:
    out = []
    if ev["level"] == "overloaded":
        out.append("liveness")
    if ev["heavy_lagging"]:
        out.append("heavy")
    if ev["truncated"]:
        out.append("truncated")
    if ev["coverage_gap"]:
        out.append("coverage")
    return out


async def _alert(session: AsyncSession, agent: ScanAgent, ev: dict[str, Any], failing: bool) -> None:
    from app.services.state_alert import observe
    change = await observe(session, key=f"scan_load:{agent.id}", failing=failing, threshold=ALERT_THRESHOLD)
    if change is None:
        return
    from app.services.health_alert import _notify
    link = f"/scan-agents?load={agent.id}"
    pct = round(ev["ratio"] * 100)
    if change == "down":
        reasons = _reasons(ev)
        await _notify(
            session, event=EVENT, link=link,
            title=f"掃描代理負載過重：{agent.name}",
            body=(f"上線偵測一輪 {ev['duration_s']:.0f} 秒／週期 {ev['interval_s']} 秒（{pct}%），"
                  f"背景待辦 {ev['heavy_backlog']} 台。到掃描代理頁的負載面板看建議。"),
            title_key="notif.agent_overloaded", body_key="notif.agent_overloaded_body",
            params={"agent": agent.name, "pct": pct, "duration": int(ev["duration_s"]),
                    "interval": ev["interval_s"], "backlog": ev["heavy_backlog"],
                    "reasons": reasons})
    else:
        await _notify(
            session, event=EVENT, link=link, severity="info",
            title=f"掃描代理負載恢復正常：{agent.name}",
            body=f"上線偵測一輪 {ev['duration_s']:.0f} 秒／週期 {ev['interval_s']} 秒（{pct}%）。",
            title_key="notif.agent_overload_ok", body_key="notif.agent_overload_ok_body",
            params={"agent": agent.name, "pct": pct, "duration": int(ev["duration_s"]),
                    "interval": ev["interval_s"]})

