"""保存期限（規格 §7.3）：結束或封存的計畫保留 180 天、失敗的分析 30 天（可在設定調整）。

清除整份計畫時，證據、發現、待辦、覆核、AI 產出跟著刪；稽核記錄只留「清除了哪一份」，
不保留假裝還能查驗的引用。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_impact import ChangePlan, ImpactRun
from app.services.change_impact.config import get_config


async def purge(session: AsyncSession, *, now: datetime | None = None) -> dict[str, int]:
    """呼叫端 commit。"""
    from app.core.audit import append_audit
    now = now or datetime.now(UTC)
    cfg = await get_config(session)
    plan_cut = now - timedelta(days=int(cfg["retention_days"]))
    fail_cut = now - timedelta(days=int(cfg["failed_retention_days"]))
    old = (await session.execute(select(ChangePlan.id, ChangePlan.title).where(
        ChangePlan.updated_at < plan_cut,
        or_(ChangePlan.archived_at.is_not(None), ChangePlan.lifecycle.in_(("closed", "cancelled")))))).all()
    for pid, title in old:
        await append_audit(session, actor_user_id=None, actor_ip=None, actor_user_agent="retention",
                           object_type="change_plan", object_id=str(pid), action="change_plan_purge",
                           diff={"title": title, "reason": "retention"}, request_id=None)
    if old:
        await session.execute(delete(ChangePlan).where(ChangePlan.id.in_([p for p, _ in old])))  # bounded: expired plans
    runs = await session.execute(delete(ImpactRun).where(
        ImpactRun.job_status.in_(("failed", "cancelled")), ImpactRun.created_at < fail_cut))
    return {"plans": len(old), "failed_runs": runs.rowcount or 0}
