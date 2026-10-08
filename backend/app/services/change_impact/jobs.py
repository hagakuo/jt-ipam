"""分析作業：建立、領取、心跳、取消、逾時、回收（規格 §8.4）。

專案沒有工作佇列（M0 §5）：作業以 `spawn_task` 在 uvicorn worker 裡跑（作業頁看得到），
正式狀態以 impact_runs 為準：
- 領取：UPDATE … WHERE job_status='queued' RETURNING，只有一個 worker 拿得到
- 心跳：每個階段更新 heartbeat_at；超過 60 秒沒心跳就回收（attempt < 3 重新排隊，否則 failed: worker_lost）
- 取消：每個階段之間檢查 cancel_requested_at；被取消或失敗的中間產物不會留下
- 同時上限：同一個單位同時最多 N 個進行中的分析（建立時以 advisory lock 計數）
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_impact import JOB_ACTIVE, ChangePlan, ChangePlanRevision, ImpactRun
from app.services.change_impact.config import get_config
from app.services.change_impact.model import ENGINE_VERSION, RULES_VERSION
from app.services.change_impact.scenario import ScenarioError

logger = logging.getLogger(__name__)

HEARTBEAT_STALE = timedelta(seconds=60)
MAX_ATTEMPTS = 3
# 測試設成 False：建立 run 的請求直接跑完分析再回應（背景作業在測試裡會跟清表打架）
SPAWN_IN_BACKGROUND = True


class Cancelled(Exception):
    pass


class JobError(ScenarioError):
    pass


async def create_run(session: AsyncSession, *, plan: ChangePlan, user: Any, idempotency_key: str | None,
                     request_hash: str | None) -> tuple[ImpactRun, bool]:
    """回 (run, 是否新建)。同一個冪等鍵＋同樣的內容回原本那個；內容不同回 409。"""
    cfg = await get_config(session)
    if idempotency_key:
        old = (await session.execute(select(ImpactRun).where(
            ImpactRun.requested_by == user.id, ImpactRun.idempotency_key == idempotency_key))).scalars().first()
        if old is not None:
            if old.request_hash != request_hash:
                raise JobError("impact_idempotency_conflict", "Idempotency-Key reused with a different request",
                               status=409)
            return old, False
    # 同一個單位同時進行中的分析有上限；鎖住計數，兩個請求同時進來也不會超過
    lock_key = f"impact:{plan.customer_id or 'none'}"
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": lock_key})
    active = (await session.execute(
        select(func.count()).select_from(ImpactRun).join(ChangePlan, ChangePlan.id == ImpactRun.plan_id)
        .where(ImpactRun.job_status.in_(JOB_ACTIVE),
               ChangePlan.customer_id.is_(None) if plan.customer_id is None
               else ChangePlan.customer_id == plan.customer_id))).scalar() or 0
    limit = int(cfg["limits"]["per_customer_active_runs"])
    if active >= limit:
        raise JobError("impact_concurrency_limit", "Too many analyses running for this unit", status=409,
                       limit=limit)
    run = ImpactRun(plan_id=plan.id, plan_revision=plan.revision, job_status="queued", requested_by=user.id,
                    idempotency_key=idempotency_key, request_hash=request_hash, engine_version=ENGINE_VERSION,
                    rules_version=RULES_VERSION)
    session.add(run)
    await session.flush()
    plan.latest_run_id = run.id
    return run, True


async def launch(run_id: uuid.UUID, *, label: str, actor_user_id: uuid.UUID | None, plan_id: uuid.UUID) -> None:
    """建立 run 的交易 commit 之後呼叫：背景開始分析（或測試時直接跑完）。"""
    if not SPAWN_IN_BACKGROUND:
        await execute_run(run_id)
        return
    from app.core.db import SessionLocal
    from app.services.background_tasks import spawn_task

    async def runner(_s: AsyncSession, _task: Any) -> dict[str, Any]:
        return await execute_run(run_id)

    async with SessionLocal() as s:
        task = await spawn_task(session=s, kind="impact.run", target_type="change_plan", target_id=plan_id,
                                target_label=label[:120], actor_user_id=actor_user_id, trigger="manual",
                                runner=runner)
        await s.execute(update(ImpactRun).where(ImpactRun.id == run_id).values(background_task_id=task.id))
        await s.commit()


async def _claim(run_id: uuid.UUID) -> bool:
    from app.core.db import SessionLocal
    async with SessionLocal() as s:
        row = (await s.execute(
            update(ImpactRun).where(ImpactRun.id == run_id, ImpactRun.job_status == "queued")
            .values(job_status="snapshotting", stage="snapshotting", attempt=ImpactRun.attempt + 1,
                    heartbeat_at=func.now(), started_at=func.coalesce(ImpactRun.started_at, func.now()))
            .returning(ImpactRun.id))).first()
        await s.commit()
        return row is not None


async def _beat(run_id: uuid.UUID, stage: str, job_status: str | None = None) -> None:
    """心跳＋取消檢查。用自己的連線寫，分析那條交易還沒 commit 也看得到進度。"""
    from app.core.db import SessionLocal
    async with SessionLocal() as s:
        values: dict[str, Any] = {"heartbeat_at": func.now(), "stage": stage}
        if job_status:
            values["job_status"] = job_status
        await s.execute(update(ImpactRun).where(ImpactRun.id == run_id).values(**values))
        cancel = (await s.execute(select(ImpactRun.cancel_requested_at).where(ImpactRun.id == run_id))).scalar()
        await s.commit()
    if cancel is not None:
        raise Cancelled()


async def _finish(run_id: uuid.UUID, **values: Any) -> None:
    from app.core.db import SessionLocal
    async with SessionLocal() as s:
        await s.execute(update(ImpactRun).where(ImpactRun.id == run_id)
                        .values(completed_at=func.now(), heartbeat_at=func.now(), **values))
        await s.commit()


async def execute_run(run_id: uuid.UUID) -> dict[str, Any]:
    """跑一個 run（已經被別的 worker 領走就什麼都不做）。永遠不 raise：結果寫進 run。"""
    from app.core.db import SessionLocal
    from app.models.user import User
    from app.services.change_impact.engine import analyze, persist
    from app.services.change_impact.plans import after_run_completed

    if not await _claim(run_id):
        return {"skipped": "not_queued"}
    try:
        async with SessionLocal() as s:
            # 快照：整段分析在同一個 REPEATABLE READ 交易裡讀，來源之間看到的是同一個時間點。
            # 要在這個交易的第一個查詢之前設定才有效
            await s.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            run = await s.get(ImpactRun, run_id)
            assert run is not None
            plan = await s.get(ChangePlan, run.plan_id)
            rev = (await s.execute(select(ChangePlanRevision).where(
                ChangePlanRevision.plan_id == run.plan_id,
                ChangePlanRevision.revision == run.plan_revision))).scalars().first()
            user = await s.get(User, run.requested_by) if run.requested_by else None
            if plan is None or rev is None or user is None or not user.is_active:
                await _finish(run_id, job_status="failed", error_code="impact_permission_scope_changed",
                              stage="failed")
                return {"status": "failed"}
            cfg = await get_config(s)
            payload = rev.payload
            await _beat(run_id, "extracting", "extracting")

            async def checkpoint(stage: str) -> None:
                await _beat(run_id, stage)

            res = await asyncio.wait_for(
                analyze(s, user=user, scenario_type=payload["scenario_type"], target_type=payload["target_type"],
                        target_id=uuid.UUID(payload["target_id"]), parameters=payload.get("parameters") or {},
                        cfg=cfg, checkpoint=checkpoint),
                timeout=float(cfg["limits"]["analysis_seconds"]))
            await s.rollback()        # 結束唯讀快照交易；結果用新的交易寫
        await _beat(run_id, "persisting", "analyzing")
        async with SessionLocal() as s:
            await _beat(run_id, "persisting", "persisting")
            counts = await persist(s, run_id, res)
            valid = int(cfg.get("run_valid_hours", 24))
            final = "partial" if res.completeness == "partial" else "completed"
            await s.execute(update(ImpactRun).where(ImpactRun.id == run_id).values(
                job_status=final, stage=final, decision_status=res.decision, completeness=res.completeness,
                scope_manifest=res.manifest, source_watermarks=res.watermarks, snapshot_hash=res.snapshot_hash,
                scenario_hash=res.scenario_hash, visible_scope_hash=res.scope_hash, counts=counts,
                truncated=bool(res.truncated), truncation=res.truncated, completed_at=func.now(),
                heartbeat_at=func.now(), expires_at=datetime.now(UTC) + timedelta(hours=valid)))
            # 正式環境 autoflush 關閉：先送出發現，模板待辦才查得到
            await s.flush()
            await after_run_completed(s, run_id)
            await s.commit()
        return {"status": final, **counts}
    except Cancelled:
        await _cleanup(run_id)
        await _finish(run_id, job_status="cancelled", stage="cancelled")
        return {"status": "cancelled"}
    except TimeoutError:
        await _cleanup(run_id)
        await _finish(run_id, job_status="failed", stage="failed", error_code="impact_analysis_timeout")
        return {"status": "failed", "error": "timeout"}
    except ScenarioError as exc:
        await _cleanup(run_id)
        code = "impact_permission_scope_changed" if exc.status in (403, 404) else exc.code
        await _finish(run_id, job_status="failed", stage="failed", error_code=code[:64])
        return {"status": "failed", "error": code}
    except Exception as exc:
        logger.exception("impact run %s failed", run_id)
        await _cleanup(run_id)
        await _finish(run_id, job_status="failed", stage="failed", error_code=f"impact_internal:{type(exc).__name__}"[:64])
        return {"status": "failed", "error": type(exc).__name__}


async def _cleanup(run_id: uuid.UUID) -> None:
    """失敗或取消的中間產物不可以被當成正式結果（規格 §8.4）。"""
    from sqlalchemy import delete

    from app.core.db import SessionLocal
    from app.models.change_impact import ImpactEvidence, ImpactFinding, ImpactGap, ImpactRelation
    async with SessionLocal() as s:
        for model in (ImpactFinding, ImpactEvidence, ImpactGap, ImpactRelation):
            await s.execute(delete(model).where(model.run_id == run_id))
        await s.commit()


async def request_cancel(session: AsyncSession, run: ImpactRun) -> bool:
    """冪等：已經結束的回 False；排隊中的直接標取消；執行中的標記，由下一個檢查點停下來。"""
    if run.job_status not in JOB_ACTIVE:
        return False
    now = datetime.now(UTC)
    if run.job_status == "queued":
        res = await session.execute(update(ImpactRun).where(ImpactRun.id == run.id, ImpactRun.job_status == "queued")
                                    .values(job_status="cancelled", stage="cancelled", cancel_requested_at=now,
                                            completed_at=now).returning(ImpactRun.id))
        if res.first() is not None:
            return True
    await session.execute(update(ImpactRun).where(ImpactRun.id == run.id).values(cancel_requested_at=now))
    return True


async def reclaim_stale(session: AsyncSession, *, now: datetime | None = None) -> list[uuid.UUID]:
    """回收沒有心跳的 run（worker 重啟、程序被殺）。回傳需要重新啟動的 run id（呼叫端 commit 後 launch）。"""
    now = now or datetime.now(UTC)
    cutoff = now - HEARTBEAT_STALE
    stuck = (await session.execute(select(ImpactRun).where(
        ImpactRun.job_status.in_([s for s in JOB_ACTIVE if s != "queued"]),  # bounded: fixed set of four job states
        (ImpactRun.heartbeat_at.is_(None)) | (ImpactRun.heartbeat_at < cutoff)))).scalars().all()
    relaunch: list[uuid.UUID] = []
    for r in stuck:
        if r.attempt < MAX_ATTEMPTS and r.cancel_requested_at is None:
            res = await session.execute(update(ImpactRun).where(
                ImpactRun.id == r.id, ImpactRun.job_status == r.job_status, ImpactRun.heartbeat_at == r.heartbeat_at)
                .values(job_status="queued", stage="queued").returning(ImpactRun.id))
            if res.first() is not None:
                relaunch.append(r.id)
        else:
            await session.execute(update(ImpactRun).where(ImpactRun.id == r.id).values(
                job_status="cancelled" if r.cancel_requested_at else "failed", stage="failed",
                error_code=None if r.cancel_requested_at else "impact_worker_lost", completed_at=now))
    # 排隊太久沒人領（建立後 worker 就掛了）
    old_queued = (await session.execute(select(ImpactRun.id).where(
        ImpactRun.job_status == "queued", ImpactRun.created_at < now - timedelta(minutes=2)))).scalars().all()
    relaunch.extend(i for i in old_queued if i not in relaunch)
    return relaunch


async def reclaim_and_relaunch() -> int:
    """啟動時與每輪 jt-ipam-sync 呼叫。"""
    from app.core.db import SessionLocal
    async with SessionLocal() as s:
        ids = await reclaim_stale(s)
        rows = []
        for i in ids:
            run = await s.get(ImpactRun, i)
            plan = await s.get(ChangePlan, run.plan_id) if run else None
            if run and plan:
                rows.append((i, plan.title, run.requested_by, plan.id))
        await s.commit()
    for i, title, actor, pid in rows:
        try:
            await launch(i, label=title, actor_user_id=actor, plan_id=pid)
        except Exception:
            logger.exception("relaunch impact run %s failed", i)
    return len(rows)
