"""計畫：版本、狀態、覆核、待辦（規格 §9、§12）。

- 每次修改都產生新的版本（不可變）；修改會讓計畫回到草稿，舊的覆核失效
- 覆核綁定（版本, run, 快照雜湊）；阻擋項目不可核准；資料不完整只能「接受風險」且要理由
- 開始維護前重新分析一次比對快照：證據變了（例如核准後多了新引用）就要求重跑
- 待辦是人工操作的清單；按「完成」不會改任何來源設備
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_impact import (
    TASK_PHASE,
    ChangePlan,
    ChangePlanRevision,
    ChangeTask,
    ImpactFinding,
    ImpactReview,
    ImpactRun,
)
from app.services.change_impact.scenario import ScenarioError, build, require_target_access


class PlanError(ScenarioError):
    pass


_TERMINAL = frozenset({"closed", "cancelled"})
# 動作 → (允許的起點, 終點)
TRANSITIONS: dict[str, tuple[frozenset[str], str]] = {
    "submit": (frozenset({"draft"}), "in_review"),
    "start": (frozenset({"approved"}), "in_progress"),
    "verify": (frozenset({"in_progress"}), "verified"),
    "close": (frozenset({"verified"}), "closed"),
    "reopen": (frozenset({"in_review", "approved"}), "draft"),
    "cancel": (frozenset({"draft", "in_review", "approved", "in_progress", "verified"}), "cancelled"),
}


def _ensure_active(plan: ChangePlan) -> None:
    if plan.lifecycle in _TERMINAL or plan.archived_at is not None:
        raise PlanError("impact_plan_closed", "The plan is closed", status=409)


async def create_plan(session: AsyncSession, user: Any, *, title: str, scenario_type: str, target_type: str,
                      target_id: uuid.UUID, parameters: dict[str, Any] | None, planned_start: datetime | None,
                      planned_end: datetime | None, idempotency_key: str | None,
                      request_hash: str | None) -> tuple[ChangePlan, bool]:
    if idempotency_key:
        old = (await session.execute(select(ChangePlan).where(
            ChangePlan.created_by == user.id, ChangePlan.idempotency_key == idempotency_key))).scalars().first()
        if old is not None:
            if old.request_hash != request_hash:
                raise PlanError("impact_idempotency_conflict", "Idempotency-Key reused with a different request",
                                status=409)
            return old, False
    if planned_start and planned_end and planned_end < planned_start:
        raise PlanError("impact_invalid_window", "The maintenance window ends before it starts")
    sc = await build(session, user, scenario_type=scenario_type, target_type=target_type, target_id=target_id,
                     parameters=parameters, need="write")
    plan = ChangePlan(customer_id=sc.customer_id, title=(title or "").strip()[:200] or sc.target_label,
                      scenario_type=scenario_type, target_type=target_type, target_id=sc.target_id,
                      target_label=sc.target_label[:255], parameters=sc.payload()["parameters"],
                      planned_start=planned_start, planned_end=planned_end, created_by=user.id,
                      owner_user_id=user.id, revision=1, lifecycle="draft", idempotency_key=idempotency_key,
                      request_hash=request_hash)
    session.add(plan)
    await session.flush()
    session.add(ChangePlanRevision(plan_id=plan.id, revision=1, payload=_rev_payload(plan), created_by=user.id))
    return plan, True


def _rev_payload(plan: ChangePlan) -> dict[str, Any]:
    return {"scenario_type": plan.scenario_type, "target_type": plan.target_type, "target_id": str(plan.target_id),
            "parameters": plan.parameters, "title": plan.title,
            "planned_start": plan.planned_start.isoformat() if plan.planned_start else None,
            "planned_end": plan.planned_end.isoformat() if plan.planned_end else None}


async def can_edit(session: AsyncSession, user: Any, plan: ChangePlan) -> bool:
    if user.is_admin:
        return True
    if plan.created_by != user.id and plan.owner_user_id != user.id:
        return False
    try:
        await require_target_access(session, user, plan.target_type, plan.target_id, need="write")
    except ScenarioError:
        return False
    return True


async def update_plan(session: AsyncSession, user: Any, plan: ChangePlan, patch: dict[str, Any],
                      expected_revision: int | None) -> ChangePlan:
    """樂觀鎖：送來的版本不是目前版本 → 409，不覆蓋別人的修改（規格 T16）。"""
    _ensure_active(plan)
    if not await can_edit(session, user, plan):
        raise PlanError("impact_plan_forbidden", "Only the plan's creator, owner or an admin can edit it", status=403)
    if expected_revision is None or expected_revision != plan.revision:
        raise PlanError("impact_plan_revision_conflict", "The plan was changed by someone else", status=409,
                        current=plan.revision)
    params = dict(plan.parameters)
    if "parameters" in patch and patch["parameters"] is not None:
        params = dict(patch["parameters"])
        sc = await build(session, user, scenario_type=plan.scenario_type, target_type=plan.target_type,
                         target_id=plan.target_id, parameters=params, need="write")
        params = sc.payload()["parameters"]
    if patch.get("title"):
        plan.title = str(patch["title"]).strip()[:200]
    for k in ("planned_start", "planned_end"):
        if k in patch:
            setattr(plan, k, patch[k])
    if plan.planned_start and plan.planned_end and plan.planned_end < plan.planned_start:
        raise PlanError("impact_invalid_window", "The maintenance window ends before it starts")
    plan.parameters = params
    plan.revision += 1
    # 修改＝重新評估：已送審或已核准的回到草稿，舊覆核綁的是舊版本，自然失效
    if plan.lifecycle in ("in_review", "approved"):
        plan.lifecycle = "draft"
    session.add(ChangePlanRevision(plan_id=plan.id, revision=plan.revision, payload=_rev_payload(plan),
                                   created_by=user.id))
    return plan


async def current_run(session: AsyncSession, plan: ChangePlan) -> ImpactRun | None:
    """這個版本最新一次完成的分析。"""
    return (await session.execute(select(ImpactRun).where(
        ImpactRun.plan_id == plan.id, ImpactRun.plan_revision == plan.revision,
        ImpactRun.job_status.in_(("completed", "partial"))).order_by(ImpactRun.created_at.desc()).limit(1)
    )).scalars().first()


def run_expired(run: ImpactRun, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    return run.expires_at is None or run.expires_at <= now


async def transition(session: AsyncSession, user: Any, plan: ChangePlan, action: str) -> ChangePlan:
    if action not in TRANSITIONS:
        raise PlanError("impact_invalid_transition", "Unknown action", action=action)
    allowed, target = TRANSITIONS[action]
    if plan.lifecycle not in allowed:
        raise PlanError("impact_invalid_transition", "This action is not allowed now", status=409,
                        action=action, lifecycle=plan.lifecycle)
    if not await can_edit(session, user, plan):
        raise PlanError("impact_plan_forbidden", "Only the plan's creator, owner or an admin can do this", status=403)
    if action == "submit":
        run = await current_run(session, plan)
        if run is None:
            raise PlanError("impact_run_not_complete", "Run an analysis of this revision first", status=409)
        if run_expired(run):
            raise PlanError("impact_run_stale", "The analysis is too old; run it again", status=409)
    if action == "start":
        await _assert_still_current(session, user, plan)
    if action == "verify":
        open_tasks = (await session.execute(select(ChangeTask.id).where(
            ChangeTask.plan_id == plan.id, ChangeTask.phase == "verify",
            ChangeTask.state.not_in(("done", "skipped"))))).scalars().all()
        if open_tasks:
            raise PlanError("impact_verify_tasks_open", "Verification tasks are not finished", status=409,
                            count=len(open_tasks))
    plan.lifecycle = target
    return plan


async def _assert_still_current(session: AsyncSession, user: Any, plan: ChangePlan) -> None:
    """核准綁定的 run 還有效：同版本、沒過期、而且現在重新分析的快照跟當時一樣（規格 §9、T18）。"""
    from app.services.change_impact.config import get_config
    from app.services.change_impact.engine import analyze
    review = await latest_review(session, plan)
    if review is None or review.decision not in ("approve", "accept_risk") or review.revision != plan.revision:
        raise PlanError("impact_run_stale", "The approval does not match this revision", status=409)
    run = await session.get(ImpactRun, review.run_id) if review.run_id else None
    if run is None or run_expired(run):
        raise PlanError("impact_run_stale", "The approved analysis expired; run it again", status=409)
    res = await analyze(session, user=user, scenario_type=plan.scenario_type, target_type=plan.target_type,
                        target_id=plan.target_id, parameters=plan.parameters, cfg=await get_config(session))
    if res.snapshot_hash != review.snapshot_hash:
        plan.lifecycle = "draft"
        raise PlanError("impact_run_stale", "The evidence changed since the approval; run the analysis again",
                        status=409)


async def latest_review(session: AsyncSession, plan: ChangePlan) -> ImpactReview | None:
    return (await session.execute(select(ImpactReview).where(ImpactReview.plan_id == plan.id)
                                  .order_by(ImpactReview.created_at.desc()).limit(1))).scalars().first()


async def review(session: AsyncSession, user: Any, plan: ChangePlan, *, decision: str, rationale: str,
                 dispositions: dict[str, Any], run_id: uuid.UUID | None, allow_self_review: bool) -> ImpactReview:
    """覆核。核准條件：送審中、綁定這個版本最新且未過期的分析、沒有阻擋項目、每個需覆核項目都有處置。"""
    from app.models.change_impact import REVIEW_DECISION
    if decision not in REVIEW_DECISION:
        raise PlanError("impact_invalid_review", "Unknown decision", decision=decision)
    _ensure_active(plan)
    if plan.lifecycle != "in_review":
        raise PlanError("impact_invalid_transition", "The plan is not in review", status=409,
                        action="review", lifecycle=plan.lifecycle)
    if not user.is_admin:
        await require_target_access(session, user, plan.target_type, plan.target_id, need="write")
        if plan.created_by == user.id and not allow_self_review:
            raise PlanError("impact_self_review", "The creator cannot review their own plan", status=403)
    run = await current_run(session, plan)
    if run is None or (run_id is not None and run.id != run_id):
        raise PlanError("impact_run_stale", "Review the latest analysis of this revision", status=409)
    if run_expired(run):
        raise PlanError("impact_run_stale", "The analysis is too old; run it again", status=409)
    if decision in ("approve", "accept_risk"):
        if run.decision_status == "blocked":
            raise PlanError("impact_blocked", "Blocking items cannot be approved", status=409)
        if run.completeness != "complete" and decision == "approve":
            raise PlanError("impact_incomplete_needs_accept_risk",
                            "The analysis is incomplete; use accept risk with a reason", status=409)
        if decision == "accept_risk" and len((rationale or "").strip()) < 5:
            raise PlanError("impact_rationale_required", "A reason is required to accept the risk")
        review_ids = [str(i) for i in (await session.execute(select(ImpactFinding.id).where(
            ImpactFinding.run_id == run.id, ImpactFinding.disposition == "review"))).scalars().all()]
        missing = [i for i in review_ids if not str((dispositions.get(i) or {}).get("action") or "").strip()]
        if missing:
            raise PlanError("impact_dispositions_missing", "Every item that needs review needs a decision",
                            status=409, count=len(missing))
    if decision in ("reject", "request_changes") and len((rationale or "").strip()) < 2:
        raise PlanError("impact_rationale_required", "A reason is required")
    rv = ImpactReview(plan_id=plan.id, revision=plan.revision, run_id=run.id, snapshot_hash=run.snapshot_hash,
                      reviewer_id=user.id, decision=decision, rationale=(rationale or "")[:4000],
                      dispositions={k: {"action": str((v or {}).get("action") or "")[:64],
                                        "note": str((v or {}).get("note") or "")[:1000]}
                                    for k, v in (dispositions or {}).items()})
    session.add(rv)
    plan.lifecycle = {"approve": "approved", "accept_risk": "approved", "request_changes": "draft",
                      "reject": "cancelled"}[decision]
    plan.reviewer_user_id = user.id
    return rv


# ─────────────────── 待辦 ───────────────────

def _template_tasks(scenario_type: str, findings: list[ImpactFinding], params: dict[str, Any],
                    target_label: str) -> list[tuple[str, str, dict[str, Any], list[str]]]:
    """(phase, template_code, template_params, finding_ids)。文字由前端依語系翻譯。"""
    by_cat: dict[str, list[ImpactFinding]] = {}
    for f in findings:
        if f.impact in ("change_required", "potential_disruption") and f.disposition != "informational":
            by_cat.setdefault(f.category, []).append(f)
    out: list[tuple[str, str, dict[str, Any], list[str]]] = []
    if scenario_type == "ip_renumber":
        old, new = target_label, params.get("new_ip") or ""
        out += [("precheck", "confirm_new_ip", {"new_ip": new}, []),
                ("precheck", "confirm_scope_window", {}, []),
                ("precheck", "prepare_rollback", {"old_ip": old}, []),
                ("change", "update_device_address", {"old_ip": old, "new_ip": new}, [])]
        for cat in sorted(by_cat):
            fs = by_cat[cat]
            out.append(("change", f"update_refs_{cat}", {"count": len(fs)}, [str(f.id) for f in fs]))
        out += [("verify", "verify_address_services", {"new_ip": new}, []),
                ("verify", "verify_no_old_refs", {"old_ip": old}, []),
                ("rollback", "rollback_address", {"old_ip": old, "new_ip": new}, [])]
    else:
        out += [("precheck", "confirm_owner_window", {"device": target_label}, []),
                ("precheck", "confirm_recovery", {}, [])]
        if "virt" in by_cat:
            out.append(("precheck", "move_workloads", {"count": len(by_cat["virt"])},
                        [str(f.id) for f in by_cat["virt"]]))
        out += [("change", "stop_service", {"device": target_label}, []),
                ("change", "observe_period", {}, [])]
        for cat in sorted(c for c in by_cat if c != "virt"):
            fs = by_cat[cat]
            out.append(("change", f"remove_refs_{cat}", {"count": len(fs)}, [str(f.id) for f in fs]))
        out += [("change", "reclaim_resources", {"device": target_label}, []),
                ("verify", "verify_unreferenced", {}, []),
                ("verify", "verify_no_activity", {}, []),
                ("rollback", "rollback_restore_service", {"device": target_label}, [])]
    return out


async def after_run_completed(session: AsyncSession, run_id: uuid.UUID) -> None:
    """分析完成：依結果更新模板待辦。還沒動過（pending）的模板待辦重建；已經在處理的保留。"""
    run = await session.get(ImpactRun, run_id)
    if run is None:
        return
    plan = await session.get(ChangePlan, run.plan_id)
    if plan is None or plan.revision != run.plan_revision or plan.lifecycle in _TERMINAL:
        return
    await session.execute(delete(ChangeTask).where(
        ChangeTask.plan_id == plan.id, ChangeTask.origin == "rule_template", ChangeTask.state == "pending"))
    kept = {t.template_code for t in (await session.execute(select(ChangeTask).where(
        ChangeTask.plan_id == plan.id, ChangeTask.origin == "rule_template"))).scalars().all()}
    findings = list((await session.execute(select(ImpactFinding).where(ImpactFinding.run_id == run_id))).scalars())
    for pos, (phase, code, tparams, fids) in enumerate(_template_tasks(plan.scenario_type, findings,
                                                                       plan.parameters, plan.target_label)):
        if code in kept:
            continue
        session.add(ChangeTask(plan_id=plan.id, run_id=run_id, phase=phase, position=pos, title=code,
                               template_code=code, template_params=tparams, origin="rule_template",
                               finding_ids=fids, state="pending"))


def _assert_dag(tasks: dict[uuid.UUID, list[str]]) -> None:
    """depends_on 必須是無循環的有向圖（規格 §12）。"""
    state: dict[str, int] = {}

    def visit(n: str) -> None:
        if state.get(n) == 1:
            raise PlanError("impact_task_cycle", "Task dependencies form a cycle", status=409)
        if state.get(n) == 2:
            return
        state[n] = 1
        for d in tasks.get(uuid.UUID(n), []) if _is_uuid(n) else []:
            visit(str(d))
        state[n] = 2

    for k in tasks:
        visit(str(k))


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except ValueError:
        return False


async def add_task(session: AsyncSession, user: Any, plan: ChangePlan, *, phase: str, title: str,
                   instruction: str, depends_on: list[str], assignee_user_id: uuid.UUID | None,
                   origin: str = "manual", finding_ids: list[str] | None = None,
                   evidence_keys: list[str] | None = None) -> ChangeTask:
    _ensure_active(plan)
    if phase not in TASK_PHASE:
        raise PlanError("impact_invalid_task", "Unknown phase", phase=phase)
    if not await can_edit(session, user, plan):
        raise PlanError("impact_plan_forbidden", "Only the plan's creator, owner or an admin can add tasks",
                        status=403)
    existing = {t.id: list(t.depends_on or []) for t in (await session.execute(
        select(ChangeTask).where(ChangeTask.plan_id == plan.id))).scalars().all()}
    deps = [d for d in depends_on if _is_uuid(d)]
    if any(uuid.UUID(d) not in existing for d in deps):
        raise PlanError("impact_invalid_task", "A dependency is not a task of this plan")
    pos = len(existing)
    task = ChangeTask(plan_id=plan.id, run_id=plan.latest_run_id, phase=phase, position=pos,
                      title=(title or "").strip()[:300] or "-", instruction=(instruction or "")[:8000],
                      origin=origin, depends_on=deps, assignee_user_id=assignee_user_id,
                      finding_ids=finding_ids or [], evidence_keys=evidence_keys or [])
    session.add(task)
    await session.flush()
    existing[task.id] = deps
    _assert_dag(existing)
    return task


async def update_task(session: AsyncSession, user: Any, plan: ChangePlan, task: ChangeTask, patch: dict[str, Any],
                      expected_version: int | None) -> ChangeTask:
    """待辦是人工操作的記錄：標完成不會改任何來源設備（規格 §12）。"""
    from app.models.change_impact import TASK_STATE
    _ensure_active(plan)
    allowed = user.is_admin or task.assignee_user_id == user.id or await can_edit(session, user, plan)
    if not allowed:
        raise PlanError("impact_plan_forbidden", "Not allowed to update this task", status=403)
    if expected_version is None or expected_version != task.version:
        raise PlanError("impact_task_version_conflict", "The task was changed by someone else", status=409,
                        current=task.version)
    if patch.get("state"):
        st = patch["state"]
        if st not in TASK_STATE:
            raise PlanError("impact_invalid_task", "Unknown state", state=st)
        if st == "skipped" and len(str(patch.get("completion_note") or task.completion_note or "").strip()) < 2:
            raise PlanError("impact_skip_reason_required", "A reason is required to skip a task")
        task.state = st
        if st in ("done", "skipped"):
            task.completed_by, task.completed_at = user.id, datetime.now(UTC)
        else:
            task.completed_by, task.completed_at = None, None
    if "completion_note" in patch:
        task.completion_note = (patch["completion_note"] or "")[:4000] or None
    if "assignee_user_id" in patch:
        task.assignee_user_id = patch["assignee_user_id"]
    if "depends_on" in patch and patch["depends_on"] is not None:
        deps = [d for d in patch["depends_on"] if _is_uuid(d) and d != str(task.id)]
        graph = {t.id: list(t.depends_on or []) for t in (await session.execute(
            select(ChangeTask).where(ChangeTask.plan_id == plan.id))).scalars().all()}
        if any(uuid.UUID(d) not in graph for d in deps):
            raise PlanError("impact_invalid_task", "A dependency is not a task of this plan")
        graph[task.id] = deps
        _assert_dag(graph)
        task.depends_on = deps
    task.version += 1
    return task
