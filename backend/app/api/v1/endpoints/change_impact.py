"""變更影響預演 API（docs/SPEC_CHANGE_IMPACT_zh-TW.md §8；M0 §13.3 的落地）。

權限（M0 §13.7，使用者 2026-10-07 開工時採保守版本）：
- 看計畫與結果：對根目標（IP／裝置）有讀取權
- 建立、修改、分析：對根目標有寫入權（會規劃改這個 IP 的人，本來就要能改它）
- 覆核：寫入權且不是建立者（設定可放寬），或管理員；阻擋項目不可核准
- 結果每次讀取都依目前權限重新過濾；功能預設關閉，在網頁開

專案慣例：錯誤是 {code, params, message}、清單是 page/page_size、樂觀鎖衝突回 409（不用 412）。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import ui_detail
from app.models.change_impact import (
    JOB_ACTIVE,
    ChangePlan,
    ChangePlanRevision,
    ChangeTask,
    ImpactAIArtifact,
    ImpactEvidence,
    ImpactFinding,
    ImpactReview,
    ImpactRun,
)
from app.models.user import User
from app.schemas.base import StrictModel
from app.services.change_impact import ai as impact_ai
from app.services.change_impact import jobs, plans
from app.services.change_impact.access import Viewer, viewer
from app.services.change_impact.config import ai_available, get_config, set_config
from app.services.change_impact.model import stable_hash
from app.services.change_impact.scenario import (
    ScenarioError,
    candidates_for_address,
    require_target_access,
)

router = APIRouter(tags=["change-impact"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _err(exc: ScenarioError) -> HTTPException:
    params = {k: v for k, v in exc.params.items() if not isinstance(v, (list, dict))}
    detail = ui_detail(exc.code, str(exc), **params)
    if "candidates" in exc.params:
        detail["candidates"] = exc.params["candidates"]
    return HTTPException(status_code=exc.status, detail=detail)


async def _enabled(session: AsyncSession) -> dict[str, Any]:
    cfg = await get_config(session)
    if not cfg["enabled"]:
        raise HTTPException(403, detail=ui_detail("impact_feature_disabled", "Change impact preview is turned off"))
    return cfg


async def _audit(session: AsyncSession, request: Request, user: User, action: str, plan_id: uuid.UUID | None,
                 diff: dict[str, Any]) -> None:
    await append_audit(session, actor_user_id=str(user.id),
                       actor_ip=request.client.host if request.client else None,
                       actor_user_agent=request.headers.get("user-agent"), object_type="change_plan",
                       object_id=str(plan_id) if plan_id else None, action=action, diff=diff,
                       request_id=getattr(request.state, "request_id", None))


async def _plan(session: AsyncSession, user: User, plan_id: uuid.UUID, need: str = "read") -> ChangePlan:
    """看不到就當作不存在。根目標已經刪掉的計畫只給建立者與管理員。"""
    plan = await session.get(ChangePlan, plan_id)
    if plan is None:
        raise HTTPException(404, detail="Plan not found")
    if user.is_admin:
        return plan
    try:
        await require_target_access(session, user, plan.target_type, plan.target_id, need=need)
    except ScenarioError as exc:
        if exc.status == 404 and plan.created_by == user.id and need == "read":
            return plan
        if exc.status == 404:
            raise HTTPException(404, detail="Plan not found") from exc
        raise _err(exc) from exc
    return plan


async def _run(session: AsyncSession, user: User, run_id: uuid.UUID) -> tuple[ImpactRun, ChangePlan]:
    run = await session.get(ImpactRun, run_id)
    if run is None:
        raise HTTPException(404, detail="Run not found")
    plan = await _plan(session, user, run.plan_id)
    return run, plan


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _plan_out(p: ChangePlan) -> dict[str, Any]:
    return {"id": str(p.id), "title": p.title, "scenario_type": p.scenario_type, "target_type": p.target_type,
            "target_id": str(p.target_id), "target_label": p.target_label, "parameters": p.parameters,
            "planned_start": _iso(p.planned_start), "planned_end": _iso(p.planned_end),
            "created_by": str(p.created_by) if p.created_by else None,
            "owner_user_id": str(p.owner_user_id) if p.owner_user_id else None,
            "reviewer_user_id": str(p.reviewer_user_id) if p.reviewer_user_id else None,
            "revision": p.revision, "lifecycle": p.lifecycle,
            "latest_run_id": str(p.latest_run_id) if p.latest_run_id else None,
            "archived_at": _iso(p.archived_at), "created_at": _iso(p.created_at), "updated_at": _iso(p.updated_at)}


def _run_out(r: ImpactRun, v: Viewer | None = None) -> dict[str, Any]:
    out = {"id": str(r.id), "plan_id": str(r.plan_id), "plan_revision": r.plan_revision, "job_status": r.job_status,
           "stage": r.stage, "decision_status": r.decision_status, "completeness": r.completeness,
           "scope_manifest": r.scope_manifest, "counts": r.counts, "snapshot_hash": r.snapshot_hash,
           "scenario_hash": r.scenario_hash, "engine_version": r.engine_version, "rules_version": r.rules_version,
           "attempt": r.attempt, "started_at": _iso(r.started_at), "completed_at": _iso(r.completed_at),
           "expires_at": _iso(r.expires_at), "truncated": r.truncated, "truncation": r.truncation,
           "error_code": r.error_code, "created_at": _iso(r.created_at),
           "cancel_requested": r.cancel_requested_at is not None,
           "requested_by": str(r.requested_by) if r.requested_by else None}
    if v is not None:
        out["permission_scope_changed"] = bool(r.visible_scope_hash and r.visible_scope_hash != v.scope_hash())
    return out


# ─────────────────── 設定 ───────────────────

class SettingsIn(StrictModel):
    enabled: bool | None = None
    ai_enabled: bool | None = None
    allow_self_review: bool | None = None
    run_valid_hours: int | None = None
    default_stale_hours: int | None = None
    retention_days: int | None = None
    failed_retention_days: int | None = None
    limits: dict[str, int] | None = None


@router.get("/change-impact/settings")
async def get_settings(user: CurrentUser, session: Session) -> dict[str, Any]:
    cfg = await get_config(session)
    out: dict[str, Any] = {"enabled": cfg["enabled"], "ai_available": cfg["enabled"] and await ai_available(session, cfg)}
    if user.is_admin:
        out["config"] = cfg
    return out


@router.put("/change-impact/settings", dependencies=[Depends(require_admin)])
async def put_settings(body: SettingsIn, user: CurrentUser, request: Request, session: Session) -> dict[str, Any]:
    patch = body.model_dump(exclude_none=True)
    before = await get_config(session)
    cfg = await set_config(session, patch, updated_by=user.id)
    await _audit(session, request, user, "change_impact_settings", None,
                 {"before": {k: before.get(k) for k in patch}, "after": {k: cfg.get(k) for k in patch}})
    await session.commit()
    return {"enabled": cfg["enabled"], "ai_available": cfg["enabled"] and await ai_available(session, cfg),
            "config": cfg}


# ─────────────────── 候選目標（同一個位址好幾筆） ───────────────────

@router.get("/change-impact/candidates")
async def candidates(ip: str, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    try:
        return {"items": await candidates_for_address(session, user, ip)}
    except ScenarioError as exc:
        raise _err(exc) from exc


# ─────────────────── 計畫 ───────────────────

class PlanIn(StrictModel):
    title: str = Field(default="", max_length=200)
    scenario_type: str
    target_type: str
    target_id: uuid.UUID
    parameters: dict[str, Any] = Field(default_factory=dict)
    planned_start: datetime | None = None
    planned_end: datetime | None = None


class PlanPatch(StrictModel):
    title: str | None = Field(default=None, max_length=200)
    parameters: dict[str, Any] | None = None
    planned_start: datetime | None = None
    planned_end: datetime | None = None
    expected_revision: int | None = None


@router.get("/change-plans")
async def list_plans(user: CurrentUser, session: Session, scenario_type: str | None = None,
                     lifecycle: str | None = None, q: str | None = None, include_archived: bool = False,
                     target_type: str | None = None, target_id: uuid.UUID | None = None,
                     page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    await _enabled(session)
    stmt = select(ChangePlan)
    if not user.is_admin:
        from app.core.sqlin import in_values
        from app.services.permission import visible_ids
        vis_ip = await visible_ids(session, user=user, object_type="ip")
        vis_dev = await visible_ids(session, user=user, object_type="device")
        conds = [ChangePlan.created_by == user.id]
        conds.append(ChangePlan.target_type == "ip_address" if vis_ip is None else
                     (ChangePlan.target_type == "ip_address") & in_values(ChangePlan.target_id, list(vis_ip)))
        conds.append(ChangePlan.target_type == "device" if vis_dev is None else
                     (ChangePlan.target_type == "device") & in_values(ChangePlan.target_id, list(vis_dev)))
        stmt = stmt.where(or_(*conds))
    if scenario_type:
        stmt = stmt.where(ChangePlan.scenario_type == scenario_type)
    if lifecycle:
        stmt = stmt.where(ChangePlan.lifecycle == lifecycle)
    if target_type and target_id:
        stmt = stmt.where(ChangePlan.target_type == target_type, ChangePlan.target_id == target_id)
    if not include_archived:
        stmt = stmt.where(ChangePlan.archived_at.is_(None))
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(or_(ChangePlan.title.ilike(like, escape="\\"), ChangePlan.target_label.ilike(like, escape="\\")))
    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await session.execute(stmt.order_by(ChangePlan.created_at.desc())
                                  .offset((page - 1) * page_size).limit(page_size))).scalars().all()
    runs = {}
    ids = [r.latest_run_id for r in rows if r.latest_run_id]
    if ids:
        runs = {r.id: r for r in (await session.execute(select(ImpactRun).where(ImpactRun.id.in_(ids)))).scalars()}  # bounded: one page
    items = []
    for p in rows:
        o = _plan_out(p)
        lr = runs.get(p.latest_run_id) if p.latest_run_id else None
        o["latest_run"] = {"job_status": lr.job_status, "decision_status": lr.decision_status,
                           "completeness": lr.completeness, "counts": lr.counts,
                           "completed_at": _iso(lr.completed_at)} if lr else None
        items.append(o)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("/change-plans", status_code=status.HTTP_201_CREATED)
async def create_plan(body: PlanIn, user: CurrentUser, request: Request, session: Session, response: Response,
                      idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None) -> dict[str, Any]:
    await _enabled(session)
    rh = stable_hash(body.model_dump(mode="json"))
    try:
        plan, created = await plans.create_plan(
            session, user, title=body.title, scenario_type=body.scenario_type, target_type=body.target_type,
            target_id=body.target_id, parameters=body.parameters, planned_start=body.planned_start,
            planned_end=body.planned_end, idempotency_key=(idempotency_key or None) and idempotency_key[:128],
            request_hash=rh)
    except ScenarioError as exc:
        raise _err(exc) from exc
    if created:
        await _audit(session, request, user, "change_plan_create", plan.id,
                     {"title": plan.title, "scenario": plan.scenario_type, "target": plan.target_label,
                      "parameters": plan.parameters})
        await session.commit()
        await session.refresh(plan)
    else:
        response.status_code = status.HTTP_200_OK
    return _plan_out(plan)


@router.get("/change-plans/{plan_id}")
async def get_plan(plan_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    out = _plan_out(plan)
    cur = await plans.current_run(session, plan)
    out["current_run_id"] = str(cur.id) if cur else None
    out["current_run_expired"] = plans.run_expired(cur) if cur else None
    out["can_edit"] = await plans.can_edit(session, user, plan)
    review = await plans.latest_review(session, plan)
    out["latest_review"] = _review_out(review) if review else None
    return out


@router.patch("/change-plans/{plan_id}")
async def patch_plan(plan_id: uuid.UUID, body: PlanPatch, user: CurrentUser, request: Request, session: Session,
                     if_match: Annotated[str | None, Header(alias="If-Match")] = None) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    expected = body.expected_revision
    if expected is None and if_match:
        try:
            expected = int(if_match.strip('"W/ '))
        except ValueError:
            expected = None
    patch = body.model_dump(exclude_unset=True, exclude={"expected_revision"})
    before = {"revision": plan.revision, "parameters": plan.parameters, "title": plan.title}
    try:
        await plans.update_plan(session, user, plan, patch, expected)
    except ScenarioError as exc:
        raise _err(exc) from exc
    await _audit(session, request, user, "change_plan_update", plan.id,
                 {"before": before, "after": {"revision": plan.revision, "parameters": plan.parameters,
                                              "title": plan.title}})
    await session.commit()
    await session.refresh(plan)       # updated_at 由資料庫更新，不重新讀就會在序列化時觸發延遲載入
    return _plan_out(plan)


@router.delete("/change-plans/{plan_id}")
async def archive_plan(plan_id: uuid.UUID, user: CurrentUser, request: Request, session: Session) -> dict[str, Any]:
    """一般使用者的刪除＝封存（規格 §7.3）；證據依保存期限清除。"""
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    if not await plans.can_edit(session, user, plan):
        raise HTTPException(403, detail=ui_detail("impact_plan_forbidden", "Not allowed"))
    from datetime import UTC
    plan.archived_at = datetime.now(UTC)
    await _audit(session, request, user, "change_plan_archive", plan.id, {"title": plan.title})
    await session.commit()
    return {"ok": True}


@router.get("/change-plans/{plan_id}/revisions")
async def list_revisions(plan_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    rows = (await session.execute(select(ChangePlanRevision).where(ChangePlanRevision.plan_id == plan.id)
                                  .order_by(ChangePlanRevision.revision.desc()))).scalars().all()
    return {"items": [{"revision": r.revision, "payload": r.payload, "created_at": _iso(r.created_at),
                       "created_by": str(r.created_by) if r.created_by else None} for r in rows]}


class TransitionIn(StrictModel):
    action: str


@router.post("/change-plans/{plan_id}/transitions")
async def transition(plan_id: uuid.UUID, body: TransitionIn, user: CurrentUser, request: Request,
                     session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    before = plan.lifecycle
    try:
        await plans.transition(session, user, plan, body.action)
    except plans.PlanError as exc:
        if plan.lifecycle != before:      # 開始維護前發現證據變了：計畫退回草稿要寫進去
            await _audit(session, request, user, "change_plan_transition", plan.id,
                         {"action": body.action, "from": before, "to": plan.lifecycle, "reason": exc.code})
            await session.commit()
        raise _err(exc) from exc
    except ScenarioError as exc:
        raise _err(exc) from exc
    await _audit(session, request, user, "change_plan_transition", plan.id,
                 {"action": body.action, "from": before, "to": plan.lifecycle})
    await session.commit()
    await session.refresh(plan)
    return _plan_out(plan)


# ─────────────────── 分析 ───────────────────

@router.post("/change-plans/{plan_id}/runs", status_code=status.HTTP_202_ACCEPTED)
async def start_run(plan_id: uuid.UUID, user: CurrentUser, request: Request, session: Session, response: Response,
                    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id, need="write")
    try:
        plans._ensure_active(plan)
        run, created = await jobs.create_run(session, plan=plan, user=user,
                                             idempotency_key=(idempotency_key or None) and idempotency_key[:128],
                                             request_hash=stable_hash({"plan": str(plan.id), "rev": plan.revision}))
    except ScenarioError as exc:
        raise _err(exc) from exc
    if not created:
        response.status_code = status.HTTP_200_OK
        return _run_out(run)
    await _audit(session, request, user, "impact_run_start", plan.id,
                 {"run_id": str(run.id), "revision": plan.revision})
    await session.commit()
    await jobs.launch(run.id, label=plan.title, actor_user_id=user.id, plan_id=plan.id)
    await session.refresh(run)
    return _run_out(run)


@router.get("/change-plans/{plan_id}/runs")
async def list_runs(plan_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    rows = (await session.execute(select(ImpactRun).where(ImpactRun.plan_id == plan.id)
                                  .order_by(ImpactRun.created_at.desc()).limit(100))).scalars().all()
    return {"items": [_run_out(r) for r in rows]}


@router.get("/impact-runs/{run_id}")
async def get_run(run_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, _plan_row = await _run(session, user, run_id)
    if run.job_status in JOB_ACTIVE:
        # 輪詢時順便回收沒有心跳的 run（worker 重啟、程序被殺；規格 §8.4）
        relaunch = await jobs.reclaim_stale(session)
        await session.commit()
        if relaunch:
            for rid in relaunch:
                r = await session.get(ImpactRun, rid)
                p = await session.get(ChangePlan, r.plan_id) if r else None
                if r and p:
                    await jobs.launch(rid, label=p.title, actor_user_id=r.requested_by, plan_id=p.id)
        await session.refresh(run)
    return _run_out(run, await viewer(session, user))


@router.get("/impact-runs/{run_id}/findings")
async def run_findings(run_id: uuid.UUID, user: CurrentUser, session: Session, disposition: str | None = None,
                       category: str | None = None, severity: str | None = None,
                       page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    await _enabled(session)
    run, _p = await _run(session, user, run_id)
    v = await viewer(session, user)
    bundle = await impact_ai.visible_bundle(session, run, v)
    items = [f for f in bundle["findings"]
             if (not disposition or f.disposition == disposition) and (not category or f.category == category)
             and (not severity or f.severity == severity)]
    ev_ids = {e.key: str(e.id) for e in bundle["evidence"]}
    page_items = items[(page - 1) * page_size: page * page_size]
    return {"items": [_finding_out(f, ev_ids) for f in page_items], "total": len(items), "page": page,
            "page_size": page_size, "permission_scope_changed": bool(run.visible_scope_hash and
                                                                      run.visible_scope_hash != v.scope_hash())}


def _finding_out(f: ImpactFinding, ev_ids: dict[str, str]) -> dict[str, Any]:
    return {"id": str(f.id), "rule_id": f.rule_id, "rule_version": f.rule_version, "category": f.category,
            "subject_type": f.subject_type, "subject_id": str(f.subject_id) if f.subject_id else None,
            "subject_key": f.subject_key, "subject_label": f.subject_label, "match_kind": f.match_kind,
            "impact": f.impact, "severity": f.severity, "disposition": f.disposition,
            "evidence_strength": f.evidence_strength, "reason_code": f.reason_code, "params": f.params,
            "evidence_ids": [ev_ids[k] for k in f.evidence_keys if k in ev_ids], "relationship_path": f.path_refs,
            "suggested_action": f.suggested_action, "fingerprint": f.fingerprint}


@router.get("/impact-runs/{run_id}/evidence/{evidence_id}")
async def run_evidence(run_id: uuid.UUID, evidence_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, _p = await _run(session, user, run_id)
    e = await session.get(ImpactEvidence, evidence_id)
    v = await viewer(session, user)
    # 證據一定要屬於這個 run，而且現在看得到（拿別的 run 的 id 來問一律 404，規格 T21）
    if e is None or e.run_id != run.id or not v.can(e.visibility_type, e.visibility_id):
        raise HTTPException(404, detail="Evidence not found")
    return {"id": str(e.id), "key": e.key, "source_type": e.source_type, "integration_ref": e.integration_ref,
            "object_type": e.source_object_type, "object_id": str(e.source_object_id) if e.source_object_id else None,
            "object_key": e.source_object_key, "label": e.label, "observed_at": _iso(e.observed_at),
            "collected_at": _iso(e.collected_at), "payload": e.sanitized_payload, "payload_hash": e.payload_hash,
            "freshness": e.freshness}


@router.get("/impact-runs/{run_id}/evidence")
async def run_evidence_list(run_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, _p = await _run(session, user, run_id)
    bundle = await impact_ai.visible_bundle(session, run, await viewer(session, user))
    return {"items": [{"id": str(e.id), "key": e.key, "source_type": e.source_type,
                       "object_type": e.source_object_type, "label": e.label, "observed_at": _iso(e.observed_at),
                       "collected_at": _iso(e.collected_at), "freshness": e.freshness,
                       "integration_ref": e.integration_ref} for e in bundle["evidence"]]}


@router.get("/impact-runs/{run_id}/gaps")
async def run_gaps(run_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, _p = await _run(session, user, run_id)
    bundle = await impact_ai.visible_bundle(session, run, await viewer(session, user))
    return {"items": [{"id": str(g.id), "category": g.category, "reason_code": g.reason_code, "params": g.params,
                       "source_scope": g.source_scope, "affected_analysis": g.affected_analysis}
                      for g in bundle["gaps"]]}


@router.post("/impact-runs/{run_id}/cancel")
async def cancel_run(run_id: uuid.UUID, user: CurrentUser, request: Request, session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, plan = await _run(session, user, run_id)
    if not (user.is_admin or run.requested_by == user.id):
        raise HTTPException(403, detail=ui_detail("impact_plan_forbidden", "Only the requester or an admin can cancel"))
    changed = await jobs.request_cancel(session, run)
    if changed:
        await _audit(session, request, user, "impact_run_cancel", plan.id, {"run_id": str(run.id)})
    await session.commit()
    await session.refresh(run)
    return _run_out(run)


@router.get("/impact-runs/{run_id}/export")
async def export_run(run_id: uuid.UUID, user: CurrentUser, request: Request, session: Session,
                     format: str = Query("md", pattern="^(md|json)$")) -> Response:
    import json as _json

    from app.services.change_impact import export as ex
    await _enabled(session)
    run, plan = await _run(session, user, run_id)
    if run.job_status not in ("completed", "partial"):
        raise HTTPException(409, detail=ui_detail("impact_run_not_complete", "The analysis is not finished"))
    v = await viewer(session, user)
    bundle = await impact_ai.visible_bundle(session, run, v)
    tasks = list((await session.execute(select(ChangeTask).where(ChangeTask.plan_id == plan.id)
                                        .order_by(ChangeTask.phase, ChangeTask.position))).scalars())
    changed = bool(run.visible_scope_hash and run.visible_scope_hash != v.scope_hash())
    await _audit(session, request, user, "impact_export", plan.id, {"run_id": str(run.id), "format": format})
    await session.commit()
    stamp = (run.completed_at or run.created_at).strftime("%Y%m%d-%H%M")
    if format == "json":
        body = _json.dumps(ex.as_json(plan, run, bundle, tasks, scope_changed=changed), ensure_ascii=False, indent=2)
        media, ext = "application/json", "json"
    else:
        body = ex.as_markdown(plan, run, bundle, tasks, scope_changed=changed)
        media, ext = "text/markdown; charset=utf-8", "md"
    return Response(content=body.encode("utf-8"), media_type=media, headers={
        "Content-Disposition": f'attachment; filename="change-impact-{stamp}.{ext}"', "Cache-Control": "no-store"})


# ─────────────────── 覆核 ───────────────────

class ReviewIn(StrictModel):
    decision: str
    rationale: str = Field(default="", max_length=4000)
    dispositions: dict[str, dict[str, str]] = Field(default_factory=dict)
    run_id: uuid.UUID | None = None


def _review_out(r: ImpactReview) -> dict[str, Any]:
    return {"id": str(r.id), "revision": r.revision, "run_id": str(r.run_id) if r.run_id else None,
            "snapshot_hash": r.snapshot_hash, "reviewer_id": str(r.reviewer_id) if r.reviewer_id else None,
            "decision": r.decision, "rationale": r.rationale, "dispositions": r.dispositions,
            "created_at": _iso(r.created_at)}


@router.post("/change-plans/{plan_id}/reviews", status_code=status.HTTP_201_CREATED)
async def create_review(plan_id: uuid.UUID, body: ReviewIn, user: CurrentUser, request: Request,
                        session: Session) -> dict[str, Any]:
    cfg = await _enabled(session)
    plan = await _plan(session, user, plan_id)
    try:
        rv = await plans.review(session, user, plan, decision=body.decision, rationale=body.rationale,
                                dispositions=body.dispositions, run_id=body.run_id,
                                allow_self_review=bool(cfg.get("allow_self_review")))
    except ScenarioError as exc:
        raise _err(exc) from exc
    await session.flush()
    await _audit(session, request, user, "impact_review", plan.id,
                 {"decision": body.decision, "revision": plan.revision, "run_id": str(rv.run_id),
                  "snapshot_hash": rv.snapshot_hash, "lifecycle": plan.lifecycle})
    await session.commit()
    return _review_out(rv)


@router.get("/change-plans/{plan_id}/reviews")
async def list_reviews(plan_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    rows = (await session.execute(select(ImpactReview).where(ImpactReview.plan_id == plan.id)
                                  .order_by(ImpactReview.created_at.desc()))).scalars().all()
    return {"items": [_review_out(r) for r in rows]}


# ─────────────────── 待辦 ───────────────────

class TaskIn(StrictModel):
    phase: str
    title: str = Field(max_length=300)
    instruction: str = Field(default="", max_length=8000)
    depends_on: list[str] = Field(default_factory=list)
    assignee_user_id: uuid.UUID | None = None


class TaskPatch(StrictModel):
    state: str | None = None
    completion_note: str | None = Field(default=None, max_length=4000)
    assignee_user_id: uuid.UUID | None = None
    depends_on: list[str] | None = None
    expected_version: int


class AcceptDraftIn(StrictModel):
    artifact_id: uuid.UUID
    indices: list[int]


def _task_out(t: ChangeTask) -> dict[str, Any]:
    return {"id": str(t.id), "phase": t.phase, "position": t.position, "title": t.title,
            "instruction": t.instruction, "template_code": t.template_code, "template_params": t.template_params,
            "origin": t.origin, "finding_ids": t.finding_ids, "depends_on": t.depends_on,
            "assignee_user_id": str(t.assignee_user_id) if t.assignee_user_id else None, "state": t.state,
            "version": t.version, "completed_by": str(t.completed_by) if t.completed_by else None,
            "completed_at": _iso(t.completed_at), "completion_note": t.completion_note}


@router.get("/change-plans/{plan_id}/tasks")
async def list_tasks(plan_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    rows = (await session.execute(select(ChangeTask).where(ChangeTask.plan_id == plan.id)
                                  .order_by(ChangeTask.position))).scalars().all()
    return {"items": [_task_out(t) for t in rows]}


@router.post("/change-plans/{plan_id}/tasks", status_code=status.HTTP_201_CREATED)
async def create_task(plan_id: uuid.UUID, body: TaskIn, user: CurrentUser, request: Request,
                      session: Session) -> dict[str, Any]:
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    try:
        t = await plans.add_task(session, user, plan, phase=body.phase, title=body.title,
                                 instruction=body.instruction, depends_on=body.depends_on,
                                 assignee_user_id=body.assignee_user_id)
    except ScenarioError as exc:
        raise _err(exc) from exc
    await _audit(session, request, user, "change_task_create", plan.id,
                 {"task_id": str(t.id), "phase": t.phase, "title": t.title, "origin": t.origin})
    await session.commit()
    return _task_out(t)


@router.post("/change-plans/{plan_id}/tasks/from-ai", status_code=status.HTTP_201_CREATED)
async def accept_ai_tasks(plan_id: uuid.UUID, body: AcceptDraftIn, user: CurrentUser, request: Request,
                          session: Session) -> dict[str, Any]:
    """接受 AI 草擬的待辦：只有使用者勾選的才存（規格 §10.2「確認選取後才存成待辦」）。"""
    await _enabled(session)
    plan = await _plan(session, user, plan_id)
    art = await session.get(ImpactAIArtifact, body.artifact_id)
    run = await session.get(ImpactRun, art.run_id) if art else None
    if art is None or run is None or run.plan_id != plan.id or art.status != "completed":
        raise HTTPException(404, detail="Draft not found")
    drafts = (art.output_json or {}).get("suggested_tasks") or []
    created = []
    try:
        for i in sorted(set(body.indices)):
            if not 0 <= i < len(drafts):
                raise plans.PlanError("impact_invalid_task", "No such draft item", index=i)
            d = drafts[i]
            created.append(await plans.add_task(session, user, plan, phase=d["phase"], title=d["text"][:300],
                                                instruction=d["text"], depends_on=[], assignee_user_id=None,
                                                origin="ai_draft", finding_ids=[str(x) for x in d.get("finding_ids") or []]))
    except ScenarioError as exc:
        raise _err(exc) from exc
    await _audit(session, request, user, "change_task_create", plan.id,
                 {"origin": "ai_draft", "artifact_id": str(art.id), "count": len(created)})
    await session.commit()
    return {"items": [_task_out(t) for t in created]}


@router.patch("/change-tasks/{task_id}")
async def patch_task(task_id: uuid.UUID, body: TaskPatch, user: CurrentUser, request: Request,
                     session: Session) -> dict[str, Any]:
    await _enabled(session)
    task = await session.get(ChangeTask, task_id)
    if task is None:
        raise HTTPException(404, detail="Task not found")
    plan = await _plan(session, user, task.plan_id)
    before = {"state": task.state, "version": task.version}
    try:
        await plans.update_task(session, user, plan, task, body.model_dump(exclude_unset=True,
                                                                          exclude={"expected_version"}),
                                body.expected_version)
    except ScenarioError as exc:
        raise _err(exc) from exc
    await _audit(session, request, user, "change_task_update", plan.id,
                 {"task_id": str(task.id), "before": before, "after": {"state": task.state, "version": task.version}})
    await session.commit()
    return _task_out(task)


# ─────────────────── AI ───────────────────

class AIIn(StrictModel):
    artifact_type: str = Field(pattern="^(summary|checklist|explanation)$")


class QuestionIn(StrictModel):
    question: str = Field(min_length=1, max_length=1000)


def _artifact_out(a: ImpactAIArtifact, v: Viewer) -> dict[str, Any]:
    hidden = bool(a.scope_hash and a.scope_hash != v.scope_hash())
    return {"id": str(a.id), "artifact_type": a.artifact_type, "status": a.status, "question": a.question,
            "model": a.model, "prompt_version": a.prompt_version, "validation_state": a.validation_state,
            "truncated": a.truncated, "error_code": a.error_code, "generated_at": _iso(a.generated_at),
            "created_at": _iso(a.created_at),
            # 用不同權限範圍產生的解說整份隱藏：不能只遮 id 卻留下名稱與數量（規格 §11.1 第 4 點）
            "hidden_scope_changed": hidden, "output": None if hidden else a.output_json}


async def _create_artifact(session: AsyncSession, user: User, request: Request, run: ImpactRun, plan: ChangePlan,
                           kind: str, question: str | None) -> ImpactAIArtifact:
    cfg = await get_config(session)
    if not await ai_available(session, cfg):
        raise HTTPException(409, detail=ui_detail("impact_ai_unavailable", "AI is not available"))
    if run.job_status not in ("completed", "partial"):
        raise HTTPException(409, detail=ui_detail("impact_run_not_complete", "The analysis is not finished"))
    busy = (await session.execute(select(func.count()).select_from(ImpactAIArtifact).where(
        ImpactAIArtifact.requested_by == user.id, ImpactAIArtifact.status.in_(("pending", "running"))))).scalar() or 0
    if busy >= int(cfg["limits"]["per_user_ai_jobs"]):
        raise HTTPException(409, detail=ui_detail("impact_concurrency_limit", "An AI request is already running",
                                                  limit=int(cfg["limits"]["per_user_ai_jobs"])))
    if question:
        from app.services.ai_guard import screen_text
        try:
            screen_text(question)
        except Exception as exc:
            raise HTTPException(400, detail=ui_detail("impact_question_rejected", "The question was rejected")) from exc
    from app.services.ai import user_locale
    art = ImpactAIArtifact(run_id=run.id, artifact_type=kind, status="pending", question=question,
                           prompt_version=impact_ai.PROMPT_VERSION, language=(await user_locale(session, user)) or "zh-TW",
                           requested_by=user.id)
    session.add(art)
    await session.flush()
    await _audit(session, request, user, "impact_ai_request", plan.id,
                 {"run_id": str(run.id), "artifact_id": str(art.id), "type": kind})
    await session.commit()
    await impact_ai.launch(art.id, actor_user_id=user.id, plan_id=plan.id, label=plan.title)
    await session.refresh(art)
    return art


@router.post("/impact-runs/{run_id}/ai-artifacts", status_code=status.HTTP_202_ACCEPTED)
async def request_ai(run_id: uuid.UUID, body: AIIn, user: CurrentUser, request: Request,
                     session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, plan = await _run(session, user, run_id)
    art = await _create_artifact(session, user, request, run, plan, body.artifact_type, None)
    return _artifact_out(art, await viewer(session, user))


@router.post("/impact-runs/{run_id}/questions", status_code=status.HTTP_202_ACCEPTED)
async def ask(run_id: uuid.UUID, body: QuestionIn, user: CurrentUser, request: Request,
              session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, plan = await _run(session, user, run_id)
    art = await _create_artifact(session, user, request, run, plan, "answer", body.question.strip())
    return _artifact_out(art, await viewer(session, user))


@router.get("/impact-runs/{run_id}/ai-artifacts")
async def list_ai(run_id: uuid.UUID, user: CurrentUser, session: Session) -> dict[str, Any]:
    await _enabled(session)
    run, _p = await _run(session, user, run_id)
    v = await viewer(session, user)
    rows = (await session.execute(select(ImpactAIArtifact).where(ImpactAIArtifact.run_id == run.id)
                                  .order_by(ImpactAIArtifact.created_at.desc()).limit(50))).scalars().all()
    # 追問的內容只給問的人看（其他人看得到這份結果，但不是他問的問題）
    return {"items": [_artifact_out(a, v) for a in rows
                      if a.artifact_type != "answer" or a.requested_by == user.id or user.is_admin]}
