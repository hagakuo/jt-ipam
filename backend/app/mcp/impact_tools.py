"""變更影響預演的 MCP／AI 對話工具（規格 §10.6）。

讀取類（逐物件層，跟 REST 一樣依目前權限過濾）：impact_list_plans、impact_get_run、impact_list_findings、
impact_get_evidence。草稿類：impact_prepare_scenario 只驗證、不寫入，回一個綁定內容的草稿憑證。
有副作用的（列在 MUTATING_TOOLS，只給管理員、唯讀金鑰不能呼叫、AI 對話要人按確認）：
impact_create_plan（必須帶有效的草稿憑證，內容被改過就拒絕）、impact_start_run、impact_accept_task_draft。

沒有、也不會有 apply_change／execute_shell／push_firewall 這類工具：預演不寫回任何來源。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User

DRAFT_TTL = 600


def _secret() -> bytes:
    from app.core.config import get_settings
    return hashlib.sha256(("impact-draft:" + get_settings().secret_key.get_secret_value()).encode()).digest()


def _payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def make_draft_token(user_id: uuid.UUID, payload: dict[str, Any], *, now: float | None = None) -> str:
    """伺服器簽發：綁定使用者、內容雜湊與期限。模型的輸出無法自己產生有效的憑證（規格 §10.6）。"""
    exp = int((now or time.time()) + DRAFT_TTL)
    msg = f"{user_id}|{_payload_hash(payload)}|{exp}"
    sig = hmac.new(_secret(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def check_draft_token(token: str, user_id: uuid.UUID, payload: dict[str, Any]) -> bool:
    try:
        exp_s, sig = str(token).split(".", 1)
        exp = int(exp_s)
    except (ValueError, AttributeError):
        return False
    if exp < time.time():
        return False
    msg = f"{user_id}|{_payload_hash(payload)}|{exp}"
    return hmac.compare_digest(sig, hmac.new(_secret(), msg.encode(), hashlib.sha256).hexdigest())


async def _enabled(session: AsyncSession) -> bool:
    from app.services.change_impact.config import get_config
    return bool((await get_config(session))["enabled"])


_OFF = {"error": "impact_feature_disabled", "message": "變更影響預演尚未啟用"}


def _draft_payload(scenario_type: str, target_type: str, target_id: str, parameters: dict[str, Any],
                   title: str) -> dict[str, Any]:
    return {"scenario_type": scenario_type, "target_type": target_type, "target_id": str(target_id),
            "parameters": {k: parameters.get(k) for k in ("new_ip", "target_subnet_id") if parameters.get(k)},
            "title": title or ""}


async def impact_prepare_scenario(session: AsyncSession, *, user: User, scenario_type: str = "ip_renumber",
                                  target_ip: str | None = None, target_id: str | None = None,
                                  new_ip: str | None = None, target_subnet_id: str | None = None,
                                  title: str | None = None) -> dict[str, Any]:
    """草稿：解析目標與參數、驗證，回草稿與憑證。不寫入任何東西；同一個位址有好幾筆時回候選、不猜。"""
    from app.services.change_impact.scenario import ScenarioError, build, candidates_for_address
    if not await _enabled(session):
        return _OFF
    target_type = "ip_address" if scenario_type == "ip_renumber" else "device"
    try:
        if not target_id and target_ip and target_type == "ip_address":
            cands = await candidates_for_address(session, user, target_ip)
            if not cands:
                return {"error": "impact_target_not_found", "message": "找不到你看得到的這個位址"}
            if len(cands) > 1:
                return {"needs_choice": True, "candidates": cands,
                        "message": "同一個位址有好幾筆（重疊網段），請指定 target_id"}
            target_id = cands[0]["id"]
        if not target_id:
            return {"error": "impact_target_not_found", "message": "需要 target_id（或 IP 改址時給 target_ip）"}
        params = {"new_ip": new_ip, "target_subnet_id": target_subnet_id}
        sc = await build(session, user, scenario_type=scenario_type, target_type=target_type,
                         target_id=uuid.UUID(str(target_id)), parameters=params, need="write")
    except (ScenarioError, ValueError) as exc:
        return {"error": getattr(exc, "code", "impact_invalid_scenario"), "message": str(exc),
                "params": getattr(exc, "params", {})}
    default_title = f"{sc.target_label} → {sc.new_ip}" if sc.new_ip else sc.target_label
    payload = _draft_payload(scenario_type, target_type, str(sc.target_id), sc.payload()["parameters"],
                             title or default_title)
    return {"draft": payload, "target_label": sc.target_label, "target_subnet": sc.target_subnet_cidr,
            "cross_subnet": sc.cross_subnet, "draft_token": make_draft_token(user.id, payload),
            "message": "這是草稿，還沒有建立任何東西。要建立請呼叫 impact_create_plan 並帶 draft_token。"}


async def impact_create_plan(session: AsyncSession, *, user: User, draft_token: str = "", scenario_type: str = "",
                             target_type: str = "", target_id: str = "", parameters: dict[str, Any] | None = None,
                             title: str = "") -> dict[str, Any]:
    from app.core.audit import append_audit
    from app.services.change_impact import plans
    from app.services.change_impact.scenario import ScenarioError
    if not await _enabled(session):
        return _OFF
    payload = _draft_payload(scenario_type, target_type, target_id, parameters or {}, title)
    if not check_draft_token(draft_token, user.id, payload):
        return {"error": "impact_draft_invalid",
                "message": "草稿憑證無效、過期，或內容跟草稿不一樣；請先呼叫 impact_prepare_scenario"}
    try:
        plan, _created = await plans.create_plan(
            session, user, title=title, scenario_type=scenario_type, target_type=target_type,
            target_id=uuid.UUID(target_id), parameters=parameters or {}, planned_start=None, planned_end=None,
            idempotency_key=None, request_hash=None)
    except ScenarioError as exc:
        return {"error": exc.code, "message": str(exc), "params": exc.params}
    await append_audit(session, actor_user_id=str(user.id), actor_ip=None, actor_user_agent="mcp",
                       object_type="change_plan", object_id=str(plan.id), action="change_plan_create",
                       diff={"title": plan.title, "via": "mcp", "parameters": plan.parameters}, request_id=None)
    await session.commit()
    return {"plan_id": str(plan.id), "title": plan.title, "lifecycle": plan.lifecycle,
            "message": "計畫已建立（草稿）。分析請呼叫 impact_start_run。"}


async def impact_start_run(session: AsyncSession, *, user: User, plan_id: str = "") -> dict[str, Any]:
    from app.core.audit import append_audit
    from app.models.change_impact import ChangePlan
    from app.services.change_impact import jobs, plans
    from app.services.change_impact.scenario import ScenarioError, require_target_access
    if not await _enabled(session):
        return _OFF
    plan = await session.get(ChangePlan, uuid.UUID(plan_id)) if plan_id else None
    if plan is None:
        return {"error": "impact_target_not_found", "message": "找不到計畫"}
    try:
        await require_target_access(session, user, plan.target_type, plan.target_id, need="write")
        plans._ensure_active(plan)
        run, _created = await jobs.create_run(session, plan=plan, user=user, idempotency_key=None, request_hash=None)
    except ScenarioError as exc:
        return {"error": exc.code, "message": str(exc)}
    await append_audit(session, actor_user_id=str(user.id), actor_ip=None, actor_user_agent="mcp",
                       object_type="change_plan", object_id=str(plan.id), action="impact_run_start",
                       diff={"run_id": str(run.id), "via": "mcp"}, request_id=None)
    await session.commit()
    await jobs.launch(run.id, label=plan.title, actor_user_id=user.id, plan_id=plan.id)
    return {"run_id": str(run.id), "message": "分析已開始；用 impact_get_run 查看結果。"}


async def impact_accept_task_draft(session: AsyncSession, *, user: User, plan_id: str = "", artifact_id: str = "",
                                   indices: list[int] | None = None) -> dict[str, Any]:
    from app.core.audit import append_audit
    from app.models.change_impact import ChangePlan, ImpactAIArtifact, ImpactRun
    from app.services.change_impact import plans
    from app.services.change_impact.scenario import ScenarioError
    if not await _enabled(session):
        return _OFF
    plan = await session.get(ChangePlan, uuid.UUID(plan_id)) if plan_id else None
    art = await session.get(ImpactAIArtifact, uuid.UUID(artifact_id)) if artifact_id else None
    run = await session.get(ImpactRun, art.run_id) if art else None
    if plan is None or art is None or run is None or run.plan_id != plan.id or art.status != "completed":
        return {"error": "impact_target_not_found", "message": "找不到這份草稿"}
    drafts = (art.output_json or {}).get("suggested_tasks") or []
    made = []
    try:
        for i in sorted(set(indices or [])):
            if 0 <= i < len(drafts):
                d = drafts[i]
                t = await plans.add_task(session, user, plan, phase=d["phase"], title=d["text"][:300],
                                         instruction=d["text"], depends_on=[], assignee_user_id=None,
                                         origin="ai_draft")
                made.append(str(t.id))
    except ScenarioError as exc:
        return {"error": exc.code, "message": str(exc)}
    await append_audit(session, actor_user_id=str(user.id), actor_ip=None, actor_user_agent="mcp",
                       object_type="change_plan", object_id=str(plan.id), action="change_task_create",
                       diff={"origin": "ai_draft", "count": len(made), "via": "mcp"}, request_id=None)
    await session.commit()
    return {"created": made}


async def _visible_plan(session: AsyncSession, user: User, plan_id: str) -> Any:
    from app.models.change_impact import ChangePlan
    from app.services.change_impact.scenario import ScenarioError, require_target_access
    try:
        plan = await session.get(ChangePlan, uuid.UUID(plan_id))
    except ValueError:
        return None
    if plan is None:
        return None
    if user.is_admin:
        return plan
    try:
        await require_target_access(session, user, plan.target_type, plan.target_id, need="read")
    except ScenarioError:
        return plan if plan.created_by == user.id else None
    return plan


async def impact_list_plans(session: AsyncSession, *, user: User, limit: int = 20,
                            lifecycle: str | None = None) -> dict[str, Any]:
    from app.models.change_impact import ChangePlan
    if not await _enabled(session):
        return _OFF
    stmt = select(ChangePlan).where(ChangePlan.archived_at.is_(None)).order_by(ChangePlan.created_at.desc())
    if lifecycle:
        stmt = stmt.where(ChangePlan.lifecycle == lifecycle)
    out = []
    for p in (await session.execute(stmt.limit(500))).scalars():
        if await _visible_plan(session, user, str(p.id)) is None:
            continue
        out.append({"id": str(p.id), "title": p.title, "scenario": p.scenario_type, "target": p.target_label,
                    "lifecycle": p.lifecycle, "latest_run_id": str(p.latest_run_id) if p.latest_run_id else None})
        if len(out) >= min(int(limit), 100):
            break
    return {"count": len(out), "plans": out}


async def impact_get_run(session: AsyncSession, *, user: User, run_id: str = "") -> dict[str, Any]:
    from app.models.change_impact import ImpactRun
    from app.services.change_impact.access import viewer
    from app.services.change_impact.ai import visible_bundle
    if not await _enabled(session):
        return _OFF
    try:
        run = await session.get(ImpactRun, uuid.UUID(run_id))
    except ValueError:
        run = None
    if run is None or await _visible_plan(session, user, str(run.plan_id)) is None:
        return {"error": "not_found"}
    b = await visible_bundle(session, run, await viewer(session, user))
    return {"run_id": str(run.id), "status": run.job_status, "decision_status": run.decision_status,
            "completeness": run.completeness, "notice": "預演結果，尚未執行任何變更；只涵蓋你目前的權限範圍",
            "visible_findings": len(b["findings"]),
            "top_findings": [{"id": str(f.id), "rule": f.rule_id, "subject": f.subject_label, "impact": f.impact,
                              "severity": f.severity, "disposition": f.disposition} for f in b["findings"][:20]],
            "gaps": [{"id": str(g.id), "reason": g.reason_code, "category": g.category} for g in b["gaps"][:20]]}


async def impact_list_findings(session: AsyncSession, *, user: User, run_id: str = "", disposition: str | None = None,
                               limit: int = 50) -> dict[str, Any]:
    from app.models.change_impact import ImpactRun
    from app.services.change_impact.access import viewer
    from app.services.change_impact.ai import visible_bundle
    if not await _enabled(session):
        return _OFF
    try:
        run = await session.get(ImpactRun, uuid.UUID(run_id))
    except ValueError:
        run = None
    if run is None or await _visible_plan(session, user, str(run.plan_id)) is None:
        return {"error": "not_found"}
    b = await visible_bundle(session, run, await viewer(session, user))
    items = [f for f in b["findings"] if not disposition or f.disposition == disposition][:min(int(limit), 200)]
    ev = {e.key: str(e.id) for e in b["evidence"]}
    return {"count": len(items), "findings": [
        {"id": str(f.id), "rule": f.rule_id, "subject": f.subject_label, "impact": f.impact, "severity": f.severity,
         "disposition": f.disposition, "strength": f.evidence_strength, "reason": f.reason_code, "params": f.params,
         "evidence_ids": [ev[k] for k in f.evidence_keys if k in ev]} for f in items]}


async def impact_get_evidence(session: AsyncSession, *, user: User, run_id: str = "",
                              evidence_id: str = "") -> dict[str, Any]:
    from app.models.change_impact import ImpactEvidence, ImpactRun
    from app.services.change_impact.access import viewer
    if not await _enabled(session):
        return _OFF
    try:
        run = await session.get(ImpactRun, uuid.UUID(run_id))
        e = await session.get(ImpactEvidence, uuid.UUID(evidence_id))
    except ValueError:
        return {"error": "not_found"}
    if run is None or e is None or e.run_id != run.id or await _visible_plan(session, user, str(run.plan_id)) is None:
        return {"error": "not_found"}
    if not (await viewer(session, user)).can(e.visibility_type, e.visibility_id):
        return {"error": "not_found"}
    return {"id": str(e.id), "source_type": e.source_type, "object_type": e.source_object_type, "label": e.label,
            "observed_at": e.observed_at.isoformat() if e.observed_at else None, "payload": e.sanitized_payload}


def _p(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required or []}


IMPACT_TOOLS: dict[str, dict[str, Any]] = {
    "impact_list_plans": {
        "fn": impact_list_plans,
        "description": "List change impact preview plans the user can see (IP renumber / device decommission dry runs).",
        "parameters": _p({"limit": {"type": "integer"}, "lifecycle": {"type": "string"}}),
    },
    "impact_get_run": {
        "fn": impact_get_run,
        "description": "Get one change impact analysis run: decision status, completeness, top findings and data gaps. "
                       "It is a dry run: nothing was changed.",
        "parameters": _p({"run_id": {"type": "string"}}, ["run_id"]),
    },
    "impact_list_findings": {
        "fn": impact_list_findings,
        "description": "List findings of a change impact run (filter by disposition: blocker, review, informational).",
        "parameters": _p({"run_id": {"type": "string"}, "disposition": {"type": "string"},
                          "limit": {"type": "integer"}}, ["run_id"]),
    },
    "impact_get_evidence": {
        "fn": impact_get_evidence,
        "description": "Get one evidence item of a change impact run.",
        "parameters": _p({"run_id": {"type": "string"}, "evidence_id": {"type": "string"}}, ["run_id", "evidence_id"]),
    },
    "impact_prepare_scenario": {
        "fn": impact_prepare_scenario,
        "description": "Prepare (validate only, nothing is saved) a change impact dry run: scenario_type ip_renumber "
                       "with target_ip or target_id and new_ip, or device_decommission with target_id. Returns a draft "
                       "and a draft_token. If the address exists in several overlapping subnets, it returns candidates; "
                       "never guess.",
        "parameters": _p({"scenario_type": {"type": "string", "enum": ["ip_renumber", "device_decommission"]},
                          "target_ip": {"type": "string"}, "target_id": {"type": "string"},
                          "new_ip": {"type": "string"}, "target_subnet_id": {"type": "string"},
                          "title": {"type": "string"}}),
    },
    "impact_create_plan": {
        "fn": impact_create_plan,
        "description": "ADMIN ONLY. Create a change impact plan from a prepared draft. Pass the draft fields exactly "
                       "as returned by impact_prepare_scenario plus its draft_token.",
        "parameters": _p({"draft_token": {"type": "string"}, "scenario_type": {"type": "string"},
                          "target_type": {"type": "string"}, "target_id": {"type": "string"},
                          "parameters": {"type": "object"}, "title": {"type": "string"}},
                         ["draft_token", "scenario_type", "target_type", "target_id"]),
    },
    "impact_start_run": {
        "fn": impact_start_run,
        "description": "ADMIN ONLY. Start the analysis of a change impact plan (read-only dry run).",
        "parameters": _p({"plan_id": {"type": "string"}}, ["plan_id"]),
    },
    "impact_accept_task_draft": {
        "fn": impact_accept_task_draft,
        "description": "ADMIN ONLY. Save selected AI-drafted tasks (by index) into a change impact plan.",
        "parameters": _p({"plan_id": {"type": "string"}, "artifact_id": {"type": "string"},
                          "indices": {"type": "array", "items": {"type": "integer"}}},
                         ["plan_id", "artifact_id", "indices"]),
    },
}

IMPACT_MUTATING = frozenset({"impact_create_plan", "impact_start_run", "impact_accept_task_draft"})
