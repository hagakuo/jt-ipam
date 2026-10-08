"""匯出：JSON（給系統）與 Markdown（給人看、貼到變更單）。

每次下載都依「現在這個人」重新過濾（規格 §11.1 第 5 點）；檔案即時產生、不存檔，所以不需要下載票證。
Markdown 只放引擎的結論與證據原文，不放 AI 的文字（AI 解說在畫面上另外看）。
"""

from __future__ import annotations

import json
from typing import Any

from app.models.change_impact import ChangePlan, ChangeTask, ImpactRun

_SEV = {"critical": "嚴重", "high": "高", "medium": "中", "low": "低", "info": "資訊"}
_DISP = {"blocker": "阻擋", "review": "需覆核", "informational": "參考"}
_DECISION = {"blocked": "存在阻擋項目", "needs_review": "需覆核", "no_known_blocker": "未發現已知阻擋"}


def _iso(d: Any) -> str | None:
    return d.isoformat() if d else None


def as_json(plan: ChangePlan, run: ImpactRun, bundle: dict[str, Any], tasks: list[ChangeTask],
            *, scope_changed: bool) -> dict[str, Any]:
    ev_ids = {e.key: str(e.id) for e in bundle["evidence"]}
    return {
        "schema_version": "1",
        "notice": "dry_run_no_changes_executed",
        "plan": {"id": str(plan.id), "title": plan.title, "scenario_type": plan.scenario_type,
                 "target": plan.target_label, "parameters": plan.parameters, "revision": plan.revision,
                 "lifecycle": plan.lifecycle, "planned_start": _iso(plan.planned_start),
                 "planned_end": _iso(plan.planned_end)},
        "run": {"id": str(run.id), "plan_revision": run.plan_revision, "status": run.job_status,
                "decision_status": run.decision_status, "completeness": run.completeness,
                "snapshot_hash": run.snapshot_hash, "scenario_hash": run.scenario_hash,
                "engine_version": run.engine_version, "rules_version": run.rules_version,
                "completed_at": _iso(run.completed_at), "expires_at": _iso(run.expires_at),
                "truncated": run.truncated, "permission_scope_changed": scope_changed,
                "scope_limited_to_current_permissions": True},
        "findings": [{"id": str(f.id), "rule_id": f.rule_id, "rule_version": f.rule_version,
                      "category": f.category, "subject_type": f.subject_type, "subject": f.subject_label,
                      "impact": f.impact, "severity": f.severity, "disposition": f.disposition,
                      "evidence_strength": f.evidence_strength, "reason_code": f.reason_code, "params": f.params,
                      "match_kind": f.match_kind, "evidence_ids": [ev_ids[k] for k in f.evidence_keys if k in ev_ids],
                      "relationship_path": f.path_refs, "suggested_action": f.suggested_action,
                      "fingerprint": f.fingerprint} for f in bundle["findings"]],
        "evidence": [{"id": str(e.id), "source_type": e.source_type, "integration_ref": e.integration_ref,
                      "object_type": e.source_object_type, "object_id": str(e.source_object_id)
                      if e.source_object_id else None, "label": e.label, "observed_at": _iso(e.observed_at),
                      "collected_at": _iso(e.collected_at), "freshness": e.freshness,
                      "payload": e.sanitized_payload, "payload_hash": e.payload_hash} for e in bundle["evidence"]],
        "gaps": [{"id": str(g.id), "category": g.category, "reason_code": g.reason_code, "params": g.params,
                  "source_scope": g.source_scope, "affected_analysis": g.affected_analysis} for g in bundle["gaps"]],
        "tasks": [{"id": str(t.id), "phase": t.phase, "title": t.title, "template_code": t.template_code,
                   "template_params": t.template_params, "instruction": t.instruction, "origin": t.origin,
                   "state": t.state, "completed_at": _iso(t.completed_at), "completion_note": t.completion_note}
                  for t in tasks],
    }


def _cell(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")[:200]


def as_markdown(plan: ChangePlan, run: ImpactRun, bundle: dict[str, Any], tasks: list[ChangeTask],
                *, scope_changed: bool) -> str:
    c = run.counts or {}
    out = [f"# 變更影響預演：{plan.title}", "",
           "> 這是預演結果，尚未執行任何變更。結果僅涵蓋產生時與下載時的授權範圍。", "",
           f"- 情境：{plan.scenario_type}；目標：{plan.target_label}；計畫版本 {plan.revision}",
           f"- 分析：{_iso(run.completed_at) or '-'}（引擎 {run.engine_version}、規則 {run.rules_version}），"
           f"有效至 {_iso(run.expires_at) or '-'}",
           f"- 決策狀態：{_DECISION.get(run.decision_status or '', run.decision_status or '-')}；"
           f"完整性：{run.completeness or '-'}",
           f"- 發現 {c.get('findings', 0)}（阻擋 {c.get('blockers', 0)}、需覆核 {c.get('review', 0)}、"
           f"參考 {c.get('informational', 0)}）；資料缺口 {len(bundle['gaps'])}"]
    if plan.parameters.get("new_ip"):
        out.append(f"- 新位址：{plan.parameters['new_ip']}")
    if scope_changed:
        out.append("- 注意：你的權限範圍與產生這份結果時不同，看不到的項目已省略。")
    out += ["", "## 影響清單", "", "| 處置 | 嚴重度 | 類別 | 物件 | 影響 | 證據強度 | 原因碼 |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for f in bundle["findings"]:
        out.append(f"| {_DISP.get(f.disposition, f.disposition)} | {_SEV.get(f.severity, f.severity)} | "
                   f"{_cell(f.category)} | {_cell(f.subject_label)} | {_cell(f.impact)} | "
                   f"{_cell(f.evidence_strength)} | {_cell(f.reason_code)} |")
    if not bundle["findings"]:
        out.append("| - | - | - | 在本次可取得且支援的資料中，未找到符合條件的引用；仍須查看資料缺口 | - | - | - |")
    out += ["", "## 資料缺口", ""]
    for g in bundle["gaps"]:
        params = ", ".join(f"{k}={v}" for k, v in (g.params or {}).items() if v not in (None, ""))
        out.append(f"- [{g.category}] {g.reason_code}" + (f"（{_cell(params)}）" if params else ""))
    if not bundle["gaps"]:
        out.append("- 無")
    out += ["", "## 待辦（人工操作）", ""]
    for t in sorted(tasks, key=lambda t: (["precheck", "change", "rollback", "verify"].index(t.phase), t.position)):
        mark = "x" if t.state in ("done", "skipped") else " "
        label = t.template_code or t.title
        params = json.dumps(t.template_params, ensure_ascii=False) if t.template_params else ""
        out.append(f"- [{mark}] {t.phase}：{_cell(label)} {params}".rstrip())
    out += ["", "## 證據", ""]
    for e in bundle["evidence"]:
        out.append(f"- `{_cell(e.key)}` {_cell(e.label)}（{e.source_type}，觀察 {_iso(e.observed_at) or '-'}，"
                   f"收錄 {_iso(e.collected_at) or '-'}，{e.freshness}）")
    return "\n".join(out) + "\n"
