"""變更影響預演（docs/SPEC_CHANGE_IMPACT_zh-TW.md，M1）。

預演只讀：不改任何來源設備或 IPAM 資料。計畫（change_plans）每次修改產生新的版本（change_plan_revisions，
不可變）；每次分析是一個 impact_runs，結果（證據、關係、發現、缺口）以 run 為單位保存成快照，
之後來源資料怎麼變，這份結果都不會變。覆核（impact_reviews）只能新增。

刻意的設計：
- 單位（customer_id）就是規格的 tenant；IP 沒有 VRF 欄位，命名空間由 IP 物件 → 子網路 → VRF 推得
- change_plans.latest_run_id 不設外鍵：impact_runs.plan_id 已經指回來，兩邊都設會形成循環，
  系統匯出入（往後指的外鍵要兩趟寫入）會踩到
- 沒有工作佇列：impact_runs 自帶 job_status／attempt／heartbeat_at，由 services/change_impact/jobs.py 回收
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

SCENARIOS = ("ip_renumber", "device_decommission")
TARGET_TYPES = ("ip_address", "device")
LIFECYCLE = ("draft", "in_review", "approved", "in_progress", "verified", "closed", "cancelled")
JOB_STATUS = ("queued", "snapshotting", "extracting", "analyzing", "persisting",
              "completed", "partial", "failed", "cancelled")
JOB_ACTIVE = ("queued", "snapshotting", "extracting", "analyzing", "persisting")
DECISION = ("blocked", "needs_review", "no_known_blocker")
COMPLETENESS = ("complete", "partial", "failed")
IMPACT = ("reference_only", "change_required", "potential_disruption", "modeled_disruption",
          "redundancy_unverified", "unknown")
STRENGTH = ("explicit", "corroborated", "inferred", "manual_assumption")
SEVERITY = ("critical", "high", "medium", "low", "info")
DISPOSITION = ("blocker", "review", "informational")
TASK_PHASE = ("precheck", "change", "rollback", "verify")
TASK_ORIGIN = ("rule_template", "ai_draft", "manual")
TASK_STATE = ("pending", "in_progress", "done", "blocked", "skipped")
REVIEW_DECISION = ("approve", "reject", "accept_risk", "request_changes")
AI_ARTIFACTS = ("summary", "checklist", "explanation", "answer")
AI_STATUS = ("pending", "running", "completed", "failed", "fallback")


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in values)})"


def _fk_ix(table: str, col: str) -> Index:
    """外鍵欄位都要有索引（tests/test_fk_indexes.py）：刪掉被參照的使用者或作業時才不會整表掃描。
    可為 NULL 的用部分索引。"""
    return Index(f"ix_{table}_{col}", col, postgresql_where=f"{col} IS NOT NULL")


class ChangePlan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "change_plans"

    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("customers.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    scenario_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # 建立時的顯示名稱（IP 或裝置名稱）：根目標之後被刪掉，清單照樣看得懂
    target_label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    planned_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    planned_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    reviewer_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    lifecycle: Mapped[str] = mapped_column(String(16), nullable=False, default="draft")
    latest_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))   # 刻意不設外鍵（見檔頭）
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    request_hash: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        CheckConstraint(_in("scenario_type", SCENARIOS), name="scenario_type"),
        CheckConstraint(_in("target_type", TARGET_TYPES), name="target_type"),
        CheckConstraint(_in("lifecycle", LIFECYCLE), name="lifecycle"),
        Index("ix_change_plans_customer_created", "customer_id", "created_at"),
        Index("ix_change_plans_target", "target_type", "target_id"),
        Index("uq_change_plans_idem", "created_by", "idempotency_key", unique=True,
              postgresql_where="idempotency_key IS NOT NULL"),
        _fk_ix("change_plans", "created_by"),
        _fk_ix("change_plans", "owner_user_id"),
        _fk_ix("change_plans", "reviewer_user_id"),
    )


class ChangePlanRevision(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "change_plan_revisions"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("change_plans.id", ondelete="CASCADE"), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (UniqueConstraint("plan_id", "revision", name="uq_change_plan_revision"),
                      _fk_ix("change_plan_revisions", "created_by"))


class ImpactRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "impact_runs"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("change_plans.id", ondelete="CASCADE"), nullable=False)
    plan_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    job_status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    decision_status: Mapped[str | None] = mapped_column(String(16))
    completeness: Mapped[str | None] = mapped_column(String(16))
    # 這次分析涵蓋了哪些來源、各來源的狀態與時效（規格 §4.2）
    scope_manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    source_watermarks: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    scenario_hash: Mapped[str | None] = mapped_column(String(64))
    engine_version: Mapped[str | None] = mapped_column(String(16))
    rules_version: Mapped[str | None] = mapped_column(String(16))
    # 分析當下的可見範圍：之後讀結果時範圍變了，不可以用舊授權看結果
    visible_scope_hash: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    background_task_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("background_tasks.id", ondelete="SET NULL"))
    stage: Mapped[str | None] = mapped_column(String(32))
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    truncation: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64))
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    request_hash: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        CheckConstraint(_in("job_status", JOB_STATUS), name="job_status"),
        CheckConstraint(f"decision_status IS NULL OR {_in('decision_status', DECISION)}", name="decision_status"),
        CheckConstraint(f"completeness IS NULL OR {_in('completeness', COMPLETENESS)}", name="completeness"),
        Index("ix_impact_runs_plan_created", "plan_id", "created_at"),
        Index("ix_impact_runs_job_status", "job_status"),
        Index("uq_impact_runs_idem", "requested_by", "idempotency_key", unique=True,
              postgresql_where="idempotency_key IS NOT NULL"),
        _fk_ix("impact_runs", "requested_by"),
        _fk_ix("impact_runs", "background_task_id"),
    )


class ImpactEvidence(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "impact_evidence"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("impact_runs.id", ondelete="CASCADE"), nullable=False)
    # 同一個 run 內的穩定鍵（例：dns_record:<uuid>）：發現以它引用證據，AI 也只能引用這些
    key: Mapped[str] = mapped_column(String(160), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    integration_ref: Mapped[str | None] = mapped_column(String(80))
    source_object_type: Mapped[str] = mapped_column(String(48), nullable=False)
    source_object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_object_key: Mapped[str | None] = mapped_column(String(255))
    label: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 已去密的最小資料：解析後的引用與判定依據，不放密碼、金鑰、整份設定
    sanitized_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    freshness: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    # 讀取時要重新檢查的可見性：物件型別與 id（IP 物件、子網路、裝置）；全域來源標 global
    visibility_type: Mapped[str | None] = mapped_column(String(16))
    visibility_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    __table_args__ = (
        UniqueConstraint("run_id", "key", name="uq_impact_evidence_key"),
        Index("ix_impact_evidence_object", "source_object_type", "source_object_id"),
    )


class ImpactRelation(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "impact_relations"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("impact_runs.id", ondelete="CASCADE"), nullable=False)
    from_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    to_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    relation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(120))
    evidence_keys: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    strength: Mapped[str] = mapped_column(String(24), nullable=False)

    __table_args__ = (
        Index("ix_impact_relations_from", "run_id", "from_ref"),
        Index("ix_impact_relations_to", "run_id", "to_ref"),
    )


class ImpactFinding(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "impact_findings"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("impact_runs.id", ondelete="CASCADE"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(8), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(48), nullable=False)
    subject_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    subject_key: Mapped[str | None] = mapped_column(String(255))
    subject_label: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    match_kind: Mapped[str | None] = mapped_column(String(24))
    impact: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_strength: Mapped[str] = mapped_column(String(24), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    evidence_keys: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    path_refs: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    suggested_action: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    sort_key: Mapped[str] = mapped_column(String(120), nullable=False)
    visibility_type: Mapped[str | None] = mapped_column(String(16))
    visibility_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    __table_args__ = (
        CheckConstraint(_in("impact", IMPACT), name="impact"),
        CheckConstraint(_in("severity", SEVERITY), name="severity"),
        CheckConstraint(_in("disposition", DISPOSITION), name="disposition"),
        CheckConstraint(_in("evidence_strength", STRENGTH), name="evidence_strength"),
        Index("ix_impact_findings_run_sort", "run_id", "sort_key"),
        Index("ix_impact_findings_run_disposition", "run_id", "disposition"),
    )


class ImpactGap(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "impact_gaps"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("impact_runs.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    source_scope: Mapped[str | None] = mapped_column(String(120))
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    affected_analysis: Mapped[str | None] = mapped_column(String(64))
    remediation_hint: Mapped[str | None] = mapped_column(String(64))
    sort_key: Mapped[str] = mapped_column(String(120), nullable=False, default="")

    __table_args__ = (Index("ix_impact_gaps_run", "run_id"),)


class ChangeTask(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "change_tasks"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("change_plans.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("impact_runs.id", ondelete="SET NULL"))
    phase: Mapped[str] = mapped_column(String(16), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    instruction: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # 模板待辦存代碼與參數，畫面依語系翻譯；手動與 AI 草稿存文字
    template_code: Mapped[str | None] = mapped_column(String(64))
    template_params: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_keys: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    finding_ids: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    depends_on: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    completed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completion_note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(_in("phase", TASK_PHASE), name="phase"),
        CheckConstraint(_in("origin", TASK_ORIGIN), name="origin"),
        CheckConstraint(_in("state", TASK_STATE), name="state"),
        Index("ix_change_tasks_plan_phase", "plan_id", "phase"),
        _fk_ix("change_tasks", "run_id"),
        _fk_ix("change_tasks", "assignee_user_id"),
        _fk_ix("change_tasks", "completed_by"),
    )


class ImpactReview(Base, UUIDPrimaryKeyMixin):
    """覆核決策：綁定計畫版本、run 與快照雜湊。只能新增（資料庫觸發器擋 UPDATE／DELETE）。"""

    __tablename__ = "impact_reviews"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("change_plans.id", ondelete="CASCADE"), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # 逐項處置：{finding_id: {"action": "...", "note": "..."}}
    dispositions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (CheckConstraint(_in("decision", REVIEW_DECISION), name="decision"),
                      Index("ix_impact_reviews_plan", "plan_id", "created_at"))


class ImpactAIArtifact(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "impact_ai_artifacts"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("impact_runs.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    question: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str | None] = mapped_column(String(32))
    model: Mapped[str | None] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(16), nullable=False)
    language: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_hash: Mapped[str | None] = mapped_column(String(64))
    input_hash: Mapped[str | None] = mapped_column(String(64))
    output_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    validation_state: Mapped[str | None] = mapped_column(String(24))
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(_in("artifact_type", AI_ARTIFACTS), name="artifact_type"),
        CheckConstraint(_in("status", AI_STATUS), name="status"),
        Index("ix_impact_ai_run_type", "run_id", "artifact_type"),
        _fk_ix("impact_ai_artifacts", "requested_by"),
    )
