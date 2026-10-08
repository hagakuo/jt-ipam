"""change_impact：變更影響預演 M1（docs/SPEC_CHANGE_IMPACT_zh-TW.md）

計畫與不可變的版本、每次分析的快照（證據、關係、發現、缺口）、待辦、只能新增的覆核、AI 產出。
預演只讀，不改任何來源資料。功能預設關閉（system_settings 的 change_impact 鍵，在網頁開）。

Revision ID: 0187_change_impact
Revises: 0186_unmanaged_sightings
"""

from __future__ import annotations

from alembic import op

revision: str = "0187_change_impact"
down_revision: str | None = "0186_unmanaged_sightings"
branch_labels: str | None = None
depends_on: str | None = None

_TABLES = ("change_plans", "change_plan_revisions", "impact_runs", "impact_evidence", "impact_relations",
           "impact_findings", "impact_gaps", "change_tasks", "impact_reviews", "impact_ai_artifacts")


# 建表語句在寫這個 migration 時由模型產生後固定下來：之後改模型不會改變這個 migration 建出來的東西
_DDL = (
    """
    CREATE TABLE change_plans (
    	customer_id UUID, 
    	title VARCHAR(200) NOT NULL, 
    	scenario_type VARCHAR(32) NOT NULL, 
    	target_type VARCHAR(16) NOT NULL, 
    	target_id UUID NOT NULL, 
    	target_label VARCHAR(255) NOT NULL, 
    	parameters JSONB NOT NULL, 
    	planned_start TIMESTAMP WITH TIME ZONE, 
    	planned_end TIMESTAMP WITH TIME ZONE, 
    	created_by UUID, 
    	owner_user_id UUID, 
    	reviewer_user_id UUID, 
    	revision INTEGER NOT NULL, 
    	lifecycle VARCHAR(16) NOT NULL, 
    	latest_run_id UUID, 
    	archived_at TIMESTAMP WITH TIME ZONE, 
    	idempotency_key VARCHAR(128), 
    	request_hash VARCHAR(64), 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	CONSTRAINT pk_change_plans PRIMARY KEY (id), 
    	CONSTRAINT ck_change_plans_scenario_type CHECK (scenario_type IN ('ip_renumber', 'device_decommission')), 
    	CONSTRAINT ck_change_plans_target_type CHECK (target_type IN ('ip_address', 'device')), 
    	CONSTRAINT ck_change_plans_lifecycle CHECK (lifecycle IN ('draft', 'in_review', 'approved', 'in_progress', 'verified', 'closed', 'cancelled')), 
    	CONSTRAINT fk_change_plans_customer_id_customers FOREIGN KEY(customer_id) REFERENCES customers (id) ON DELETE SET NULL, 
    	CONSTRAINT fk_change_plans_created_by_users FOREIGN KEY(created_by) REFERENCES users (id) ON DELETE SET NULL, 
    	CONSTRAINT fk_change_plans_owner_user_id_users FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE SET NULL, 
    	CONSTRAINT fk_change_plans_reviewer_user_id_users FOREIGN KEY(reviewer_user_id) REFERENCES users (id) ON DELETE SET NULL
    )
    """,
    """
    CREATE INDEX ix_change_plans_created_by ON change_plans (created_by) WHERE created_by IS NOT NULL
    """,
    """
    CREATE INDEX ix_change_plans_customer_created ON change_plans (customer_id, created_at)
    """,
    """
    CREATE INDEX ix_change_plans_owner_user_id ON change_plans (owner_user_id) WHERE owner_user_id IS NOT NULL
    """,
    """
    CREATE INDEX ix_change_plans_reviewer_user_id ON change_plans (reviewer_user_id) WHERE reviewer_user_id IS NOT NULL
    """,
    """
    CREATE INDEX ix_change_plans_target ON change_plans (target_type, target_id)
    """,
    """
    CREATE UNIQUE INDEX uq_change_plans_idem ON change_plans (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL
    """,
    """
    CREATE TABLE change_plan_revisions (
    	plan_id UUID NOT NULL, 
    	revision INTEGER NOT NULL, 
    	payload JSONB NOT NULL, 
    	created_by UUID, 
    	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_change_plan_revisions PRIMARY KEY (id), 
    	CONSTRAINT uq_change_plan_revision UNIQUE (plan_id, revision), 
    	CONSTRAINT fk_change_plan_revisions_plan_id_change_plans FOREIGN KEY(plan_id) REFERENCES change_plans (id) ON DELETE CASCADE, 
    	CONSTRAINT fk_change_plan_revisions_created_by_users FOREIGN KEY(created_by) REFERENCES users (id) ON DELETE SET NULL
    )
    """,
    """
    CREATE INDEX ix_change_plan_revisions_created_by ON change_plan_revisions (created_by) WHERE created_by IS NOT NULL
    """,
    """
    CREATE TABLE impact_runs (
    	plan_id UUID NOT NULL, 
    	plan_revision INTEGER NOT NULL, 
    	job_status VARCHAR(16) NOT NULL, 
    	decision_status VARCHAR(16), 
    	completeness VARCHAR(16), 
    	scope_manifest JSONB NOT NULL, 
    	source_watermarks JSONB NOT NULL, 
    	snapshot_hash VARCHAR(64), 
    	scenario_hash VARCHAR(64), 
    	engine_version VARCHAR(16), 
    	rules_version VARCHAR(16), 
    	visible_scope_hash VARCHAR(64), 
    	requested_by UUID, 
    	background_task_id UUID, 
    	stage VARCHAR(32), 
    	attempt INTEGER NOT NULL, 
    	heartbeat_at TIMESTAMP WITH TIME ZONE, 
    	cancel_requested_at TIMESTAMP WITH TIME ZONE, 
    	started_at TIMESTAMP WITH TIME ZONE, 
    	completed_at TIMESTAMP WITH TIME ZONE, 
    	expires_at TIMESTAMP WITH TIME ZONE, 
    	truncated BOOLEAN NOT NULL, 
    	truncation JSONB, 
    	counts JSONB NOT NULL, 
    	error_code VARCHAR(64), 
    	idempotency_key VARCHAR(128), 
    	request_hash VARCHAR(64), 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	CONSTRAINT pk_impact_runs PRIMARY KEY (id), 
    	CONSTRAINT ck_impact_runs_job_status CHECK (job_status IN ('queued', 'snapshotting', 'extracting', 'analyzing', 'persisting', 'completed', 'partial', 'failed', 'cancelled')), 
    	CONSTRAINT ck_impact_runs_decision_status CHECK (decision_status IS NULL OR decision_status IN ('blocked', 'needs_review', 'no_known_blocker')), 
    	CONSTRAINT ck_impact_runs_completeness CHECK (completeness IS NULL OR completeness IN ('complete', 'partial', 'failed')), 
    	CONSTRAINT fk_impact_runs_plan_id_change_plans FOREIGN KEY(plan_id) REFERENCES change_plans (id) ON DELETE CASCADE, 
    	CONSTRAINT fk_impact_runs_requested_by_users FOREIGN KEY(requested_by) REFERENCES users (id) ON DELETE SET NULL, 
    	CONSTRAINT fk_impact_runs_background_task_id_background_tasks FOREIGN KEY(background_task_id) REFERENCES background_tasks (id) ON DELETE SET NULL
    )
    """,
    """
    CREATE INDEX ix_impact_runs_background_task_id ON impact_runs (background_task_id) WHERE background_task_id IS NOT NULL
    """,
    """
    CREATE INDEX ix_impact_runs_job_status ON impact_runs (job_status)
    """,
    """
    CREATE INDEX ix_impact_runs_plan_created ON impact_runs (plan_id, created_at)
    """,
    """
    CREATE INDEX ix_impact_runs_requested_by ON impact_runs (requested_by) WHERE requested_by IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX uq_impact_runs_idem ON impact_runs (requested_by, idempotency_key) WHERE idempotency_key IS NOT NULL
    """,
    """
    CREATE TABLE impact_evidence (
    	run_id UUID NOT NULL, 
    	key VARCHAR(160) NOT NULL, 
    	source_type VARCHAR(32) NOT NULL, 
    	integration_ref VARCHAR(80), 
    	source_object_type VARCHAR(48) NOT NULL, 
    	source_object_id UUID, 
    	source_object_key VARCHAR(255), 
    	label VARCHAR(300) NOT NULL, 
    	observed_at TIMESTAMP WITH TIME ZONE, 
    	collected_at TIMESTAMP WITH TIME ZONE, 
    	sanitized_payload JSONB NOT NULL, 
    	payload_hash VARCHAR(64) NOT NULL, 
    	freshness VARCHAR(16) NOT NULL, 
    	visibility_type VARCHAR(16), 
    	visibility_id UUID, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_impact_evidence PRIMARY KEY (id), 
    	CONSTRAINT uq_impact_evidence_key UNIQUE (run_id, key), 
    	CONSTRAINT fk_impact_evidence_run_id_impact_runs FOREIGN KEY(run_id) REFERENCES impact_runs (id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX ix_impact_evidence_object ON impact_evidence (source_object_type, source_object_id)
    """,
    """
    CREATE TABLE impact_relations (
    	run_id UUID NOT NULL, 
    	from_ref VARCHAR(160) NOT NULL, 
    	to_ref VARCHAR(160) NOT NULL, 
    	relation_type VARCHAR(32) NOT NULL, 
    	namespace VARCHAR(120), 
    	evidence_keys JSONB NOT NULL, 
    	strength VARCHAR(24) NOT NULL, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_impact_relations PRIMARY KEY (id), 
    	CONSTRAINT fk_impact_relations_run_id_impact_runs FOREIGN KEY(run_id) REFERENCES impact_runs (id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX ix_impact_relations_from ON impact_relations (run_id, from_ref)
    """,
    """
    CREATE INDEX ix_impact_relations_to ON impact_relations (run_id, to_ref)
    """,
    """
    CREATE TABLE impact_findings (
    	run_id UUID NOT NULL, 
    	rule_id VARCHAR(64) NOT NULL, 
    	rule_version VARCHAR(8) NOT NULL, 
    	subject_type VARCHAR(48) NOT NULL, 
    	subject_id UUID, 
    	subject_key VARCHAR(255), 
    	subject_label VARCHAR(300) NOT NULL, 
    	category VARCHAR(24) NOT NULL, 
    	match_kind VARCHAR(24), 
    	impact VARCHAR(32) NOT NULL, 
    	severity VARCHAR(16) NOT NULL, 
    	disposition VARCHAR(16) NOT NULL, 
    	evidence_strength VARCHAR(24) NOT NULL, 
    	reason_code VARCHAR(64) NOT NULL, 
    	params JSONB NOT NULL, 
    	evidence_keys JSONB NOT NULL, 
    	path_refs JSONB NOT NULL, 
    	suggested_action JSONB, 
    	fingerprint VARCHAR(64) NOT NULL, 
    	sort_key VARCHAR(120) NOT NULL, 
    	visibility_type VARCHAR(16), 
    	visibility_id UUID, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_impact_findings PRIMARY KEY (id), 
    	CONSTRAINT ck_impact_findings_impact CHECK (impact IN ('reference_only', 'change_required', 'potential_disruption', 'modeled_disruption', 'redundancy_unverified', 'unknown')), 
    	CONSTRAINT ck_impact_findings_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')), 
    	CONSTRAINT ck_impact_findings_disposition CHECK (disposition IN ('blocker', 'review', 'informational')), 
    	CONSTRAINT ck_impact_findings_evidence_strength CHECK (evidence_strength IN ('explicit', 'corroborated', 'inferred', 'manual_assumption')), 
    	CONSTRAINT fk_impact_findings_run_id_impact_runs FOREIGN KEY(run_id) REFERENCES impact_runs (id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX ix_impact_findings_run_disposition ON impact_findings (run_id, disposition)
    """,
    """
    CREATE INDEX ix_impact_findings_run_sort ON impact_findings (run_id, sort_key)
    """,
    """
    CREATE TABLE impact_gaps (
    	run_id UUID NOT NULL, 
    	category VARCHAR(24) NOT NULL, 
    	source_scope VARCHAR(120), 
    	reason_code VARCHAR(64) NOT NULL, 
    	params JSONB NOT NULL, 
    	affected_analysis VARCHAR(64), 
    	remediation_hint VARCHAR(64), 
    	sort_key VARCHAR(120) NOT NULL, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_impact_gaps PRIMARY KEY (id), 
    	CONSTRAINT fk_impact_gaps_run_id_impact_runs FOREIGN KEY(run_id) REFERENCES impact_runs (id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX ix_impact_gaps_run ON impact_gaps (run_id)
    """,
    """
    CREATE TABLE change_tasks (
    	plan_id UUID NOT NULL, 
    	run_id UUID, 
    	phase VARCHAR(16) NOT NULL, 
    	position INTEGER NOT NULL, 
    	title VARCHAR(300) NOT NULL, 
    	instruction TEXT NOT NULL, 
    	template_code VARCHAR(64), 
    	template_params JSONB, 
    	origin VARCHAR(16) NOT NULL, 
    	evidence_keys JSONB NOT NULL, 
    	finding_ids JSONB NOT NULL, 
    	depends_on JSONB NOT NULL, 
    	assignee_user_id UUID, 
    	state VARCHAR(16) NOT NULL, 
    	version INTEGER NOT NULL, 
    	completed_by UUID, 
    	completed_at TIMESTAMP WITH TIME ZONE, 
    	completion_note TEXT, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	CONSTRAINT pk_change_tasks PRIMARY KEY (id), 
    	CONSTRAINT ck_change_tasks_phase CHECK (phase IN ('precheck', 'change', 'rollback', 'verify')), 
    	CONSTRAINT ck_change_tasks_origin CHECK (origin IN ('rule_template', 'ai_draft', 'manual')), 
    	CONSTRAINT ck_change_tasks_state CHECK (state IN ('pending', 'in_progress', 'done', 'blocked', 'skipped')), 
    	CONSTRAINT fk_change_tasks_plan_id_change_plans FOREIGN KEY(plan_id) REFERENCES change_plans (id) ON DELETE CASCADE, 
    	CONSTRAINT fk_change_tasks_run_id_impact_runs FOREIGN KEY(run_id) REFERENCES impact_runs (id) ON DELETE SET NULL, 
    	CONSTRAINT fk_change_tasks_assignee_user_id_users FOREIGN KEY(assignee_user_id) REFERENCES users (id) ON DELETE SET NULL, 
    	CONSTRAINT fk_change_tasks_completed_by_users FOREIGN KEY(completed_by) REFERENCES users (id) ON DELETE SET NULL
    )
    """,
    """
    CREATE INDEX ix_change_tasks_assignee_user_id ON change_tasks (assignee_user_id) WHERE assignee_user_id IS NOT NULL
    """,
    """
    CREATE INDEX ix_change_tasks_completed_by ON change_tasks (completed_by) WHERE completed_by IS NOT NULL
    """,
    """
    CREATE INDEX ix_change_tasks_plan_phase ON change_tasks (plan_id, phase)
    """,
    """
    CREATE INDEX ix_change_tasks_run_id ON change_tasks (run_id) WHERE run_id IS NOT NULL
    """,
    """
    CREATE TABLE impact_reviews (
    	plan_id UUID NOT NULL, 
    	revision INTEGER NOT NULL, 
    	run_id UUID, 
    	snapshot_hash VARCHAR(64), 
    	reviewer_id UUID, 
    	decision VARCHAR(24) NOT NULL, 
    	rationale TEXT NOT NULL, 
    	dispositions JSONB NOT NULL, 
    	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_impact_reviews PRIMARY KEY (id), 
    	CONSTRAINT ck_impact_reviews_decision CHECK (decision IN ('approve', 'reject', 'accept_risk', 'request_changes')), 
    	CONSTRAINT fk_impact_reviews_plan_id_change_plans FOREIGN KEY(plan_id) REFERENCES change_plans (id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX ix_impact_reviews_plan ON impact_reviews (plan_id, created_at)
    """,
    """
    CREATE TABLE impact_ai_artifacts (
    	run_id UUID NOT NULL, 
    	artifact_type VARCHAR(16) NOT NULL, 
    	status VARCHAR(16) NOT NULL, 
    	question TEXT, 
    	provider VARCHAR(32), 
    	model VARCHAR(128), 
    	prompt_version VARCHAR(16) NOT NULL, 
    	language VARCHAR(16) NOT NULL, 
    	scope_hash VARCHAR(64), 
    	input_hash VARCHAR(64), 
    	output_json JSONB, 
    	validation_state VARCHAR(24), 
    	truncated BOOLEAN NOT NULL, 
    	requested_by UUID, 
    	generated_at TIMESTAMP WITH TIME ZONE, 
    	error_code VARCHAR(64), 
    	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
    	id UUID DEFAULT gen_random_uuid() NOT NULL, 
    	CONSTRAINT pk_impact_ai_artifacts PRIMARY KEY (id), 
    	CONSTRAINT ck_impact_ai_artifacts_artifact_type CHECK (artifact_type IN ('summary', 'checklist', 'explanation', 'answer')), 
    	CONSTRAINT ck_impact_ai_artifacts_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'fallback')), 
    	CONSTRAINT fk_impact_ai_artifacts_run_id_impact_runs FOREIGN KEY(run_id) REFERENCES impact_runs (id) ON DELETE CASCADE, 
    	CONSTRAINT fk_impact_ai_artifacts_requested_by_users FOREIGN KEY(requested_by) REFERENCES users (id) ON DELETE SET NULL
    )
    """,
    """
    CREATE INDEX ix_impact_ai_artifacts_requested_by ON impact_ai_artifacts (requested_by) WHERE requested_by IS NOT NULL
    """,
    """
    CREATE INDEX ix_impact_ai_run_type ON impact_ai_artifacts (run_id, artifact_type)
    """,
)


def upgrade() -> None:
    for stmt in _DDL:
        op.execute(stmt)
    # 覆核只能新增：改寫既有決策等於竄改覆核記錄。刪除只發生在保存期限到期、整份計畫一起清除
    op.execute("""
        CREATE OR REPLACE FUNCTION impact_reviews_no_update() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'impact_reviews is append-only: UPDATE is not allowed (id=%)', OLD.id
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER impact_reviews_no_update
        BEFORE UPDATE ON impact_reviews
        FOR EACH ROW EXECUTE FUNCTION impact_reviews_no_update()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS impact_reviews_no_update ON impact_reviews")
    op.execute("DROP FUNCTION IF EXISTS impact_reviews_no_update()")
    for name in reversed(_TABLES):
        op.drop_table(name)
