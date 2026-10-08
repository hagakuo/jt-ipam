import { apiClient } from "./client";

/**
 * 變更影響預演（docs/SPEC_CHANGE_IMPACT_zh-TW.md；後端 endpoints/change_impact.py）。
 * 預演只讀：不會改任何來源設備。結果每次讀取都依目前權限重新過濾。
 */
export type ScenarioType = "ip_renumber" | "device_decommission";
export type Lifecycle = "draft" | "in_review" | "approved" | "in_progress" | "verified" | "closed" | "cancelled";
export type JobStatus = "queued" | "snapshotting" | "extracting" | "analyzing" | "persisting"
  | "completed" | "partial" | "failed" | "cancelled";

export interface ImpactSettings {
  enabled: boolean;
  ai_available: boolean;
  config?: Record<string, any>;
}
export interface ChangePlan {
  id: string; title: string; scenario_type: ScenarioType; target_type: "ip_address" | "device";
  target_id: string; target_label: string; parameters: { new_ip?: string; target_subnet_id?: string };
  planned_start: string | null; planned_end: string | null; created_by: string | null;
  owner_user_id: string | null; reviewer_user_id: string | null; revision: number; lifecycle: Lifecycle;
  latest_run_id: string | null; archived_at: string | null; created_at: string; updated_at: string;
  latest_run?: { job_status: JobStatus; decision_status: string | null; completeness: string | null;
                 counts: Record<string, number>; completed_at: string | null } | null;
  current_run_id?: string | null; current_run_expired?: boolean | null; can_edit?: boolean;
  latest_review?: ImpactReview | null;
}
export interface ImpactRun {
  id: string; plan_id: string; plan_revision: number; job_status: JobStatus; stage: string | null;
  decision_status: "blocked" | "needs_review" | "no_known_blocker" | null;
  completeness: "complete" | "partial" | "failed" | null;
  scope_manifest: { sources?: { kind: string; name: string; freshness: string; last_sync_at: string | null }[];
                    permission_limited?: string[]; roots?: string[]; new_ip?: string | null;
                    target_subnet?: string | null; cross_subnet?: boolean;
                    observed_from?: string | null; observed_to?: string | null };
  counts: Record<string, number>; snapshot_hash: string | null; engine_version: string | null;
  rules_version: string | null; attempt: number; started_at: string | null; completed_at: string | null;
  expires_at: string | null; truncated: boolean; truncation: { what: string; limit: number; stage: string } | null;
  error_code: string | null; created_at: string; cancel_requested: boolean; permission_scope_changed?: boolean;
}
export interface ImpactFinding {
  id: string; rule_id: string; rule_version: string; category: string; subject_type: string;
  subject_id: string | null; subject_key: string | null; subject_label: string; match_kind: string | null;
  impact: string; severity: "critical" | "high" | "medium" | "low" | "info";
  disposition: "blocker" | "review" | "informational"; evidence_strength: string; reason_code: string;
  params: Record<string, any>; evidence_ids: string[]; relationship_path: { ref: string; label: string }[];
  suggested_action: Record<string, any> | null; fingerprint: string;
}
export interface ImpactEvidence {
  id: string; key: string; source_type: string; integration_ref: string | null; object_type: string;
  object_id?: string | null; label: string; observed_at: string | null; collected_at: string | null;
  freshness: string; payload?: Record<string, any>;
}
export interface ImpactGap {
  id: string; category: string; reason_code: string; params: Record<string, any>;
  source_scope: string | null; affected_analysis: string | null;
}
export interface ChangeTask {
  id: string; phase: "precheck" | "change" | "rollback" | "verify"; position: number; title: string;
  instruction: string; template_code: string | null; template_params: Record<string, any> | null;
  origin: "rule_template" | "ai_draft" | "manual"; finding_ids: string[]; depends_on: string[];
  assignee_user_id: string | null; state: "pending" | "in_progress" | "done" | "blocked" | "skipped";
  version: number; completed_by: string | null; completed_at: string | null; completion_note: string | null;
}
export interface ImpactReview {
  id: string; revision: number; run_id: string | null; snapshot_hash: string | null; reviewer_id: string | null;
  decision: "approve" | "reject" | "accept_risk" | "request_changes"; rationale: string;
  dispositions: Record<string, { action: string; note: string }>; created_at: string;
}
export interface AIItem { text?: string; code?: string; params?: Record<string, any>; finding_ids?: string[];
                          evidence_ids?: string[]; gap_ids?: string[]; phase?: string; requires_confirmation?: boolean }
export interface ImpactAIArtifact {
  id: string; artifact_type: "summary" | "checklist" | "explanation" | "answer";
  status: "pending" | "running" | "completed" | "failed" | "fallback"; question: string | null;
  model: string | null; validation_state: string | null; truncated: boolean; error_code: string | null;
  generated_at: string | null; created_at: string; hidden_scope_changed: boolean;
  output: { template?: boolean; summary?: AIItem[]; uncertainties?: AIItem[]; suggested_tasks?: AIItem[] } | null;
}

export async function getImpactSettings(): Promise<ImpactSettings> {
  return (await apiClient.get("/api/v1/change-impact/settings")).data;
}
export async function putImpactSettings(body: Record<string, any>): Promise<ImpactSettings> {
  return (await apiClient.put("/api/v1/change-impact/settings", body)).data;
}
export async function listPlans(params: Record<string, any>): Promise<{ items: ChangePlan[]; total: number }> {
  return (await apiClient.get("/api/v1/change-plans", { params })).data;
}
export async function createPlan(body: Record<string, any>, idemKey?: string): Promise<ChangePlan> {
  return (await apiClient.post("/api/v1/change-plans", body,
                               idemKey ? { headers: { "Idempotency-Key": idemKey } } : undefined)).data;
}
export async function getPlan(id: string): Promise<ChangePlan> {
  return (await apiClient.get(`/api/v1/change-plans/${id}`)).data;
}
export async function patchPlan(id: string, revision: number, body: Record<string, any>): Promise<ChangePlan> {
  return (await apiClient.patch(`/api/v1/change-plans/${id}`, body, { headers: { "If-Match": String(revision) } })).data;
}
export async function archivePlan(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/change-plans/${id}`);
}
export async function transitionPlan(id: string, action: string): Promise<ChangePlan> {
  return (await apiClient.post(`/api/v1/change-plans/${id}/transitions`, { action })).data;
}
export async function startRun(planId: string): Promise<ImpactRun> {
  return (await apiClient.post(`/api/v1/change-plans/${planId}/runs`, null,
                               { headers: { "Idempotency-Key": crypto.randomUUID?.() ?? String(Date.now()) } })).data;
}
export async function listRuns(planId: string): Promise<ImpactRun[]> {
  return (await apiClient.get(`/api/v1/change-plans/${planId}/runs`)).data.items;
}
export async function listRevisions(planId: string): Promise<{ revision: number; payload: any; created_at: string }[]> {
  return (await apiClient.get(`/api/v1/change-plans/${planId}/revisions`)).data.items;
}
export async function getRun(id: string): Promise<ImpactRun> {
  return (await apiClient.get(`/api/v1/impact-runs/${id}`)).data;
}
export async function cancelRun(id: string): Promise<ImpactRun> {
  return (await apiClient.post(`/api/v1/impact-runs/${id}/cancel`)).data;
}
export async function listFindings(runId: string): Promise<{ items: ImpactFinding[]; total: number;
                                                             permission_scope_changed: boolean }> {
  return (await apiClient.get(`/api/v1/impact-runs/${runId}/findings`, { params: { page_size: 200 } })).data;
}
export async function listEvidence(runId: string): Promise<ImpactEvidence[]> {
  return (await apiClient.get(`/api/v1/impact-runs/${runId}/evidence`)).data.items;
}
export async function getEvidence(runId: string, evId: string): Promise<ImpactEvidence> {
  return (await apiClient.get(`/api/v1/impact-runs/${runId}/evidence/${evId}`)).data;
}
export async function listGaps(runId: string): Promise<ImpactGap[]> {
  return (await apiClient.get(`/api/v1/impact-runs/${runId}/gaps`)).data.items;
}
export async function listTasks(planId: string): Promise<ChangeTask[]> {
  return (await apiClient.get(`/api/v1/change-plans/${planId}/tasks`)).data.items;
}
export async function createTask(planId: string, body: Record<string, any>): Promise<ChangeTask> {
  return (await apiClient.post(`/api/v1/change-plans/${planId}/tasks`, body)).data;
}
export async function acceptAiTasks(planId: string, artifactId: string, indices: number[]): Promise<ChangeTask[]> {
  return (await apiClient.post(`/api/v1/change-plans/${planId}/tasks/from-ai`,
                               { artifact_id: artifactId, indices })).data.items;
}
export async function patchTask(id: string, version: number, body: Record<string, any>): Promise<ChangeTask> {
  return (await apiClient.patch(`/api/v1/change-tasks/${id}`, { ...body, expected_version: version })).data;
}
export async function createReview(planId: string, body: Record<string, any>): Promise<ImpactReview> {
  return (await apiClient.post(`/api/v1/change-plans/${planId}/reviews`, body)).data;
}
export async function listReviews(planId: string): Promise<ImpactReview[]> {
  return (await apiClient.get(`/api/v1/change-plans/${planId}/reviews`)).data.items;
}
export async function requestAi(runId: string, artifactType: string): Promise<ImpactAIArtifact> {
  return (await apiClient.post(`/api/v1/impact-runs/${runId}/ai-artifacts`, { artifact_type: artifactType })).data;
}
export async function askAi(runId: string, question: string): Promise<ImpactAIArtifact> {
  return (await apiClient.post(`/api/v1/impact-runs/${runId}/questions`, { question })).data;
}
export async function listAi(runId: string): Promise<ImpactAIArtifact[]> {
  return (await apiClient.get(`/api/v1/impact-runs/${runId}/ai-artifacts`)).data.items;
}
export async function candidates(ip: string): Promise<{ id: string; ip: string; subnet: string; hostname: string | null }[]> {
  return (await apiClient.get("/api/v1/change-impact/candidates", { params: { ip } })).data.items;
}
/** 匯出是即時產生的檔案：用 blob 下載（帶登入權杖），不產生永久網址 */
export async function exportRun(runId: string, format: "md" | "json"): Promise<Blob> {
  return (await apiClient.get(`/api/v1/impact-runs/${runId}/export`, { params: { format }, responseType: "blob" })).data;
}
