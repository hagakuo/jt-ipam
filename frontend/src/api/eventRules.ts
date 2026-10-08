import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// 事件規則。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface RuleCondition {
  field: string;
  op: string;
  value?: unknown;
}

export interface RuleAction {
  type: "notify_admins" | "webhook";
  severity?: "info" | "warning" | "error";
  title?: string;
  body?: string;
  subscription_id?: string;
}

export interface EventRule {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  events: string[];
  conditions: RuleCondition[];
  actions: RuleAction[];
  match_count: number;
  last_matched_at: string | null;
  last_error: string | null;
}

export type EventRuleWrite = Omit<EventRule,
  "id" | "match_count" | "last_matched_at" | "last_error">;

export interface RuleTestResult {
  event_matched: boolean;
  matched: boolean;
  conditions: { field: string; op: string; value: unknown; actual: unknown; passed: boolean }[];
}

export async function listEventRules(): Promise<Paginated<EventRule>> {
  const { data } = await apiClient.get("/api/v1/event-rules", { params: { page_size: 200 } });
  return data;
}

export async function createEventRule(payload: Partial<EventRuleWrite>): Promise<EventRule> {
  const { data } = await apiClient.post("/api/v1/event-rules", payload);
  return data;
}

export async function updateEventRule(
  id: string, payload: Partial<EventRuleWrite>,
): Promise<EventRule> {
  const { data } = await apiClient.patch(`/api/v1/event-rules/${id}`, payload);
  return data;
}

export async function deleteEventRule(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/event-rules/${id}`);
}

export async function testEventRule(
  id: string, event: string, payload: Record<string, unknown>,
): Promise<RuleTestResult> {
  const { data } = await apiClient.post(`/api/v1/event-rules/${id}/test`, { event, payload });
  return data;
}

/** 後端支援的運算子（與 services/event_rules.OPS 對齊；刻意不含 regex） */
export const RULE_OPS = [
  "eq", "ne", "contains", "not_contains", "startswith", "endswith",
  "in", "not_in", "gt", "lt", "gte", "lte", "exists", "missing",
] as const;

/** 已知的事件名稱（可自由輸入，這裡只是給下拉建議） */
export const KNOWN_EVENTS = [
  "*", "subnet.created", "ip.allocated", "ip.request.created",
  "ip.request.approved", "ip.request.rejected", "anomaly.detected",
] as const;
