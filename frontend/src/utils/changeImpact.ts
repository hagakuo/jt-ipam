/**
 * 變更影響預演的顯示輔助：標籤顏色、把後端的代碼（原因碼、缺口、模板待辦）依語系翻成句子。
 * 後端只送代碼與參數（沒有寫死任何語言的句子），翻不到時退回代碼本身，不會整格空白。
 */
import { fmtDateTime } from "@/utils/datetime";

type TagType = "default" | "info" | "success" | "warning" | "error";
type T = (key: string, params?: Record<string, unknown>) => string;
type Te = (key: string) => boolean;

export function lifecycleType(s: string): TagType {
  return ({ draft: "default", in_review: "info", approved: "success", in_progress: "warning",
            verified: "success", closed: "default", cancelled: "default" } as Record<string, TagType>)[s] ?? "default";
}
export function decisionType(s: string | null | undefined): TagType {
  return ({ blocked: "error", needs_review: "warning", no_known_blocker: "success" } as Record<string, TagType>)[s ?? ""]
    ?? "default";
}
export function dispositionType(s: string): TagType {
  return ({ blocker: "error", review: "warning", informational: "default" } as Record<string, TagType>)[s] ?? "default";
}
export function severityType(s: string): TagType {
  return ({ critical: "error", high: "error", medium: "warning", low: "info", info: "default" } as Record<string, TagType>)[s]
    ?? "default";
}

// 參數本身也是代碼的（來源／目的、跨子網路要確認的項目）：一併翻譯
const CODED_PARAMS = new Set(["side", "item"]);
// 時間參數一律以本地時區顯示（後端送 ISO 8601）
const TIME_PARAMS = new Set(["last_sync_at", "last_seen", "until"]);

function params(t: T, te: Te, p: Record<string, unknown> | null | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p ?? {})) {
    if (v === null || v === undefined || v === "") { out[k] = "—"; continue; }
    if (TIME_PARAMS.has(k)) { out[k] = fmtDateTime(String(v)); continue; }
    const key = `change_impact.param.${k}.${String(v)}`;
    out[k] = CODED_PARAMS.has(k) && te(key) ? t(key) : v;
  }
  return out;
}

/** 發現的原因碼 → 句子（例：OLD_IP_IN_ADDRESS_RECORD → 「DNS 記錄 erp.example.net 指向 198.51.100.10」） */
export function reasonText(t: T, te: Te, code: string, p: Record<string, unknown>): string {
  const key = `change_impact.reason.${code}`;
  return te(key) ? t(key, params(t, te, p)) : code;
}
export function gapText(t: T, te: Te, code: string, p: Record<string, unknown>): string {
  const key = `change_impact.gap.${code}`;
  return te(key) ? t(key, params(t, te, p)) : code;
}
export function taskTitle(t: T, te: Te, task: { template_code: string | null; template_params: Record<string, unknown> | null;
                                                  title: string }): string {
  if (!task.template_code) return task.title;
  const key = `change_impact.task.${task.template_code}`;
  if (te(key)) return t(key, params(t, te, task.template_params));
  // update_refs_<類別>／remove_refs_<類別>：類別多，用一個句型帶類別名稱
  const m = /^(update|remove)_refs_(\w+)$/.exec(task.template_code);
  if (m) {
    const cat = te(`change_impact.category.${m[2]}`) ? t(`change_impact.category.${m[2]}`) : m[2];
    return t(`change_impact.task.${m[1]}_refs`, { ...params(t, te, task.template_params), category: cat });
  }
  return task.template_code;
}
