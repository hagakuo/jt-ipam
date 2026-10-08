/**
 * 頁面載入診斷：這一頁是怎麼開起來的，回報給後端寫進日誌（`client page load`）。
 *
 * 為什麼：使用者回報「從別的分頁切回來，整頁會重新載入」。伺服器只看得到請求，
 * 分不出是瀏覽器把背景分頁回收了、分頁被凍結，還是我們自己的「程式檔載入失敗就重載」
 * （router/index.ts 的 reloadOnce）觸發的。這裡把瀏覽器才知道的事實帶過去：
 *   - nav_type：navigate／reload／back_forward（Navigation Timing）
 *   - was_discarded：Chrome 回收背景分頁後重新載入時為 true（document.wasDiscarded）
 *   - reload_reason：reloadOnce 重載前留下的原因
 *   - lifecycle：上一次頁面存活期間的 visibility／freeze／resume／pagehide 事件
 * sessionStorage 在重新載入、分頁被回收後還原時都會保留，所以上一次的事件帶得過來。
 */
import { apiClient } from "@/api/client";

const LC_KEY = "jt-diag-lifecycle";
export const RELOAD_REASON_KEY = "jt-diag-reload-reason";

function push(ev: string) {
  try {
    const arr: string[] = JSON.parse(sessionStorage.getItem(LC_KEY) || "[]");
    arr.push(`${ev}@${new Date().toISOString().slice(11, 19)}`);
    sessionStorage.setItem(LC_KEY, JSON.stringify(arr.slice(-20)));
  } catch { /* 隱私模式等存不了就算了 */ }
}

let started = false;
export function startPageDiag() {
  if (started) return;
  started = true;
  document.addEventListener("visibilitychange", () => push(document.visibilityState));
  document.addEventListener("freeze", () => push("freeze"));
  document.addEventListener("resume", () => push("resume"));
  window.addEventListener("pagehide", (e) => push(`pagehide${(e as PageTransitionEvent).persisted ? "(bfcache)" : ""}`));
}

export function reportPageLoad() {
  if (!localStorage.getItem("access_token")) return;
  let lifecycle: string[] = [];
  let reloadReason: string | null = null;
  try {
    lifecycle = JSON.parse(sessionStorage.getItem(LC_KEY) || "[]");
    reloadReason = sessionStorage.getItem(RELOAD_REASON_KEY);
    sessionStorage.removeItem(LC_KEY);
    sessionStorage.removeItem(RELOAD_REASON_KEY);
  } catch { /* noop */ }
  const nav = (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined);
  const navType = nav?.type && ["navigate", "reload", "back_forward", "prerender"].includes(nav.type) ? nav.type : "unknown";
  const doc = document as Document & { wasDiscarded?: boolean; prerendering?: boolean };
  const vis = document.visibilityState;
  void apiClient.post("/api/v1/client/page-load", {
    path: location.pathname.slice(0, 200),
    nav_type: navType,
    was_discarded: !!doc.wasDiscarded,
    prerendered: !!doc.prerendering || ((nav as any)?.activationStart ?? 0) > 0,
    visibility: ["visible", "hidden", "prerender"].includes(vis) ? vis : "unknown",
    reload_reason: reloadReason ? reloadReason.slice(0, 300) : null,
    lifecycle: lifecycle.slice(-20).map((x) => String(x).slice(0, 80)),
    build: String(__APP_VERSION__).slice(0, 40),
  }).catch(() => { /* 診斷失敗不影響使用 */ });
}
