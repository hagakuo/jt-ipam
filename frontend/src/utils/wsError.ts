/**
 * 伺服器送來的訊息：後端給代碼與參數，句子在這裡組。
 *
 * 為什麼不直接顯示後端的 message：那是後端寫死的中文，英文與日文的使用者一樣
 * 會看到中文 —— 伺服器產生的文字沒有辦法跟著使用者的語言走。實際被回報過。
 *
 * 三種形狀都走這一支：
 *   - HTTP 錯誤的 `detail`（由 api/client.ts 的攔截器處理，不必自己呼叫）
 *   - 主控台 WebSocket 的 error frame
 *   - 以 200 回應但帶 `{ok:false, code, params, message}` 的測試連線類端點
 *
 * 有 `errors.<code>` 的翻譯就用翻譯，沒有才退回 message（不會變成空白）。
 */
import { i18n } from "@/i18n";

export interface ServerMessage {
  code?: string | null;
  params?: Record<string, unknown> | null;
  message?: string | null;
}

export function srvText(payload: ServerMessage | null | undefined, fallback = ""): string {
  const t = (i18n.global as any).t;
  if (payload?.code) {
    const key = `errors.${payload.code}`;
    const out = t(key, payload.params ?? {});
    if (out !== key) return out;
  }
  return payload?.message || fallback;
}

/** 主控台 WebSocket 的 error frame 用；與 srvText 同一套規則。 */
export const wsErrorText = srvText;

/**
 * AI 對話／IP 調查串流的 error 事件：`{code, params, detail}`。
 * 一般帳號只有代碼；管理員多一個 `params.reason`（底層原因），接在句子後面。
 */
export function aiErrText(ev: { code?: string | null; params?: Record<string, unknown> | null;
                                detail?: string | null }, fallback = ""): string {
  const base = srvText({ code: ev.code, params: ev.params, message: ev.detail }, fallback);
  const reason = typeof ev.params?.reason === "string" ? ev.params.reason : "";
  return reason && !base.includes(reason) ? `${base}（${reason}）` : base;
}
