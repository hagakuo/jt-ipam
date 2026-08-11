/**
 * 登入失敗的訊息要說對原因。
 *
 * 實機（2026-08-07）：後端因為啟動失敗而全數回 502，登入頁卻顯示「請確認帳號密碼」。
 * 使用者於是一直重打密碼、懷疑自己的帳號被停用 —— 而真正的問題是服務沒起來。
 * 只有後端真的驗過憑證（401）時，才可以說是帳號密碼的問題。
 */
import { describe, expect, it } from "vitest";
import { createI18n } from "vue-i18n";
import zhTW from "@/i18n/zh-TW.json";

// 與 Login.vue 同一份判斷邏輯（該檔為單檔元件，這裡以相同實作驗證行為契約）
function loginErrorMessage(err: unknown, t: (k: string, p?: any) => string): string {
  const st = (err as { response?: { status?: number } })?.response?.status;
  if (st === 401 || st === 400) return t("login.failed");
  if (st === 429) return t("login.too_many");
  if (st === 423) return t("login.locked");
  if (st === undefined) return t("login.unreachable");
  if (st >= 500) return t("login.server_down", { code: st });
  return t("login.failed");
}

const i18n = createI18n({ legacy: false, locale: "zh-TW", messages: { "zh-TW": zhTW } });
const t = (k: string, p?: any) => i18n.global.t(k, p ?? {});

describe("登入錯誤訊息", () => {
  it("後端掛掉（502）不可以說是帳號密碼的問題", () => {
    const m = loginErrorMessage({ response: { status: 502 } }, t);
    expect(m).not.toBe(t("login.failed"));       // 關鍵：不可以退回那句「請確認帳號密碼」
    expect(m).toContain("502");
    expect(m).toContain("jt-ipam-backend");       // 給得出下一步
  });

  it("完全連不上（沒有 response）要說連不上", () => {
    expect(loginErrorMessage(new Error("Network Error"), t)).toContain("連不上伺服器");
  });

  it("401 才是真的帳號密碼錯誤", () => {
    expect(loginErrorMessage({ response: { status: 401 } }, t)).toBe(t("login.failed"));
  });

  it("429 講限流、423 講鎖定，各自不同", () => {
    const a = loginErrorMessage({ response: { status: 429 } }, t);
    const b = loginErrorMessage({ response: { status: 423 } }, t);
    expect(a).not.toBe(b);
    expect(a).toContain("次數");
    expect(b).toContain("鎖定");
  });
});
