/**
 * RustDesk 網頁連線斷線後自動重新連線（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 G）：畫面這一側的接線。
 *
 * 使用者回報（2026-10-05）：Linux 受控端停在 GDM 登入畫面，從網頁連線登入後，受控端切到新的桌面工作階段、
 * 把連線結束（沒有 close_reason）。畫面停在「連線已中斷」，要自己按「重新連線」；官方客戶端會自己連回去。
 *
 * 規則本身在 src/rdweb/reconnect.ts（有自己的單元測試）；這裡驗證畫面真的照規則做：倒數、立即重連、取消、
 * 每次重連都重新換票證並開新的連線、沿用密碼與選項、不重複存密碼。協定流程用假的 RdSession 代替。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import { defineComponent, h, nextTick } from "vue";
import { createI18n } from "vue-i18n";
import { NMessageProvider } from "naive-ui";
import zhTW from "@/i18n/zh-TW.json";
import type { CloseInfo, SessionOptions } from "@/rdweb/session";
import type { PeerInfo } from "@/rdweb/messages";
import RustDeskScreen from "../RustDeskScreen.vue";

interface FakeSession {
  opts: SessionOptions;
  closed: boolean;
  clipboardEnabled: boolean;
  logins: string[];
  selected: number[];
  osLogins: (string | undefined)[][];
  connect(): void;
  drop(info: CloseInfo): void;
}

const m = vi.hoisted(() => ({
  sessions: [] as unknown[],
  requestRustDeskTicket: vi.fn(),
  listRustDeskCredentials: vi.fn(),
  saveRustDeskPassword: vi.fn(),
  deleteSavedRustDeskPassword: vi.fn(),
}));

vi.mock("@/api/rustdeskWeb", () => ({
  requestRustDeskTicket: m.requestRustDeskTicket,
  buildRustDeskWsUrl: (p: string, t: string) => `wss://jt.example${p}?ticket=${t}`,
  listRustDeskCredentials: m.listRustDeskCredentials,
  saveRustDeskPassword: m.saveRustDeskPassword,
  deleteSavedRustDeskPassword: m.deleteSavedRustDeskPassword,
}));

vi.mock("@/rdweb/video", () => ({
  probeDecoding: async () => ({ webcodecs: true, vp9: true, h264: false, vp8: false, av1: false }),
  VideoPipeline: class { push() {} close() {} waitForKeyframe() {} },
}));

vi.mock("@/rdweb/session", () => {
  const info = {
    username: "", hostname: "pc", platform: "Linux", currentDisplay: 0, version: "1.4.1", platformAdditions: "",
    displays: [{ x: 0, y: 0, width: 1280, height: 800, name: "", cursorEmbedded: false, scale: 1 }],
  };
  class RdSession {
    opts: SessionOptions;
    closed = false;
    clipboardEnabled: boolean;
    lastPointer = null;
    logins: string[] = [];
    selected: number[] = [];
    osLogins: (string | undefined)[][] = [];
    constructor(opts: SessionOptions) {
      this.opts = opts;
      this.clipboardEnabled = !!opts.clipboard && !opts.viewOnly;
      m.sessions.push(this);
    }
    close() {
      if (this.closed) return;
      this.closed = true;
      this.opts.events.closed?.({ byUser: true });
    }
    async login(pw: string) { this.logins.push(pw); }
    async loginOs(u: string, p: string, r?: string) { this.osLogins.push([u, p, r]); }
    selectWindowsSession(sid: number) { this.selected.push(sid); }
    submit2fa() {}
    setClipboard(on: boolean) { this.clipboardEnabled = on && !this.opts.viewOnly; }
    sendClipboard() { return false; }
    requestKeyframe() {}
    sendMouse() { return false; }
    sendKey() {}
    sendCtrlAltDel() {}
    sendLockScreen() {}
    // 測試用：受控端登入成功／連線結束
    connect() { this.opts.events.connected?.(info as PeerInfo); }
    drop(i: CloseInfo) { this.closed = true; this.opts.events.closed?.(i); }
  }
  return { RdSession };
});

const sessions = () => m.sessions as FakeSession[];
let ticketNo = 0;
const ticket = (saved = false) => ({
  ticket: `t${++ticketNo}`, ws_path: "/api/v1/addresses/a1/rustdesk/ws", peer_id: "123456789", server_name: "rd",
  my_name: "alice (jt-ipam)", transport: "tcp", has_saved_password: saved, ttl: 30,
});

async function flush() {
  for (let i = 0; i < 12; i++) {
    await Promise.resolve();
    await nextTick();
  }
}

let wrapper: VueWrapper | null = null;

function render() {
  const i18n = createI18n({ legacy: false, locale: "zh-TW", messages: { "zh-TW": zhTW } });
  const Host = defineComponent({
    setup: () => () => h(NMessageProvider, null, {
      default: () => h(RustDeskScreen, { addressId: "a1", ip: "192.0.2.10" }),
    }),
  });
  wrapper = mount(Host, { global: { plugins: [i18n] }, attachTo: document.body });
  return wrapper;
}

const status = (w: VueWrapper) => w.find('[data-testid="rdweb-status"]');
const overlay = (w: VueWrapper) => w.find(".cdo");
const tid = (w: VueWrapper, id: string) => w.find(`[data-testid="${id}"]`);

/** 輸入密碼（可選擇勾記住、唯讀檢視）並按「連線」 */
async function connectWith(w: VueWrapper, opts: { password?: string; remember?: boolean; viewOnly?: boolean } = {}) {
  await flush();
  if (opts.password !== undefined) await w.find('[data-testid="rdweb-password"] input').setValue(opts.password);
  if (opts.remember) await tid(w, "rdweb-remember").trigger("click");
  if (opts.viewOnly) await tid(w, "rdweb-view-only").trigger("click");
  await tid(w, "rdweb-connect").trigger("click");
  await flush();
}

/** 連上之後受控端直接結束（G.1 的情況） */
async function liveThenDrop(w: VueWrapper, opts: Parameters<typeof connectWith>[1] = { password: "Pa55-word" }) {
  await connectWith(w, opts);
  sessions()[0].connect();
  await flush();
  sessions()[0].drop({ code: "rd_peer_closed", detail: "peer_closed" });
  await flush();
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  m.sessions.length = 0;
  ticketNo = 0;
  m.requestRustDeskTicket.mockReset().mockImplementation(async () => ticket());
  m.listRustDeskCredentials.mockReset().mockResolvedValue([]);
  m.saveRustDeskPassword.mockReset().mockResolvedValue({ id: "cred-new", label: "RustDesk 123456789",
    protocol: "rustdesk", target_ip_id: "a1", has_password: true, last_used_at: null, created_at: "" });
  m.deleteSavedRustDeskPassword.mockReset().mockResolvedValue(undefined);
  HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as unknown as typeof HTMLCanvasElement.prototype.getContext;
});

afterEach(() => {
  wrapper?.unmount();
  wrapper = null;
  vi.useRealTimers();
});

describe("連上之後意外中斷：倒數後自動重新連線（G.2、G.3）", () => {
  it("顯示倒數而不是「連線已中斷」；時間到就換新票證、開新連線，用同一組密碼並沿用唯讀檢視；不再存一次密碼", async () => {
    const w = render();
    await connectWith(w, { password: "Pa55-word", remember: true, viewOnly: true });
    expect(sessions()).toHaveLength(1);
    expect(sessions()[0].opts.password).toBe("Pa55-word");
    expect(sessions()[0].opts.viewOnly).toBe(true);
    sessions()[0].connect();
    await flush();
    expect(m.saveRustDeskPassword).toHaveBeenCalledTimes(1);      // 手動登入成功：存一次

    sessions()[0].drop({ code: "rd_peer_closed", detail: "peer_closed" });
    await flush();
    expect(status(w).attributes("data-state")).toBe("reconnecting");
    expect(overlay(w).text()).toContain("連線中斷");
    expect(overlay(w).text()).toContain("1 秒後自動重新連線（第 1 次，共 8 次）");
    expect(overlay(w).text()).not.toContain("連線已中斷");
    expect(tid(w, "rdweb-reconnect-now").exists()).toBe(true);
    expect(tid(w, "rdweb-reconnect-cancel").exists()).toBe(true);
    expect(tid(w, "rdweb-reconnect").exists()).toBe(false);     // 不是終止狀態，沒有手動「重新連線」

    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(m.requestRustDeskTicket).toHaveBeenCalledTimes(2);      // 票證是單次的：每次都重新要
    expect(sessions()).toHaveLength(2);
    const s2 = sessions()[1];
    expect(s2.opts.url).toContain("ticket=t2");
    expect(s2.opts.password).toBe("Pa55-word");
    expect(s2.opts.savedCredentialId).toBeUndefined();
    expect(s2.opts.viewOnly).toBe(true);
    expect(overlay(w).text()).toContain("正在重新連線（第 1 次，共 8 次）");

    s2.connect();
    await flush();
    expect(status(w).attributes("data-state")).toBe("connected");
    expect(overlay(w).exists()).toBe(false);
    expect(m.saveRustDeskPassword).toHaveBeenCalledTimes(1);      // 自動重連成功不重複存
  });

  it("剪貼簿開關沿用使用者當下的設定", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    expect(sessions()[0].opts.clipboard).toBe(true);
    sessions()[0].connect();
    await flush();
    await tid(w, "rdweb-clipboard").trigger("click");            // 連線中把剪貼簿關掉
    await flush();
    sessions()[0].drop({ code: "ws_closed" });
    await flush();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(sessions()[1].opts.clipboard).toBe(false);
  });

  it("已存的密碼：重連照樣只帶 credential_id（每次由後端算這一次的 h2），不帶密碼", async () => {
    m.listRustDeskCredentials.mockResolvedValue([{ id: "cred-1", label: "RustDesk 123456789", protocol: "rustdesk",
      target_ip_id: "a1", has_password: true, last_used_at: null, created_at: "" }]);
    m.requestRustDeskTicket.mockImplementation(async () => ticket(true));
    const w = render();
    await connectWith(w);
    expect(sessions()[0].opts.savedCredentialId).toBe("cred-1");
    sessions()[0].connect();
    await flush();
    sessions()[0].drop({ code: "rd_peer_closed" });
    await flush();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(sessions()[1].opts.savedCredentialId).toBe("cred-1");
    expect(sessions()[1].opts.password).toBeUndefined();
    expect(m.saveRustDeskPassword).not.toHaveBeenCalled();
  });

  it("「立即重連」：不等倒數", async () => {
    const w = render();
    await liveThenDrop(w);
    await tid(w, "rdweb-reconnect-now").trigger("click");
    await flush();
    expect(sessions()).toHaveLength(2);
  });

  it("「取消」：回到「連線已中斷」與手動「重新連線」，不再自動重連；回到表單時密碼框是空的", async () => {
    const w = render();
    await liveThenDrop(w);
    await tid(w, "rdweb-reconnect-cancel").trigger("click");
    await flush();
    expect(status(w).attributes("data-state")).toBe("closed");
    expect(overlay(w).text()).toContain("連線已中斷");
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
    await tid(w, "rdweb-reconnect").trigger("click");
    await flush();
    expect((w.find('[data-testid="rdweb-password"] input').element as HTMLInputElement).value).toBe("");
  });

  it("重連進行中「取消」：關掉這一次的連線，不再重連", async () => {
    const w = render();
    await liveThenDrop(w);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(sessions()).toHaveLength(2);
    await tid(w, "rdweb-reconnect-cancel").trigger("click");
    await flush();
    expect(sessions()[1].closed).toBe(true);
    expect(status(w).attributes("data-state")).toBe("closed");
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(2);
  });

  it("受控端還沒回來（離線、中繼失敗、後端重新啟動中換不到票證）：繼續下一次；用完 8 次才顯示錯誤，帶最後一次的原因", async () => {
    const w = render();
    await liveThenDrop(w);
    const delays = [1, 2, 3, 5, 5, 10, 10, 15];
    for (let k = 1; k <= 8; k++) {
      expect(overlay(w).text()).toContain(`${delays[k - 1]} 秒後自動重新連線（第 ${k} 次，共 8 次）`);
      if (k === 3) m.requestRustDeskTicket.mockRejectedValueOnce(new Error("Network Error"));   // 沒有回應
      await vi.advanceTimersByTimeAsync(delays[k - 1] * 1000);
      await flush();
      if (k === 3) continue;
      const s = sessions()[sessions().length - 1];
      s.drop(k === 8 ? { code: "rd_relay_timeout", detail: "30s" } : { code: "rd_offline" });
      await flush();
    }
    expect(sessions()).toHaveLength(1 + 7);                       // 第 3 次在換票證就失敗
    expect(m.requestRustDeskTicket).toHaveBeenCalledTimes(1 + 8);
    expect(status(w).attributes("data-state")).toBe("error");
    const err = tid(w, "rdweb-error").text();
    expect(err).toContain("自動重新連線 8 次都沒有成功");
    expect(err).toContain("中繼在時限內沒有配對成功");
    expect(tid(w, "rdweb-reconnect").exists()).toBe(true);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(m.requestRustDeskTicket).toHaveBeenCalledTimes(9);
  });

  it("重連時受控端剛啟動、登入回 connection refused：繼續下一次，之後連上（黑箱實測 2026-10-05）", async () => {
    const w = render();
    await liveThenDrop(w);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    sessions()[1].drop({ code: "rd_login_error", detail: "connection refused",
                         params: { reason: "connection refused" } });
    await flush();
    expect(status(w).attributes("data-state")).toBe("reconnecting");
    expect(overlay(w).text()).toContain("2 秒後自動重新連線（第 2 次，共 8 次）");
    expect(tid(w, "rdweb-error").exists()).toBe(false);
    await vi.advanceTimersByTimeAsync(2000);
    await flush();
    expect(sessions()).toHaveLength(3);
    sessions()[2].connect();
    await flush();
    expect(status(w).attributes("data-state")).toBe("connected");
  });

  it("重連時對方回 Wrong Password：停止自動重連，改請使用者輸入", async () => {
    const w = render();
    await liveThenDrop(w);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    sessions()[1].opts.events.needPassword?.("wrong");
    await flush();
    expect(status(w).attributes("data-state")).toBe("need_password");
    expect(tid(w, "rdweb-password-prompt").exists()).toBe(true);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(2);
    // 使用者沒輸入，對方把連線關了：照常顯示，不再倒數
    sessions()[1].drop({ code: "rd_peer_closed" });
    await flush();
    expect(status(w).attributes("data-state")).not.toBe("reconnecting");
  });

  it("重連時要 2FA：停止自動重連，顯示驗證碼輸入框", async () => {
    const w = render();
    await liveThenDrop(w);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    sessions()[1].opts.events.need2fa?.(false);
    await flush();
    expect(tid(w, "rdweb-2fa-prompt").exists()).toBe(true);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(2);
  });
});

describe("不自動重連的情況（G.2）", () => {
  it("受控端送了 close_reason：照現在顯示原因", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].connect();
    await flush();
    sessions()[0].drop({ code: "rd_peer_closed", detail: "對方結束了", peerReason: "對方結束了" });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    expect(tid(w, "rdweb-error").text()).toContain("對方結束了");
    await vi.advanceTimersByTimeAsync(60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
  });

  it("第一次（手動）連線的登入錯誤照舊直接顯示，不自動重試", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].drop({ code: "rd_login_error", detail: "connection refused", params: { reason: "connection refused" } });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    expect(tid(w, "rdweb-error").text()).toContain("connection refused");
    await vi.advanceTimersByTimeAsync(60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
  });

  it("從沒連上過：照現在顯示錯誤", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].drop({ code: "rd_relay_timeout" });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    await vi.advanceTimersByTimeAsync(60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
  });

  it("使用者自己按「中斷」：不重連", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].connect();
    await flush();
    await tid(w, "rdweb-disconnect").trigger("click");
    await flush();
    expect(status(w).attributes("data-state")).toBe("closed");
    await vi.advanceTimersByTimeAsync(60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
  });

  it("倒數中離開頁面：不再重連", async () => {
    const w = render();
    await liveThenDrop(w);
    w.unmount();
    wrapper = null;
    await vi.advanceTimersByTimeAsync(60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
    expect(m.requestRustDeskTicket).toHaveBeenCalledTimes(1);
  });
});

/** 自動重連的那一次（第 1 次）已經開了新的連線 */
async function reconnectedOnce(w: VueWrapper) {
  await liveThenDrop(w);
  await vi.advanceTimersByTimeAsync(1000);
  await flush();
  expect(sessions()).toHaveLength(2);
  return sessions()[1];
}

describe("G.5：受控端切換工作階段", () => {
  it("同一個頁面的每一次連線（自動重連、手動重新連線）都用同一個 session_id", async () => {
    const w = render();
    const s2 = await reconnectedOnce(w);
    const id = sessions()[0].opts.sessionId;
    expect(typeof id).toBe("bigint");
    expect(s2.opts.sessionId).toBe(id);
    expect(s2.opts.myName).toBe(sessions()[0].opts.myName);
    await tid(w, "rdweb-reconnect-cancel").trigger("click");
    await flush();
    await tid(w, "rdweb-reconnect").trigger("click");
    await connectWith(w, { password: "pw" });
    expect(sessions()[2].opts.sessionId).toBe(id);
  });

  it("重連時 Wrong Password：提示一次性密碼可能已經換了", async () => {
    const w = render();
    const s2 = await reconnectedOnce(w);
    s2.opts.events.needPassword?.("wrong");
    await flush();
    expect(tid(w, "rdweb-password-prompt").text()).toContain("一次性密碼可能已更換");
  });

  it("手動登入的 Wrong Password 不會出現一次性密碼的提示", async () => {
    const w = render();
    await connectWith(w, { password: "bad" });
    sessions()[0].opts.events.needPassword?.("wrong");
    await flush();
    expect(tid(w, "rdweb-password-prompt").text()).not.toContain("一次性密碼");
  });

  it("等對方同意時受控端回 No Password Access（在登入畫面）：提示「受控端目前在登入畫面，請輸入密碼」", async () => {
    const w = render();
    await connectWith(w, { password: "" });
    sessions()[0].opts.events.waitingApproval?.();
    await flush();
    sessions()[0].opts.events.needPassword?.("login_screen");
    await flush();
    expect(tid(w, "rdweb-password-prompt").text()).toContain("受控端目前在登入畫面，請輸入密碼");
  });

  it("Wayland login screen is not supported：停止重連，顯示說明，連結只當文字", async () => {
    const w = render();
    const s2 = await reconnectedOnce(w);
    s2.drop({ code: "rd_login_error", detail: "Wayland login screen is not supported",
              params: { reason: "Wayland login screen is not supported" } });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    const err = tid(w, "rdweb-error");
    expect(err.text()).toContain("Wayland 登入畫面");
    expect(err.text()).toContain("https://rustdesk.com/docs/en/manual/linux/#login-screen");
    expect(err.find("a").exists()).toBe(false);
    await vi.advanceTimersByTimeAsync(60_000);
    await flush();
    expect(sessions()).toHaveLength(2);
  });

  it("重連後收到 Wayland 分享畫面的 message_box：照常顯示，繼續等", async () => {
    const w = render();
    const s2 = await reconnectedOnce(w);
    s2.connect();
    await flush();
    s2.opts.events.messageBox?.({ msgtype: "nook-nocancel-hasclose", title: "Wayland",
                                  text: "Please Select the screen to be shared(Operate on the peer side).", link: "" });
    await flush();
    expect(w.text()).toContain("Please Select the screen to be shared");
    expect(status(w).attributes("data-state")).toBe("connected");
    expect(s2.closed).toBe(false);
  });
});

describe("§7.1：受控端在 Hash 之前送來的拒絕（G.3）", () => {
  const refusals: [string, string][] = [
    ["Your ip is blocked by the peer", "對方的 IP 允許清單不包含 jt-ipam 伺服器"],
    ["The main window is not open", "對方設定成只有主視窗開著時才接受連線"],
  ];

  it.each(refusals)("重連途中收到 %s：立刻停止並顯示原因，不試滿 8 次", async (raw, shown) => {
    const w = render();
    const s2 = await reconnectedOnce(w);
    s2.drop({ code: "rd_login_error", detail: raw, params: { reason: raw } });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    const err = tid(w, "rdweb-error").text();
    expect(err).toContain(shown);
    expect(err).toContain(raw);                                   // §7.1：原文也要顯示
    expect(err).not.toContain("都沒有成功");                      // 不是「試滿 8 次」的訊息
    expect(overlay(w).text()).not.toContain("秒後自動重新連線");
    expect(tid(w, "rdweb-reconnect").exists()).toBe(true);       // 回到手動「重新連線」
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(2);
    expect(m.requestRustDeskTicket).toHaveBeenCalledTimes(2);
  });

  it.each(refusals)("第一次（手動）連線收到 %s：照舊直接顯示，不自動重試", async (raw, shown) => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].drop({ code: "rd_login_error", detail: raw, params: { reason: raw } });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    const err = tid(w, "rdweb-error").text();
    expect(err).toContain(shown);
    expect(err).toContain(raw);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(1);
  });

  it.each(refusals)("重連途中受控端用 close_reason 送 %s：同樣停止並顯示原文", async (raw) => {
    const w = render();
    const s2 = await reconnectedOnce(w);
    s2.drop({ code: "rd_peer_closed", detail: raw, peerReason: raw });
    await flush();
    expect(status(w).attributes("data-state")).toBe("error");
    expect(tid(w, "rdweb-error").text()).toContain(raw);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(sessions()).toHaveLength(2);
  });
});

describe("G.6：Windows 的工作階段選擇", () => {
  const two = (current: number) => ({ sessions: [{ sid: 1, name: "Console" }, { sid: 3, name: "RDP alice" }],
                                      currentSid: current });

  it("只有一個工作階段：直接送 selected_sid，不問", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].connect();
    sessions()[0].opts.events.windowsSessions?.({ sessions: [{ sid: 2, name: "Console" }], currentSid: 2 });
    await flush();
    expect(sessions()[0].selected).toEqual([2]);
    expect(tid(w, "rdweb-winsession").exists()).toBe(false);
  });

  it("有好幾個：列出來並標出目前的那一個，預設選它；確定後送出", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].connect();
    sessions()[0].opts.events.windowsSessions?.(two(1));
    await flush();
    const card = tid(w, "rdweb-winsession");
    expect(card.exists()).toBe(true);
    expect(card.text()).toContain("Console");
    expect(card.text()).toContain("RDP alice");
    expect(tid(w, "rdweb-winsession-1").text()).toContain("目前");
    expect(sessions()[0].selected).toEqual([]);
    await tid(w, "rdweb-winsession-submit").trigger("click");
    await flush();
    expect(sessions()[0].selected).toEqual([1]);
    expect(tid(w, "rdweb-winsession").exists()).toBe(false);
  });

  it("選了別的：送出後受控端中斷 → 自動重連；重連後 current_sid 就是剛選的，自動送出、不再詢問", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].connect();
    sessions()[0].opts.events.windowsSessions?.(two(1));
    await flush();
    await w.find('[data-testid="rdweb-winsession-3"] input').setValue(true);
    await tid(w, "rdweb-winsession-submit").trigger("click");
    await flush();
    expect(sessions()[0].selected).toEqual([3]);
    sessions()[0].drop({ code: "rd_peer_closed" });             // 受控端到那個工作階段重新啟動
    await flush();
    expect(status(w).attributes("data-state")).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    sessions()[1].connect();
    sessions()[1].opts.events.windowsSessions?.(two(3));
    await flush();
    expect(sessions()[1].selected).toEqual([3]);
    expect(tid(w, "rdweb-winsession").exists()).toBe(false);
  });
});

describe("G.7：Linux 受控端沒有桌面時的作業系統登入", () => {
  it("Desktop session not ready：顯示作業系統帳號密碼；送出後在同一條連線登入，密碼欄清空", async () => {
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].opts.events.needOsLogin?.("not_ready");
    await flush();
    expect(status(w).attributes("data-state")).toBe("need_os_login");
    expect(tid(w, "rdweb-os-login").exists()).toBe(true);
    expect(tid(w, "rdweb-os-rdpassword").exists()).toBe(false);
    await w.find('[data-testid="rdweb-os-user"] input').setValue("bob");
    await w.find('[data-testid="rdweb-os-password"] input').setValue("os-secret");
    await tid(w, "rdweb-os-submit").trigger("click");
    await flush();
    expect(sessions()).toHaveLength(1);                           // 同一條連線
    expect(sessions()[0].osLogins).toEqual([["bob", "os-secret", undefined]]);
    sessions()[0].opts.events.needOsLogin?.("xsession_failed");  // 登入失敗：再問一次
    await flush();
    expect(tid(w, "rdweb-os-login").text()).toContain("作業系統登入或啟動桌面失敗");
    expect((w.find('[data-testid="rdweb-os-password"] input').element as HTMLInputElement).value).toBe("");
  });

  it("password empty／wrong：RustDesk 密碼也要輸入（沒填不能送）", async () => {
    const w = render();
    await connectWith(w, { password: "" });
    sessions()[0].opts.events.needOsLogin?.("password_empty");
    await flush();
    expect(tid(w, "rdweb-os-rdpassword").exists()).toBe(true);
    await w.find('[data-testid="rdweb-os-user"] input').setValue("bob");
    await w.find('[data-testid="rdweb-os-password"] input').setValue("os-secret");
    await tid(w, "rdweb-os-submit").trigger("click");
    await flush();
    expect(sessions()[0].osLogins).toEqual([]);
    await w.find('[data-testid="rdweb-os-rdpassword"] input').setValue("rd-pw");
    await tid(w, "rdweb-os-submit").trigger("click");
    await flush();
    expect(sessions()[0].osLogins).toEqual([["bob", "os-secret", "rd-pw"]]);
    sessions()[0].opts.events.needOsLogin?.("password_wrong");
    await flush();
    expect(tid(w, "rdweb-os-login").text()).toContain("RustDesk 密碼錯誤");
  });

  it("作業系統帳號密碼不儲存、重連時不自動重送", async () => {
    localStorage.clear();
    sessionStorage.clear();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const w = render();
    await connectWith(w, { password: "pw" });
    sessions()[0].opts.events.needOsLogin?.("not_ready");
    await flush();
    await w.find('[data-testid="rdweb-os-user"] input').setValue("bob");
    await w.find('[data-testid="rdweb-os-password"] input').setValue("os-secret");
    await tid(w, "rdweb-os-submit").trigger("click");
    await flush();
    sessions()[0].connect();
    await flush();
    sessions()[0].drop({ code: "rd_peer_closed" });
    await flush();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    const s2 = sessions()[1];
    expect(s2.opts.password).toBe("pw");                          // RustDesk 密碼照樣用來重連
    expect(JSON.stringify(s2.opts, (_k, v) => (typeof v === "bigint" ? String(v) : v))).not.toContain("os-secret");
    s2.opts.events.needOsLogin?.("not_ready");                    // 受控端又要：照樣請使用者輸入，不自動送
    await flush();
    expect(s2.osLogins).toEqual([]);
    expect((w.find('[data-testid="rdweb-os-password"] input').element as HTMLInputElement).value).toBe("");
    expect(setItem.mock.calls.flat().join(" ")).not.toContain("os-secret");
    expect(localStorage.length + sessionStorage.length).toBe(0);
    setItem.mockRestore();
  });
});
