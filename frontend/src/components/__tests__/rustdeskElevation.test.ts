/**
 * RustDesk 網頁連線：Windows 免安裝受控端的系統管理員視窗、UAC 與請求提權（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md
 * 附錄 K.2、K.3）：畫面這一側的接線。
 *
 * 使用者回報（2026-10-06）：受控端是免安裝的 RustDesk，在那台執行安裝程式（UAC 按「是」）後，網頁畫面照常更新、
 * 但完全不能操作。這是 Windows 的權限限制（K.1）；本實作原本沒處理這幾個訊息，使用者只看到「不能動」。
 *
 * 規則本身在 src/rdweb/elevation.ts（有自己的單元測試）；這裡驗證畫面真的照設計做：「免安裝版」標籤、前景／UAC 提示、
 * 工具列「請求提權」的條件、用帳號提權的對話框（密碼不記住、不進瀏覽器儲存、不送給後端、送出後清空）、
 * 送出後的回覆（已送出／成功／錯誤／逾時）、自動重連後一切重新判斷，以及 Linux 受控端什麼都不顯示（回歸）。
 * 協定流程用假的 RdSession 代替。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import { defineComponent, h, nextTick } from "vue";
import { createI18n } from "vue-i18n";
import { NMessageProvider } from "naive-ui";
import zhTW from "@/i18n/zh-TW.json";
import type { CloseInfo, SessionOptions } from "@/rdweb/session";
import type { ElevationRequest, PeerInfo } from "@/rdweb/messages";
import RustDeskScreen from "../RustDeskScreen.vue";

interface FakeSession {
  opts: SessionOptions;
  closed: boolean;
  elevations: ElevationRequest[];
  reports: [string, string, string][];
  refuseElevation: boolean;
  connect(over?: Partial<PeerInfo>): void;
  drop(info: CloseInfo): void;
}

const m = vi.hoisted(() => ({ sessions: [] as unknown[], requestRustDeskTicket: vi.fn() }));

vi.mock("@/api/rustdeskWeb", () => ({
  requestRustDeskTicket: m.requestRustDeskTicket,
  buildRustDeskWsUrl: (p: string, t: string) => `wss://jt.example${p}?ticket=${t}`,
  listRustDeskCredentials: vi.fn(async () => []),
  saveRustDeskPassword: vi.fn(),
  deleteSavedRustDeskPassword: vi.fn(),
}));

vi.mock("@/rdweb/video", () => ({
  probeDecoding: async () => ({ webcodecs: true, vp9: true, h264: false, vp8: false, av1: false }),
  VideoPipeline: class { decoded = 0; currentCodec = "vp9"; push() {} close() {} waitForKeyframe() {} },
}));

vi.mock("@/rdweb/session", () => {
  class RdSession {
    opts: SessionOptions;
    closed = false;
    clipboardEnabled = false;
    lastPointer = null;
    elevations: ElevationRequest[] = [];
    reports: [string, string, string][] = [];
    refuseElevation = false;
    constructor(opts: SessionOptions) {
      this.opts = opts;
      m.sessions.push(this);
    }
    close() {
      if (this.closed) return;
      this.closed = true;
      this.opts.events.closed?.({ byUser: true });
    }
    async login() {}
    requestElevation(req: ElevationRequest) {
      if (this.refuseElevation) return false;
      this.elevations.push({ ...req });
      return true;
    }
    reportElevation(method: string, result: string, detail = "") { this.reports.push([method, result, detail]); }
    setQuality() { return false; }
    setClipboard() {}
    sendClipboard() { return false; }
    requestKeyframe() {}
    sendMouse() { return false; }
    sendKey() {}
    connect(over: Partial<PeerInfo> = {}) {
      const info = {
        username: "", hostname: "pc", platform: "Windows", currentDisplay: 0, version: "1.5.0",
        platformAdditions: '{"is_installed":false}', resolutions: [], encoding: null,
        displays: [{ x: 0, y: 0, width: 1920, height: 1080, name: "", cursorEmbedded: false, scale: 1, online: true,
                     originalResolution: { width: 0, height: 0 } }],
        ...over,
      };
      this.opts.events.connected?.(info as PeerInfo);
    }
    drop(i: CloseInfo) { this.closed = true; this.opts.events.closed?.(i); }
  }
  return { RdSession };
});

const sessions = () => m.sessions as FakeSession[];
const current = () => sessions()[sessions().length - 1];
let ticketNo = 0;

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

const tid = (w: VueWrapper, id: string) => w.find(`[data-testid="${id}"]`);
const body = (id: string) => document.body.querySelector<HTMLElement>(`[data-testid="${id}"]`);

async function connected(w: VueWrapper, over: Partial<PeerInfo> = {}, opts: { viewOnly?: boolean } = {}) {
  await flush();
  if (opts.viewOnly) await tid(w, "rdweb-view-only").trigger("click");
  await w.find('[data-testid="rdweb-password"] input').setValue("pw");
  await tid(w, "rdweb-connect").trigger("click");
  await flush();
  current().connect(over);
  await flush();
}

/** 受控端送來 K.1 的 Misc（經過 session 的事件） */
async function peer(ev: "uac" | "foregroundElevated" | "portableService", v: boolean): Promise<void>;
async function peer(ev: "elevationResponse", v: string): Promise<void>;
async function peer(ev: string, v: boolean | string) {
  const events = current().opts.events as unknown as Record<string, (x: unknown) => void>;
  events[ev]?.(v);
  await flush();
}

/** 打開下拉選單，按下文字符合的項目（選單畫在 body 底下） */
async function pick(trigger: HTMLElement, text: string) {
  trigger.click();
  await flush();
  const opts = Array.from(document.body.querySelectorAll<HTMLElement>(".n-dropdown-option-body"));
  const hit = opts.find((o) => (o.textContent || "").includes(text));
  expect(hit, `選單裡找不到「${text}」：${opts.map((o) => o.textContent).join(" / ")}`).toBeTruthy();
  hit!.click();
  await flush();
}

const menuButton = (w: VueWrapper) => tid(w, "rdweb-elev-menu").element as HTMLElement;
const noticeText = () => body("rdweb-elev-notice")?.textContent ?? "";

function setInput(id: string, value: string) {
  const el = document.body.querySelector<HTMLInputElement>(`[data-testid="${id}"] input`)!;
  expect(el, id).toBeTruthy();
  el.value = value;
  el.dispatchEvent(new Event("input"));
}

function storageDump(): string {
  const all: string[] = [];
  for (const st of [localStorage, sessionStorage]) {
    for (let i = 0; i < st.length; i++) {
      const k = st.key(i)!;
      all.push(k, st.getItem(k) || "");
    }
  }
  return all.join("\n");
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  m.sessions.length = 0;
  ticketNo = 0;
  localStorage.clear();
  sessionStorage.clear();
  m.requestRustDeskTicket.mockReset().mockImplementation(async () => ({
    ticket: `t${++ticketNo}`, ws_path: "/api/v1/addresses/a1/rustdesk/ws", peer_id: "123456789", server_name: "rd",
    my_name: "alice (jt-ipam)", transport: "tcp", has_saved_password: false, ttl: 30,
  }));
  HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as unknown as typeof HTMLCanvasElement.prototype.getContext;
});

afterEach(() => {
  wrapper?.unmount();
  wrapper = null;
  vi.useRealTimers();
  localStorage.clear();
  sessionStorage.clear();
});

const ELEV_IDS = ["rdweb-elev-tag", "rdweb-elev-menu", "rdweb-elev-foreground", "rdweb-elev-uac", "rdweb-elev-notice"];
const noElevationUi = (w: VueWrapper) => ELEV_IDS.filter((id) => tid(w, id).exists());

describe("沒有提權相關訊息的受控端（K.3 黑箱回歸）", () => {
  it("Linux 受控端（測試靶）：畫面不出現任何提權相關的標籤、提示或按鈕", async () => {
    const w = render();
    await connected(w, { platform: "Linux", platformAdditions: '{"is_wayland":false}' });
    expect(tid(w, "rdweb-status").attributes("data-state")).toBe("connected");
    expect(noElevationUi(w)).toEqual([]);
    expect(w.text()).not.toContain("免安裝版");
    expect(w.text()).not.toContain("請求提權");
  });

  it("已安裝的 Windows 受控端、沒有 is_installed 的舊版：也什麼都不顯示", async () => {
    for (const additions of ['{"is_installed":true}', "", "{broken"]) {
      const w = render();
      await connected(w, { platformAdditions: additions });
      expect(noElevationUi(w), additions).toEqual([]);
      w.unmount();
      wrapper = null;
      m.sessions.length = 0;
    }
  });
});

describe("Windows 免安裝受控端：狀態列標籤與工具列「請求提權」", () => {
  it("平台標籤旁有「免安裝版」（滑過有說明）；工具列有「請求提權」", async () => {
    const w = render();
    await connected(w);
    const tag = tid(w, "rdweb-elev-tag");
    expect(tag.text()).toBe("免安裝版");
    await tag.trigger("mouseenter");
    await vi.advanceTimersByTimeAsync(400);
    await flush();
    expect(document.body.textContent).toContain("免安裝執行的 RustDesk 無法操作以系統管理員身分執行的視窗與 UAC 確認畫面");
    expect(tid(w, "rdweb-elev-menu").exists()).toBe(true);
    expect(tid(w, "rdweb-elev-menu").text()).toContain("請求提權");
  });

  it("唯讀檢視：標籤照常、沒有「請求提權」；對方關閉控制權時也沒有", async () => {
    const ro = render();
    await connected(ro, {}, { viewOnly: true });
    expect(tid(ro, "rdweb-elev-tag").exists()).toBe(true);
    expect(tid(ro, "rdweb-elev-menu").exists()).toBe(false);
    ro.unmount();
    wrapper = null;

    const kb = render();
    await connected(kb);
    current().opts.events.keyboardPermission?.(false);
    await flush();
    expect(tid(kb, "rdweb-elev-menu").exists()).toBe(false);
    current().opts.events.keyboardPermission?.(true);
    await flush();
    expect(tid(kb, "rdweb-elev-menu").exists()).toBe(true);
  });

  it("輔助服務已經在跑：標籤是「免安裝版・已提權」，沒有「請求提權」", async () => {
    const w = render();
    await connected(w);
    await peer("portableService", false);
    expect(tid(w, "rdweb-elev-menu").exists()).toBe(true);
    await peer("portableService", true);
    expect(tid(w, "rdweb-elev-tag").text()).toBe("免安裝版・已提權");
    expect(tid(w, "rdweb-elev-menu").exists()).toBe(false);
  });
});

describe("前景是系統管理員視窗、UAC 確認畫面的提示（不擋畫面）", () => {
  it("收到 true 顯示、收到 false 移除；提示裡有「請求提權」", async () => {
    const w = render();
    await connected(w);
    await peer("foregroundElevated", true);
    const fg = tid(w, "rdweb-elev-foreground");
    expect(fg.exists()).toBe(true);
    expect(fg.text()).toContain("受控端目前在前景的視窗以系統管理員權限執行");
    expect(fg.text()).toContain("請求提權");
    expect(tid(w, "rdweb-canvas").exists()).toBe(true);           // 畫面照常
    expect(document.body.querySelector(".n-modal")).toBeNull();     // 不是對話框
    await peer("uac", true);
    expect(tid(w, "rdweb-elev-uac").text()).toContain("受控端正在顯示 UAC 確認畫面");
    await peer("foregroundElevated", false);
    expect(tid(w, "rdweb-elev-foreground").exists()).toBe(false);
    expect(tid(w, "rdweb-elev-uac").exists()).toBe(true);
    await peer("uac", false);
    expect(tid(w, "rdweb-elev-uac").exists()).toBe(false);
  });

  it("唯讀檢視時不顯示", async () => {
    const w = render();
    await connected(w, {}, { viewOnly: true });
    await peer("foregroundElevated", true);
    await peer("uac", true);
    expect(tid(w, "rdweb-elev-foreground").exists()).toBe(false);
    expect(tid(w, "rdweb-elev-uac").exists()).toBe(false);
  });

  it("提示裡的「請求提權」也能選兩種方式", async () => {
    const w = render();
    await connected(w);
    await peer("foregroundElevated", true);
    await pick(tid(w, "rdweb-elev-foreground-request").element as HTMLElement, "由受控端確認");
    expect(current().elevations).toEqual([{ method: "direct" }]);
  });
});

describe("請求提權：由受控端確認（direct）", () => {
  it("送出 → 已送出（請受控端的人按「是」）→ 提權成功：標籤改成已提權、移除提示；稽核送兩則", async () => {
    const w = render();
    await connected(w);
    await peer("foregroundElevated", true);
    await peer("uac", true);
    await pick(menuButton(w), "由受控端確認（受控端要在 UAC 按「是」）");
    const s = current();
    expect(s.elevations).toEqual([{ method: "direct" }]);
    expect(s.reports).toEqual([["direct", "requested", ""]]);
    expect(noticeText()).toContain("正在送出提權請求");
    expect((menuButton(w) as HTMLButtonElement).disabled).toBe(true);    // 進行中不能再送

    await peer("elevationResponse", "");
    expect(noticeText()).toContain("已送出：請受控端那台的人在 UAC 視窗按「是」");

    await peer("portableService", true);
    expect(noticeText()).toContain("提權成功");
    expect(tid(w, "rdweb-elev-tag").text()).toBe("免安裝版・已提權");
    expect(tid(w, "rdweb-elev-foreground").exists()).toBe(false);
    expect(tid(w, "rdweb-elev-uac").exists()).toBe(false);
    expect(tid(w, "rdweb-elev-menu").exists()).toBe(false);
    expect(s.reports).toEqual([["direct", "requested", ""], ["direct", "ok", ""]]);
  });

  it("選單裡寫明稽核是瀏覽器自報的", async () => {
    const w = render();
    await connected(w);
    menuButton(w).click();
    await flush();
    expect(document.body.textContent).toContain("由這個瀏覽器回報");
  });
});

describe("請求提權：用系統管理員帳號（logon）", () => {
  it("對話框寫明帳號密碼直接加密送到受控端；送出後立刻清空；不送給後端、不寫進瀏覽器儲存", async () => {
    const w = render();
    await connected(w);
    await pick(menuButton(w), "用系統管理員帳號");
    const dlg = body("rdweb-elev-logon");
    expect(dlg).toBeTruthy();
    expect(dlg!.textContent).toContain("帳號密碼直接加密送到受控端，jt-ipam 伺服器看不到");
    const pwInput = document.body.querySelector<HTMLInputElement>('[data-testid="rdweb-elev-password"] input')!;
    expect(pwInput.type).toBe("password");
    expect(pwInput.getAttribute("autocomplete")).toBe("new-password");     // 不讓瀏覽器填入或記住
    setInput("rdweb-elev-user", "CORP\\administrator");
    setInput("rdweb-elev-password", "S3cret-Pa55");
    await flush();
    body("rdweb-elev-logon-submit")!.click();
    await flush();

    const s = current();
    expect(s.elevations).toEqual([{ method: "logon", username: "CORP\\administrator", password: "S3cret-Pa55" }]);
    expect(s.reports).toEqual([["logon", "requested", ""]]);
    expect(noticeText()).toContain("正在送出提權請求");
    await peer("elevationResponse", "");
    expect(noticeText()).toContain("已送出：等待受控端啟動");
    await peer("portableService", true);
    expect(noticeText()).toContain("提權成功");

    // 帳號密碼：不在送給後端的稽核、不在瀏覽器儲存、不留在畫面上
    const reported = JSON.stringify(s.reports);
    expect(reported).not.toContain("administrator");
    expect(reported).not.toContain("S3cret-Pa55");
    expect(storageDump()).not.toContain("S3cret-Pa55");
    expect(storageDump()).not.toContain("administrator");
    expect(document.body.innerHTML).not.toContain("S3cret-Pa55");
  });

  it("取消對話框：欄位清空，什麼都不送；再打開是空的", async () => {
    const w = render();
    await connected(w);
    await pick(menuButton(w), "用系統管理員帳號");
    setInput("rdweb-elev-user", "admin");
    setInput("rdweb-elev-password", "pw-typed");
    await flush();
    body("rdweb-elev-logon-cancel")!.click();
    await vi.advanceTimersByTimeAsync(500);
    await flush();
    expect(current().elevations).toEqual([]);
    expect(current().reports).toEqual([]);
    await pick(menuButton(w), "用系統管理員帳號");
    expect(document.body.querySelector<HTMLInputElement>('[data-testid="rdweb-elev-user"] input')!.value).toBe("");
    expect(document.body.querySelector<HTMLInputElement>('[data-testid="rdweb-elev-password"] input')!.value).toBe("");
  });

  it("沒有帳號不能送出", async () => {
    const w = render();
    await connected(w);
    await pick(menuButton(w), "用系統管理員帳號");
    setInput("rdweb-elev-password", "pw");
    await flush();
    expect((body("rdweb-elev-logon-submit") as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("回覆是錯誤、逾時", () => {
  it("三種常見原文翻譯成說明（附原文），其他顯示原文；稽核 error 帶原文", async () => {
    const cases: [string, string][] = [
      ["No permission", "受控端不允許鍵盤控制"],
      ["No need to elevate", "不需要提權"],
      ["Failed to run portable service process: canceled", "受控端無法啟動輔助服務"],
      ["already running", "提權失敗：already running"],
      ["Access is denied.", "提權失敗：Access is denied."],
    ];
    for (const [raw, shown] of cases) {
      const w = render();
      await connected(w);
      await pick(menuButton(w), "由受控端確認");
      await peer("elevationResponse", raw);
      expect(noticeText(), raw).toContain(shown);
      expect(noticeText(), raw).toContain(raw);
      expect(current().reports[1]).toEqual(["direct", "error", raw]);
      expect(tid(w, "rdweb-elev-tag").text()).toBe("免安裝版");
      expect((menuButton(w) as HTMLButtonElement).disabled).toBe(false);      // 可以再試
      w.unmount();
      wrapper = null;
      m.sessions.length = 0;
    }
  });

  it("送出後 60 秒還沒成功：提權沒有完成，可以再試；稽核 timeout", async () => {
    const w = render();
    await connected(w);
    await pick(menuButton(w), "由受控端確認");
    await peer("elevationResponse", "");
    await vi.advanceTimersByTimeAsync(59_000);
    await flush();
    expect(noticeText()).toContain("已送出");
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    expect(noticeText()).toContain("提權沒有完成（UAC 可能被拒絕或沒有人按）");
    expect(current().reports.map((r) => r[1])).toEqual(["requested", "timeout"]);
    await pick(menuButton(w), "由受控端確認");
    expect(current().elevations).toHaveLength(2);
  });

  it("結果的提示可以關掉", async () => {
    const w = render();
    await connected(w);
    await pick(menuButton(w), "由受控端確認");
    await peer("elevationResponse", "No permission");
    const close = document.body.querySelector<HTMLElement>('[data-testid="rdweb-elev-notice"] .n-base-close');
    expect(close).toBeTruthy();
    close!.click();
    await flush();
    expect(body("rdweb-elev-notice")).toBeNull();
  });

  it("session 沒有送出（例如對方剛關閉控制權）：提示無法請求，不記稽核", async () => {
    const w = render();
    await connected(w);
    current().refuseElevation = true;
    await pick(menuButton(w), "由受控端確認");
    expect(current().reports).toEqual([]);
    expect(body("rdweb-elev-notice")).toBeNull();
    expect(document.body.textContent).toContain("目前無法請求提權");
  });
});

describe("自動重連（附錄 G）：提權狀態與提示都不沿用", () => {
  it("已提權、有提示的連線斷了：重連後以新連線收到的訊息重新判斷", async () => {
    const w = render();
    await connected(w);
    await peer("foregroundElevated", true);
    await pick(menuButton(w), "由受控端確認");
    await peer("portableService", true);
    expect(tid(w, "rdweb-elev-tag").text()).toBe("免安裝版・已提權");
    await peer("uac", true);                              // 服務在跑時受控端不會送 true；就算送了也不顯示
    expect(tid(w, "rdweb-elev-uac").exists()).toBe(false);

    current().drop({ code: "rd_peer_closed" });
    await flush();
    expect(tid(w, "rdweb-status").attributes("data-state")).toBe("reconnecting");
    expect(noElevationUi(w)).toEqual([]);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(sessions()).toHaveLength(2);
    current().connect();
    await flush();
    expect(tid(w, "rdweb-elev-tag").text()).toBe("免安裝版");
    expect(tid(w, "rdweb-elev-menu").exists()).toBe(true);
    expect(tid(w, "rdweb-elev-foreground").exists()).toBe(false);
    expect(body("rdweb-elev-notice")).toBeNull();
    expect(current().reports).toEqual([]);
  });

  it("請求進行中斷線：重連後不會再跳出逾時、不記稽核", async () => {
    const w = render();
    await connected(w);
    await pick(menuButton(w), "由受控端確認");
    const first = current();
    first.drop({ code: "ws_closed" });
    await flush();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    current().connect();
    await flush();
    await vi.advanceTimersByTimeAsync(120_000);
    await flush();
    expect(body("rdweb-elev-notice")).toBeNull();
    expect(first.reports).toEqual([["direct", "requested", ""]]);
    expect(current().reports).toEqual([]);
  });
});
