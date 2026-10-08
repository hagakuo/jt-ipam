/**
 * RustDesk 網頁連線的「螢幕」與「畫質」選單（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 H.5、I.2）：畫面這一側的接線。
 *
 * 協定本身在 src/rdweb/（displays.test.ts、quality.test.ts）；這裡驗證畫面真的照設計做：
 * 只有一個螢幕、而且沒有可選的解析度時不顯示「螢幕」選單（單一螢幕時只有解析度子選單）、選了就切換、被拔除時出提示、自動重連回到選的螢幕；
 * 畫質選了立刻送出、localStorage 只記三個選項、重連沿用；狀態列的小字。協定流程用假的 RdSession 代替。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import { defineComponent, h, nextTick } from "vue";
import { createI18n } from "vue-i18n";
import { NMessageProvider } from "naive-ui";
import zhTW from "@/i18n/zh-TW.json";
import type { CloseInfo, SessionOptions } from "@/rdweb/session";
import type { DisplayInfo, PeerInfo, QualityOption } from "@/rdweb/messages";
import type { DisplayView } from "@/rdweb/displays";
import { QUALITY_STORAGE_KEY, SHOW_STATS_STORAGE_KEY } from "@/rdweb/quality";
import RustDeskScreen from "../RustDeskScreen.vue";

interface FakeSession {
  opts: SessionOptions;
  switched: number[];
  qualities: [QualityOption, readonly string[]][];
  resolutions: { width: number; height: number }[];
  connect(info?: Partial<PeerInfo>): void;
  drop(info: CloseInfo): void;
}

const m = vi.hoisted(() => ({
  sessions: [] as unknown[],
  requestRustDeskTicket: vi.fn(),
}));

vi.mock("@/api/rustdeskWeb", () => ({
  requestRustDeskTicket: m.requestRustDeskTicket,
  buildRustDeskWsUrl: (p: string, t: string) => `wss://jt.example${p}?ticket=${t}`,
  listRustDeskCredentials: vi.fn(async () => []),
  saveRustDeskPassword: vi.fn(),
  deleteSavedRustDeskPassword: vi.fn(),
}));

vi.mock("@/rdweb/video", () => ({
  probeDecoding: async () => ({ webcodecs: true, vp9: true, h264: true, vp8: false, av1: true }),
  VideoPipeline: class { decoded = 0; currentCodec = "vp9"; push() {} close() {} waitForKeyframe() {} },
}));

vi.mock("@/rdweb/session", () => {
  class RdSession {
    opts: SessionOptions;
    closed = false;
    clipboardEnabled = false;
    lastPointer = null;
    switched: number[] = [];
    qualities: [QualityOption, readonly string[]][] = [];
    resolutions: { width: number; height: number }[] = [];
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
    switchDisplay(n: number) { this.switched.push(n); return true; }
    setQuality(q: QualityOption, touched: readonly string[] = []) { this.qualities.push([q, touched]); return true; }
    changeResolution(r: { width: number; height: number }) { this.resolutions.push(r); return true; }
    setClipboard() {}
    sendClipboard() { return false; }
    requestKeyframe() {}
    sendMouse() { return false; }
    sendKey() {}
    connect(over: Partial<PeerInfo> = {}) {
      const info = {
        username: "", hostname: "pc", platform: "Linux", currentDisplay: 0, version: "1.4.1", platformAdditions: "",
        displays: [display(0, 1920, 1080)], resolutions: [], encoding: { h264: true, h265: false, vp8: false, av1: false },
        ...over,
      };
      this.opts.events.connected?.(info as PeerInfo);
    }
    drop(i: CloseInfo) { this.closed = true; this.opts.events.closed?.(i); }
  }
  function display(x: number, width: number, height: number) {
    return { x, y: 0, width, height, name: "", cursorEmbedded: false, scale: 1, online: true,
             originalResolution: { width: 0, height: 0 } };
  }
  return { RdSession };
});

const disp = (x: number, width: number, height: number, orig = { width: 0, height: 0 }): DisplayInfo => ({
  x, y: 0, width, height, name: "", cursorEmbedded: false, scale: 1, online: true, originalResolution: orig,
});
const TWO = [disp(0, 1920, 1080), disp(1920, 2560, 1440)];
const sessions = () => m.sessions as FakeSession[];
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

async function connected(w: VueWrapper, over: Partial<PeerInfo> = {}) {
  await flush();
  await w.find('[data-testid="rdweb-password"] input').setValue("pw");
  await tid(w, "rdweb-connect").trigger("click");
  await flush();
  sessions()[sessions().length - 1].connect(over);
  await flush();
}

/** 打開工具列的下拉選單，按下文字符合的項目（選單畫在 body 底下） */
async function pick(w: VueWrapper, trigger: string, text: string) {
  await tid(w, trigger).trigger("click");
  await flush();
  const opts = Array.from(document.body.querySelectorAll<HTMLElement>(".n-dropdown-option-body"));
  const hit = opts.find((o) => (o.textContent || "").includes(text));
  expect(hit, `選單裡找不到「${text}」：${opts.map((o) => o.textContent).join(" / ")}`).toBeTruthy();
  hit!.click();
  await flush();
}

function view(over: Partial<DisplayView> = {}): DisplayView {
  return { list: TWO, primary: 0, current: 0, geometry: { x: 0, y: 0, width: 1920, height: 1080, scale: 1, cursorEmbedded: false },
           resolutions: [], originalResolution: { width: 0, height: 0 }, ...over };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"] });
  m.sessions.length = 0;
  ticketNo = 0;
  localStorage.clear();
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
});

describe("「螢幕」選單（H.5）", () => {
  it("只有一個螢幕、而且沒有可選的解析度時不顯示", async () => {
    const w = render();
    await connected(w);
    expect(tid(w, "rdweb-displays").exists()).toBe(false);
    expect(tid(w, "rdweb-quality").exists()).toBe(true);
  });

  it("單一螢幕但可以改解析度：照樣顯示，裡面只有解析度子選單（規格 H.5 更新）", async () => {
    const w = render();
    await connected(w, { resolutions: [{ width: 1280, height: 720 }, { width: 1920, height: 1080 }] });
    expect(tid(w, "rdweb-displays").exists()).toBe(true);
    await tid(w, "rdweb-displays").trigger("click");
    await flush();
    const top = Array.from(document.body.querySelectorAll(".n-dropdown-option-body__label")).map((o) => o.textContent);
    expect(top).toEqual(["解析度"]);                 // 沒有「螢幕 1（…）」也沒有分隔線前的螢幕清單
    const parent = document.body.querySelector<HTMLElement>(".n-dropdown-option-body")!;
    parent.dispatchEvent(new MouseEvent("mouseenter"));
    parent.dispatchEvent(new MouseEvent("mousemove", { bubbles: true }));
    await flush();
    const hit = Array.from(document.body.querySelectorAll<HTMLElement>(".n-dropdown-option-body"))
      .find((o) => o.textContent === "1280×720")!;
    expect(hit).toBeTruthy();
    hit.click();
    await flush();
    expect(sessions()[0].resolutions).toEqual([{ width: 1280, height: 720 }]);
  });

  it("單一螢幕：唯讀檢視、對方關閉控制權、或只有目前這一個解析度時不顯示", async () => {
    const ro = render();
    await flush();
    await tid(ro, "rdweb-view-only").trigger("click");
    await connected(ro, { resolutions: [{ width: 1280, height: 720 }] });
    expect(tid(ro, "rdweb-displays").exists()).toBe(false);
    ro.unmount();

    const kb = render();
    await connected(kb, { resolutions: [{ width: 1280, height: 720 }] });
    expect(tid(kb, "rdweb-displays").exists()).toBe(true);
    sessions()[sessions().length - 1].opts.events.keyboardPermission?.(false);
    await flush();
    expect(tid(kb, "rdweb-displays").exists()).toBe(false);
    kb.unmount();

    // 能選的只有目前的大小（例如只回報了跟目前一樣的原始解析度）：沒有東西可以選
    const same = render();
    await connected(same, { resolutions: [{ width: 1920, height: 1080 }],
                            displays: [disp(0, 1920, 1080, { width: 1920, height: 1080 })] });
    expect(tid(same, "rdweb-displays").exists()).toBe(false);
  });

  it("兩個螢幕：列出「螢幕 N（寬×高）」並標出目前的與主螢幕；選了就切換", async () => {
    const w = render();
    await connected(w, { displays: TWO });
    expect(tid(w, "rdweb-displays").exists()).toBe(true);
    await tid(w, "rdweb-displays").trigger("click");
    await flush();
    const text = document.body.textContent || "";
    expect(text).toContain("螢幕 1（1920×1080）");
    expect(text).toContain("螢幕 2（2560×1440）");
    expect(text).toContain("目前");
    expect(text).toContain("主螢幕");
    const hit = Array.from(document.body.querySelectorAll<HTMLElement>(".n-dropdown-option-body"))
      .find((o) => (o.textContent || "").includes("螢幕 2"))!;
    hit.click();
    await flush();
    expect(sessions()[0].switched).toEqual([1]);
  });

  it("螢幕被拔除：出提示", async () => {
    const w = render();
    await connected(w, { displays: TWO });
    sessions()[0].opts.events.displays?.(view({ list: [TWO[0]], current: 0 }), "removed", 1);
    await flush();
    expect(document.body.textContent).toContain("螢幕 2 已拔除，改看螢幕 1");
    expect(tid(w, "rdweb-displays").exists()).toBe(false);     // 只剩一個螢幕
  });

  it("自動重連後回到使用者選的螢幕；手動重新連線不帶", async () => {
    const w = render();
    await connected(w, { displays: TWO });
    expect(sessions()[0].opts.display).toBeUndefined();
    await pick(w, "rdweb-displays", "螢幕 2");
    sessions()[0].drop({ code: "rd_peer_closed", detail: "peer_closed" });
    await flush();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(sessions()).toHaveLength(2);
    expect(sessions()[1].opts.display).toBe(1);
  });

  it("解析度子選單（H.4）：列出原始解析度與受控端給的清單，選了就送", async () => {
    const w = render();
    await connected(w, { displays: TWO });
    sessions()[0].opts.events.displays?.(view({ resolutions: [{ width: 1280, height: 720 }],
                                                 originalResolution: { width: 1920, height: 1080 } }), "switch");
    await flush();
    await tid(w, "rdweb-displays").trigger("click");
    await flush();
    const parent = Array.from(document.body.querySelectorAll<HTMLElement>(".n-dropdown-option"))
      .find((o) => o.querySelector(".n-dropdown-option-body__label")?.textContent === "解析度");
    expect(parent).toBeTruthy();
    parent!.querySelector(".n-dropdown-option-body")!.dispatchEvent(new MouseEvent("mouseenter"));
    parent!.querySelector(".n-dropdown-option-body")!.dispatchEvent(new MouseEvent("mousemove", { bubbles: true }));
    await flush();
    const labels = Array.from(document.body.querySelectorAll(".n-dropdown-option-body")).map((o) => o.textContent || "");
    expect(labels).toContain("原始解析度（1920×1080）");
    const hit = Array.from(document.body.querySelectorAll<HTMLElement>(".n-dropdown-option-body"))
      .find((o) => o.textContent === "1280×720")!;
    hit.click();
    await flush();
    expect(sessions()[0].resolutions).toEqual([{ width: 1280, height: 720 }]);
  });

  it("唯讀檢視時沒有解析度子選單", async () => {
    const w = render();
    await flush();
    await tid(w, "rdweb-view-only").trigger("click");
    await connected(w, { displays: TWO });
    sessions()[0].opts.events.displays?.(view({ resolutions: [{ width: 1280, height: 720 }] }), "switch");
    await flush();
    await tid(w, "rdweb-displays").trigger("click");
    await flush();
    const labels = Array.from(document.body.querySelectorAll(".n-dropdown-option-body__label")).map((o) => o.textContent);
    expect(labels).toContain("螢幕 2（2560×1440）");       // 選單確實打開了
    expect(labels).not.toContain("解析度");
  });
});

describe("「畫質」選單（I.2）", () => {
  it("選了立刻送出（Misc.option 由 session 只送改變的欄位）；localStorage 只記三個選項；重連沿用", async () => {
    const w = render();
    await connected(w);
    expect(sessions()[0].opts.quality).toMatchObject({ imageQuality: 3, customFps: 30, prefer: 0 });
    const lastSet = () => sessions()[0].qualities[sessions()[0].qualities.length - 1];
    await pick(w, "rdweb-quality", "低（省頻寬）");
    expect(lastSet()).toEqual([{ imageQuality: 2, customImageQuality: 0, customFps: 30, prefer: 0 }, ["imageQuality"]]);
    await pick(w, "rdweb-quality", "60 fps");
    expect(lastSet()).toEqual([{ imageQuality: 2, customImageQuality: 0, customFps: 60, prefer: 0 }, ["customFps"]]);
    expect(localStorage.length).toBe(1);
    expect(JSON.parse(localStorage.getItem(QUALITY_STORAGE_KEY)!)).toEqual(
      { level: "low", custom: 50, fps: 60, codec: "auto" });
    sessions()[0].drop({ code: "ws_closed" });
    await flush();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(sessions()[1].opts.quality).toMatchObject({ imageQuality: 2, customFps: 60 });
  });

  it("編碼偏好只列瀏覽器解得了、受控端也編得出來的；旁邊有「最後設定的為準」的說明", async () => {
    const w = render();
    await connected(w);           // 瀏覽器：VP9、H.264、AV1；受控端：H.264
    await tid(w, "rdweb-quality").trigger("click");
    await flush();
    const labels = Array.from(document.body.querySelectorAll(".n-dropdown-option-body")).map((o) => o.textContent || "");
    expect(labels).toContain("VP9");
    expect(labels).toContain("H.264");
    expect(labels).not.toContain("AV1");
    expect(document.body.textContent).toContain("多人同時看同一台時，畫質以最後設定的為準。");
  });

  it("沒有改設定就不寫 localStorage", async () => {
    const w = render();
    await connected(w);
    expect(localStorage.length).toBe(0);
  });
});

describe("狀態列的小字（I.2）", () => {
  it("延遲、位元率、每秒解出的張數、編碼名稱", async () => {
    // 效能列預設不顯示（畫質選單勾「顯示效能資訊」才出現）：這裡直接打開
    localStorage.setItem(SHOW_STATS_STORAGE_KEY, "1");
    const w = render();
    await connected(w);
    sessions()[0].opts.events.delay?.({ lastDelay: 23, targetBitrate: 2073 });
    await vi.advanceTimersByTimeAsync(2000);
    await flush();
    const text = tid(w, "rdweb-stats").text();
    expect(text).toContain("延遲 23 ms");
    expect(text).toContain("2073 kbps");
    expect(text).toContain("0 fps");
    expect(text).toContain("VP9");
  });
});
