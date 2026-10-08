/**
 * 主控台狀態列的連線時間（使用者 2026-10-06：VNC、SSH、RDP、RustDesk 等所有連線都要顯示連線時間）。
 * 連上開始計時；斷線停在最後的時間；再連上（新的一次）從 0 開始；RustDesk 自動重連中照樣計時。
 */
import { describe, expect, it, vi, afterEach, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { mount } from "@vue/test-utils";
import { nextTick } from "vue";
import { createI18n } from "vue-i18n";
import zh from "../../i18n/zh-TW.json";
import ConnElapsed from "../ConnElapsed.vue";
import { fmtClock } from "../../utils/datetime";

const i18n = () => createI18n({ legacy: false, locale: "zh-TW", messages: { "zh-TW": zh } });

function mk(props: { active: boolean; paused?: boolean }) {
  return mount(ConnElapsed, { props, global: { plugins: [i18n()] } });
}
const text = (w: ReturnType<typeof mk>) => w.find("[data-testid='conn-elapsed']").text();

describe("fmtClock", () => {
  it("時:分:秒，小時至少兩位、超過一天照樣累加", () => {
    expect(fmtClock(0)).toBe("00:00:00");
    expect(fmtClock(65.9)).toBe("00:01:05");
    expect(fmtClock(3725)).toBe("01:02:05");
    expect(fmtClock(26 * 3600 + 3)).toBe("26:00:03");
    expect(fmtClock(-5)).toBe("00:00:00");
  });
});

describe("ConnElapsed", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-06T08:00:00Z")); });
  afterEach(() => { vi.useRealTimers(); });

  it("還沒連上不顯示", () => {
    const w = mk({ active: false });
    expect(w.find("[data-testid='conn-elapsed']").exists()).toBe(false);
  });

  it("連上開始計時、斷線停住、再連上從 0 開始", async () => {
    const w = mk({ active: false });
    await w.setProps({ active: true });
    expect(text(w)).toContain("00:00:00");
    vi.advanceTimersByTime(65_000);
    await nextTick();
    expect(text(w)).toContain("00:01:05");
    await w.setProps({ active: false });
    vi.advanceTimersByTime(30_000);
    await nextTick();
    expect(text(w)).toContain("00:01:05");           // 斷線後停在最後的時間
    await w.setProps({ active: true });
    expect(text(w)).toContain("00:00:00");           // 新的一次連線
  });

  it("自動重連中照樣計時，重連成功不歸零", async () => {
    const w = mk({ active: true });
    vi.advanceTimersByTime(10_000);
    await w.setProps({ active: false, paused: true });
    vi.advanceTimersByTime(5_000);
    await nextTick();
    expect(text(w)).toContain("00:00:15");
    await w.setProps({ active: true, paused: false });
    vi.advanceTimersByTime(1_000);
    await nextTick();
    expect(text(w)).toContain("00:00:16");
  });

  it("卸載後不再跑計時器", async () => {
    const w = mk({ active: true });
    w.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("每個主控台的狀態列都有連線時間", () => {
  const files = ["SshTerminal", "SftpBrowser", "RdpScreen", "VncScreen", "NoVncScreen", "BmcScreen",
                 "RustDeskScreen", "RustDeskFileBrowser"];
  for (const f of files) {
    it(f, () => {
      const src = readFileSync(resolve(__dirname, `../${f}.vue`), "utf-8");
      expect(src, `${f} 的狀態列沒有 <ConnElapsed>`).toMatch(/<ConnElapsed\b/);
    });
  }
});
