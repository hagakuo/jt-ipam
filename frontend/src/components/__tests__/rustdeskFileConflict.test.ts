/**
 * RustDesk 網頁檔案傳輸：上傳遇到同名時的詢問視窗（規格附錄 J.4 第 2 步、J.6）。
 *
 * 實機（官方 1.4.1 受控端）回的 digest 沒有大小與時間，畫面曾經顯示「受控端已經有 （0 B）」：檔名與大小一律用這次上傳的，
 * 受控端的大小與時間只有看起來有意義（大於 0）才顯示；is_identical 時說內容看起來相同。協定流程用假的 RdFileSession 代替。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import { defineComponent, h, nextTick } from "vue";
import { createI18n } from "vue-i18n";
import { createPinia, setActivePinia } from "pinia";
import { NMessageProvider } from "naive-ui";
import zhTW from "@/i18n/zh-TW.json";
import type { ConflictAnswer, ConflictInfo, FileSessionOptions } from "@/rdweb/fileSession";
import RustDeskFileBrowser from "../RustDeskFileBrowser.vue";

const m = vi.hoisted(() => ({ sessions: [] as { opts: FileSessionOptions }[] }));

vi.mock("@/api/rustdeskWeb", () => ({
  requestRustDeskTicket: vi.fn(async () => ({
    ticket: "t1", ws_path: "/api/v1/addresses/a1/rustdesk/ws", peer_id: "123456789", server_name: "rd",
    my_name: "alice (jt-ipam)", transport: "tcp", has_saved_password: false, ttl: 30, kind: "file",
    file_limits: { max_file_bytes: 2048 * 1024 * 1024, max_total_bytes: 10240 * 1024 * 1024 },
  })),
  buildRustDeskWsUrl: (p: string, t: string) => `wss://jt.example${p}?ticket=${t}`,
  listRustDeskCredentials: vi.fn(async () => []),
  saveRustDeskPassword: vi.fn(),
  deleteSavedRustDeskPassword: vi.fn(),
}));

vi.mock("@/rdweb/fileSession", async (importOriginal) => {
  const mod = await importOriginal<typeof import("@/rdweb/fileSession")>();
  class RdFileSession {
    opts: FileSessionOptions;
    constructor(opts: FileSessionOptions) {
      this.opts = opts;
      m.sessions.push(this);
    }
    close() { this.opts.events.closed?.({ byUser: true }); }
    async list() { return { path: "/root", entries: [], windows: false, drives: false }; }
    setShowHidden() { return null; }
    clearFinished() {}
    cancel() {}
  }
  return { ...mod, RdFileSession };
});

async function flush() {
  for (let i = 0; i < 12; i++) {
    await Promise.resolve();
    await nextTick();
  }
}

let wrapper: VueWrapper | null = null;

async function connected(): Promise<FileSessionOptions> {
  const i18n = createI18n({ legacy: false, locale: "zh-TW", messages: { "zh-TW": zhTW } });
  const Host = defineComponent({
    setup: () => () => h(NMessageProvider, null, {
      default: () => h(RustDeskFileBrowser, { addressId: "a1", ip: "192.0.2.10" }),
    }),
  });
  wrapper = mount(Host, { global: { plugins: [i18n] }, attachTo: document.body });
  await flush();
  await wrapper.find('[data-testid="rdfile-password"] input').setValue("pw");
  await wrapper.find('[data-testid="rdfile-connect"]').trigger("click");
  await flush();
  const opts = m.sessions[m.sessions.length - 1].opts;
  opts.events.connected?.({ username: "", hostname: "pc", platform: "Linux", displays: [], currentDisplay: 0,
                            version: "1.4.1", platformAdditions: "" } as never);
  opts.events.listing?.({ path: "/root", entries: [], windows: false, drives: false });
  await flush();
  return opts;
}

const dialogText = () => document.body.querySelector('[data-testid="rdfile-conflict"]')?.textContent ?? "";

beforeEach(() => {
  setActivePinia(createPinia());
  m.sessions.length = 0;
});

afterEach(() => {
  wrapper?.unmount();
  wrapper = null;
});

describe("上傳遇到同名的詢問視窗", () => {
  it("受控端的 digest 沒有大小（0）也沒有檔名：照樣顯示這次上傳的檔名與大小，不顯示 0 B；is_identical 說內容看起來相同", async () => {
    const opts = await connected();
    let answer: ConflictAnswer | null = null;
    const info: ConflictInfo = { name: "jt-up.txt", size: 26, identical: true, remaining: 0 };
    void opts.events.conflict!(info).then((a) => { answer = a; });
    await flush();
    const text = dialogText();
    expect(text).toContain("jt-up.txt");
    expect(text).toContain("26 B");
    expect(text).not.toContain("0 B）");
    expect(text).toContain(zhTW.rdfile.conflict_identical);
    expect(text).not.toContain(zhTW.rdfile.conflict_theirs.split("{")[0]);
    (document.body.querySelector('[data-testid="rdfile-conflict-skip"]') as HTMLElement).click();
    await flush();
    expect(answer).toEqual({ action: "skip", all: false });
    // 視窗淡出的期間內容還在畫面上：不可以變成空的檔名與 0 B
    const after = dialogText();
    if (after) expect(after).toContain("jt-up.txt");
  });

  it("受控端的 digest 帶了大小與時間：另外顯示受控端那個檔案的大小", async () => {
    const opts = await connected();
    void opts.events.conflict!({ name: "a.txt", size: 3, identical: false, remaining: 0, peerSize: 2048,
                                 peerModified: 1_700_000_000 });
    await flush();
    const text = dialogText();
    expect(text).toContain("a.txt");
    expect(text).toContain("3 B");
    expect(text).toContain("2.0 KB");
    expect(text).not.toContain(zhTW.rdfile.conflict_identical);
  });
});
