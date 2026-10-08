import { describe, it, expect, beforeEach, vi } from "vitest";

// usePinned 已改為「跟著帳號存」（後端 user_preferences.pinned）。
// 這裡 mock preferences API，並用 vi.resetModules 隔離 module-level 快取（loaded / allPinned / cache）。

const getPreferences = vi.fn();
const updatePreferences = vi.fn();

vi.mock("@/api/preferences", () => ({
  getPreferences: (...a: unknown[]) => getPreferences(...a),
  updatePreferences: (...a: unknown[]) => updatePreferences(...a),
}));

async function freshUsePinned() {
  vi.resetModules();
  const mod = await import("@/composables/usePinned");
  return mod.usePinned;
}

// 等 ensureLoaded() 的 microtask 鏈跑完（getPreferences 是 mock resolved promise）
async function flush() {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

describe("usePinned", () => {
  beforeEach(() => {
    localStorage.clear();
    getPreferences.mockReset();
    updatePreferences.mockReset();
    getPreferences.mockResolvedValue({ pinned: {} });
    updatePreferences.mockResolvedValue(undefined);
  });

  it("toggle 會更新狀態並寫回後端 preferences.pinned", async () => {
    const usePinned = await freshUsePinned();
    const { toggle, isPinned } = usePinned("test-sync");
    await flush();

    toggle("a");
    expect(isPinned("a")).toBe(true);
    expect(updatePreferences).toHaveBeenCalledWith(
      expect.objectContaining({ pinned: expect.objectContaining({ "test-sync": ["a"] }) }),
    );

    toggle("a"); // 再 toggle → 取消釘選
    expect(isPinned("a")).toBe(false);
  });

  it("初始化時讀回後端既有的釘選清單", async () => {
    getPreferences.mockResolvedValue({ pinned: { "test-load": ["x", "y"] } });
    const usePinned = await freshUsePinned();
    const { isPinned } = usePinned("test-load");
    await flush();

    expect(isPinned("x")).toBe(true);
    expect(isPinned("y")).toBe(true);
    expect(isPinned("z")).toBe(false);
  });

  it("舊版 localStorage 內容會在首次載入時搬移到後端", async () => {
    const ns = "test-migrate";
    localStorage.setItem(`jtipam.pinned.${ns}`, JSON.stringify(["m1", "m2"]));
    const usePinned = await freshUsePinned();
    const { isPinned } = usePinned(ns);
    await flush();

    expect(isPinned("m1")).toBe(true);
    expect(updatePreferences).toHaveBeenCalledWith(
      expect.objectContaining({ pinned: expect.objectContaining({ [ns]: ["m1", "m2"] }) }),
    );
    expect(localStorage.getItem(`jtipam.pinned.${ns}`)).toBeNull();
  });

  it("sortPinnedFirst 把釘選項排到最前面且穩定", async () => {
    const usePinned = await freshUsePinned();
    const { toggle, sortPinnedFirst } = usePinned("test-sort");
    await flush();

    toggle("2");
    const rows = [{ id: "1" }, { id: "2" }, { id: "3" }, { id: "4" }];
    const sorted = sortPinnedFirst(rows).map((r) => r.id);
    expect(sorted[0]).toBe("2");
    expect(sorted.slice(1)).toEqual(["1", "3", "4"]);
  });

  it("壞掉的 localStorage 內容不會炸，退回空清單", async () => {
    const ns = "test-bad";
    localStorage.setItem(`jtipam.pinned.${ns}`, "{not json");
    const usePinned = await freshUsePinned();
    const { isPinned } = usePinned(ns);
    await flush();

    expect(isPinned("anything")).toBe(false);
  });

  it("連續兩次 setAll：寫回依序送出、最後一次帶齊最新狀態（不會被晚到的舊請求蓋掉）", async () => {
    // 儀表板機櫃卡片存檔時先清機房、再寫機櫃：以前兩個 PUT 同時在路上，舊的那個晚到就把設定蓋掉
    // （e2e「重新整理後設定還在」時好時壞）
    const usePinned = await freshUsePinned();
    const room = usePinned("dash_rack_room");
    const racks = usePinned("dash_racks");
    await flush();
    let release!: () => void;
    updatePreferences.mockImplementationOnce(() => new Promise<void>((r) => { release = r; }));
    room.setAll([]);
    racks.setAll(["k1"]);
    expect(updatePreferences).toHaveBeenCalledTimes(1);          // 第二個要等第一個回來
    release();
    await flush();
    await flush();
    expect(updatePreferences).toHaveBeenCalledTimes(2);
    expect(updatePreferences.mock.calls[1][0]).toEqual(
      { pinned: expect.objectContaining({ dash_rack_room: [], dash_racks: ["k1"] }) });
  });
});
