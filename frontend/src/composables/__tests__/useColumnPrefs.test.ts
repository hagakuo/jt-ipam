import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// 欄位順序（使用者 2026-10-05）：存在 table_columns[`${表}:order`]，跟可見欄位分開。
// 模組層有快取（cache / loaded），每個測試 vi.resetModules 重新載入。

const get = vi.fn();
const patch = vi.fn();
vi.mock("@/api/client", () => ({
  apiClient: {
    get: (...a: unknown[]) => get(...a),
    patch: (...a: unknown[]) => patch(...a),
  },
}));

async function fresh() {
  vi.resetModules();
  return (await import("@/composables/useColumnPrefs")).useColumnPrefs;
}
async function flush() {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

const ALL = ["ip", "hostname", "mac", "state"];
const COLS = [
  { type: "selection" },
  { key: "ip" }, { key: "hostname" }, { key: "mac" }, { key: "state" },
  { key: "actions", fixed: "right" },
];
const keysOf = (cols: { key?: string; type?: string }[]) => cols.map((c) => c.key ?? c.type);

describe("useColumnPrefs 欄位順序", () => {
  beforeEach(() => {
    localStorage.clear();
    get.mockReset();
    patch.mockReset();
    get.mockResolvedValue({ data: { table_columns: null } });
    patch.mockResolvedValue({ data: {} });
    vi.useFakeTimers();
  });
  afterEach(() => { vi.useRealTimers(); });

  it("沒自訂過順序：欄位原樣（同一個陣列），order 是 null", async () => {
    const use = await fresh();
    const p = use("t_default", ALL, ALL);
    await flush();
    expect(p.order.value).toBeNull();
    expect(p.orderColumns(COLS)).toBe(COLS);
  });

  it("既有資料的可見清單是勾選先後，不可以被當成顯示順序", async () => {
    // 舊版存下來的：後勾的 mac 接在最後 —— 畫面一直是照欄位定義的順序顯示
    get.mockResolvedValue({ data: { table_columns: { t_legacy: ["ip", "state", "mac"] } } });
    const use = await fresh();
    const p = use("t_legacy", ALL, ["ip", "state"]);
    await flush();
    expect(p.order.value).toBeNull();
    expect(keysOf(p.orderColumns(COLS))).toEqual(["selection", "ip", "hostname", "mac", "state", "actions"]);
  });

  it("setOrder：重排可動的欄位，勾選欄與固定在右邊的操作欄不動；存進本機與後端", async () => {
    const use = await fresh();
    const p = use("t_set", ALL, ALL);
    await flush();
    p.setOrder(["state", "ip", "mac", "hostname"]);
    expect(keysOf(p.orderColumns(COLS))).toEqual(["selection", "state", "ip", "mac", "hostname", "actions"]);
    expect(JSON.parse(localStorage.getItem("jt-ipam:table_columns") || "{}")["t_set:order"])
      .toEqual(["state", "ip", "mac", "hostname"]);
    vi.advanceTimersByTime(500);
    expect(patch).toHaveBeenCalledWith("/api/v1/me/preferences", {
      table_columns: expect.objectContaining({ "t_set:order": ["state", "ip", "mac", "hostname"] }),
    });
  });

  it("順序跟可見分開：隱藏再勾回來的欄位回到排好的位置", async () => {
    const use = await fresh();
    const p = use("t_hide", ALL, ALL);
    await flush();
    p.setOrder(["mac", "ip", "hostname", "state"]);
    p.setVisible(["ip", "hostname", "state"]);          // 隱藏 mac
    p.setVisible(["ip", "hostname", "state", "mac"]);   // 勾回來（接在可見清單最後）
    const shown = p.orderColumns(COLS.filter((c) => !c.key || c.fixed || p.visibleKeys.value.includes(c.key)));
    expect(keysOf(shown)).toEqual(["selection", "mac", "ip", "hostname", "state", "actions"]);
  });

  it("後端讀回的順序會套用；之後才新增的欄位留在畫面定義的位置", async () => {
    get.mockResolvedValue({ data: { table_columns: { "t_load:order": ["state", "ip", "hostname", "gone"] } } });
    const use = await fresh();
    const p = use("t_load", ALL, ALL);   // mac 是後來加的欄位（存順序的時候還沒有）；gone 是已移除的欄位
    await flush();
    expect(p.order.value).toEqual(["state", "ip", "hostname"]);
    expect(keysOf(p.orderColumns(COLS))).toEqual(["selection", "state", "ip", "mac", "hostname", "actions"]);
    expect(p.orderKeys(["ip", "hostname", "mac", "state", "unknown"]))
      .toEqual(["state", "ip", "mac", "hostname", "unknown"]);
  });

  it("不在選單裡的常駐欄（在 allKeys、不在順序裡）不會跟著鄰居被拖走", async () => {
    const use = await fresh();
    const keys = [...ALL, "actions_inline"];
    const p = use("t_inline", keys, keys);
    await flush();
    p.setOrder(["state", "ip", "hostname", "mac"]);   // 選單只送出它有的欄位
    const cols = [{ key: "ip" }, { key: "hostname" }, { key: "mac" }, { key: "state" }, { key: "actions_inline" }];
    expect(keysOf(p.orderColumns(cols))).toEqual(["state", "ip", "hostname", "mac", "actions_inline"]);
  });

  it("還原預設值：可見欄位與順序一起還原，後端的順序 key 被拿掉", async () => {
    const use = await fresh();
    const p = use("t_reset", ALL, ["ip", "hostname"]);
    await flush();
    p.setOrder(["hostname", "ip", "mac", "state"]);
    p.setVisible(ALL);
    p.reset();
    expect(p.order.value).toBeNull();
    expect(p.visibleKeys.value).toEqual(["ip", "hostname"]);
    vi.advanceTimersByTime(500);
    const sent = patch.mock.calls[patch.mock.calls.length - 1][1].table_columns;
    expect(sent).not.toHaveProperty("t_reset:order");
    expect(sent.t_reset).toEqual(["ip", "hostname"]);
  });

  it("兩個元件用同一張表：一邊改順序，另一邊跟著變", async () => {
    const use = await fresh();
    const a = use("t_shared", ALL, ALL);
    const b = use("t_shared", ALL, ALL);
    await flush();
    a.setOrder(["hostname", "ip", "mac", "state"]);
    expect(b.order.value).toEqual(["hostname", "ip", "mac", "state"]);
  });
});
