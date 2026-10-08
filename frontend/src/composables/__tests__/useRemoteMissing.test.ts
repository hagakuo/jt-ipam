/**
 * 「未裝 Agent 的 IP」改成伺服器端分頁之後（2026-10-01），篩選、排序、分頁都靠送給後端的參數；
 * 送錯一個參數畫面照樣渲染、只是內容不對，所以這裡直接驗參數與幾個容易出錯的時序。
 */
import { describe, expect, it, vi } from "vitest";
import { nextTick } from "vue";

vi.mock("vue-i18n", () => ({ useI18n: () => ({ t: (k: string) => k }) }));
const setPageSize = vi.fn();
vi.mock("@/stores/ui", () => ({ useUiStore: () => ({ pageSize: 100, setPageSize }) }));

import { useRemoteMissing, type MissingPage, type MissingQuery } from "../useRemoteMissing";

type Row = { ip: string };
const facets = (subnets: string[] = ["n1", "n2"]) => ({
  sections: [{ value: "s1", label: "HQ" }], subnets: subnets.map((v) => ({ value: v, label: v })),
  customers: [], statuses: [{ value: "online", label: "online" }],
});
const page = (items: Row[], total = items.length, subnets?: string[]): MissingPage<Row> =>
  ({ items, total, total_all: 500, facets: facets(subnets) });
const flush = () => new Promise((r) => setTimeout(r, 0));
const last = <T>(xs: T[]): T | undefined => xs[xs.length - 1];

describe("useRemoteMissing", () => {
  it("篩選條件、排序、頁碼都轉成後端的參數；換篩選回到第 1 頁", async () => {
    const calls: MissingQuery[] = [];
    const m = useRemoteMissing<Row>(async (q) => { calls.push(q); return page([{ ip: "a" }], 250); });
    await m.load();
    expect(last(calls)).toEqual({ page: 1, page_size: 100 });
    expect(m.pagination.itemCount).toBe(250);
    expect(m.totalAll.value).toBe(500);

    m.pagination.onUpdatePage(3);
    await flush();
    expect(last(calls)).toEqual({ page: 3, page_size: 100 });

    m.status.value = "online";
    m.section.value = "s1";
    await nextTick();
    await flush();
    expect(last(calls)).toEqual({ page: 1, page_size: 100, status: "online", section_id: "s1" });
    expect(m.active.value).toBe(true);

    m.onSorter({ columnKey: "hostname", order: "descend", sorter: true });
    await flush();
    expect(last(calls)).toMatchObject({ sort: "hostname", order: "desc", page: 1 });
    m.onSorter({ columnKey: "hostname", order: false, sorter: true });
    await flush();
    expect(last(calls)?.sort).toBeUndefined();
  });

  it("關鍵字等停手 300ms 才查（打字時不要每個字都打一次 API）", async () => {
    vi.useFakeTimers();
    const fetch = vi.fn(async (_q: MissingQuery) => page([]));
    const m = useRemoteMissing<Row>(fetch);
    m.q.value = "p";
    await nextTick();
    m.q.value = "pc-1";
    await nextTick();
    vi.advanceTimersByTime(299);
    expect(fetch).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][0]).toMatchObject({ q: "pc-1", page: 1 });
    vi.useRealTimers();
  });

  it("較早送出、較晚回來的結果不可蓋掉新條件的結果", async () => {
    const resolvers: ((v: MissingPage<Row>) => void)[] = [];
    const m = useRemoteMissing<Row>(() => new Promise((r) => resolvers.push(r)));
    const first = m.load();
    const second = m.load();
    resolvers[1](page([{ ip: "new" }]));
    await second;
    resolvers[0](page([{ ip: "old" }]));
    await first;
    expect(m.rows.value.map((r) => r.ip)).toEqual(["new"]);
    expect(m.loading.value).toBe(false);
  });

  it("換了區段、原本選的子網路不在新區段裡 → 清掉再查一次", async () => {
    const calls: MissingQuery[] = [];
    const m = useRemoteMissing<Row>(async (q) => {
      calls.push(q);
      return page([], 0, q.section_id ? ["n1"] : ["n1", "n2"]);
    });
    await m.load();
    m.subnet.value = "n2";
    await nextTick();
    await flush();
    m.section.value = "s1";
    await nextTick();
    await flush();
    await nextTick();
    await flush();
    expect(m.subnet.value).toBeNull();
    expect(last(calls)).toEqual({ page: 1, page_size: 100, section_id: "s1" });
  });

  it("可排序的欄交給後端（sorter: true＋受控箭頭），操作欄不排序", () => {
    const m = useRemoteMissing<Row>(async () => page([]));
    m.onSorter({ columnKey: "ip", order: "ascend", sorter: true });
    const cols = m.remoteSort([
      { key: "ip", sorter: () => 0 }, { key: "subnet" }, { key: "actions" },
    ] as Record<string, any>[]);
    expect(cols.map((c) => [c.key, c.sorter, c.sortOrder])).toEqual([
      ["ip", true, "ascend"], ["subnet", true, false], ["actions", undefined, undefined],
    ]);
  });

  it("匯出依目前條件分批抓完整份", async () => {
    const calls: MissingQuery[] = [];
    const total = 45_000;
    const m = useRemoteMissing<Row>(async (q) => {
      calls.push(q);
      const start = (q.page - 1) * q.page_size;
      const n = Math.max(0, Math.min(q.page_size, total - start));
      return page(Array.from({ length: n }, (_, i) => ({ ip: String(start + i) })), total);
    });
    m.customer.value = "c1";
    const all = await m.fetchAll();
    expect(all).toHaveLength(total);
    const exportCalls = calls.filter((c) => c.page_size === 20_000);
    expect(exportCalls.map((c) => c.page)).toEqual([1, 2, 3]);
    expect(exportCalls.every((c) => c.customer_id === "c1")).toBe(true);
  });
});
