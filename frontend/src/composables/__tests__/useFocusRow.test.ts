/**
 * useFocusRow：IP 詳細頁點進來「只看這一筆」。
 * 規則頁、別名頁同一頁兩個分頁時只對網址指定的那個分頁生效；pfSense 規則沒有 id，
 * 用 `#<在完整清單中的位置>` 對（跟後端 fw_lookup 同一套）。
 */
import { describe, expect, it, vi, beforeEach } from "vitest";
import { nextTick, ref } from "vue";

const route = { query: {} as Record<string, string> };
const replace = vi.fn();
vi.mock("vue-router", () => ({ useRoute: () => route, useRouter: () => ({ replace }) }));

import { useFocusRow } from "@/composables/useFocusRow";

beforeEach(() => { replace.mockReset(); route.query = {}; });

describe("useFocusRow", () => {
  it("只留相符的那一筆；沒有 focus 時原樣回傳", () => {
    route.query = { focus: "b" };
    const rows = ref([{ id: "a" }, { id: "b" }]);
    const f = useFocusRow(rows, (r, k) => r.id === k);
    expect(f.apply(rows.value)).toEqual([{ id: "b" }]);
    f.clear();
    expect(f.apply(rows.value)).toHaveLength(2);
    expect(replace).toHaveBeenCalledWith({ query: {} });
  });

  it("只對網址 tab 指定的那個分頁生效", () => {
    route.query = { tab: "aliases", focus: "web" };
    const rules = useFocusRow(ref([{ id: "web" }]), (r, k) => r.id === k, "rules");
    const aliases = useFocusRow(ref([{ name: "web" }]), (a, k) => a.name === k, "aliases");
    expect(rules.focus.value).toBeNull();
    expect(aliases.focus.value).toBe("web");
  });

  it("pfSense：沒有 tracker 的規則用完整清單中的位置對", () => {
    route.query = { tab: "rules", focus: "#2" };
    const rows = ref([{ tracker: null }, { tracker: 17 }, { tracker: null, descr: "third" }]);
    const f = useFocusRow(rows, (r, k, i) =>
      k.startsWith("#") ? `#${i}` === k : String(r.tracker ?? "") === k, "rules");
    expect(f.focused.value).toEqual([{ tracker: null, descr: "third" }]);
  });

  it("清單載入過才算數（還沒載入前不下「找不到」的結論）", async () => {
    route.query = { focus: "x" };
    const rows = ref<{ id: string }[]>([]);
    const f = useFocusRow(rows, (r, k) => r.id === k);
    expect(f.settled.value).toBe(false);
    rows.value = [];                  // 載入完成、真的沒有
    await nextTick();
    expect(f.settled.value).toBe(true);
    expect(f.focused.value).toEqual([]);
  });
});
