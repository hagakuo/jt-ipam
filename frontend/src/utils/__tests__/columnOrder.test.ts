import { describe, expect, it } from "vitest";
import { applyOrder, cleanOrder, columnOrderKey, moveItem } from "@/utils/columnOrder";

// 使用者要求（2026-10-05）：所有可以挑欄位的頁面，也要可以拖拉改變欄位順序

describe("cleanOrder", () => {
  it("照儲存的順序；丟掉已不存在、重複、非字串的 key", () => {
    expect(cleanOrder(["c", "a", "gone", "a", 3, null, "b"], ["a", "b", "c"])).toEqual(["c", "a", "b"]);
  });

  it("不替順序裡沒有的欄位補位置（它們由 applyOrder 留在原位置）", () => {
    expect(cleanOrder(["b", "a"], ["a", "n1", "n2", "b"])).toEqual(["b", "a"]);
    expect(cleanOrder([], ["a", "b"])).toEqual([]);
  });
});

describe("applyOrder", () => {
  const key = (s: string) => s;

  it("沒自訂順序 → 原樣（同一個陣列，沒有多餘的重新渲染）", () => {
    const items = ["a", "b"];
    expect(applyOrder(items, null, key)).toBe(items);
    expect(applyOrder(items, [], key)).toBe(items);
  });

  it("不可動的項目留在原位置，其餘在自己的位置之間互換", () => {
    // _sel 與 _act 不在順序裡（勾選欄、操作欄）
    const out = applyOrder(["_sel", "a", "b", "c", "_act"], ["c", "a", "b"], key);
    expect(out).toEqual(["_sel", "c", "a", "b", "_act"]);
  });

  it("中間夾著常駐欄：常駐欄不動，可動的照順序填進其他位置", () => {
    expect(applyOrder(["a", "fixed", "b", "c"], ["c", "b", "a"], (s) => (s === "fixed" ? null : s)))
      .toEqual(["c", "fixed", "b", "a"]);
  });

  it("之後新增的欄位、不在選單裡的操作欄（順序裡沒有）：留在原位置，不會跟著鄰居跑", () => {
    // 使用者把 b 拖到最前面；n 是新版加的欄、_act 是不在選單裡的操作欄
    expect(applyOrder(["a", "n", "b", "_act"], ["b", "a"], key)).toEqual(["b", "n", "a", "_act"]);
  });

  it("隱藏的欄位不在清單裡也沒關係（順序裡有、清單裡沒有）", () => {
    expect(applyOrder(["a", "c"], ["c", "hidden", "a"], key)).toEqual(["c", "a"]);
  });

  it("不改動傳入的陣列", () => {
    const items = ["a", "b"];
    applyOrder(items, ["b", "a"], key);
    expect(items).toEqual(["a", "b"]);
  });
});

describe("columnOrderKey", () => {
  it("勾選欄、展開欄、固定在左右的欄不參與排序", () => {
    expect(columnOrderKey({ type: "selection" })).toBeNull();
    expect(columnOrderKey({ type: "expand", key: "_" })).toBeNull();
    expect(columnOrderKey({ key: "actions", fixed: "right" })).toBeNull();
    expect(columnOrderKey({ key: "ip", fixed: "left" })).toBeNull();
    expect(columnOrderKey({ title: "沒有 key" })).toBeNull();
    expect(columnOrderKey(null)).toBeNull();
  });

  it("一般欄位用 key（數字 key 轉字串）", () => {
    expect(columnOrderKey({ key: "hostname" })).toBe("hostname");
    expect(columnOrderKey({ key: 3 })).toBe("3");
  });
});

describe("moveItem", () => {
  it("往後、往前移動；越界夾在頭尾", () => {
    expect(moveItem(["a", "b", "c"], 0, 2)).toEqual(["b", "c", "a"]);
    expect(moveItem(["a", "b", "c"], 2, 0)).toEqual(["c", "a", "b"]);
    expect(moveItem(["a", "b", "c"], 1, 99)).toEqual(["a", "c", "b"]);
    expect(moveItem(["a", "b", "c"], 9, 0)).toEqual(["a", "b", "c"]);
  });
});
