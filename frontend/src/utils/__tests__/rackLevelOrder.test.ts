import { describe, expect, it } from "vitest";

import { levelEditOrder } from "../rackSlots";

describe("levelEditOrder", () => {
  it("top-down：最高層排在最前面，跟機櫃圖由上往下看到的一樣", () => {
    // 3 層、top-down → 畫面上由上而下是 第3層、第2層、第1層
    expect(levelEditOrder(3, "top-down")).toEqual([2, 1, 0]);
  });

  it("bottom-up：第 1 層畫在最上面，編輯順序就跟著正著排", () => {
    expect(levelEditOrder(3, "bottom-up")).toEqual([0, 1, 2]);
  });

  it("沒設定編號方向時照預設（top-down）", () => {
    expect(levelEditOrder(2, null)).toEqual([1, 0]);
    expect(levelEditOrder(2, undefined)).toEqual([1, 0]);
  });

  it("回傳的是索引，拿去查原陣列要對得回原本那一層", () => {
    // 這是真正會出錯的地方：顯示順序反過來、但值必須仍綁在同一層上，
    // 否則使用者改的是「看起來那一層」，存進去的卻是另一層。
    const heights = [210, 140, 45]; // 第1層=210、第2層=140、第3層=45
    const shown = levelEditOrder(heights.length, "top-down")
      .map((i) => ({ label: i + 1, mm: heights[i] }));
    expect(shown).toEqual([
      { label: 3, mm: 45 },
      { label: 2, mm: 140 },
      { label: 1, mm: 210 },
    ]);
  });

  it("沒有層時回空陣列（不是 undefined，模板要能直接 v-for）", () => {
    expect(levelEditOrder(0, "top-down")).toEqual([]);
    expect(levelEditOrder(-1, "top-down")).toEqual([]);
  });
});
