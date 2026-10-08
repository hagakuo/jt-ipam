import { describe, expect, it } from "vitest";

import { slotNotation, slotWhere } from "../rackSlots";

const FULL = { h0: 0, h1: 60, v0: 0, v1: 60 };

describe("slotWhere", () => {
  it("整層整格：沒有什麼位置好說的", () => {
    expect(slotWhere(FULL)).toEqual([]);
  });

  it("左半 / 右半", () => {
    expect(slotWhere({ ...FULL, h0: 0, h1: 30 })).toEqual([{ axis: "h", parts: 2, pos: 1 }]);
    expect(slotWhere({ ...FULL, h0: 30, h1: 60 })).toEqual([{ axis: "h", parts: 2, pos: 2 }]);
  });

  it("層內上下：疊在上面的是第 2 格", () => {
    expect(slotWhere({ ...FULL, v0: 30, v1: 60 })).toEqual([{ axis: "v", parts: 2, pos: 2 }]);
  });

  it("兩個方向都切時兩個都要講（橫向先）", () => {
    expect(slotWhere({ h0: 0, h1: 30, v0: 0, v1: 30 }))
      .toEqual([{ axis: "h", parts: 2, pos: 1 }, { axis: "v", parts: 2, pos: 1 }]);
  });

  it("1/3 的第 2 格", () => {
    expect(slotWhere({ ...FULL, h0: 20, h1: 40 })).toEqual([{ axis: "h", parts: 3, pos: 2 }]);
  });

  it("不是整齊分割的資料就不硬掰（模型允許手動塞）", () => {
    expect(slotWhere({ ...FULL, h0: 7, h1: 29 })).toEqual([]);
  });
});

describe("slotNotation", () => {
  it("整層整格就沒有東西要標", () => {
    expect(slotNotation({ rack_slot: 0, rack_slot_span: 60, rack_vslot: 0, rack_vslot_span: 60 }))
      .toBe("");
    expect(slotNotation({})).toBe("");   // 舊資料沒有這些欄位
  });

  it("橫向與層內上下都標得出來（匯出檔用固定寫法，不翻譯）", () => {
    expect(slotNotation({ rack_slot: 30, rack_slot_span: 30 })).toBe("1/2 #2");
    expect(slotNotation({ rack_slot: 0, rack_slot_span: 30, rack_vslot: 30, rack_vslot_span: 30 }))
      .toBe("1/2 #1 ↕1/2 #2");
  });
});
