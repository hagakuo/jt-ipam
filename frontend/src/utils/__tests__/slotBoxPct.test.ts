import { describe, expect, it } from "vitest";

import { RACK_SLOTS, slotBoxPct } from "../rackSlots";

describe("slotBoxPct", () => {
  it("整格 = 從左到右、從下到上鋪滿", () => {
    expect(slotBoxPct({ h0: 0, h1: RACK_SLOTS, v0: 0, v1: RACK_SLOTS }))
      .toEqual({ left: 0, width: 100, bottom: 0, height: 100 });
  });

  it("右半格", () => {
    expect(slotBoxPct({ h0: 30, h1: 60, v0: 0, v1: 60 }))
      .toEqual({ left: 50, width: 50, bottom: 0, height: 100 });
  });

  it("層內疊放：垂直是由下往上長，不是由上往下", () => {
    // 疊在上面那台 v0=30 → 距離**底部** 50%，不是距離頂端 50%
    expect(slotBoxPct({ h0: 0, h1: 60, v0: 30, v1: 60 }))
      .toEqual({ left: 0, width: 100, bottom: 50, height: 50 });
  });

  it("1/3 寬的第 2 格", () => {
    const b = slotBoxPct({ h0: 20, h1: 40, v0: 0, v1: 60 });
    // 除不盡，比到小數點後 10 位就夠（CSS 只會用到前幾位）
    expect(b.left).toBeCloseTo(100 / 3, 10);
    expect(b.width).toBeCloseTo(100 / 3, 10);
    expect(b.bottom).toBe(0);
    expect(b.height).toBe(100);
  });
});
