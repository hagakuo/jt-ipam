import { describe, expect, it } from "vitest";

import { rackPickRows, rackRowIsTop } from "../rackSlots";

describe("rackPickRows", () => {
  it("標準機櫃：由上而下是大 U 在上", () => {
    expect(rackPickRows({ u_height: 5, numbering: "top-down" })).toEqual([5, 4, 3, 2, 1]);
  });

  it("層架開放頂：可選的層位比層數多一層", () => {
    // 客戶回報：木架最上面那片板的上面明明放得下，挑選器卻只列到第 9 層
    expect(rackPickRows({ u_height: 9, open_top: true, numbering: "top-down" }))
      .toEqual([10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
  });

  it("bottom-up：第 1 層排在最上面，但「頂」永遠是實體最上面那一列", () => {
    expect(rackPickRows({ u_height: 4, open_top: true, numbering: "bottom-up" }))
      .toEqual([5, 1, 2, 3, 4]);
  });

  it("bottom-up 沒有開放頂就單純倒過來", () => {
    expect(rackPickRows({ u_height: 4, numbering: "bottom-up" })).toEqual([1, 2, 3, 4]);
  });

  it("沒有機櫃資料時回空陣列", () => {
    expect(rackPickRows(null)).toEqual([]);
    expect(rackPickRows({ u_height: 0 })).toEqual([]);
  });
});

describe("rackRowIsTop", () => {
  it("只有開放頂多出來的那一列算「頂」", () => {
    const d = { u_height: 9, open_top: true };
    expect(rackRowIsTop(d, 10)).toBe(true);
    expect(rackRowIsTop(d, 9)).toBe(false);
    expect(rackRowIsTop({ u_height: 9 }, 9)).toBe(false);
  });
});
