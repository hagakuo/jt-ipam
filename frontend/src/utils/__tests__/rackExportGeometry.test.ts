import { describe, expect, it } from "vitest";

import { deviceBox, postSpan, rowBoxes } from "../rackGraphicsExport";

const SHELF = {
  name: "IVAR", u_height: 3, devices: [], kind: "wood_shelf",
  numbering: "top-down", open_top: true,
  render_row_px: 60, render_row_px_list: [100, 60, 40], render_board_px: 10,
  render_width_px: 240,
};

describe("rowBoxes", () => {
  it("由上而下排，開放頂多一列，每一列含層板厚度", () => {
    const rows = rowBoxes(SHELF);
    // 頂（沿用最高層號那一層的高度 40）、第 3 層 40、第 2 層 60、第 1 層 100
    expect(rows.map((r) => [r.u, r.isTop, r.h]))
      .toEqual([[4, true, 50], [3, false, 50], [2, false, 70], [1, false, 110]]);
    // y 是累加的
    expect(rows.map((r) => r.y)).toEqual([0, 50, 100, 170]);
  });

  it("bottom-up：第 1 層在最上面，但「頂」仍然是實體最上面那一列", () => {
    const rows = rowBoxes({ ...SHELF, numbering: "bottom-up" });
    expect(rows.map((r) => r.u)).toEqual([4, 1, 2, 3]);
  });

  it("標準機櫃沒有開放頂，列高一律用 render_row_px", () => {
    const rows = rowBoxes({ name: "R", u_height: 3, devices: [], kind: "rack",
                            render_row_px: 28, render_row_px_list: [] });
    expect(rows.map((r) => [r.u, r.h])).toEqual([[3, 28], [2, 28], [1, 28]]);
  });
});

describe("deviceBox", () => {
  it("整列的裝置佔滿寬度與可放高度（不含層板）", () => {
    const b = deviceBox(SHELF, { u_position: 2, u_size: 1 }, 240)!;
    // 第 2 層在 y=100、高 70（含 10 的層板）→ 可放 60
    expect(b).toEqual({ x: 0, y: 100, w: 240, h: 60 });
  });

  it("右半格 + 只佔下半高度", () => {
    const b = deviceBox(SHELF,
      { u_position: 2, u_size: 1, rack_slot: 30, rack_slot_span: 30,
        rack_vslot: 0, rack_vslot_span: 30 }, 240)!;
    expect(b.x).toBe(120);
    expect(b.w).toBe(120);
    // 層內垂直是由下往上：下半 → 落在可放區的下半
    expect(b.h).toBe(30);
    expect(b.y).toBe(130);
  });

  it("放在頂板上面的裝置畫得出來（以前整台不見）", () => {
    const b = deviceBox(SHELF, { u_position: 4, u_size: 1 }, 240);
    expect(b).not.toBeNull();
    expect(b!.y).toBe(0);
  });

  it("沒有位置的裝置回 null，不要畫到奇怪的地方", () => {
    expect(deviceBox(SHELF, { u_position: null, u_size: null }, 240)).toBeNull();
    expect(deviceBox(SHELF, { u_position: 99, u_size: 1 }, 240)).toBeNull();
  });
});

describe("postSpan", () => {
  it("開放頂：立柱只到**最上面那片層板**，不會長到頂板上方那一列", () => {
    // 頂板上方那一列高 50（含 10 的板）→ 立柱從 40 起算（板的頂端）
    const s = postSpan(SHELF);
    expect(s.y).toBe(40);
    expect(s.y + s.h).toBe(280);          // 一路到最底
  });

  it("沒有開放頂就從最上緣起算", () => {
    const s = postSpan({ ...SHELF, open_top: false });
    expect(s.y).toBe(0);
  });
});
