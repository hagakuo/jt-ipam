/**
 * 三種新型態（角鋼層架、KALLAX、LackRack）的前端匯出。
 * 畫面、前端匯出、對外嵌入是同一張圖的三份畫法 —— 這裡量匯出的產物本身。
 */
import { describe, it, expect } from "vitest";
import { buildRacksSvg, buildRacksDrawio, rowBoxes, deviceBox, type ExportDiagram } from "@/utils/rackGraphicsExport";
import { FINISH_COLORS } from "@/utils/rackFinish";

const V = 28 / 44.45;
const H = 250 / 482.6;

function angle(finish: string | null = null): ExportDiagram {
  const board = 18;
  return {
    name: "ANG", u_height: 3, kind: "angle_shelf", open_top: true, finish,
    render_width_px: 900 * H, render_side_px: 40 * H, render_row_px: 160,
    render_board_px: board, render_board_px_list: [board, board, board, board],
    devices: [{ name: "nas", type: "storage", u_position: 1, u_size: 1, rack_slot: 0, rack_slot_span: 30 }],
  };
}
function kallax(cols: number, rows: number): ExportDiagram {
  const inner = 15 * V;
  const edge = 40 * V;
  return {
    name: "K", u_height: rows, kind: "kallax", open_top: true, finish: "oak",
    render_width_px: (65 + 350 * cols - 80) * H, render_side_px: 40 * H, render_row_px: 160,
    render_board_px: inner, render_board_px_list: [edge, ...Array(rows - 1).fill(inner), edge],
    render_cols: cols, render_divider_px: 15 * H,
    devices: [{ name: "nas-k", type: "storage", u_position: 1, u_size: 1, rack_slot: 0, rack_slot_span: 60 / cols }],
  };
}
function lack(u: number): ExportDiagram {
  const seg = (44.4 + 50) * V;
  const slab = 50 * V;
  // 最上面一列是桌面上方（可以放東西），它底下那片板＝桌面
  return {
    name: "L", u_height: u, kind: "lackrack", open_top: true,
    render_width_px: 250, render_side_px: (550 - 482.6) / 2 * H, render_row_px: 28,
    render_board_px: 0, render_top_px: 0,
    render_board_px_list: [slab, ...Array.from({ length: u }, (_, i) => ((u - i) > 1 && (u - i - 1) % 8 === 0 ? seg : 0))],
    devices: [{ name: "sw", type: "switch", u_position: u, u_size: 1, rack_slot: 0, rack_slot_span: 60 },
              { name: "ap", type: "other", u_position: u + 1, u_size: 1, rack_slot: 0, rack_slot_span: 20 }],
  };
}
const count = (s: string, needle: string) => s.split(needle).length - 1;

describe("角鋼層架", () => {
  it("兩支 L 型立柱、每層一片夾板、立柱上有葫蘆孔", () => {
    const svg = buildRacksSvg([angle()], 0, "left")!.svg;
    expect(count(svg, 'class="angle-post"')).toBe(2);
    expect(count(svg, 'class="angle-ply"')).toBe(4);           // 3 層＋頂板
    expect(svg).toContain('id="keyholes-black"');             // 預設黑色
    expect(svg).toContain(FINISH_COLORS.angle_shelf.black.post);
    expect(buildRacksSvg([angle("white")], 0, "left")!.svg).toContain(FINISH_COLORS.angle_shelf.white.post);
  });
});

describe("KALLAX", () => {
  it("4×4 畫 16 格、3 片直隔板，而且隔板畫在裝置上面", () => {
    const svg = buildRacksSvg([kallax(4, 4)], 0, "left")!.svg;
    expect(count(svg, 'class="kallax-cell"')).toBe(16);
    expect(count(svg, 'class="kallax-divider"')).toBe(3);
    expect(svg.indexOf('class="kallax-divider"')).toBeGreaterThan(svg.indexOf(">nas-k<"));
    expect(svg).toContain(FINISH_COLORS.kallax.oak.frame);
  });
  it("外框的頂板、底板比內隔板厚", () => {
    const rows = rowBoxes(kallax(2, 4));
    expect(rows[0].board).toBeGreaterThan(rows[1].board);
    expect(rows[rows.length - 1].board).toBeCloseTo(rows[0].board, 5);
  });
  it("draw.io 也有格子與隔板", () => {
    const x = buildRacksDrawio([kallax(2, 4)], 0, "left", "t")!;
    expect(count(x, `fillColor=${FINISH_COLORS.kallax.oak.cell}`)).toBe(8);
  });
});

describe("LackRack", () => {
  it("疊兩張就有兩片桌面、兩支桌腳", () => {
    const svg = buildRacksSvg([lack(16)], 0, "left")!.svg;
    expect(count(svg, 'class="lack-top"')).toBe(2);
    expect(count(svg, 'class="lack-leg"')).toBe(2);
    expect(count(buildRacksSvg([lack(8)], 0, "left")!.svg, 'class="lack-top"')).toBe(1);
  });
  it("設備從桌面底下開始排；桌面上方那一列也放得了東西", () => {
    const d = lack(8);
    const top = deviceBox(d, d.devices[0], 250)!;        // U8：桌面正下方
    expect(top.y).toBeCloseTo(28 + 50 * V, 5);           // 桌面上方那一列（28）＋桌面
    const on = deviceBox(d, d.devices[1], 250)!;         // 第 9 個位置＝桌面上方
    expect(on.y + on.h).toBeCloseTo(28, 5);              // 站在桌面上
  });
  it("不畫機櫃的走線空間（兩側是桌腳）", () => {
    expect(buildRacksSvg([lack(8)], 0, "left")!.svg).not.toContain('class="rack-channel"');
  });
});

describe("既有型態不受逐片板厚影響", () => {
  it("給了每片一樣厚的清單，跟沒給的一模一樣", () => {
    const base: ExportDiagram = {
      name: "IVAR", u_height: 6, kind: "wood_shelf", open_top: true, render_width_px: 217,
      render_row_px: 160, render_board_px: 11.3,
      devices: [{ name: "srv", type: "server", u_position: 2, u_size: 1, rack_slot: 0, rack_slot_span: 60 }],
    };
    const withList = { ...base, render_board_px_list: Array(7).fill(11.3) };
    expect(buildRacksSvg([withList], 0, "left")!.svg).toBe(buildRacksSvg([base], 0, "left")!.svg);
    expect(buildRacksDrawio([withList], 0, "left", "t")).toBe(buildRacksDrawio([base], 0, "left", "t"));
  });
});

describe("機櫃的頂板與底座", () => {
  const rack = (kind: string): ExportDiagram => ({
    name: "R", u_height: 6, kind, open_top: false, render_width_px: 250, render_side_px: 34.9,
    render_row_px: 28, render_board_px: 0, render_top_px: 50 * V,
    render_board_px_list: [0, 0, 0, 0, 0, 75 * V],
    devices: [{ name: "u1", type: "server", u_position: 1, u_size: 1, rack_slot: 0, rack_slot_span: 60 }],
  });
  it("SVG 與 draw.io 都畫出來，而且設備不會蓋到底座", () => {
    for (const k of ["rack", "industrial"]) {
      const svg = buildRacksSvg([rack(k)], 0, "left")!.svg;
      expect(count(svg, 'class="rack-roof"'), k).toBe(1);
      expect(count(svg, 'class="rack-base"'), k).toBe(1);
      expect(count(buildRacksDrawio([rack(k)], 0, "left", "t")!, 'id="rb'), k).toBe(1);
    }
    const d = rack("rack");
    const b = deviceBox(d, d.devices[0], 250)!;
    const rows = rowBoxes(d);
    const bottom = rows[rows.length - 1].y + rows[rows.length - 1].h;
    expect(b.y + b.h).toBeCloseTo(bottom - 75 * V, 5);   // U1 的下緣＝底座的上緣
    expect(rows[0].y).toBeCloseTo(50 * V, 5);            // 最上面那一 U 從頂板下面開始
  });
});
