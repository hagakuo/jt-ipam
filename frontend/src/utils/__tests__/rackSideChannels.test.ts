/**
 * 機櫃兩側的走線空間：匯出（SVG／draw.io）與畫面吃同一個 render_side_px。
 * 設備區固定是 19 吋 —— 800mm 的機櫃比 600mm 的寬，但寬在兩側，裝置本身一樣寬。
 */
import { describe, it, expect } from "vitest";
import { buildRacksSvg, buildRacksDrawio, sidePx } from "../rackGraphicsExport";

const dev = { name: "sw-01", type: "switch", u_position: 10, u_size: 1, rack_slot: 0, rack_slot_span: 60 };
const rack = (side: number, kind = "rack") => ({
  name: `R-${side}`, u_height: 12, kind, devices: [dev],
  render_width_px: 250, render_row_px: 28, render_side_px: side,
});

function deviceWidth(svg: string): number {
  // 裝置矩形：fill 是裝置顏色（非灰階機櫃色）、有 rgba 邊框
  const m = svg.match(/<rect x="[\d.]+" y="[\d.]+" width="([\d.]+)" height="[\d.]+" fill="[^"]+" stroke="rgba\(0,0,0,0.3\)"\/>/);
  return m ? Number(m[1]) : NaN;
}

describe("機櫃走線空間", () => {
  it("800mm 的匯出圖比 600mm 寬，寬出來的剛好是兩側走線區的差", () => {
    const a = buildRacksSvg([rack(34.9)], 0, "left")!;
    const b = buildRacksSvg([rack(86.7)], 0, "left")!;
    expect(b.W - a.W).toBeCloseTo(2 * (86.7 - 34.9), 1);
  });

  it("裝置本身一樣寬（設備區固定 19 吋）", () => {
    const a = buildRacksSvg([rack(34.9)], 0, "left")!.svg;
    const b = buildRacksSvg([rack(86.7)], 0, "left")!.svg;
    expect(deviceWidth(a)).toBeGreaterThan(0);
    expect(deviceWidth(a)).toBe(deviceWidth(b));
  });

  it("有走線空間時畫出兩側的走線區（SVG 與 draw.io 都要）", () => {
    const svg = buildRacksSvg([rack(86.7)], 0, "left")!.svg;
    expect((svg.match(/class="rack-channel"/g) || []).length).toBe(2);
    const drawio = buildRacksDrawio([rack(86.7)], 0, "left", "t")!;
    expect((drawio.match(/fillColor=#eceef0/g) || []).length).toBe(2);
  });

  it("層架沒有走線區（寬度就是層板本身）", () => {
    expect(sidePx(rack(86.7, "wood_shelf"))).toBe(0);
    expect(buildRacksSvg([rack(86.7, "wire_shelf")], 0, "left")!.svg).not.toContain("#eceef0");
  });
});
