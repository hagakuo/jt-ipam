/**
 * 機架的表面顏色與配色。
 *
 * **FINISH_COLORS 必須與後端 `app/services/rack_svg.py` 的 FINISH_COLORS 一模一樣**
 * （backend/tests/test_rack_more_kinds.py 會比對這個檔）：畫面、前端匯出、對外嵌入是同一張圖
 * 的三份畫法，顏色各寫一份就會各自漂走。
 *
 * - 角鋼：post＝立柱正面、edge＝另一片翼（從正面看是外緣一條暗邊）、beam＝鋼橫桿、hole＝葫蘆孔
 * - KALLAX：frame＝外框與隔板、cell＝格子裡面（沒有背板，看到的是更深一點的內側）
 * - LACK：wood＝桌面與桌腳
 */
import type { RackFinish } from "@/api/racks";

/** 各型態可選的顏色，第一個是預設（台灣角鋼以黑色最常見、KALLAX／LACK 以白色最常見）。 */
export const FINISHES: Record<string, RackFinish[]> = {
  angle_shelf: ["black", "white", "galvanized"],
  kallax: ["white", "black_brown", "oak"],
  lackrack: ["white", "black", "brown"],
};

export const FINISH_COLORS: Record<string, Record<string, Record<string, string>>> = {
  angle_shelf: {
    black: { post: "#303338", edge: "#1c1e21", beam: "#35383d", hole: "rgba(255,255,255,0.32)" },
    white: { post: "#eceef0", edge: "#c3c8cd", beam: "#e3e6e9", hole: "rgba(0,0,0,0.38)" },
    galvanized: { post: "#b9c0c6", edge: "#8b939a", beam: "#aeb5bc", hole: "rgba(0,0,0,0.42)" },
  },
  kallax: {
    white: { frame: "#f4f4f1", cell: "#e4e4df", line: "#c6c6c0" },
    black_brown: { frame: "#3d332d", cell: "#2a221e", line: "#1f1915" },
    oak: { frame: "#e2d3b8", cell: "#d2c0a0", line: "#b9a585" },
  },
  lackrack: {
    // 輪廓線要看得出來：白色桌子放在白色卡片上、黑色桌腳貼著黑色桌面（使用者回報「沒框線」）
    white: { wood: "#f4f4f2", line: "#8f8f89" },
    black: { wood: "#2c2c2e", line: "#66666a" },
    brown: { wood: "#5c4736", line: "#221810" },
  },
};

/** 角鋼層架上面那片夾板的顏色 */
export const PLY_COLOR = "#d6b17c";

/** 這個型態實際用的顏色：沒填或不適用就用預設；沒有顏色選項的型態回 null。 */
export function normalizeFinish(kind: string | null | undefined, finish: string | null | undefined): string | null {
  const opts = FINISHES[kind || ""];
  if (!opts) return null;
  return finish && (opts as string[]).includes(finish) ? finish : opts[0];
}

/** 配色（沒有顏色選項的型態回空物件）。 */
export function finishColors(kind: string | null | undefined, finish: string | null | undefined): Record<string, string> {
  const f = normalizeFinish(kind, finish);
  return f ? FINISH_COLORS[kind || ""][f] : {};
}

/** 角鋼層架的實物規格換成 px（與後端 rack.py 的 ANGLE_* 同一組）。
 *  葫蘆孔孔距 30mm、夾板 9mm。層架寬高同一個比例（19 吋 482.6mm＝250px，見後端
 *  rack.v_px_per_mm）；機櫃的垂直比例 1U 44.45mm＝28px 比水平多 1.22 倍，套在層架上
 *  KALLAX 的正方形格子會變成直立長方形。 */
const PX_PER_MM_SHELF = 250 / 482.6;
export const ANGLE_HOLE_PITCH_PX = 30 * PX_PER_MM_SHELF;
export const ANGLE_PLY_PX = 9 * PX_PER_MM_SHELF;

/**
 * 立柱上的一個葫蘆孔（圓孔接一條往下的窄槽），當成可以直向重複的圖磚。
 * 用 CSS 漸層畫不出「只有一小段」的窄槽（漸層會貫穿整個圖磚），所以做成一小張 SVG。
 */
export function keyholeTile(hole: string, postPx: number): string {
  const w = postPx.toFixed(2);
  const h = ANGLE_HOLE_PITCH_PX.toFixed(3);
  const cx = (postPx * 0.56).toFixed(2);
  const cy = (ANGLE_HOLE_PITCH_PX * 0.3).toFixed(2);
  const sh = (ANGLE_HOLE_PITCH_PX * 0.32).toFixed(2);
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' width='${w}' height='${h}'>`
    + `<circle cx='${cx}' cy='${cy}' r='2.3' fill='${hole}'/>`
    + `<rect x='${(postPx * 0.56 - 0.8).toFixed(2)}' y='${cy}' width='1.6' height='${sh}' fill='${hole}'/></svg>`;
  return `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
}
