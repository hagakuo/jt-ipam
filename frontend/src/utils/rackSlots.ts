/**
 * 機櫃一個 U 的橫向分格（GitHub issue #31）。
 *
 * 資料模型是「起始格 + 跨幾格」的區間，網格 **60 格 = 1~6 的最小公倍數**，
 * 所以 1/2、1/3、1/4、1/5、1/6 都表達得出來（1/5 是 issue #30 層架要的，12 格做不到）。
 *
 * 介面上不讓使用者面對 60 個格子，而是選「寬度 + 第幾格」，由這裡換算。
 * 必須與後端 `app/services/rack.py` 的 RACK_SLOTS 一致。
 */
export const RACK_SLOTS = 60;

/** 介面提供的寬度：1=整列、2=1/2、3=1/3、4=1/4、5=1/5、6=1/6。分母都要整除 RACK_SLOTS。 */
export const WIDTH_PARTS = [1, 2, 3, 4, 5, 6] as const;

/** 寬度 1/parts 佔幾格。 */
export function spanFor(parts: number): number {
  return RACK_SLOTS / parts;
}

/** 跨幾格 → 是幾分之一（用來把既有資料還原成介面上的選項）。 */
export function partsFor(span: number | null | undefined): number {
  const n = Number(span ?? RACK_SLOTS);
  const parts = RACK_SLOTS / (n || RACK_SLOTS);
  // 資料若是手動塞的非整齊跨度（模型允許），就近取一個能顯示的選項
  return (WIDTH_PARTS as readonly number[]).includes(parts) ? parts : 1;
}

/** 第 pos 格（1-based）的起始格。 */
export function slotFor(parts: number, pos: number): number {
  return (pos - 1) * spanFor(parts);
}

/** 起始格 → 第幾格（1-based）。 */
export function posFor(slot: number | null | undefined, parts: number): number {
  const s = Number(slot ?? 0);
  return Math.floor(s / spanFor(parts)) + 1;
}

/**
 * 各型態的預設外寬與每層高度（mm）。留白時後端就是用這組值，介面拿它當提示文字，
 * 使用者才知道「不填會變成多少」。
 *
 * 必須與後端 `app/services/rack.py` 的 _DEFAULT_WIDTH_MM / _DEFAULT_ROW_MM 一致
 * （backend/tests/test_rack_slots.py 有守門測試會比對這個檔）。
 */
export const RACK_DEFAULTS: Record<string, { width: number; row: number }> = {
  rack: { width: 600, row: 44 },
  industrial: { width: 600, row: 44 },
  shelf: { width: 900, row: 350 },
  wire_shelf: { width: 1200, row: 400 },
  // IKEA IVAR 最小的那組：層板 42×30 公分、側架高 179 公分（官方要求至少 4 層，
  // 實務上多半放 6 層 → 每層約 300mm）。
  wood_shelf: { width: 420, row: 300 },
  // 角鋼層架：台灣最常見 90×45×180 公分、4 層（淨空約 52 公分）
  angle_shelf: { width: 900, row: 520 },
  // KALLAX 2×4：外寬＝65＋350×格數，格子 335mm
  kallax: { width: 765, row: 335 },
  // LackRack：LACK 邊桌 55 公分寬，裝的是 19 吋設備（列＝U）
  lackrack: { width: 550, row: 44 },
};

/**
 * 各型態的層板厚度預設（mm）。層高填的是**淨空高**（不含板），所以板厚另計。
 * 木質層架 18mm 是 IKEA IVAR 層板的官方規格（1.8 cm）。
 * 必須與後端 `app/services/rack.py` 的 _DEFAULT_BOARD_MM 一致（有守門測試比對）。
 */
export const RACK_BOARD_MM: Record<string, number> = {
  rack: 0, industrial: 0, shelf: 20, wire_shelf: 35, wood_shelf: 18,
  // 角鋼層架＝50mm 鋼橫桿＋9mm 夾板；KALLAX 是內隔板（外框 40mm 另計）
  angle_shelf: 59, kallax: 15, lackrack: 0,
};
export function boardDefault(kind: string | null | undefined): number {
  return RACK_BOARD_MM[kind || "rack"] ?? 0;
}

/** 以「層」計的型態。多一種層架時只改這裡，標籤、表單、圖都會跟著對。 */
const LEVEL_KINDS = new Set(["shelf", "wire_shelf", "wood_shelf", "angle_shelf", "kallax"]);

/** 離地高度的預設（mm）。沒列的型態沒填就是 0。必須與後端 _DEFAULT_FLOOR_MM 一致。
 *  KALLAX 沒有腳直接落地；LackRack 桌面下裝滿 8U 之後底下還有約 44mm。 */
export const RACK_FLOOR_MM: Record<string, number> = { angle_shelf: 10, kallax: 0, lackrack: 44 };

/** 型態的預設值（未知型態一律當標準機櫃）。 */
export function rackDefaults(kind: string | null | undefined) {
  return RACK_DEFAULTS[kind || "rack"] ?? RACK_DEFAULTS.rack;
}

/** 這個型態的列是「層」而不是「U」。標題、下拉選單與匯出都問這支，才不會某一處
 *  漏掉而出現「SHELF-01 (4U)」這種矛盾。必須與後端 rack.py 的 uses_rack_units 相反。 */
export function usesLevels(kind: string | null | undefined): boolean {
  return LEVEL_KINDS.has(kind || "");
}

/**
 * 逐層高度的編輯順序 —— 回傳 `level_heights` 的索引，由上而下。
 *
 * 機櫃圖 top-down 時最高層畫在最上面；編輯清單若照陣列順序從第 1 層列起，兩邊就是
 * 顛倒的，使用者要改「畫面最上面那一層」得往清單最下面找。這裡只決定**顯示順序**，
 * 陣列本身永遠是「第 1 層＝索引 0（最底層）」，存檔格式不變 —— 顯示順序若連帶動到
 * 資料順序，改的會是另一層。
 */
export function levelEditOrder(count: number, numbering: string | null | undefined): number[] {
  const idx = Array.from({ length: Math.max(0, count) }, (_, i) => i);
  return numbering === "bottom-up" ? idx : idx.reverse();
}

/** 挑選器／層位下拉要列出的層位，由上而下。 */
type PickShape = { u_height?: number; open_top?: boolean; numbering?: string | null };

/**
 * 兩個很容易漏掉的地方：
 * 1. 層架最上面那片板的**上面**也放得下（開放頂）→ 可放層位比層數多一層。漏了的話
 *    畫面上明明有空位，挑選器裡卻選不到（客戶實際回報過）。
 * 2. 編號方向 bottom-up 時第 1 層畫在最上面，清單要跟著倒過來；而「頂板上方」在實體上
 *    永遠是最上面那一列，與編號方向無關，所以要另外提到最前面。
 */
export function rackPickRows(d: PickShape | null | undefined): number[] {
  const real = d?.u_height ?? 0;
  if (real <= 0) return [];
  const n = real + (d?.open_top ? 1 : 0);
  const asc = Array.from({ length: n }, (_, i) => i + 1);
  const order = d?.numbering === "bottom-up" ? asc : asc.reverse();
  if (d?.open_top && d?.numbering === "bottom-up") {
    const i = order.indexOf(n);
    if (i > 0) order.unshift(...order.splice(i, 1));
  }
  return order;
}

/** 這一列是不是「最上面那片板的上面」（標「頂」而不是層號）。 */
export function rackRowIsTop(d: PickShape | null | undefined, u: number): boolean {
  return Boolean(d?.open_top) && u > (d?.u_height ?? 0);
}

/** 一塊佔了某一軸的第幾格（parts＝分成幾份、pos＝第幾份，皆 1 起算）。 */
export interface SpanDesc { axis: "h" | "v"; parts: number; pos: number }

/**
 * 這一塊在一層裡佔哪個位置 —— 橫向先、層內上下在後；佔滿整條的那一軸不回傳。
 *
 * 只列名字的話，同一層放兩台就分不出誰在左誰在右（客戶回報「看不出它是該層第幾個位置」）。
 * 回傳結構而不是字串：文案留給畫面去翻譯，utils 不碰 i18n。
 */
export function slotWhere(o: { h0: number; h1: number; v0: number; v1: number }): SpanDesc[] {
  const out: SpanDesc[] = [];
  for (const [axis, a, b] of [["h", o.h0, o.h1], ["v", o.v0, o.v1]] as const) {
    const span = b - a;
    if (span <= 0 || span >= RACK_SLOTS) continue;
    const parts = RACK_SLOTS / span;
    // 手動塞進來的資料可能不是整齊分割；講不清楚就不要硬掰一個格號出來
    if (!Number.isInteger(parts) || !Number.isInteger(a / span)) continue;
    out.push({ axis, parts, pos: a / span + 1 });
  }
  return out;
}

/**
 * 匯出檔用的位置寫法：「1/2 #2」＝橫向半寬的第 2 格，再接「↕1/3 #1」＝層內下 1/3。
 *
 * 匯出出去的是資料，用固定寫法比翻譯過的句子好對照；整層整格就回空字串。
 */
export function slotNotation(dev: {
  rack_slot?: number | null; rack_slot_span?: number | null;
  rack_vslot?: number | null; rack_vslot_span?: number | null;
} | null | undefined): string {
  const box = {
    h0: Number(dev?.rack_slot ?? 0), h1: Number(dev?.rack_slot ?? 0) + Number(dev?.rack_slot_span ?? RACK_SLOTS),
    v0: Number(dev?.rack_vslot ?? 0), v1: Number(dev?.rack_vslot ?? 0) + Number(dev?.rack_vslot_span ?? RACK_SLOTS),
  };
  return slotWhere(box)
    .map((d) => `${d.axis === "v" ? "↕" : ""}1/${d.parts} #${d.pos}`)
    .join(" ");
}

/**
 * 把「橫向區間 + 層內垂直區間」換成 CSS 百分比框。
 *
 * 垂直是**由下往上**長的（裝置站在層板上），所以回傳 `bottom` 而不是 `top` ——
 * 拿去當 top 用會讓疊在上面的那台畫到下面，而且看起來「只是有點怪」而不像壞掉。
 */
export function slotBoxPct(o: { h0: number; h1: number; v0: number; v1: number }): {
  left: number; width: number; bottom: number; height: number;
} {
  return {
    left: (o.h0 / RACK_SLOTS) * 100,
    width: ((o.h1 - o.h0) / RACK_SLOTS) * 100,
    bottom: (o.v0 / RACK_SLOTS) * 100,
    height: ((o.v1 - o.v0) / RACK_SLOTS) * 100,
  };
}

/**
 * 一台機櫃／層架畫出來總共多高 px。
 *
 * 多台並排要「底部對齊」時**必須**用這個，不能用 U 數 —— 20U 機櫃的列高 28px、
 * 10 層的層架列高可能近 100px，用數量算出來的補白會把層架推到畫面外。
 */
export function rackPixelHeight(d: {
  u_height?: number;
  render_row_px?: number;
  render_row_px_list?: number[];
  render_board_px?: number;
  render_board_px_list?: number[];
  render_top_px?: number;
  open_top?: boolean;
} | null | undefined): number {
  if (!d) return 0;
  const n = d.u_height ?? 0;
  if (!n) return 0;
  const base = d.render_row_px ?? 28;
  const list = (d.render_row_px_list ?? []).slice(0, n);
  while (list.length < n) list.push(base);
  const rows = d.open_top ? [...list, list[list.length - 1] ?? base] : list;
  const boards = boardList(d, rows.length);
  return rows.reduce((a, v, i) => a + v + boards[i], 0) + (Number(d.render_top_px) || 0);
}

/**
 * 每一列**底下**那片板的厚度 px，由上往下（畫面順序），長度＝畫出來的列數。
 * 後端有給逐片清單就用它（KALLAX 外框比內隔板厚、LackRack 每張桌子一片桌面），
 * 沒給（舊版後端）就是每片一樣厚 —— 畫出來與以前相同。畫面、匯出都叫這支。
 */
export function boardList(d: { render_board_px?: number; render_board_px_list?: number[] },
                          rows: number): number[] {
  const one = Number(d.render_board_px ?? 0) || 0;
  const raw = (d.render_board_px_list ?? []).map((v) => Number(v) || 0);
  return Array.from({ length: rows }, (_, i) => raw[i] ?? one);
}
