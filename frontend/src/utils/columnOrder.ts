/**
 * 表格欄位順序（使用者在「欄位」選單拖拉調整的順序）。
 *
 * 儲存格式：每張表一份「欄位選單上全部欄位 key 的順序」（含目前隱藏的欄位），
 * 跟可見欄位分開存。分開的原因：既有的可見欄位清單是「勾選先後」的順序（後勾的接在最後），
 * 拿它當顯示順序會讓所有既有使用者的欄位一夕之間亂掉；而且隱藏欄位也要有位置，
 * 重新勾回來時才會回到使用者排好的地方。
 *
 * 沒有自訂過順序（null）＝完全照畫面原本定義的順序，行為與加入此功能前一模一樣。
 */

/**
 * 整理儲存的順序：已不存在的 key（欄位被移除、舊資料）、重複的 key、非字串一律丟掉。
 *
 * 不會替「順序裡沒有的欄位」補位置：之後版本新增的欄位、以及不在欄位選單裡的常駐欄（例如操作欄）
 * 都留在畫面定義的位置（applyOrder 只在有排序的欄位之間互換位置）。曾經試過依預設順序插在鄰居後面，
 * 結果不在選單裡的操作欄會跟著被拖到前面的鄰居一起跑。
 */
export function cleanOrder(saved: readonly unknown[], known: readonly string[]): string[] {
  const ok = new Set(known);
  const out: string[] = [];
  const placed = new Set<string>();
  for (const k of saved) {
    if (typeof k !== "string" || !ok.has(k) || placed.has(k)) continue;
    out.push(k);
    placed.add(k);
  }
  return out;
}

/**
 * 依 order 重排 items。只動「key 在 order 裡」的項目，而且只在這些項目原本佔的位置之間互換；
 * keyOf 回 null 的項目（勾選欄、固定在左右的操作欄、不在選單裡的常駐欄）留在原位置不動。
 * order 為 null／空 → 原樣回傳（同一個陣列）。
 */
export function applyOrder<T>(
  items: readonly T[],
  order: readonly string[] | null | undefined,
  keyOf: (item: T) => string | null,
): T[] {
  if (!order || order.length === 0) return items as T[];
  const rank = new Map(order.map((k, i) => [k, i]));
  const movable: { item: T; r: number }[] = [];
  const slots: number[] = [];
  items.forEach((item, i) => {
    const k = keyOf(item);
    const r = k == null ? undefined : rank.get(k);
    if (r === undefined) return;
    movable.push({ item, r });
    slots.push(i);
  });
  if (movable.length < 2) return items as T[];
  movable.sort((a, b) => a.r - b.r);   // Array.sort 是穩定排序：同 key 重複時維持原相對位置
  const out = items.slice();
  slots.forEach((slot, j) => { out[slot] = movable[j].item; });
  return out;
}

/** naive-ui DataTable 欄位的「可排序 key」：勾選欄、展開欄、固定在左右的欄不參與排序。 */
export function columnOrderKey(col: unknown): string | null {
  const c = col as { key?: unknown; type?: unknown; fixed?: unknown } | null;
  if (!c || typeof c !== "object") return null;
  if (c.type === "selection" || c.type === "expand") return null;
  if (c.fixed === "left" || c.fixed === "right") return null;
  if (c.key === undefined || c.key === null || c.key === "") return null;
  return String(c.key);
}

/** 把 from 位置的項目移到 to 位置（回傳新陣列；越界就夾在頭尾）。 */
export function moveItem<T>(list: readonly T[], from: number, to: number): T[] {
  const out = list.slice();
  if (from < 0 || from >= out.length) return out;
  const dest = Math.max(0, Math.min(out.length - 1, to));
  const [it] = out.splice(from, 1);
  out.splice(dest, 0, it);
  return out;
}
