/** 把任意字串變成正規表示式裡的字面值（所有特殊字元都跳脫，包括反斜線）。 */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}
