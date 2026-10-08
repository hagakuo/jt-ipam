/**
 * SFTP 檔案清單的排序。
 *
 * 兩種模式，由使用者偏好決定：
 * - **資料夾優先**（預設，與檔案總管一致）：資料夾永遠排在檔案前面，**不論升冪或降冪**。
 *   把「資料夾優先」寫進比較函式裡是不夠的 —— 表格切成降冪時會連分組一起反轉，
 *   資料夾就跑到最後面去了，那不是任何人要的行為。所以分組要在方向之外處理。
 * - **混合排序**：資料夾與檔案一起排，只看選中的欄位。
 *
 * 排序在這裡自己做（而不是交給表格元件的 sorter），就是為了拿到方向這個資訊。
 */

export interface SortableEntry {
  name: string;
  is_dir?: boolean;
  size?: number | null;
  mtime?: number | null;
}

export type SortKey = "name" | "size" | "mtime" | "mode";
export type SortOrder = "ascend" | "descend" | false;

export interface SortState {
  key: SortKey;
  order: SortOrder;
  /** 資料夾優先（預設 true）；false = 檔案與資料夾一起排 */
  dirsFirst: boolean;
}

function compareBy<T extends SortableEntry>(key: SortKey, a: T, b: T): number {
  switch (key) {
    case "size":
      // 資料夾沒有大小；用 -1 讓它們排在最小的檔案之前，行為穩定可預期
      return (a.size ?? -1) - (b.size ?? -1);
    case "mtime":
      return (a.mtime ?? 0) - (b.mtime ?? 0);
    default:
      // localeCompare：中文檔名要照當地習慣排，不是照 code point
      return a.name.localeCompare(b.name);
  }
}

export function sortEntries<T extends SortableEntry>(entries: T[], state: SortState): T[] {
  const { key, order, dirsFirst } = state;
  const dir = order === "descend" ? -1 : 1;
  const out = [...entries];
  out.sort((a, b) => {
    if (dirsFirst) {
      const grouped = Number(!!b.is_dir) - Number(!!a.is_dir);
      if (grouped !== 0) return grouped;      // 分組不受升冪／降冪影響
    }
    const primary = compareBy(key, a, b) * dir;
    if (primary !== 0) return primary;
    // 同值時用名稱穩定收斂，否則每次重新整理順序會跳動
    return a.name.localeCompare(b.name);
  });
  return out;
}
