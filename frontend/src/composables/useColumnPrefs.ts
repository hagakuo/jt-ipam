/**
 * Per-user column visibility + order preference.
 *
 * 從 /api/v1/me/preferences 拉 table_columns，本機 localStorage 快取一份。
 * 切換可見欄位／拖拉欄位順序時馬上更新 UI + 後台 patch。
 *
 * 用法 (在 view 內)：
 *
 *   const { visibleKeys, setVisible, reset, order, setOrder, orderColumns } = useColumnPrefs(
 *     "addresses",
 *     ["live", "ip", "hostname", "mac", "state", "discovery_source"],   // 全部選用欄位 key
 *     ["live", "ip", "hostname", "state"],                              // 預設可見
 *   );
 *
 *   const cols = computed(() => orderColumns(allColumns.filter((c) => visibleKeys.value.includes(c.key))));
 *
 *   <ColumnPicker :all="pickerItems" :visible="visibleKeys" @update:visible="setVisible"
 *                 :order="order" @update:order="setOrder" @reset="reset" />
 *
 * 儲存格式（同一個 table_columns 袋子）：
 *   table_columns[tableKey]            可見欄位 key（集合語意，陣列順序沒有意義：是勾選的先後）
 *   table_columns[tableKey + ":order"] 使用者拖拉排好的欄位順序（欄位選單上的全部欄位，含隱藏的）；沒有＝照畫面預設順序
 * 順序另外存而不是拿可見清單的順序來用：既有資料的可見清單是勾選先後，直接當順序會讓舊使用者的欄位全部亂掉。
 * 後端 table_columns 是 dict[str, Any] 的 JSONB，原樣存取、不排序不去重，不需要 migration。
 */

import { computed, ref, watch } from "vue";
import { apiClient } from "@/api/client";
import { applyOrder, cleanOrder, columnOrderKey } from "@/utils/columnOrder";

const LS_KEY = "jt-ipam:table_columns";
// 記錄「使用者曾被提供過的欄位集合」（每表一份，localStorage）。用來區分
// 「新加的預設欄位（從沒被提供過 → 應自動顯示）」與「使用者刻意隱藏的欄位」。
const SEEN_KEY = "jt-ipam:table_columns_seen";
// 欄位順序在 table_columns 裡的 key 後綴（每張表一份）
export const ORDER_SUFFIX = ":order";

// 全局 cache(一個 SPA session 內共用一份)
const cache = ref<Record<string, string[]>>({});
let loaded = false;

function loadSeen(): Record<string, string[]> {
  try { return JSON.parse(localStorage.getItem(SEEN_KEY) || "{}") ?? {}; } catch { return {}; }
}
function markSeen(tableKey: string, allKeys: string[]): void {
  const s = loadSeen();
  s[tableKey] = [...new Set([...(s[tableKey] ?? []), ...allKeys])];
  try { localStorage.setItem(SEEN_KEY, JSON.stringify(s)); } catch { /* ignore */ }
}
// 既有偏好 + 自動補上「新加的預設欄位」（在 defaultVisible/allKeys、但使用者從沒被提供過）。
// 使用者一旦在欄位選單做過選擇（setVisible→markSeen），其隱藏選擇就會被尊重、不再自動補。
function withNewDefaults(
  saved: string[], allKeys: string[], defaultVisible: string[], tableKey: string,
): string[] {
  const seen = loadSeen()[tableKey] ?? [];
  const adds = defaultVisible.filter(
    (k) => allKeys.includes(k) && !seen.includes(k) && !saved.includes(k),
  );
  return adds.length ? [...saved, ...adds] : saved;
}

async function loadCache(): Promise<void> {
  if (loaded) return;
  loaded = true;
  // 1. 先讀 localStorage(避免登入後第一次拉時的閃爍)
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) cache.value = JSON.parse(raw) ?? {};
  } catch {}
  // 2. 再拉後端覆寫 (authoritative)
  try {
    const { data } = await apiClient.get<{ table_columns: Record<string, string[]> | null }>(
      "/api/v1/me/preferences",
    );
    if (data?.table_columns) {
      cache.value = data.table_columns;
      localStorage.setItem(LS_KEY, JSON.stringify(cache.value));
    }
  } catch {
    // 沒登入 / API 失敗 → 用 localStorage 版本就好
  }
}

let saveTimer: ReturnType<typeof setTimeout> | null = null;
async function persist(): Promise<void> {
  localStorage.setItem(LS_KEY, JSON.stringify(cache.value));
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    try {
      await apiClient.patch("/api/v1/me/preferences", { table_columns: cache.value });
    } catch {
      // 後端失敗不回滾 UI；下次重整時會以後端為準 (loadCache)
    }
  }, 400);
}

export function useColumnPrefs(
  tableKey: string,
  allKeys: string[],
  defaultVisible: string[],
) {
  void loadCache();
  const saved0 = cache.value[tableKey];
  const initial = saved0
    ? withNewDefaults(saved0, allKeys, defaultVisible, tableKey)
    : [...defaultVisible];
  const visibleKeys = ref<string[]>([...initial]);

  // 同步 cache → local（後端載入 / 其他 view 改了）；同樣補上未曾提供過的新預設欄位
  watch(
    () => cache.value[tableKey],
    (v) => { if (v) visibleKeys.value = withNewDefaults(v, allKeys, defaultVisible, tableKey); },
  );

  function isVisible(key: string): boolean {
    return visibleKeys.value.includes(key);
  }

  function setVisible(keys: string[]) {
    // 過濾掉不在 allKeys 裡的 (防 stale)
    const filtered = keys.filter((k) => allKeys.includes(k));
    visibleKeys.value = filtered;
    cache.value[tableKey] = filtered;
    markSeen(tableKey, allKeys);   // 使用者已做過明確選擇 → 之後尊重其隱藏、不再自動補
    void persist();
  }

  // ── 欄位順序 ──
  const orderKey = `${tableKey}${ORDER_SUFFIX}`;
  // 使用者排好的順序；null = 沒自訂過 → 照畫面原本的順序。
  // 順序裡沒有的欄位（之後版本新增的、不在選單裡的常駐欄）留在畫面定義的位置不動。
  const order = computed<string[] | null>(() => {
    const s: unknown = cache.value[orderKey];
    const o = Array.isArray(s) ? cleanOrder(s, allKeys) : [];
    return o.length ? o : null;
  });

  function setOrder(keys: string[]) {
    cache.value[orderKey] = cleanOrder(keys, allKeys);
    void persist();
  }

  /**
   * 依使用者的順序重排表格欄位（給 view 的 columns computed 用，ExportButton 吃同一份就跟著走）。
   * 勾選欄、展開欄、fixed left/right 的欄、不在順序裡的欄（常駐欄、之後新增的欄）都留在原位置；
   * 其餘欄位只在彼此原本佔的位置之間互換。沒自訂過順序就原樣回傳。
   */
  function orderColumns<T>(cols: T[]): T[] {
    return applyOrder(cols, order.value, (c) => {
      const k = columnOrderKey(c);
      return k !== null && allKeys.includes(k) ? k : null;
    });
  }

  /** 同 orderColumns，對象是 key 清單（view 自己由 key 逐一組欄位時用，例如異常偵測各類別的表） */
  function orderKeys(keys: string[]): string[] {
    return applyOrder(keys, order.value, (k) => (allKeys.includes(k) ? k : null));
  }

  function reset() {
    // 「還原預設值」同時還原可見欄位與順序
    delete cache.value[orderKey];
    setVisible([...defaultVisible]);
  }

  return { visibleKeys, isVisible, setVisible, reset, allKeys, order, setOrder, orderColumns, orderKeys };
}
