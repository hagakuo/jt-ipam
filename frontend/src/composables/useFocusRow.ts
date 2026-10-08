import { computed, ref, watch, type ComputedRef, type Ref } from "vue";
import { useRoute, useRouter } from "vue-router";

/**
 * 從別頁點進來「只看這一筆」：網址帶 `?focus=<key>`（有分頁籤的頁面再帶 `tab`），
 * 表格只留相符的那幾列，上方用 FocusRowBanner 提示並提供「顯示全部」。
 *
 * 目前的來源是 IP 詳細頁的防火牆規則／所屬別名／NAT（使用者要求點了要能帶到那一筆）。
 *
 * @param rows  未經篩選的完整清單（位置型的 key 例如 pfSense 的 `#3` 要用完整清單的索引）
 * @param match 這一列是不是要找的那一筆
 * @param tab   只在網址的 `tab` 等於這個值時生效（同一頁有規則、別名兩個分頁時用）
 */
export function useFocusRow<T>(
  rows: Ref<T[]>,
  match: (row: T, key: string, index: number) => boolean,
  tab?: string,
) {
  const route = useRoute();
  const router = useRouter();
  const q = route.query.focus;
  const focus = ref<string | null>(
    typeof q === "string" && q && (!tab || route.query.tab === tab) ? q : null);
  const focused = computed<T[] | null>(() => {
    const key = focus.value;
    if (key == null) return null;
    return rows.value.filter((r, i) => match(r, key, i));
  });
  /** 有 focus 時回相符的那幾列，否則原樣回傳（通常傳已套用其他篩選的清單） */
  function apply(list: T[]): T[] {
    return focused.value ?? list;
  }
  // 清單至少載入過一次才算數：還沒載入前就說「找不到」會閃一下誤導（空清單重新指派也會觸發）
  const settled = ref(false);
  watch(rows, () => { settled.value = true; });
  function clear() {
    if (focus.value == null) return;
    focus.value = null;
    const next = { ...route.query };
    delete next.focus;
    void router.replace({ query: next });
  }
  return { focus, focused, settled, apply, clear };
}

/** FocusRowBanner 只需要這幾樣（不帶列型別，任何清單的 useFocusRow 都能傳進去） */
export interface FocusRow {
  focus: Ref<string | null>;
  focused: ComputedRef<readonly unknown[] | null>;
  settled: Ref<boolean>;
  clear: () => void;
}
