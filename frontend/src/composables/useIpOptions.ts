import { ref } from "vue";
import { getAddress, listAddresses } from "@/api/addresses";

/**
 * 「選一個 IP 位址」的下拉選項 —— 搜尋走後端，不是前端過濾。
 *
 * 由來（GitHub issue #27）：裝置表單的「主要 IP」原本一次載 500 筆，然後靠
 * `n-select` 的 `filterable` 在**已載入的那 500 筆裡**過濾。站台一旦超過 500 個
 * 位址，剛建好的那筆就不在清單裡 —— 而且**打關鍵字也找不到**，因為關鍵字只搜
 * 記憶體裡的東西。使用者看到的是「我明明有這個 IP，但選不到」。
 *
 * 所以搜尋要送到後端（`q`）。另外選中的值也要能顯示名稱：編輯一台主要 IP 不在
 * 第一批結果裡的裝置時，若不補抓那一筆，下拉會顯示一個 UUID 或空白。
 */
export function useIpOptions(pageSize = 200, debounceMs = 250) {
  const options = ref<{ label: string; value: string }[]>([]);
  const loading = ref(false);
  const labels = new Map<string, string>();

  const label = (ip: string, hostname?: string | null) =>
    (hostname ? `${ip} — ${hostname}` : ip);

  function remember(items: { id: string; ip: string; hostname?: string | null }[]) {
    return items.map((a) => {
      const l = label(String(a.ip), a.hostname);
      labels.set(a.id, l);
      return { label: l, value: a.id };
    });
  }

  /** 依關鍵字向後端要一批（空字串＝要第一批，開下拉時用）。 */
  async function search(q?: string) {
    loading.value = true;
    try {
      const res = await listAddresses({ page: 1, pageSize, q: q || undefined });
      options.value = remember(res.items as never);
    } catch {
      options.value = [];
    } finally {
      loading.value = false;
    }
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  /** 綁在 `@search`：邊打邊送會把後端打爛，這裡壓到停手之後才問。 */
  function onSearch(q: string) {
    clearTimeout(timer);
    timer = setTimeout(() => void search(q), debounceMs);
  }

  /**
   * 確保某個已選中的 id 在選項裡（編輯既有裝置時用）。
   * 少了這一步，選中的那筆若不在第一批結果內，畫面上會是空白或 UUID。
   */
  async function ensure(id?: string | null) {
    if (!id || labels.has(id)) return;
    try {
      const a = await getAddress(id);
      const l = label(String(a.ip), a.hostname);
      labels.set(id, l);
      if (!options.value.some((o) => o.value === id)) {
        options.value = [{ label: l, value: id }, ...options.value];
      }
    } catch { /* 那筆被刪掉了就算了，下拉會顯示空白而不是壞掉 */ }
  }

  return { options, loading, search, onSearch, ensure };
}
