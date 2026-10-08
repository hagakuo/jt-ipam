import { ref } from "vue";
import { getImpactSettings, type ImpactSettings } from "@/api/changeImpact";

/**
 * 變更影響預演是否啟用（選單與 IP／裝置頁的入口共用）。功能預設關閉，管理員在系統設定打開；
 * 讀不到（舊後端、網路問題）就當作沒開，不要顯示會點不進去的入口。
 */
const settings = ref<ImpactSettings>({ enabled: false, ai_available: false });
let loading: Promise<void> | null = null;

export function useChangeImpact() {
  function load(force = false): Promise<void> {
    if (loading && !force) return loading;
    loading = getImpactSettings()
      .then((s) => { settings.value = s; })
      .catch(() => { settings.value = { enabled: false, ai_available: false }; });
    return loading;
  }
  return { settings, load };
}
