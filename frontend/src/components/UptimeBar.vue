<template>
  <div class="uptime">
    <div class="uptime-head">
      <span class="uptime-title">{{ t("uptime.title") }}</span>
      <n-tooltip v-if="!loading && data && !data.has_source" trigger="hover">
        <template #trigger>
          <n-tag size="small" round :bordered="false">{{ t("uptime.no_source") }}</n-tag>
        </template>
        {{ t("uptime.no_source_hint") }}
      </n-tooltip>
    </div>

    <div v-if="loading" class="uptime-bars">
      <span v-for="i in days" :key="i" class="bar bar-unknown" />
    </div>

    <div v-else-if="data" class="uptime-bars">
      <n-tooltip v-for="d in data.items" :key="d.date" trigger="hover" :delay="80">
        <template #trigger>
          <span class="bar" :class="`bar-${d.status}`" />
        </template>
        <div class="tip">
          <div class="tip-date">{{ d.date }}</div>
          <div>{{ t(`uptime.st_${d.status}`) }}</div>
        </div>
      </n-tooltip>
    </div>

    <div class="uptime-foot">
      <span>{{ t("uptime.days_ago", { n: days }) }}</span>
      <span class="uptime-pct">
        <template v-if="data && data.uptime_pct !== null">
          {{ data.uptime_pct }}% {{ t("uptime.uptime") }}
          <span class="uptime-basis">{{ t("uptime.basis", { n: data.known_days }) }}</span>
        </template>
        <template v-else>{{ t("uptime.no_data") }}</template>
      </span>
      <span>{{ t("uptime.today") }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { NTag, NTooltip } from "naive-ui";
import { apiClient, apiErrMsg } from "@/api/client";

// 同一個元件服務兩種來源：IP 詳情頁與裝置詳情頁（裝置會合併它名下所有 IP）
const props = withDefaults(
  defineProps<{ addressId?: string; deviceId?: string; days?: number }>(),
  { addressId: undefined, deviceId: undefined, days: 90 },
);
const { t } = useI18n();

interface UptimeDay { date: string; status: "up" | "down" | "unknown" }
interface UptimeData {
  days: number;
  items: UptimeDay[];
  uptime_pct: number | null;
  known_days: number;
  down_days: number;
  has_source: boolean;
}

const data = ref<UptimeData | null>(null);
const loading = ref(true);

async function load() {
  loading.value = true;
  try {
    const url = props.deviceId
      ? `/api/v1/devices/${props.deviceId}/uptime`
      : `/api/v1/addresses/${props.addressId}/uptime`;
    const r = await apiClient.get(url, { params: { days: props.days } });
    data.value = r.data;
  } catch {
    // 讀不到就維持骨架（不彈錯誤打擾使用者）；apiErrMsg 供未來需要時使用
    void apiErrMsg;
    data.value = null;
  } finally {
    loading.value = false;
  }
}

onMounted(load);
watch(() => [props.addressId, props.deviceId], load);
</script>

<style scoped>
.uptime { width: 100%; }
.uptime-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.uptime-title { font-size: 13px; font-weight: 600; color: var(--n-text-color); }

/* 每條等比壓縮：min-width:0 讓 flex item 可以縮到比內容窄，窄螢幕才不會撐破 */
.uptime-bars { display: flex; gap: 2px; align-items: stretch; height: 34px; }
/* 膠囊狀圓角（比照參考的 status page 樣式）：半徑取夠大讓兩端呈半圓，
   實際圓角會被條寬夾住，所以窄螢幕壓縮時仍然好看 */
.bar {
  flex: 1 1 0; min-width: 0; border-radius: 999px;
  transition: opacity .12s ease, transform .12s ease;
}
.bar:hover { opacity: .75; transform: scaleY(1.06); }

/* 綠／橘是狀態語意色，深淺主題下都成立 → 固定色。
   「無資料」必須跟著主題走，否則深色模式會亮得刺眼。 */
.bar-up { background: #18a058; }
.bar-down { background: #f0a020; }
.bar-unknown { background: var(--n-border-color); }

.uptime-foot {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-top: 8px; font-size: 12px; color: var(--n-text-color-disabled);
}
.uptime-pct { font-weight: 700; color: var(--n-text-color); }
.uptime-basis { font-weight: 400; font-size: 11.5px; color: var(--n-text-color-disabled); margin-left: 6px; }
.tip-date { font-weight: 600; margin-bottom: 2px; }
</style>
