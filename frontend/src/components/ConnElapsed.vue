<script setup lang="ts">
/**
 * 主控台狀態列的連線時間（使用者 2026-10-06：VNC、SSH、RDP、RustDesk 等所有連線都要顯示連線時間）。
 *
 * active：已連線。paused：還是同一次連線、只是暫時斷開（RustDesk 自動重連中）→ 照樣計時、不歸零。
 * 斷線後停在最後的時間（狀態列看得到這次連了多久）；再連上是新的一次，從 0 開始。
 * 每秒更新一次；只在計時中才有計時器。
 */
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { NIcon, NTooltip } from "naive-ui";
import { ElapsedIcon } from "@/icons";
import { fmtClock, fmtDateTime } from "@/utils/datetime";

const props = defineProps<{ active: boolean; paused?: boolean }>();
const { t } = useI18n();

const startedAt = ref<number | null>(null);
const endedAt = ref<number | null>(null);
const now = ref(Date.now());
let timer: ReturnType<typeof setInterval> | null = null;

function run(on: boolean) {
  if (on && !timer) {
    now.value = Date.now();
    timer = setInterval(() => { now.value = Date.now(); }, 1000);
  } else if (!on && timer) {
    clearInterval(timer);
    timer = null;
  }
}

watch(() => [props.active, !!props.paused] as const, ([active, paused], old) => {
  const wasLive = !!old && (old[0] || old[1]);
  if (active && !wasLive) {             // 新的一次連線
    startedAt.value = Date.now();
    endedAt.value = null;
  } else if (!active && !paused && wasLive && startedAt.value !== null) {
    endedAt.value = Date.now();         // 結束：停在最後的時間
  }
  run((active || paused) && startedAt.value !== null);
}, { immediate: true });

onBeforeUnmount(() => run(false));

const seconds = computed(() =>
  startedAt.value === null ? 0 : ((endedAt.value ?? now.value) - startedAt.value) / 1000);
const tip = computed(() => {
  if (startedAt.value === null) return "";
  const since = fmtDateTime(new Date(startedAt.value).toISOString());
  return endedAt.value === null ? t("common.conn_elapsed_since", { at: since })
    : t("common.conn_elapsed_ended", { at: since, end: fmtDateTime(new Date(endedAt.value).toISOString()) });
});
</script>

<template>
  <n-tooltip v-if="startedAt !== null" :delay="200">
    <template #trigger>
      <span class="conn-elapsed" data-testid="conn-elapsed" :aria-label="t('common.conn_elapsed')">
        <n-icon :component="ElapsedIcon" :size="13" />{{ fmtClock(seconds) }}
      </span>
    </template>
    {{ tip }}
  </n-tooltip>
</template>

<style scoped>
.conn-elapsed { display: inline-flex; align-items: center; gap: 3px; font-variant-numeric: tabular-nums;
  font-weight: 500; opacity: .85; }
</style>
