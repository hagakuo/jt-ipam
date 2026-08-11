<template>
  <div class="peek">
    <div class="peek-ip">{{ name }}</div>
    <n-spin v-if="!data" :size="14" style="margin: 6px 0" />
    <div v-else-if="data.missing" class="peek-missing">{{ t("ip_peek.not_found") }}</div>
    <div v-else class="peek-rows">
      <div v-if="data.type" class="peek-row">
        <span class="k">{{ t("common.type") }}</span><span class="v">{{ data.type }}</span>
      </div>
      <div v-if="data.ip" class="peek-row">
        <span class="k">IP</span><span class="v mono">{{ data.ip }}</span>
      </div>
      <div v-if="data.vendor || data.model" class="peek-row">
        <span class="k">{{ t("devices.model") }}</span>
        <span class="v">{{ [data.vendor, data.model].filter(Boolean).join(" ") }}</span>
      </div>
      <div v-if="data.serial" class="peek-row">
        <span class="k">{{ t("devices.serial") }}</span><span class="v mono">{{ data.serial }}</span>
      </div>
      <div v-if="data.location" class="peek-row">
        <span class="k">{{ t("nav.locations") }}</span><span class="v">{{ data.location }}</span>
      </div>
      <div v-if="data.description" class="peek-row">
        <span class="k">{{ t("common.description") }}</span>
        <span class="v">{{ data.description }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * 裝置的懸停摘要卡（給 AI 巡檢的「依據資料」用）。
 *
 * 為什麼要有：依據資料列裡的 IP 懸停會彈出細節，主機名稱卻只能點 —— 同一列裡兩種東西
 * 行為不一樣，使用者得先點進去才知道那台是什麼。兩者都是「查證這筆發現」的線索，
 * 應該一樣好查。
 */
import { NSpin } from "naive-ui";
import { useI18n } from "vue-i18n";

export interface DevicePeekData {
  missing?: boolean;
  type?: string | null;
  ip?: string | null;
  vendor?: string | null;
  model?: string | null;
  serial?: string | null;
  location?: string | null;
  description?: string | null;
}

defineProps<{ name: string; data?: DevicePeekData }>();
const { t } = useI18n();
</script>

<style scoped>
.peek { min-width: 210px; max-width: 320px; font-size: 12.5px; }
.peek-ip { font-weight: 600; margin-bottom: 4px; }
.peek-missing { opacity: 0.6; }
.peek-rows { display: grid; gap: 3px; }
.peek-row { display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 8px; align-items: baseline; }
.k { opacity: 0.55; }
.v { word-break: break-word; }
.mono { font-family: var(--jt-mono, monospace); }
</style>
