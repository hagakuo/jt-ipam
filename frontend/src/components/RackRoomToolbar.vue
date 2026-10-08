<script setup lang="ts">
/**
 * 機房整排機櫃的共用工具列：正面／背面、顯示大小、匯出 —— 一次套用到整排。
 *
 * 整排並列時逐櫃的工具列是藏起來的（工具列的寬度會讓窄機櫃的卡片收不進來），所以整排
 * 共用一條。合併卡片與分開卡片用同一條：以前只有合併卡片有（而且沒有顯示大小），分開卡片
 * 什麼都沒有，機櫃一多就只能橫向捲動（使用者回報：要「一拉全部一起改變大小」）。
 */
import { useI18n } from "vue-i18n";
import { NButton, NButtonGroup, NDropdown, NIcon, NSlider, type DropdownOption } from "naive-ui";
import { ExportIcon } from "@/icons";

defineProps<{
  face: "front" | "rear";
  zoom: number;
  hasRear: boolean;
  exportOptions: DropdownOption[];
}>();
const emit = defineEmits<{
  (e: "update:face", v: "front" | "rear"): void;
  (e: "update:zoom", v: number): void;
  (e: "export", key: string): void;
}>();
const { t } = useI18n();
</script>

<template>
  <!-- 用 flex 而不是 n-space：n-space 的項目靠 baseline 對齊，而按鈕群組與單顆按鈕的
       line-height 不一樣，就會差個一兩 px 對不齊（與 RackDiagram 的 .rd-toolbar 同一個理由）。 -->
  <div class="merged-toolbar">
    <n-button-group size="tiny">
      <n-button :type="face === 'front' ? 'primary' : 'default'" @click="emit('update:face', 'front')">
        {{ t("racks.face_front") }}
      </n-button>
      <n-button :type="face === 'rear' ? 'primary' : 'default'" @click="emit('update:face', 'rear')">
        {{ t("racks.face_rear") }}<span v-if="hasRear" style="margin-left:3px">•</span>
      </n-button>
    </n-button-group>
    <span class="zoom-ctl" :title="t('rack_diagram.zoom')">
      <n-slider :value="zoom" :min="0.35" :max="1" :step="0.05"
                :format-tooltip="(v: number) => Math.round(v * 100) + '%'" style="width: 110px"
                @update:value="(v: number) => emit('update:zoom', v)" />
      <span class="zoom-ctl__val">{{ Math.round(zoom * 100) }}%</span>
    </span>
    <n-dropdown trigger="click" :options="exportOptions" @select="(k: string) => emit('export', k)">
      <n-button size="tiny">
        <template #icon><n-icon><ExportIcon /></n-icon></template>
        {{ t("common.export") }}
      </n-button>
    </n-dropdown>
  </div>
</template>

<style scoped>
.merged-toolbar {
  display: flex; align-items: center; justify-content: flex-end;
  /* 要能換行：靠右又不換行時，放不下的部分會往左邊溢出（手機上「正面」凸出去） */
  flex-wrap: wrap;
  gap: 8px; margin-bottom: 10px;
}
.zoom-ctl { display: flex; align-items: center; gap: 8px; }
.zoom-ctl__val { font-size: 11px; opacity: 0.6; min-width: 32px; text-align: right; }
</style>
