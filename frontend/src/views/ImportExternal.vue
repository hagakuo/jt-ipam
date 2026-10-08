<script setup lang="ts">
/**
 * RIPE / TWNIC 匯入的獨立頁面。
 *
 * v0.6.5 起這個工具的入口在「工具 → RIPE / TWNIC」（原本掛在管理選單下）。
 * 這條路由保留是為了舊書籤與舊連結不要變成 404，內容與工具頁完全相同
 * （共用 `RegistryImportTabs`）。
 */
import { useI18n } from "vue-i18n";
import { NCard, NIcon, NSpace } from "naive-ui";
import { ImportIcon } from "@/icons";
import RegistryImportTabs from "@/components/RegistryImportTabs.vue";

const { t } = useI18n();
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><ImportIcon /></n-icon>
        <span>{{ t("import.title") }}</span>
      </n-space>
    </template>
    <RegistryImportTabs />
  </n-card>
</template>
