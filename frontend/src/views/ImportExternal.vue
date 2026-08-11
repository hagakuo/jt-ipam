<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { NCard, NIcon, NSpace, NTabs, NTabPane } from "naive-ui";
import { ImportIcon } from "@/icons";
import RegistryImport from "@/components/RegistryImport.vue";

const { t } = useI18n();
const tab = ref<"ripe" | "twnic">("ripe");
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><ImportIcon /></n-icon>
        <span>{{ t("import.title") }}</span>
      </n-space>
    </template>
    <n-tabs v-model:value="tab" type="line">
      <n-tab-pane name="ripe">
        <template #tab>
          <span class="tab-label"><n-icon :size="16"><ImportIcon /></n-icon>RIPE</span>
        </template>
        <!-- 每個分頁各自持有輸入狀態，切換不會把另一邊的查詢結果帶過來 -->
        <RegistryImport source="ripe" />
      </n-tab-pane>
      <n-tab-pane name="twnic">
        <template #tab>
          <span class="tab-label"><n-icon :size="16"><ImportIcon /></n-icon>TWNIC</span>
        </template>
        <RegistryImport source="twnic" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>

<style scoped>
.tab-label { display: inline-flex; align-items: center; gap: 6px; }
</style>
