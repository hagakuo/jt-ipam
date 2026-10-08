<script setup lang="ts">
/**
 * RIPE / TWNIC 匯入的兩個分頁。
 *
 * 抽成元件是因為它同時出現在「工具」頁與 `/import` 路由 —— 兩邊必須完全一樣，
 * 各自複製一份 template 遲早會只改到其中一份。
 */
import { ref } from "vue";
import { NIcon, NTabs, NTabPane } from "naive-ui";
import { ImportIcon } from "@/icons";
import RegistryImport from "@/components/RegistryImport.vue";

const tab = ref<"ripe" | "twnic">("ripe");
</script>

<template>
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
</template>

<style scoped>
.tab-label { display: inline-flex; align-items: center; gap: 6px; }
</style>
