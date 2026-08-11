<template>
  <span v-if="parts" class="cv">
    <span class="cv-dev">{{ parts.device }}</span><span class="cv-at">@</span><span class="cv-port">{{ parts.port }}</span>
  </span>
  <span v-else>{{ text }}</span>
</template>

<script setup lang="ts">
/**
 * 異動記錄的值顯示。`switch_port` 會拆成「裝置＠埠號」並把 @ 標色 ——
 * 兩段都是深色文字時，中間那個符號看不出來，一長串讀起來像一個字。
 */
import { computed } from "vue";
import { fmtChangeVal } from "@/utils/changelog";

const props = defineProps<{ field?: string | null; value?: string | null }>();

const text = computed(() => fmtChangeVal(props.field, props.value));
const parts = computed(() => {
  if (props.field !== "switch_port") return null;
  const i = text.value.indexOf("@");
  return i > 0 ? { device: text.value.slice(0, i), port: text.value.slice(i + 1) } : null;
});
</script>

<style scoped>
.cv-at { color: #18a058; font-weight: 600; margin: 0 1px; }
.cv-port { opacity: .85; }
</style>
