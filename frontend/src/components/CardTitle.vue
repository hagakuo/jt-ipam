<template>
  <div class="card-title">
    <n-icon :component="icon" :size="18" class="card-title-icon" />
    <span class="card-title-text">{{ text }}</span>
    <slot />
  </div>
</template>

<script setup lang="ts">
import { NIcon } from "naive-ui";
import type { Component } from "vue";

// 卡片標題（icon + 文字 + 可選附加內容，如計數標籤）。
// 抽成元件而不是每張卡片各自排版：n-space 會把每個子項包成 inline-block，icon(18px)、
// 文字(行高)、標籤(22px) 三者高度不同時就會一高一低。這裡用單一 flex 容器 +
// align-items:center，並讓 icon 走 block，對齊才是由同一份規則決定。
defineProps<{ icon: Component; text: string }>();
</script>

<style scoped>
.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
/* n-icon 預設 inline-flex，會跟著文字基線走；改 block 讓它只受 flex 對齊控制 */
.card-title-icon {
  display: block;
  flex: none;
  color: var(--n-text-color);
  opacity: 0.75;
}
.card-title-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
