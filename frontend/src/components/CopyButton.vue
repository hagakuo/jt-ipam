<script setup lang="ts">
/**
 * 表格裡、文字後面的小「複製」按鈕。用按鈕而不是裸圖示：滑鼠移過去有底色與顏色變化、游標變手指，
 * 還有提示文字，一看就知道可以點（使用者 2026-10-04：「移游標過去要有效果，讓人一看知道是可以點」）。
 */
import { NButton, NIcon, NTooltip, useMessage, useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import { CopyIcon } from "@/icons";

const props = defineProps<{ text: string; label?: string }>();
const { t } = useI18n();
const msg = useMessage();
const theme = useThemeVars();

async function copy() {
  try {
    await navigator.clipboard.writeText(props.text);
    msg.success(t("common.copied"));
  } catch { msg.error(t("common.fail")); }
}
</script>

<template>
  <n-tooltip>
    <template #trigger>
      <n-button quaternary circle size="tiny" class="copy-btn" :aria-label="props.label || t('common.copy')"
                :style="{ '--copy-hover': theme.primaryColor }" data-testid="copy-btn" @click.stop="copy">
        <template #icon><n-icon :size="13"><CopyIcon /></n-icon></template>
      </n-button>
    </template>
    {{ props.label || t("common.copy") }}
  </n-tooltip>
</template>

<style scoped>
.copy-btn { opacity: .55; margin-left: 2px; vertical-align: middle; transition: opacity .15s, color .15s; }
.copy-btn:hover, .copy-btn:focus-visible { opacity: 1; color: var(--copy-hover) !important; }
</style>
