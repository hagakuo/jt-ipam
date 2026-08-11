<template>
  <n-card v-if="summary" size="small" class="dash-ai">
    <template #header>
      <CardTitle :icon="AnomalyIcon" :text="t('ai_audit.title')">
        <n-tag v-if="summary.total" size="small" round :bordered="false" type="warning">
          {{ summary.total }}
        </n-tag>
      </CardTitle>
    </template>
    <template #header-extra>
      <n-button size="small" @click="go()">
        <template #icon><n-icon :component="ListIcon" /></template>
        {{ t("ai_audit.view_all") }}
      </n-button>
    </template>

    <n-empty v-if="!summary.total" :description="t('ai_audit.none')" size="small" />
    <div v-else class="ai-row">
      <div v-for="s in order" :key="s" class="ai-cell" :class="`ai-${s}`" @click="go(s)">
        <div class="ai-n">{{ summary.counts[s] }}</div>
        <div class="ai-l">{{ t(`ai_audit.sev_${s}`) }}</div>
      </div>
      <!-- 發現數不等於問題規模：一筆發現可能點名很多個位址 -->
      <div class="ai-cell" @click="go()">
        <div class="ai-n">{{ summary.ip_count }}</div>
        <div class="ai-l">{{ t("ai_audit.related_ips") }}</div>
      </div>
    </div>
    <!-- 這些是 AI 推測。不標明的話，數字擺在儀表板上會被當成查核過的事實。 -->
    <div class="ai-note">
      {{ t("ai_audit.dashboard_note") }}
      <span v-if="summary.last_run_at">· {{ fmtDateTime(summary.last_run_at) }}</span>
    </div>
  </n-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";
import { NButton, NCard, NEmpty, NIcon, NTag } from "naive-ui";
import { AnomalyIcon, ListIcon } from "@/icons";
import CardTitle from "@/components/CardTitle.vue";
import { fmtDateTime } from "@/utils/datetime";
import { getAIAuditSummary, type AIAuditSummary } from "@/api/system";

const { t } = useI18n();
const router = useRouter();
const summary = ref<AIAuditSummary | null>(null);
const order = ["high", "medium", "low"] as const;

function go(sev?: string) {
  router.push({ name: "ai_audit", query: sev ? { severity: sev } : {} }).catch(() => {});
}

onMounted(async () => {
  // 沒有全域讀取權限的帳號會拿到 403 —— 那時整個區塊不顯示，而不是顯示一個錯誤
  try { summary.value = await getAIAuditSummary(); } catch { summary.value = null; }
});
</script>

<style scoped>
.dash-ai { width: 100%; }
.ai-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
/* 跟儀表板其他 KPI 卡片一樣有框線 —— 只有底色的話，跟卡片底色相近時等於沒有邊界 */
.ai-cell {
  padding: 12px; border-radius: 8px; cursor: pointer; text-align: center;
  background: var(--n-color, #fff);
  border: 1px solid var(--n-border-color, rgba(0, 0, 0, .09));
  transition: transform .12s ease, box-shadow .12s ease;
}
.ai-cell:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0, 0, 0, .08); }
.ai-n {
  font-size: 24px; font-weight: 700; line-height: 1.2;
  font-variant-numeric: tabular-nums;
}
.ai-l { font-size: 12px; color: var(--n-text-color-disabled); margin-top: 2px; }
.ai-high .ai-n { color: #d03050; }
.ai-medium .ai-n { color: #f0a020; }
.ai-note { margin-top: 10px; font-size: 11.5px; line-height: 1.6; color: var(--n-text-color-disabled); }
</style>
