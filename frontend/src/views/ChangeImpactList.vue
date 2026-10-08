<template>
  <div class="cip-page">
    <n-card :bordered="false" content-style="padding: 14px 16px">
      <div class="cip-head">
        <div class="cip-head__title">
          <n-icon :size="20"><ChangeImpactIcon /></n-icon>
          <span>{{ t("change_impact.title") }}</span>
        </div>
        <n-button v-if="settings.enabled" type="primary" size="small" data-testid="cip-new" @click="wizard = true">
          <template #icon><n-icon><PlusIcon /></n-icon></template>{{ t("change_impact.new_plan") }}
        </n-button>
      </div>
      <p class="cip-intro">{{ t("change_impact.intro") }}</p>
    </n-card>

    <n-result v-if="loaded && !settings.enabled" status="info" :title="t('change_impact.disabled_title')"
              :description="t('change_impact.disabled_desc')" style="margin-top: 24px" data-testid="cip-disabled" />

    <n-card v-else size="small">
      <div class="cip-filters">
        <n-select v-model:value="scenario" :options="scenarioOptions" clearable size="small" style="width: 160px"
                  :placeholder="t('change_impact.f_scenario')" />
        <n-select v-model:value="lifecycle" :options="lifecycleOptions" clearable size="small" style="width: 150px"
                  :placeholder="t('change_impact.col_lifecycle')" />
        <n-input v-model:value="q" size="small" clearable style="width: 220px" :placeholder="t('common.search')" />
      </div>
      <n-data-table :columns="columns" :data="rows" :loading="loading" size="small" :bordered="false"
                    :row-key="(r: ChangePlan) => r.id" :row-props="rowProps" :scroll-x="900"
                    :pagination="{ page, pageSize, itemCount: total, onChange: (p: number) => { page = p } }" remote
                    data-testid="cip-list" />
    </n-card>

    <ChangeImpactWizard v-model:show="wizard" />
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { NButton, NCard, NDataTable, NIcon, NInput, NResult, NSelect, NTag, type DataTableColumns } from "naive-ui";
import { listPlans, type ChangePlan } from "@/api/changeImpact";
import ChangeImpactWizard from "@/components/ChangeImpactWizard.vue";
import { useChangeImpact } from "@/composables/useChangeImpact";
import { ChangeImpactIcon, PlusIcon } from "@/icons";
import { fmtDateTime } from "@/utils/datetime";
import { decisionType, lifecycleType } from "@/utils/changeImpact";

const { t } = useI18n();
const router = useRouter();
const { settings, load } = useChangeImpact();
const loaded = ref(false);
const wizard = ref(false);
const rows = ref<ChangePlan[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = 50;
const loading = ref(false);
const scenario = ref<string | null>(null);
const lifecycle = ref<string | null>(null);
const q = ref("");

const scenarioOptions = computed(() => ["ip_renumber", "device_decommission"]
  .map((v) => ({ label: t(`change_impact.scenario.${v}`), value: v })));
const lifecycleOptions = computed(() => ["draft", "in_review", "approved", "in_progress", "verified", "closed", "cancelled"]
  .map((v) => ({ label: t(`change_impact.lifecycle.${v}`), value: v })));

async function fetchRows() {
  loading.value = true;
  try {
    const r = await listPlans({ page: page.value, page_size: pageSize, scenario_type: scenario.value || undefined,
                                lifecycle: lifecycle.value || undefined, q: q.value.trim() || undefined });
    rows.value = r.items;
    total.value = r.total;
  } finally {
    loading.value = false;
  }
}

let timer: ReturnType<typeof setTimeout> | null = null;
watch([scenario, lifecycle, q], () => {
  page.value = 1;
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => void fetchRows(), 250);
});
watch(page, () => void fetchRows());

const columns = computed<DataTableColumns<ChangePlan>>(() => [
  { title: t("change_impact.col_title"), key: "title", minWidth: 220,
    render: (r) => h("div", null, [h("div", { class: "cip-strong" }, r.title),
                                   h("div", { class: "cip-muted" }, r.target_label
                                     + (r.parameters.new_ip ? ` → ${r.parameters.new_ip}` : ""))]) },
  { title: t("change_impact.f_scenario"), key: "scenario_type", width: 120,
    render: (r) => t(`change_impact.scenario.${r.scenario_type}`) },
  { title: t("change_impact.col_lifecycle"), key: "lifecycle", width: 110,
    render: (r) => h(NTag, { size: "small", type: lifecycleType(r.lifecycle) },
                     { default: () => t(`change_impact.lifecycle.${r.lifecycle}`) }) },
  { title: t("change_impact.col_latest_run"), key: "latest_run", minWidth: 220,
    render: (r) => {
      const lr = r.latest_run;
      if (!lr) return h("span", { class: "cip-muted" }, t("change_impact.never_run"));
      if (!["completed", "partial"].includes(lr.job_status)) return t(`change_impact.job.${lr.job_status}`);
      const c = lr.counts || {};
      return h("div", { class: "cip-run-cell" }, [
        lr.decision_status ? h(NTag, { size: "small", type: decisionType(lr.decision_status) },
                               { default: () => t(`change_impact.decision.${lr.decision_status}`) }) : null,
        h("span", { class: "cip-muted" }, t("change_impact.counts_short", {
          blockers: c.blockers ?? 0, review: c.review ?? 0, gaps: c.gaps ?? 0 })),
      ]);
    } },
  { title: t("change_impact.col_window"), key: "planned_start", width: 170,
    render: (r) => (r.planned_start ? fmtDateTime(r.planned_start) : "—") },
  { title: t("change_impact.col_created"), key: "created_at", width: 170, render: (r) => fmtDateTime(r.created_at) },
]);

function rowProps(r: ChangePlan) {
  return { style: "cursor: pointer", onClick: () => void router.push({ name: "change_impact_plan", params: { id: r.id } }) };
}

onMounted(async () => {
  await load(true);
  loaded.value = true;
  if (settings.value.enabled) await fetchRows();
});
</script>

<style scoped>
.cip-page { display: flex; flex-direction: column; gap: 12px; }
.cip-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.cip-head__title { display: flex; align-items: center; gap: 8px; font-size: 17px; font-weight: 600; }
.cip-intro { margin: 8px 0 0; font-size: 13px; opacity: .75; line-height: 1.6; }
.cip-filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
</style>

<style>
.cip-strong { font-weight: 600; }
.cip-muted { font-size: 12.5px; opacity: .65; }
.cip-run-cell { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
</style>
