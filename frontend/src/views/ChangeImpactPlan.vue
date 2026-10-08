<template>
  <div class="cip-page">
    <n-spin :show="loading && !plan">
      <n-card v-if="plan" :bordered="false" content-style="padding: 14px 16px">
        <div class="cip-head">
          <div class="cip-head__title">
            <n-icon :size="20"><ChangeImpactIcon /></n-icon>
            <span data-testid="cip-plan-title">{{ plan.title }}</span>
            <n-tag size="small" :type="lifecycleType(plan.lifecycle)" data-testid="cip-lifecycle">
              {{ t(`change_impact.lifecycle.${plan.lifecycle}`) }}
            </n-tag>
          </div>
          <n-space :size="8" :wrap="true">
            <n-button size="small" @click="router.push({ name: 'change_impact' })">
              <template #icon><n-icon><ArrowLeftIcon /></n-icon></template>{{ t("common.back") }}
            </n-button>
            <n-button v-if="canRun" size="small" :loading="busy === 'run'" data-testid="cip-rerun" @click="rerun">
              <template #icon><n-icon><RefreshIcon /></n-icon></template>{{ t("change_impact.rerun") }}
            </n-button>
            <n-button v-if="plan.can_edit && editable" size="small" @click="openEdit">
              <template #icon><n-icon><EditIcon /></n-icon></template>{{ t("common.edit") }}
            </n-button>
            <n-button v-for="a in actions" :key="a" size="small" :type="a === 'review' ? 'primary' : 'default'"
                      :loading="busy === a" :data-testid="`cip-act-${a}`" @click="act(a)">
              {{ t(`change_impact.act.${a}`) }}
            </n-button>
            <n-dropdown v-if="run && isDone" :options="exportOptions" @select="doExport">
              <n-button size="small"><template #icon><n-icon><DownloadIcon /></n-icon></template>{{ t("change_impact.export") }}</n-button>
            </n-dropdown>
          </n-space>
        </div>
        <div class="cip-meta">
          <span>{{ t(`change_impact.scenario.${plan.scenario_type}`) }}</span>
          <span class="cip-mono">{{ plan.target_label }}<template v-if="plan.parameters.new_ip"> → {{ plan.parameters.new_ip }}</template></span>
          <span v-if="plan.planned_start">{{ t("change_impact.window_label") }} {{ fmtDateTime(plan.planned_start) }}<template v-if="plan.planned_end"> – {{ fmtDateTime(plan.planned_end) }}</template></span>
          <span>{{ t("change_impact.revision", { n: plan.revision }) }}</span>
        </div>
        <div class="cip-dryrun" data-testid="cip-dryrun">{{ t("change_impact.dry_run_notice") }}</div>
      </n-card>
    </n-spin>
    <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>

    <!-- 分析狀態與摘要 -->
    <n-card v-if="plan" size="small">
      <div v-if="!run" class="cip-muted">{{ t("change_impact.never_run") }}</div>
      <div v-else-if="!isDone" class="cip-running" data-testid="cip-running">
        <n-spin v-if="isActive" :size="14" />
        <span>{{ t(`change_impact.job.${run.job_status}`) }}</span>
        <span v-if="run.error_code" class="cip-err">{{ errText(run.error_code) }}</span>
        <n-button v-if="isActive" size="tiny" secondary @click="cancel">{{ t("change_impact.cancel_run") }}</n-button>
      </div>
      <template v-else>
        <div class="cip-summary" data-testid="cip-summary">
          <div class="cip-stat">
            <div class="cip-stat__k">{{ t("change_impact.col_decision") }}</div>
            <n-tag :type="decisionType(run.decision_status)" data-testid="cip-decision">
              {{ t(`change_impact.decision.${run.decision_status}`) }}
            </n-tag>
          </div>
          <div class="cip-stat">
            <div class="cip-stat__k">{{ t("change_impact.col_completeness") }}</div>
            <span :class="run.completeness === 'complete' ? '' : 'cip-warn'" data-testid="cip-completeness">
              {{ t(`change_impact.completeness.${run.completeness}`) }}
            </span>
          </div>
          <div class="cip-stat" v-for="k in ['blockers', 'review', 'change_required', 'gaps']" :key="k">
            <div class="cip-stat__k">{{ t(`change_impact.count.${k}`) }}</div>
            <div class="cip-stat__v">{{ run.counts[k] ?? 0 }}</div>
          </div>
          <div class="cip-stat">
            <div class="cip-stat__k">{{ t("change_impact.analyzed_at") }}</div>
            <div>{{ fmtDateTime(run.completed_at) }}</div>
            <div class="cip-muted" :class="{ 'cip-warn': expired }">
              {{ expired ? t("change_impact.expired") : t("change_impact.valid_until", { at: fmtDateTime(run.expires_at) }) }}
            </div>
          </div>
        </div>
        <n-alert v-if="run.permission_scope_changed" type="warning" :bordered="false" style="margin-top: 10px">
          {{ t("change_impact.scope_changed") }}
        </n-alert>
        <n-alert v-if="run.truncated && run.truncation" type="warning" :bordered="false" style="margin-top: 10px">
          {{ t("change_impact.truncated", { what: run.truncation.what, limit: run.truncation.limit }) }}
        </n-alert>
        <div class="cip-scope-note">{{ t("change_impact.scope_note") }}</div>
      </template>
    </n-card>

    <n-card v-if="plan && run && isDone" size="small">
      <n-tabs v-model:value="tab" type="line" animated>
        <!-- 影響清單 -->
        <n-tab-pane name="findings" :tab="t('change_impact.tab_findings', { n: findings.length })">
          <div class="cip-filters">
            <n-select v-model:value="fDisp" :options="dispOptions" clearable size="small" style="width: 150px"
                      :placeholder="t('change_impact.col_disposition')" />
            <n-select v-model:value="fCat" :options="catOptions" clearable size="small" style="width: 150px"
                      :placeholder="t('change_impact.col_category')" />
          </div>
          <div v-if="!findings.length" class="cip-empty" data-testid="cip-zero">{{ t("change_impact.zero_findings") }}</div>
          <n-data-table v-else :columns="findingCols" :data="shownFindings" size="small" :bordered="false"
                        :row-key="(r: ImpactFinding) => r.id" :scroll-x="980" data-testid="cip-findings" />
        </n-tab-pane>

        <!-- 證據與資料缺口 -->
        <n-tab-pane name="evidence" :tab="t('change_impact.tab_evidence', { n: gaps.length })">
          <div class="cip-section-k">{{ t("change_impact.gaps_title") }}</div>
          <ul class="cip-gaps" data-testid="cip-gaps">
            <li v-for="g in gaps" :key="g.id">
              <n-tag size="tiny" :bordered="false">{{ catLabel(g.category) }}</n-tag>
              <span>{{ gapText(t, te, g.reason_code, g.params) }}</span>
            </li>
            <li v-if="!gaps.length" class="cip-muted">{{ t("change_impact.no_gaps") }}</li>
          </ul>
          <div class="cip-section-k" style="margin-top: 14px">{{ t("change_impact.evidence_title") }}</div>
          <n-data-table :columns="evidenceCols" :data="evidence" size="small" :bordered="false"
                        :row-key="(r: ImpactEvidence) => r.id" :scroll-x="820" data-testid="cip-evidence" />
          <div class="cip-section-k" style="margin-top: 14px">{{ t("change_impact.sources_title") }}</div>
          <div class="cip-sources">
            <span v-for="s in run.scope_manifest.sources ?? []" :key="s.kind + s.name" class="cip-source">
              {{ s.name }} <span class="cip-muted">（{{ s.kind }}，{{ t(`change_impact.fresh.${s.freshness}`) }}）</span>
            </span>
            <span v-if="!(run.scope_manifest.sources ?? []).length" class="cip-muted">—</span>
          </div>
        </n-tab-pane>

        <!-- 待辦與復原 -->
        <n-tab-pane name="tasks" :tab="t('change_impact.tab_tasks', { n: tasks.length })">
          <div class="cip-manual-note">{{ t("change_impact.manual_note") }}</div>
          <div v-for="ph in phases" :key="ph" class="cip-phase" :data-testid="`cip-phase-${ph}`">
            <div class="cip-section-k">{{ t(`change_impact.phase.${ph}`) }}</div>
            <div v-for="tk in tasksOf(ph)" :key="tk.id" class="cip-task" data-testid="cip-task">
              <n-select :value="tk.state" size="tiny" style="width: 110px" :options="taskStateOptions"
                        :disabled="!editable" @update:value="(v: string) => setTaskState(tk, v)" />
              <div class="cip-task__body">
                <div :class="{ 'cip-done': tk.state === 'done' || tk.state === 'skipped' }">{{ taskTitle(t, te, tk) }}</div>
                <div v-if="tk.completion_note" class="cip-muted">{{ tk.completion_note }}</div>
              </div>
              <n-tag v-if="tk.origin !== 'rule_template'" size="tiny" :bordered="false">{{ t(`change_impact.origin.${tk.origin}`) }}</n-tag>
            </div>
          </div>
          <n-button v-if="editable && plan.can_edit" size="small" style="margin-top: 8px" @click="newTask = { phase: 'change', title: '' }">
            <template #icon><n-icon><PlusIcon /></n-icon></template>{{ t("change_impact.add_task") }}
          </n-button>
        </n-tab-pane>

        <!-- AI 解說 -->
        <n-tab-pane name="ai" :tab="t('change_impact.tab_ai')">
          <div v-if="!settings.ai_available" class="cip-muted">{{ t("errors.impact_ai_unavailable") }}</div>
          <template v-else>
            <n-space :size="8" style="margin-bottom: 10px">
              <n-button v-for="k in ['summary', 'checklist', 'explanation']" :key="k" size="small" :loading="busy === `ai-${k}`"
                        :data-testid="`cip-ai-${k}`" @click="genAi(k)">{{ t(`change_impact.ai_gen.${k}`) }}</n-button>
            </n-space>
            <div class="cip-ask">
              <n-input v-model:value="question" size="small" :placeholder="t('change_impact.ask_ph')" maxlength="1000"
                       @keyup.enter="ask" />
              <n-button size="small" :disabled="!question.trim()" :loading="busy === 'ask'" @click="ask">{{ t("change_impact.ask") }}</n-button>
            </div>
          </template>
          <div class="cip-ai-note">{{ t("change_impact.ai_note") }}</div>
          <div v-for="a in artifacts" :key="a.id" class="cip-ai" data-testid="cip-ai-item">
            <div class="cip-ai__head">
              <strong>{{ t(`change_impact.ai_type.${a.artifact_type}`) }}</strong>
              <span v-if="a.question" class="cip-muted">「{{ a.question }}」</span>
              <n-spin v-if="a.status === 'pending' || a.status === 'running'" :size="12" />
              <n-tag v-if="a.status === 'fallback'" size="tiny" type="warning" :bordered="false">{{ t("change_impact.ai_fallback") }}</n-tag>
              <span class="cip-muted">{{ a.model ?? "" }} {{ a.generated_at ? fmtDateTime(a.generated_at) : "" }}</span>
            </div>
            <div v-if="a.hidden_scope_changed" class="cip-muted">{{ t("change_impact.ai_hidden") }}</div>
            <template v-else-if="a.output">
              <ul class="cip-ai__list">
                <li v-for="(it, i) in a.output.summary ?? []" :key="'s' + i">
                  {{ aiText(it) }}
                  <a v-for="fid in it.finding_ids ?? []" :key="fid" class="cip-cite" @click="focusFinding(fid)">#{{ shortRef(fid) }}</a>
                </li>
              </ul>
              <div v-if="(a.output.uncertainties ?? []).length" class="cip-section-k">{{ t("change_impact.ai_uncertain") }}</div>
              <ul class="cip-ai__list">
                <li v-for="(it, i) in a.output.uncertainties ?? []" :key="'u' + i">{{ aiText(it) }}</li>
              </ul>
              <template v-if="(a.output.suggested_tasks ?? []).length && a.status === 'completed'">
                <div class="cip-section-k">{{ t("change_impact.ai_tasks") }}</div>
                <n-checkbox-group v-model:value="picked[a.id]">
                  <div v-for="(it, i) in a.output.suggested_tasks ?? []" :key="'t' + i" class="cip-ai-task">
                    <n-checkbox :value="i" :disabled="!plan.can_edit" />
                    <span class="cip-muted">{{ t(`change_impact.phase.${it.phase}`) }}</span>
                    <span>{{ it.text }}</span>
                  </div>
                </n-checkbox-group>
                <n-button v-if="plan.can_edit" size="tiny" :disabled="!(picked[a.id] ?? []).length" style="margin-top: 6px"
                          @click="acceptDrafts(a.id)">{{ t("change_impact.ai_accept") }}</n-button>
              </template>
            </template>
          </div>
        </n-tab-pane>

        <!-- 歷史 -->
        <n-tab-pane name="history" :tab="t('change_impact.tab_history')">
          <div class="cip-section-k">{{ t("change_impact.runs_title") }}</div>
          <div v-for="r in runs" :key="r.id" class="cip-hist">
            <span>{{ fmtDateTime(r.created_at) }}</span>
            <span>{{ t("change_impact.revision", { n: r.plan_revision }) }}</span>
            <span>{{ t(`change_impact.job.${r.job_status}`) }}</span>
            <n-tag v-if="r.decision_status" size="tiny" :type="decisionType(r.decision_status)">{{ t(`change_impact.decision.${r.decision_status}`) }}</n-tag>
            <a v-if="r.id !== run.id && ['completed', 'partial'].includes(r.job_status)" @click="pickRun(r.id)">{{ t("change_impact.view") }}</a>
          </div>
          <div class="cip-section-k" style="margin-top: 12px">{{ t("change_impact.reviews_title") }}</div>
          <div v-for="rv in reviews" :key="rv.id" class="cip-hist">
            <span>{{ fmtDateTime(rv.created_at) }}</span>
            <span>{{ t(`change_impact.review_decision.${rv.decision}`) }}</span>
            <span>{{ t("change_impact.revision", { n: rv.revision }) }}</span>
            <span class="cip-muted">{{ rv.rationale }}</span>
          </div>
          <div v-if="!reviews.length" class="cip-muted">—</div>
          <div class="cip-section-k" style="margin-top: 12px">{{ t("change_impact.revisions_title") }}</div>
          <div v-for="rv in revisions" :key="rv.revision" class="cip-hist">
            <span>{{ t("change_impact.revision", { n: rv.revision }) }}</span>
            <span>{{ fmtDateTime(rv.created_at) }}</span>
            <span class="cip-mono cip-muted">{{ rv.payload?.parameters?.new_ip ?? "" }}</span>
          </div>
        </n-tab-pane>
      </n-tabs>
    </n-card>

    <!-- 覆核 -->
    <n-modal v-model:show="reviewOpen" preset="card" :title="t('change_impact.act.review')" style="width: min(720px, 96vw)">
      <n-radio-group v-model:value="review.decision" name="decision" style="margin-bottom: 10px">
        <n-radio-button v-for="d in ['approve', 'accept_risk', 'request_changes', 'reject']" :key="d" :value="d">
          {{ t(`change_impact.review_decision.${d}`) }}
        </n-radio-button>
      </n-radio-group>
      <div v-if="review.decision === 'approve' || review.decision === 'accept_risk'">
        <div class="cip-section-k">{{ t("change_impact.dispositions_title", { n: reviewFindings.length }) }}</div>
        <div v-for="f in reviewFindings" :key="f.id" class="cip-disp">
          <div class="cip-disp__label">{{ f.subject_label }}<div class="cip-muted">{{ reasonText(t, te, f.reason_code, f.params) }}</div></div>
          <n-select v-model:value="review.disp[f.id]" size="small" style="width: 170px" :options="dispActionOptions"
                    :placeholder="t('change_impact.pick_action')" />
        </div>
      </div>
      <n-input v-model:value="review.rationale" type="textarea" :rows="3" :placeholder="t('change_impact.rationale_ph')"
               style="margin-top: 10px" />
      <template #footer>
        <n-space justify="end">
          <n-button @click="reviewOpen = false">{{ t("common.cancel") }}</n-button>
          <n-button type="primary" :loading="busy === 'review'" data-testid="cip-review-submit" @click="submitReview">
            {{ t("common.confirm") }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 編輯（產生新版本） -->
    <n-modal v-model:show="editOpen" preset="card" :title="t('common.edit')" style="width: min(520px, 96vw)">
      <n-form label-placement="top">
        <n-form-item :label="t('change_impact.f_title')"><n-input v-model:value="edit.title" maxlength="200" /></n-form-item>
        <n-form-item v-if="plan?.scenario_type === 'ip_renumber'" :label="t('change_impact.f_new_ip')">
          <n-input v-model:value="edit.new_ip" />
        </n-form-item>
      </n-form>
      <div class="cip-muted">{{ t("change_impact.edit_note") }}</div>
      <template #footer>
        <n-space justify="end">
          <n-button @click="editOpen = false">{{ t("common.cancel") }}</n-button>
          <n-button type="primary" :loading="busy === 'edit'" @click="saveEdit">{{ t("common.save") }}</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- 新增手動待辦 -->
    <n-modal :show="!!newTask" preset="card" :title="t('change_impact.add_task')" style="width: min(480px, 96vw)"
             @update:show="(v: boolean) => { if (!v) newTask = null }">
      <n-form v-if="newTask" label-placement="top">
        <n-form-item :label="t('change_impact.col_phase')">
          <n-select v-model:value="newTask.phase" :options="phases.map((p) => ({ label: t(`change_impact.phase.${p}`), value: p }))" />
        </n-form-item>
        <n-form-item :label="t('change_impact.f_title')"><n-input v-model:value="newTask.title" maxlength="300" /></n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="newTask = null">{{ t("common.cancel") }}</n-button>
          <n-button type="primary" :disabled="!newTask?.title.trim()" @click="saveTask">{{ t("common.save") }}</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import {
  NAlert, NButton, NCard, NCheckbox, NCheckboxGroup, NDataTable, NDropdown, NForm, NFormItem, NIcon, NInput, NModal,
  NRadioButton, NRadioGroup, NSelect, NSpace, NSpin, NTabPane, NTabs, NTag, type DataTableColumns, useMessage,
} from "naive-ui";
import { ArrowLeft as ArrowLeftIcon } from "@iconoir/vue";
import { apiErrMsg } from "@/api/client";
import {
  acceptAiTasks, askAi, cancelRun, createReview, createTask, exportRun, getPlan, getRun, listAi, listEvidence,
  listFindings, listGaps, listReviews, listRevisions, listRuns, listTasks, patchPlan, patchTask, requestAi,
  startRun, transitionPlan,
  type AIItem, type ChangePlan, type ChangeTask, type ImpactAIArtifact, type ImpactEvidence, type ImpactFinding,
  type ImpactGap, type ImpactReview, type ImpactRun,
} from "@/api/changeImpact";
import { useChangeImpact } from "@/composables/useChangeImpact";
import { ChangeImpactIcon, DownloadIcon, EditIcon, PlusIcon, RefreshIcon } from "@/icons";
import { fmtDateTime } from "@/utils/datetime";
import {
  decisionType, dispositionType, gapText, lifecycleType, reasonText, severityType, taskTitle,
} from "@/utils/changeImpact";

const route = useRoute();
const router = useRouter();
const { t, te } = useI18n();
const msg = useMessage();
const { settings, load: loadSettings } = useChangeImpact();

const plan = ref<ChangePlan | null>(null);
const run = ref<ImpactRun | null>(null);
const runs = ref<ImpactRun[]>([]);
const findings = ref<ImpactFinding[]>([]);
const evidence = ref<ImpactEvidence[]>([]);
const gaps = ref<ImpactGap[]>([]);
const tasks = ref<ChangeTask[]>([]);
const reviews = ref<ImpactReview[]>([]);
const revisions = ref<{ revision: number; payload: any; created_at: string }[]>([]);
const artifacts = ref<ImpactAIArtifact[]>([]);
const picked = reactive<Record<string, number[]>>({});
const loading = ref(true);
const error = ref("");
const busy = ref("");
const tab = ref("findings");
const fDisp = ref<string | null>(null);
const fCat = ref<string | null>(null);
const question = ref("");
let pollTimer: ReturnType<typeof setTimeout> | null = null;
let pollDelay = 2000;

const planId = computed(() => String(route.params.id));
const ACTIVE = ["queued", "snapshotting", "extracting", "analyzing", "persisting"];
const isActive = computed(() => !!run.value && ACTIVE.includes(run.value.job_status));
const isDone = computed(() => !!run.value && ["completed", "partial"].includes(run.value.job_status));
const expired = computed(() => !!run.value?.expires_at && new Date(run.value.expires_at).getTime() < Date.now());
const editable = computed(() => !!plan.value && !["closed", "cancelled"].includes(plan.value.lifecycle));
const canRun = computed(() => !!plan.value?.can_edit && editable.value && !isActive.value
                              && ["draft", "in_review", "approved"].includes(plan.value.lifecycle));
const phases = ["precheck", "change", "verify", "rollback"] as const;

/** 依目前狀態可以做的動作（後端仍會再檢查一次） */
const actions = computed<string[]>(() => {
  const p = plan.value;
  if (!p) return [];
  const out: string[] = [];
  if (p.can_edit && p.lifecycle === "draft" && isDone.value && !expired.value) out.push("submit");
  if (p.lifecycle === "in_review") out.push("review");
  if (p.can_edit && p.lifecycle === "approved") out.push("start");
  if (p.can_edit && p.lifecycle === "in_progress") out.push("verify");
  if (p.can_edit && p.lifecycle === "verified") out.push("close");
  if (p.can_edit && editable.value) out.push("cancel");
  return out;
});

const dispOptions = computed(() => ["blocker", "review", "informational"]
  .map((v) => ({ label: t(`change_impact.disposition.${v}`), value: v })));
const catOptions = computed(() => [...new Set(findings.value.map((f) => f.category))]
  .map((v) => ({ label: catLabel(v), value: v })));
const shownFindings = computed(() => findings.value.filter((f) =>
  (!fDisp.value || f.disposition === fDisp.value) && (!fCat.value || f.category === fCat.value)));
const taskStateOptions = computed(() => ["pending", "in_progress", "done", "blocked", "skipped"]
  .map((v) => ({ label: t(`change_impact.task_state.${v}`), value: v })));
const exportOptions = computed(() => [{ label: "Markdown", key: "md" }, { label: "JSON", key: "json" }]);
const dispActionOptions = computed(() => ["will_update", "not_needed", "owner_confirm", "accepted"]
  .map((v) => ({ label: t(`change_impact.disp_action.${v}`), value: v })));

function catLabel(c: string): string {
  return te(`change_impact.category.${c}`) ? t(`change_impact.category.${c}`) : c;
}
function errText(code: string): string {
  return te(`errors.${code}`) ? t(`errors.${code}`) : code;
}
function shortRef(id: string): string {
  const i = findings.value.findIndex((f) => f.id === id);
  return i >= 0 ? String(i + 1) : id.slice(0, 6);
}
function tasksOf(ph: string): ChangeTask[] {
  return tasks.value.filter((x) => x.phase === ph).sort((a, b) => a.position - b.position);
}
function aiText(it: AIItem): string {
  if (it.text) return it.text;
  if (it.code) return t(`change_impact.ai_tpl.${it.code}`, it.params ?? {});
  return "";
}

const evById = computed(() => Object.fromEntries(evidence.value.map((e) => [e.id, e])));
const findingCols = computed<DataTableColumns<ImpactFinding>>(() => [
  { type: "expand", renderExpand: (r) => h("div", { class: "cip-expand" }, [
      ...r.evidence_ids.map((id) => {
        const e = evById.value[id];
        return e ? h("div", { class: "cip-ev" }, [
          h("span", { class: "cip-mono" }, e.label),
          h("span", { class: "cip-muted" }, ` · ${e.source_type} · ${t("change_impact.observed")} ${e.observed_at ? fmtDateTime(e.observed_at) : "—"}`
            + ` · ${t("change_impact.collected")} ${e.collected_at ? fmtDateTime(e.collected_at) : "—"}`),
        ]) : null;
      }),
      r.relationship_path.length ? h("div", { class: "cip-muted" },
        `${t("change_impact.path")}：${r.relationship_path.map((p) => p.label).join(" → ")}`) : null,
      h("div", { class: "cip-muted" }, `${r.rule_id} v${r.rule_version}`),
    ]) },
  { title: t("change_impact.col_disposition"), key: "disposition", width: 96,
    render: (r) => h(NTag, { size: "small", type: dispositionType(r.disposition) },
                     { default: () => t(`change_impact.disposition.${r.disposition}`) }) },
  { title: t("change_impact.col_severity"), key: "severity", width: 80,
    render: (r) => h(NTag, { size: "small", bordered: false, type: severityType(r.severity) },
                     { default: () => t(`change_impact.severity.${r.severity}`) }) },
  { title: t("change_impact.col_category"), key: "category", width: 96, render: (r) => catLabel(r.category) },
  { title: t("change_impact.col_subject"), key: "subject_label", minWidth: 280,
    render: (r) => h("div", { id: `cip-f-${r.id}` }, [
      h("div", { class: "cip-strong cip-wrap" }, r.subject_label),
      h("div", { class: "cip-muted cip-wrap" }, reasonText(t, te, r.reason_code, r.params)),
    ]) },
  { title: t("change_impact.col_impact"), key: "impact", width: 110, render: (r) => t(`change_impact.impact.${r.impact}`) },
  { title: t("change_impact.col_strength"), key: "evidence_strength", width: 100,
    render: (r) => t(`change_impact.strength.${r.evidence_strength}`) },
]);
const evidenceCols = computed<DataTableColumns<ImpactEvidence>>(() => [
  { title: t("change_impact.col_source"), key: "source_type", width: 100, render: (r) => catLabel(r.source_type) },
  { title: t("change_impact.col_object"), key: "label", minWidth: 260,
    render: (r) => h("span", { class: "cip-mono cip-wrap" }, r.label) },
  { title: t("change_impact.observed"), key: "observed_at", width: 160,
    render: (r) => (r.observed_at ? fmtDateTime(r.observed_at) : "—") },
  { title: t("change_impact.collected"), key: "collected_at", width: 160,
    render: (r) => (r.collected_at ? fmtDateTime(r.collected_at) : "—") },
  { title: t("change_impact.col_freshness"), key: "freshness", width: 110,
    render: (r) => (te(`change_impact.fresh.${r.freshness}`) ? t(`change_impact.fresh.${r.freshness}`) : r.freshness) },
]);

async function loadRunData(runId: string) {
  const [r, fs, ev, gp, ai] = await Promise.all([getRun(runId), listFindings(runId), listEvidence(runId),
                                                 listGaps(runId), listAi(runId)]);
  run.value = r;
  findings.value = fs.items;
  evidence.value = ev;
  gaps.value = gp;
  artifacts.value = ai;
}

async function loadAll() {
  error.value = "";
  try {
    const p = await getPlan(planId.value);
    plan.value = p;
    const [rs, tk, rv, revs] = await Promise.all([listRuns(p.id), listTasks(p.id), listReviews(p.id), listRevisions(p.id)]);
    runs.value = rs; tasks.value = tk; reviews.value = rv; revisions.value = revs;
    const latest = rs[0];
    if (latest) {
      // 完成的 run 等資料都載完才換上去：不然摘要先出現、分頁的數字還是 0
      if (["completed", "partial"].includes(latest.job_status)) await loadRunData(latest.id);
      else run.value = latest;
      schedulePoll();
    } else {
      run.value = null;
    }
  } catch (e) {
    error.value = apiErrMsg(e);
  } finally {
    loading.value = false;
  }
}

function schedulePoll() {
  if (pollTimer) clearTimeout(pollTimer);
  const pendingAi = artifacts.value.some((a) => a.status === "pending" || a.status === "running");
  if (!isActive.value && !pendingAi) { pollDelay = 2000; return; }
  pollTimer = setTimeout(async () => {
    if (!run.value) return;
    try {
      const r = await getRun(run.value.id);
      const was = run.value.job_status;
      run.value = r;
      if (ACTIVE.includes(was) && !ACTIVE.includes(r.job_status)) await loadAll();
      else if (pendingAi) artifacts.value = await listAi(r.id);
    } catch { /* 下一輪再試 */ }
    pollDelay = Math.min(10000, pollDelay * 1.5);     // 2 秒起、最多 10 秒（規格 §8.4）
    schedulePoll();
  }, pollDelay);
}

async function rerun() {
  if (!plan.value) return;
  busy.value = "run";
  try {
    run.value = await startRun(plan.value.id);
    pollDelay = 2000;
    await loadAll();
  } catch (e) { msg.error(apiErrMsg(e)); } finally { busy.value = ""; }
}
async function cancel() {
  if (!run.value) return;
  try { run.value = await cancelRun(run.value.id); } catch (e) { msg.error(apiErrMsg(e)); }
}
async function pickRun(id: string) {
  await loadRunData(id);
  tab.value = "findings";
}

const reviewOpen = ref(false);
const review = reactive<{ decision: string; rationale: string; disp: Record<string, string> }>(
  { decision: "approve", rationale: "", disp: {} });
const reviewFindings = computed(() => findings.value.filter((f) => f.disposition === "review"));

async function act(a: string) {
  if (!plan.value) return;
  if (a === "review") { review.decision = run.value?.completeness === "complete" ? "approve" : "accept_risk"; reviewOpen.value = true; return; }
  busy.value = a;
  try {
    plan.value = { ...plan.value, ...(await transitionPlan(plan.value.id, a)) };
    await loadAll();
  } catch (e) { msg.error(apiErrMsg(e)); await loadAll(); } finally { busy.value = ""; }
}
async function submitReview() {
  if (!plan.value || !run.value) return;
  busy.value = "review";
  try {
    const dispositions = Object.fromEntries(Object.entries(review.disp).filter(([, v]) => v)
      .map(([k, v]) => [k, { action: v, note: "" }]));
    await createReview(plan.value.id, { decision: review.decision, rationale: review.rationale, dispositions,
                                        run_id: run.value.id });
    reviewOpen.value = false;
    await loadAll();
  } catch (e) { msg.error(apiErrMsg(e)); } finally { busy.value = ""; }
}

const editOpen = ref(false);
const edit = reactive({ title: "", new_ip: "" });
function openEdit() {
  if (!plan.value) return;
  edit.title = plan.value.title;
  edit.new_ip = plan.value.parameters.new_ip ?? "";
  editOpen.value = true;
}
async function saveEdit() {
  if (!plan.value) return;
  busy.value = "edit";
  try {
    const body: Record<string, any> = { title: edit.title };
    if (plan.value.scenario_type === "ip_renumber") body.parameters = { new_ip: edit.new_ip.trim() };
    await patchPlan(plan.value.id, plan.value.revision, body);
    editOpen.value = false;
    await loadAll();
  } catch (e) { msg.error(apiErrMsg(e)); } finally { busy.value = ""; }
}

async function setTaskState(tk: ChangeTask, state: string) {
  let note: string | undefined;
  if (state === "skipped") {
    note = window.prompt(t("change_impact.skip_reason")) ?? "";
    if (!note.trim()) return;
  }
  try {
    const upd = await patchTask(tk.id, tk.version, { state, ...(note ? { completion_note: note } : {}) });
    Object.assign(tk, upd);
  } catch (e) { msg.error(apiErrMsg(e)); tasks.value = await listTasks(planId.value); }
}
const newTask = ref<{ phase: string; title: string } | null>(null);
async function saveTask() {
  if (!plan.value || !newTask.value) return;
  try {
    await createTask(plan.value.id, { phase: newTask.value.phase, title: newTask.value.title.trim() });
    newTask.value = null;
    tasks.value = await listTasks(plan.value.id);
  } catch (e) { msg.error(apiErrMsg(e)); }
}

async function genAi(kind: string) {
  if (!run.value) return;
  busy.value = `ai-${kind}`;
  try { await requestAi(run.value.id, kind); artifacts.value = await listAi(run.value.id); schedulePoll(); }
  catch (e) { msg.error(apiErrMsg(e)); } finally { busy.value = ""; }
}
async function ask() {
  if (!run.value || !question.value.trim()) return;
  busy.value = "ask";
  try { await askAi(run.value.id, question.value.trim()); question.value = ""; artifacts.value = await listAi(run.value.id); schedulePoll(); }
  catch (e) { msg.error(apiErrMsg(e)); } finally { busy.value = ""; }
}
async function acceptDrafts(id: string) {
  if (!plan.value) return;
  try {
    await acceptAiTasks(plan.value.id, id, picked[id] ?? []);
    picked[id] = [];
    tasks.value = await listTasks(plan.value.id);
    tab.value = "tasks";
  } catch (e) { msg.error(apiErrMsg(e)); }
}
function focusFinding(id: string) {
  tab.value = "findings";
  fDisp.value = null; fCat.value = null;
  setTimeout(() => document.getElementById(`cip-f-${id}`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 50);
}

async function doExport(fmt: "md" | "json") {
  if (!run.value || !plan.value) return;
  try {
    const blob = await exportRun(run.value.id, fmt);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `change-impact-${plan.value.title.replace(/[^\w.-]+/g, "_").slice(0, 40)}.${fmt}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } catch (e) { msg.error(apiErrMsg(e)); }
}

watch(planId, () => { loading.value = true; void loadAll(); });
onMounted(async () => { await loadSettings(); await loadAll(); });
onBeforeUnmount(() => { if (pollTimer) clearTimeout(pollTimer); });
</script>

<style scoped>
.cip-page { display: flex; flex-direction: column; gap: 12px; }
.cip-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.cip-head__title { display: flex; align-items: center; gap: 8px; font-size: 17px; font-weight: 600; flex-wrap: wrap; }
.cip-meta { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 8px; font-size: 13px; opacity: .85; }
.cip-dryrun { margin-top: 8px; font-size: 12.5px; opacity: .7; }
.cip-running { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.cip-err { color: #d03050; font-size: 13px; }
.cip-summary { display: flex; gap: 24px; flex-wrap: wrap; align-items: flex-start; }
.cip-stat { display: flex; flex-direction: column; gap: 4px; min-width: 80px; }
.cip-stat__k { font-size: 12px; opacity: .6; }
.cip-stat__v { font-size: 20px; font-weight: 600; font-variant-numeric: tabular-nums; }
.cip-warn { color: #d08a00; }
.cip-scope-note { margin-top: 10px; font-size: 12px; opacity: .6; }
.cip-filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.cip-empty { padding: 16px 4px; font-size: 13.5px; opacity: .8; line-height: 1.6; }
.cip-section-k { font-size: 12.5px; font-weight: 600; opacity: .7; margin: 6px 0; }
.cip-gaps { margin: 0; padding-left: 0; list-style: none; display: flex; flex-direction: column; gap: 6px; font-size: 13px; }
.cip-gaps li { display: flex; gap: 8px; align-items: baseline; }
.cip-sources { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; }
.cip-manual-note { font-size: 12.5px; opacity: .7; margin-bottom: 8px; }
.cip-phase { margin-bottom: 10px; }
.cip-task { display: flex; align-items: center; gap: 10px; padding: 4px 0; }
.cip-task__body { flex: 1; min-width: 0; font-size: 13.5px; }
.cip-done { text-decoration: line-through; opacity: .6; }
.cip-ask { display: flex; gap: 8px; margin-bottom: 8px; }
.cip-ai-note { font-size: 12px; opacity: .6; margin-bottom: 10px; }
.cip-ai { border-top: 1px solid rgba(128, 128, 128, .2); padding: 10px 0; }
.cip-ai__head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-size: 13px; }
.cip-ai__list { margin: 6px 0; padding-left: 18px; font-size: 13.5px; line-height: 1.7; }
.cip-ai-task { display: flex; gap: 8px; align-items: baseline; font-size: 13px; }
.cip-cite { margin-left: 4px; font-size: 12px; cursor: pointer; color: #2080f0; }
.cip-hist { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; font-size: 13px; padding: 3px 0; }
.cip-hist a { cursor: pointer; color: #2080f0; }
.cip-disp { display: flex; gap: 10px; align-items: center; justify-content: space-between; padding: 4px 0; }
.cip-disp__label { font-size: 13px; min-width: 0; flex: 1; }
@media (max-width: 720px) { .cip-summary { gap: 14px; } }
</style>

<style>
.cip-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
.cip-wrap { white-space: normal; word-break: break-word; }
.cip-expand { display: flex; flex-direction: column; gap: 4px; padding: 4px 0 4px 8px; font-size: 13px; }
.cip-ev { display: flex; flex-wrap: wrap; gap: 4px; }
</style>
