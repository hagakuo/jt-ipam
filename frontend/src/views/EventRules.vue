<script setup lang="ts">
/**
 * 事件規則：事件 → 條件 → 動作。
 *
 * 條件是結構化的（欄位／運算子／值），不是可以打字的運算式 —— 規則由使用者輸入，
 * 能執行的東西就是一條注入路徑。也因此沒有正規表示式（ReDoS）。
 *
 * 「試跑」只回報命中與否與逐條條件結果，**不會真的送出通知或 webhook**：
 * 測試按鈕不該有副作用。
 */
import { computed, h, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NDataTable, NSpace, NButton, NTag, NIcon, NTooltip, NAlert, NModal, NForm,
  NFormItem, NInput, NSelect, NSwitch, NPopconfirm, NDivider,
  useMessage, type DataTableColumns,
} from "naive-ui";
import {
  listEventRules, createEventRule, updateEventRule, deleteEventRule, testEventRule,
  RULE_OPS, KNOWN_EVENTS,
  type EventRule, type RuleCondition, type RuleAction, type RuleTestResult,
} from "@/api/eventRules";
import {
  WebhooksIcon, PlusIcon, EditIcon, DeleteIcon, RefreshIcon, TestIcon, SaveIcon, CancelIcon,
} from "@/icons";
import { autoSort } from "@/composables/useTableSort";
import { apiErrMsg } from "@/api/client";

const { t } = useI18n();
const msg = useMessage();

const rows = ref<EventRule[]>([]);
const loading = ref(false);
const show = ref(false);
const editing = ref<EventRule | null>(null);

const testOpen = ref(false);
const testResult = ref<RuleTestResult | null>(null);
const testEvent = ref("subnet.created");
const testPayload = ref('{\n  "subnet": { "cidr": "10.20.0.0/24" }\n}');
const testingRule = ref<EventRule | null>(null);

function blank() {
  return {
    name: "", description: "", enabled: true,
    events: ["subnet.created"] as string[],
    conditions: [] as RuleCondition[],
    actions: [{ type: "notify_admins", severity: "info" }] as RuleAction[],
  };
}
const form = ref(blank());

const eventOptions = computed(() => KNOWN_EVENTS.map((e) => ({ label: e, value: e })));
const opOptions = computed(() => RULE_OPS.map((o) => ({ label: o, value: o })));
const actionOptions = computed(() => [
  { label: t("event_rules.act_notify"), value: "notify_admins" },
  { label: t("event_rules.act_webhook"), value: "webhook" },
]);

async function refresh() {
  loading.value = true;
  try { rows.value = (await listEventRules()).items; }
  catch (e) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}

function openCreate() {
  editing.value = null;
  form.value = blank();
  show.value = true;
}

function openEdit(r: EventRule) {
  editing.value = r;
  form.value = {
    name: r.name, description: r.description ?? "", enabled: r.enabled,
    events: [...(r.events ?? [])],
    conditions: JSON.parse(JSON.stringify(r.conditions ?? [])),
    actions: JSON.parse(JSON.stringify(r.actions ?? [])),
  };
  show.value = true;
}

function addCondition() {
  form.value.conditions.push({ field: "", op: "eq", value: "" });
}
function addAction() {
  form.value.actions.push({ type: "notify_admins", severity: "info" });
}

async function submit() {
  const payload = {
    name: form.value.name,
    description: form.value.description || null,
    enabled: form.value.enabled,
    events: form.value.events,
    conditions: form.value.conditions.filter((c) => c.field.trim()),
    actions: form.value.actions,
  };
  try {
    if (editing.value) await updateEventRule(editing.value.id, payload);
    else await createEventRule(payload);
    show.value = false;
    msg.success(t("common.ok"));
    await refresh();
  } catch (e) { msg.error(apiErrMsg(e)); }
}

async function del(id: string) {
  try { await deleteEventRule(id); await refresh(); }
  catch (e) { msg.error(apiErrMsg(e)); }
}

function openTest(r: EventRule) {
  testingRule.value = r;
  testResult.value = null;
  testEvent.value = r.events?.[0] && r.events[0] !== "*" ? r.events[0] : "subnet.created";
  testOpen.value = true;
}

async function runTest() {
  if (!testingRule.value) return;
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(testPayload.value); }
  catch { msg.error(t("event_rules.bad_json")); return; }
  try {
    testResult.value = await testEventRule(testingRule.value.id, testEvent.value, parsed);
  } catch (e) { msg.error(apiErrMsg(e)); }
}

function iconAction(icon: unknown, label: string, onClick: () => void, type?: string) {
  return h(NTooltip, null, {
    trigger: () => h(NButton, { size: "small", quaternary: true, type: type as never,
      onClick: (e: MouseEvent) => { e.stopPropagation(); onClick(); } },
      { icon: () => h(NIcon, null, () => h(icon as never)) }),
    default: () => label,
  });
}

const cols = computed<DataTableColumns<EventRule>>(() => autoSort([
  { title: t("common.name"), key: "name", minWidth: 150, ellipsis: { tooltip: true } },
  {
    title: t("common.status"), key: "enabled", width: 100,
    render: (r) => h(NTag, { type: r.enabled ? "success" : "default", size: "small" },
      () => r.enabled ? t("common.enabled") : t("common.disabled")),
  },
  {
    title: t("event_rules.events"), key: "events", minWidth: 160, ellipsis: { tooltip: true },
    render: (r) => (r.events ?? []).join(", ") || "—",
  },
  {
    title: t("event_rules.conditions"), key: "conditions", minWidth: 220,
    ellipsis: { tooltip: true },
    render: (r) => (r.conditions ?? []).map((c) => `${c.field} ${c.op} ${c.value ?? ""}`.trim())
      .join(t("event_rules.and_join")) || t("event_rules.no_conditions"),
  },
  {
    title: t("event_rules.actions_col"), key: "actions", minWidth: 140,
    render: (r) => h(NSpace, { size: 3, wrap: true }, () =>
      (r.actions ?? []).map((a) => h(NTag, { size: "tiny", type: "info", bordered: false },
        () => a.type === "webhook" ? t("event_rules.act_webhook") : t("event_rules.act_notify")))),
  },
  { title: t("event_rules.matches"), key: "match_count", width: 100 },
  {
    title: t("cols.last_error"), key: "last_error", minWidth: 140,
    ellipsis: { tooltip: true }, render: (r) => r.last_error ?? "—",
  },
  {
    title: t("common.actions"), key: "row_actions", className: "col-actions", width: 150,
    render: (r) => h(NSpace, { size: 2, wrapItem: false, wrap: false }, () => [
      iconAction(EditIcon, t("common.edit"), () => openEdit(r)),
      iconAction(TestIcon, t("event_rules.test"), () => openTest(r)),
      h(NPopconfirm, { onPositiveClick: () => del(r.id) }, {
        trigger: () => iconAction(DeleteIcon, t("common.delete"), () => {}, "error"),
        default: () => t("common.confirm_delete"),
      }),
    ]),
  },
]));

onMounted(() => { void refresh(); });
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><WebhooksIcon /></n-icon>
        <span>{{ t("event_rules.title") }}</span>
      </n-space>
    </template>

    <n-alert type="info" :bordered="false" style="margin-bottom: 12px">
      {{ t("event_rules.intro") }}
    </n-alert>

    <n-space style="margin-bottom: 12px">
      <n-button @click="refresh" :loading="loading">
        <template #icon><n-icon><RefreshIcon /></n-icon></template>
        {{ t("common.refresh") }}
      </n-button>
      <n-button type="primary" @click="openCreate">
        <template #icon><n-icon><PlusIcon /></n-icon></template>
        {{ t("common.create") }}
      </n-button>
    </n-space>

    <n-data-table :columns="cols" :data="rows" :loading="loading" :bordered="false"
                  :scroll-x="1200" :row-key="(r: EventRule) => r.id" />

    <!-- 新增 / 編輯 -->
    <n-modal v-model:show="show" preset="card"
             :title="editing ? t('common.edit') : `${t('common.create')} — ${t('event_rules.title')}`"
             style="width: 720px">
      <n-form>
        <n-form-item :label="t('common.name')"><n-input v-model:value="form.name" /></n-form-item>
        <n-form-item :label="t('event_rules.events')">
          <n-select v-model:value="form.events" :options="eventOptions" multiple filterable tag
                    :placeholder="t('event_rules.events_ph')" />
        </n-form-item>

        <n-divider style="margin: 4px 0 12px">{{ t("event_rules.conditions") }}</n-divider>
        <div v-for="(c, i) in form.conditions" :key="i" class="rule-row">
          <n-input v-model:value="c.field" :placeholder="t('event_rules.field_ph')" style="flex: 2" />
          <n-select v-model:value="c.op" :options="opOptions" style="width: 150px" />
          <n-input v-model:value="(c.value as string)" :placeholder="t('event_rules.value_ph')"
                   style="flex: 2" />
          <n-button quaternary type="error" @click="form.conditions.splice(i, 1)">
            <template #icon><n-icon><DeleteIcon /></n-icon></template>
          </n-button>
        </div>
        <n-button size="small" dashed @click="addCondition">
          <template #icon><n-icon><PlusIcon /></n-icon></template>
          {{ t("event_rules.add_condition") }}
        </n-button>
        <div class="hint">{{ t("event_rules.conditions_hint") }}</div>

        <n-divider style="margin: 16px 0 12px">{{ t("event_rules.actions_col") }}</n-divider>
        <div v-for="(a, i) in form.actions" :key="`a${i}`" class="rule-row">
          <n-select v-model:value="a.type" :options="actionOptions" style="width: 180px" />
          <n-input v-if="a.type === 'notify_admins'" v-model:value="a.title"
                   :placeholder="t('event_rules.notify_title_ph')" style="flex: 2" />
          <n-input v-else v-model:value="a.subscription_id"
                   :placeholder="t('event_rules.webhook_id_ph')" style="flex: 2" />
          <n-button quaternary type="error" @click="form.actions.splice(i, 1)">
            <template #icon><n-icon><DeleteIcon /></n-icon></template>
          </n-button>
        </div>
        <n-button size="small" dashed @click="addAction">
          <template #icon><n-icon><PlusIcon /></n-icon></template>
          {{ t("event_rules.add_action") }}
        </n-button>

        <n-form-item :label="t('common.enable')" style="margin-top: 16px">
          <n-switch v-model:value="form.enabled" />
        </n-form-item>
        <n-form-item :label="t('common.description')">
          <n-input v-model:value="form.description" type="textarea" :rows="2" />
        </n-form-item>
      </n-form>
      <n-space justify="end">
        <n-button @click="show = false">
          <template #icon><n-icon><CancelIcon /></n-icon></template>
          {{ t("common.cancel") }}
        </n-button>
        <n-button type="primary" @click="submit">
          <template #icon><n-icon><SaveIcon /></n-icon></template>
          {{ t("common.save") }}
        </n-button>
      </n-space>
    </n-modal>

    <!-- 試跑 -->
    <n-modal v-model:show="testOpen" preset="card"
             :title="`${t('event_rules.test')} — ${testingRule?.name ?? ''}`" style="width: 640px">
      <n-alert type="info" :bordered="false" style="margin-bottom: 10px">
        {{ t("event_rules.test_hint") }}
      </n-alert>
      <n-form>
        <n-form-item :label="t('event_rules.test_event')">
          <n-input v-model:value="testEvent" />
        </n-form-item>
        <n-form-item :label="t('event_rules.test_payload')">
          <n-input v-model:value="testPayload" type="textarea" :rows="6" />
        </n-form-item>
      </n-form>
      <n-space justify="end" style="margin-bottom: 12px">
        <n-button type="primary" @click="runTest">
          <template #icon><n-icon><TestIcon /></n-icon></template>
          {{ t("event_rules.run_test") }}
        </n-button>
      </n-space>
      <template v-if="testResult">
        <n-alert :type="testResult.matched ? 'success' : 'warning'" :bordered="false">
          {{ testResult.matched ? t("event_rules.would_match") : t("event_rules.would_not_match") }}
        </n-alert>
        <div class="test-row">
          <n-tag :type="testResult.event_matched ? 'success' : 'error'" size="small" :bordered="false">
            {{ t("event_rules.event_name") }}
          </n-tag>
        </div>
        <div v-for="(c, i) in testResult.conditions" :key="i" class="test-row">
          <n-tag :type="c.passed ? 'success' : 'error'" size="small" :bordered="false">
            {{ c.passed ? "OK" : "NG" }}
          </n-tag>
          <code>{{ c.field }} {{ c.op }} {{ c.value }}</code>
          <span class="dim">{{ t("event_rules.actual") }}: {{ JSON.stringify(c.actual) }}</span>
        </div>
      </template>
    </n-modal>
  </n-card>
</template>

<style scoped>
.rule-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
.hint { font-size: 11px; opacity: 0.65; margin-top: 6px; }
.test-row { display: flex; align-items: center; gap: 8px; font-size: 13px; margin-top: 8px; }
.test-row .dim { opacity: 0.6; }
</style>
