<template>
  <n-modal :show="show" preset="card" :title="t('change_impact.new_plan')" style="width: min(560px, 96vw)"
           :mask-closable="!busy" data-testid="cip-wizard" @update:show="(v: boolean) => !v && close()">
    <n-form label-placement="top" :disabled="busy">
      <n-form-item v-if="!presetScenario" :label="t('change_impact.f_scenario')">
        <n-radio-group v-model:value="scenario" name="scenario">
          <n-radio-button value="ip_renumber">{{ t("change_impact.scenario.ip_renumber") }}</n-radio-button>
          <n-radio-button value="device_decommission">{{ t("change_impact.scenario.device_decommission") }}</n-radio-button>
        </n-radio-group>
      </n-form-item>
      <!-- 目標：IP 改址選一筆 IP 記錄（同一個位址好幾筆時要選，不猜）；除役選一台裝置 -->
      <n-form-item :label="scenario === 'ip_renumber' ? t('change_impact.f_old_ip') : t('change_impact.f_device')">
        <span v-if="presetTargetId" class="cip-wiz-target" data-testid="cip-wiz-target">{{ presetLabel }}</span>
        <template v-else-if="scenario === 'ip_renumber'">
          <n-input v-model:value="oldIp" :placeholder="t('change_impact.f_old_ip_ph')" data-testid="cip-wiz-old-ip"
                   @blur="lookupOld" />
          <n-select v-if="oldCandidates.length > 1" v-model:value="targetId" style="margin-top: 6px"
                    :options="oldCandidates.map((c) => ({ label: `${c.ip} (${c.subnet})${c.hostname ? ' · ' + c.hostname : ''}`, value: c.id }))"
                    :placeholder="t('change_impact.f_pick_record')" />
        </template>
        <n-select v-else v-model:value="targetId" filterable remote clearable :loading="devLoading"
                  :options="devOptions" :placeholder="t('change_impact.f_device_ph')" @search="searchDevices" />
      </n-form-item>
      <n-form-item v-if="scenario === 'ip_renumber'" :label="t('change_impact.f_new_ip')">
        <n-input v-model:value="newIp" placeholder="198.51.100.80" data-testid="cip-wiz-new-ip" />
      </n-form-item>
      <n-form-item v-if="subnetChoices.length" :label="t('change_impact.f_target_subnet')">
        <n-select v-model:value="targetSubnetId" :options="subnetChoices" data-testid="cip-wiz-subnet" />
      </n-form-item>
      <n-form-item :label="t('change_impact.f_title')">
        <n-input v-model:value="title" :placeholder="defaultTitle" maxlength="200" />
      </n-form-item>
      <n-form-item :label="t('change_impact.f_window')">
        <n-date-picker v-model:value="windowRange" type="datetimerange" clearable style="width: 100%" />
      </n-form-item>
    </n-form>
    <n-alert v-if="error" type="error" :bordered="false" style="margin-bottom: 10px">{{ error }}</n-alert>
    <div class="cip-wiz-note">{{ t("change_impact.wizard_note") }}</div>
    <template #footer>
      <n-space justify="end">
        <n-button :disabled="busy" @click="close">{{ t("common.cancel") }}</n-button>
        <n-button type="primary" :loading="busy" :disabled="!canSubmit" data-testid="cip-wiz-submit" @click="submit">
          {{ t("change_impact.create_and_run") }}
        </n-button>
      </n-space>
    </template>
  </n-modal>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import {
  NAlert, NButton, NDatePicker, NForm, NFormItem, NInput, NModal, NRadioButton, NRadioGroup, NSelect, NSpace,
} from "naive-ui";
import { apiErrMsg } from "@/api/client";
import { candidates, createPlan, startRun, type ScenarioType } from "@/api/changeImpact";
import { listDevices } from "@/api/basic";

const props = defineProps<{
  show: boolean;
  presetScenario?: ScenarioType;
  presetTargetId?: string;
  presetLabel?: string;
}>();
const emit = defineEmits<{ (e: "update:show", v: boolean): void }>();
const { t } = useI18n();
const router = useRouter();

const scenario = ref<ScenarioType>(props.presetScenario ?? "ip_renumber");
const targetId = ref<string | null>(props.presetTargetId ?? null);
const oldIp = ref("");
const oldCandidates = ref<{ id: string; ip: string; subnet: string; hostname: string | null }[]>([]);
const newIp = ref("");
const title = ref("");
const windowRange = ref<[number, number] | null>(null);
const targetSubnetId = ref<string | null>(null);
const subnetChoices = ref<{ label: string; value: string }[]>([]);
const busy = ref(false);
const error = ref("");
const devOptions = ref<{ label: string; value: string }[]>([]);
const devLoading = ref(false);

watch(() => props.show, (v) => {
  if (!v) return;
  scenario.value = props.presetScenario ?? "ip_renumber";
  targetId.value = props.presetTargetId ?? null;
  oldIp.value = ""; oldCandidates.value = []; newIp.value = ""; title.value = ""; windowRange.value = null;
  targetSubnetId.value = null; subnetChoices.value = []; error.value = "";
});

const defaultTitle = computed(() => {
  const who = props.presetLabel || oldIp.value || devOptions.value.find((o) => o.value === targetId.value)?.label || "";
  return scenario.value === "ip_renumber"
    ? t("change_impact.default_title_renumber", { from: who, to: newIp.value || "…" })
    : t("change_impact.default_title_decom", { device: who });
});
const canSubmit = computed(() => !!targetId.value && (scenario.value !== "ip_renumber" || !!newIp.value.trim()));

async function lookupOld() {
  const ip = oldIp.value.trim();
  oldCandidates.value = [];
  if (!ip) { targetId.value = null; return; }
  try {
    oldCandidates.value = await candidates(ip);
    targetId.value = oldCandidates.value.length === 1 ? oldCandidates.value[0].id : null;
    error.value = oldCandidates.value.length ? "" : t("change_impact.no_such_record");
  } catch (e) { error.value = apiErrMsg(e); }
}
async function searchDevices(q: string) {
  devLoading.value = true;
  try {
    const r = await listDevices({ q, pageSize: 20 });
    devOptions.value = r.items.map((d) => ({ label: d.name, value: d.id }));
  } finally { devLoading.value = false; }
}

function close() { emit("update:show", false); }

async function submit() {
  if (!targetId.value) return;
  busy.value = true;
  error.value = "";
  try {
    const params: Record<string, string> = {};
    if (scenario.value === "ip_renumber") params.new_ip = newIp.value.trim();
    if (targetSubnetId.value) params.target_subnet_id = targetSubnetId.value;
    const plan = await createPlan({
      title: title.value.trim() || defaultTitle.value, scenario_type: scenario.value,
      target_type: scenario.value === "ip_renumber" ? "ip_address" : "device", target_id: targetId.value,
      parameters: params,
      planned_start: windowRange.value ? new Date(windowRange.value[0]).toISOString() : null,
      planned_end: windowRange.value ? new Date(windowRange.value[1]).toISOString() : null,
    }, crypto.randomUUID?.());
    await startRun(plan.id);
    close();
    void router.push({ name: "change_impact_plan", params: { id: plan.id } });
  } catch (e: any) {
    // 新位址落在好幾個重疊的子網路：讓使用者選，不猜（後端附上候選）
    const d = e?.response?.data?.detail;
    if (d?.code === "impact_ambiguous_target" && Array.isArray(d.candidates)) {
      const cidrs = String(d.params?.subnets || "").split(",").map((s: string) => s.trim());
      subnetChoices.value = d.candidates.map((id: string, i: number) => ({ label: cidrs[i] || id, value: id }));
    }
    error.value = apiErrMsg(e);
  } finally {
    busy.value = false;
  }
}
</script>

<style scoped>
.cip-wiz-target { font-weight: 600; font-variant-numeric: tabular-nums; }
.cip-wiz-note { font-size: 12.5px; opacity: .7; line-height: 1.6; }
</style>
