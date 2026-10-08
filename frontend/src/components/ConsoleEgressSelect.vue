<script setup lang="ts">
/**
 * 主控台的連線出口（issue #24）：直連／跳板主機／掃描代理中繼。子網路與 IP 的編輯視窗共用這一個。
 *
 * 掃描代理只能選**這個子網路的掃描代理**：代理的自我允許清單只認它被指派掃描的子網路，選別台一定會被拒絕。
 * 還不能用的（沒被允許中繼、代理主機以 JT_IPAM_RELAY=0 否決、代理太舊）照樣列出但反灰並講原因，
 * 免得使用者以為這個選項不存在。值以 jump:<id>／agent:<id> 編碼在同一個下拉裡，兩個欄位一定只會有一個有值。
 */
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { NFormItem, NSelect, NSpace } from "naive-ui";
import { listJumpHosts } from "@/api/jumpHosts";
import { listScanAgents, type ScanAgent } from "@/api/phase3";
import { getSubnet } from "@/api/subnets";

const props = defineProps<{
  jumpHostId: string | null;
  consoleAgentId: string | null;
  /** 子網路的掃描代理（子網路視窗直接給） */
  scanAgentId?: string | null;
  /** 或給子網路 id，由這裡查它的掃描代理（IP 視窗） */
  subnetId?: string | null;
  /** IP 上留空＝沿用子網路的設定 */
  inherit?: boolean;
}>();
const emit = defineEmits<{
  (e: "update:jumpHostId", v: string | null): void;
  (e: "update:consoleAgentId", v: string | null): void;
}>();
const { t } = useI18n();

const jumps = ref<{ id: string; name: string; enabled: boolean; label: string }[]>([]);
const agents = ref<ScanAgent[]>([]);
const subnetAgent = ref<string | null>(null);

onMounted(async () => {
  try {
    jumps.value = (await listJumpHosts()).items.map((j: any) => ({
      id: j.id, name: j.name, enabled: !!j.enabled, label: `${j.name}（${j.username}@${j.host}:${j.port}）`,
    }));
  } catch { jumps.value = []; }
  try { agents.value = (await listScanAgents()).items; } catch { agents.value = []; }
});
watch(() => props.subnetId, async (id) => {
  if (!id) { subnetAgent.value = null; return; }
  try { subnetAgent.value = (await getSubnet(id)).scan_agent_id ?? null; } catch { subnetAgent.value = null; }
}, { immediate: true });

const agentId = computed(() => (props.scanAgentId !== undefined ? props.scanAgentId : subnetAgent.value));
/** 這台代理現在為什麼還不能中繼（可以就回空字串） */
function whyNot(a: ScanAgent): string {
  if (!a.enabled) return t("relay.why_agent_disabled");
  if (!a.relay_allowed) return t("relay.why_not_allowed");
  if (!a.relay_caps) return t("relay.why_agent_old");
  if (!a.relay_caps.enabled) return t("relay.why_agent_off");
  return "";
}

const options = computed(() => {
  const out: any[] = [];
  // 停用的跳板不列（會被拒絕連線）；但目前指派的那一台要留著並標示，才看得出為什麼連不上
  const js = jumps.value.filter((j) => j.enabled || j.id === props.jumpHostId);
  if (js.length) {
    out.push({ type: "group", label: t("jump_hosts.title"), key: "g-jump",
      children: js.map((j) => ({ label: j.enabled ? j.label : `${j.label}（${t("common.disabled")}）`,
                                 value: `jump:${j.id}` })) });
  }
  const a = agents.value.find((x) => x.id === agentId.value);
  // 目前指派的代理已經不是這個子網路的掃描代理（例如換過）：仍要顯示出來，才看得出設定錯在哪
  const current = props.consoleAgentId && props.consoleAgentId !== a?.id
    ? agents.value.find((x) => x.id === props.consoleAgentId) : undefined;
  const list = [a, current].filter(Boolean) as ScanAgent[];
  if (list.length) {
    out.push({ type: "group", label: t("relay.via_agent_group"), key: "g-agent",
      children: list.map((x) => {
        const why = x.id !== agentId.value ? t("relay.why_not_subnet_agent") : whyNot(x);
        return { label: why ? `${x.name}（${why}）` : x.name, value: `agent:${x.id}`,
                 disabled: !!why && props.consoleAgentId !== x.id };
      }) });
  }
  return out;
});
const visible = computed(() => jumps.value.some((j) => j.enabled) || !!props.jumpHostId
  || !!agentId.value || !!props.consoleAgentId);
const value = computed(() => (props.consoleAgentId ? `agent:${props.consoleAgentId}`
  : props.jumpHostId ? `jump:${props.jumpHostId}` : null));
// 「連線路徑 → 變更」視窗要知道有沒有東西可選（沒有就講清楚只能直連，而不是一個空視窗）
defineExpose({ visible });
function onPick(v: string | null) {
  const [kind, id] = (v ?? "").split(":");
  emit("update:jumpHostId", kind === "jump" ? id : null);
  emit("update:consoleAgentId", kind === "agent" ? id : null);
}
</script>

<template>
  <n-form-item v-if="visible" :label="t('jump_hosts.exit')">
    <n-space vertical :size="4" style="width: 100%" data-testid="console-egress">
      <n-select :value="value" :options="options" clearable filterable
                :placeholder="inherit ? t('jump_hosts.exit_inherit') : t('jump_hosts.exit_direct')"
                @update:value="onPick" />
      <span style="font-size: 11px; opacity: .7">{{ t("relay.exit_hint") }}</span>
    </n-space>
  </n-form-item>
</template>
