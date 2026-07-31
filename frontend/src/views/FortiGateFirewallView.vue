<script setup lang="ts">
/**
 * FortiGate 防火牆檢視（唯讀，Beta）：政策 / 位址物件，可依 VDOM 篩選。
 * 資料由 FortiGate 整合同步進來；本頁不呼叫 FortiGate、也不修改任何設定。
 */
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NDataTable, NSpace, NSelect, NTag, NIcon, NEmpty, NTabs, NTabPane,
  useMessage, type DataTableColumns,
} from "naive-ui";
import { FirewallIcon } from "@/icons";
import {
  listFortiGate, listFortiGatePolicies, listFortiGateAddresses,
  type FortiGateFirewall, type FortiGatePolicy, type FortiGateAddressObject,
} from "@/api/fortigate";
import { autoSort } from "@/composables/useTableSort";
import { apiErrMsg } from "@/api/client";

const { t } = useI18n();
const msg = useMessage();

const firewalls = ref<FortiGateFirewall[]>([]);
const fwId = ref<string | null>(null);
const vdom = ref<string | null>(null);
const policies = ref<FortiGatePolicy[]>([]);
const addresses = ref<FortiGateAddressObject[]>([]);
const loading = ref(false);

const fwOptions = computed(() => firewalls.value.map((f) => ({ label: f.name, value: f.id })));
const vdomOptions = computed(() => {
  const set = new Set<string>();
  for (const p of policies.value) set.add(p.vdom);
  for (const a of addresses.value) set.add(a.vdom);
  return [...set].sort().map((v) => ({ label: v, value: v }));
});

async function loadFirewalls() {
  try {
    firewalls.value = (await listFortiGate()).items;
    if (!fwId.value && firewalls.value.length) fwId.value = firewalls.value[0].id;
  } catch (e) { msg.error(apiErrMsg(e)); }
}

async function loadData() {
  if (!fwId.value) return;
  loading.value = true;
  try {
    [policies.value, addresses.value] = await Promise.all([
      listFortiGatePolicies(fwId.value, vdom.value ?? undefined),
      listFortiGateAddresses(fwId.value, vdom.value ?? undefined),
    ]);
  } catch (e) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}

watch([fwId, vdom], () => { void loadData(); });
onMounted(async () => { await loadFirewalls(); await loadData(); });

const policyCols = computed<DataTableColumns<FortiGatePolicy>>(() => autoSort([
  { title: "VDOM", key: "vdom", width: 110 },
  { title: "ID", key: "policyid", width: 80 },
  { title: t("common.name"), key: "name", minWidth: 140, ellipsis: { tooltip: true },
    render: (r) => r.name || "—" },
  { title: t("fortigate.col_action"), key: "action", width: 90,
    render: (r) => r.action
      ? { accept: "✔ accept", deny: "✘ deny" }[r.action] ?? r.action : "—" },
  { title: t("common.status"), key: "status", width: 90, render: (r) => r.status ?? "—" },
  { title: t("fortigate.col_src"), key: "srcintf", minWidth: 150, ellipsis: { tooltip: true },
    render: (r) => `${r.srcintf ?? "—"} / ${r.srcaddr ?? "—"}` },
  { title: t("fortigate.col_dst"), key: "dstintf", minWidth: 150, ellipsis: { tooltip: true },
    render: (r) => `${r.dstintf ?? "—"} / ${r.dstaddr ?? "—"}` },
  { title: t("fortigate.col_service"), key: "service", minWidth: 110, ellipsis: { tooltip: true },
    render: (r) => r.service ?? "—" },
  { title: "NAT", key: "nat", width: 70, render: (r) => (r.nat ? "✔" : "—") },
  { title: t("sections.description"), key: "comments", minWidth: 120,
    ellipsis: { tooltip: true }, render: (r) => r.comments ?? "—" },
]));

const addrCols = computed<DataTableColumns<FortiGateAddressObject>>(() => autoSort([
  { title: "VDOM", key: "vdom", width: 110 },
  { title: t("common.name"), key: "name", minWidth: 160, ellipsis: { tooltip: true } },
  { title: t("common.type"), key: "kind", width: 110,
    render: (r) => r.kind === "group" ? t("fortigate.kind_group") : (r.obj_type ?? "—") },
  { title: t("fortigate.col_value"), key: "value", minWidth: 180, ellipsis: { tooltip: true },
    render: (r) => r.kind === "group"
      ? (r.members ?? []).join(", ") || "—"
      : (r.value ?? "—") },
  { title: t("sections.description"), key: "comment", minWidth: 140,
    ellipsis: { tooltip: true }, render: (r) => r.comment ?? "—" },
]));
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><FirewallIcon /></n-icon>
        <span>{{ t("fortigate.view_title") }}</span>
        <n-tag type="warning" size="small" :bordered="false">Beta</n-tag>
      </n-space>
    </template>

    <n-space style="margin-bottom: 12px" align="center">
      <n-select v-model:value="fwId" :options="fwOptions" style="width: 220px"
                :placeholder="t('fortigate.pick_firewall')" />
      <n-select v-model:value="vdom" :options="vdomOptions" clearable style="width: 180px"
                :placeholder="t('fortigate.all_vdoms')" />
    </n-space>

    <n-empty v-if="!firewalls.length" :description="t('fortigate.none_configured')" />
    <n-tabs v-else type="line">
      <n-tab-pane name="policies" :tab="t('fortigate.policies')">
        <n-data-table :columns="policyCols" :data="policies" :loading="loading"
                      :bordered="false" :scroll-x="1180" />
      </n-tab-pane>
      <n-tab-pane name="addresses" :tab="t('fortigate.addresses')">
        <n-data-table :columns="addrCols" :data="addresses" :loading="loading"
                      :bordered="false" :scroll-x="900" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>
