<script setup lang="ts">
/**
 * Palo Alto（PAN-OS）防火牆檢視（唯讀）：安全政策 / 位址物件，可依 vsys 篩選。
 * 資料由 Palo Alto 整合同步進來；本頁不呼叫防火牆、也不修改任何設定。
 *
 * 政策依 `position` 排序，不是按名稱：PAN-OS 由上而下比對，順序本身就是語意。
 */
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NDataTable, NSpace, NSelect, NIcon, NEmpty, NTabs, NTabPane, NTag,
  useMessage, type DataTableColumns,
} from "naive-ui";
import { FirewallIcon } from "@/icons";
import {
  listPaloAlto, listPaloAltoPolicies, listPaloAltoAddresses,
  type PaloAltoFirewall, type PaloAltoPolicy, type PaloAltoAddressObject,
} from "@/api/paloalto";
import { autoSort } from "@/composables/useTableSort";
import { apiErrMsg } from "@/api/client";
import { useRoute } from "vue-router";
import { useFocusRow } from "@/composables/useFocusRow";
import FocusRowBanner from "@/components/FocusRowBanner.vue";

const { t } = useI18n();
const msg = useMessage();

const firewalls = ref<PaloAltoFirewall[]>([]);
const route = useRoute();
// IP 詳細頁點進來：?fw=<id>&focus=<政策 id>
const fwId = ref<string | null>(typeof route.query.fw === "string" ? route.query.fw : null);
const vsys = ref<string | null>(null);
const policies = ref<PaloAltoPolicy[]>([]);
const addresses = ref<PaloAltoAddressObject[]>([]);
const loading = ref(false);

const fwOptions = computed(() => firewalls.value.map((f) => ({ label: f.name, value: f.id })));
const vsysOptions = computed(() => {
  const set = new Set<string>();
  for (const p of policies.value) set.add(p.vsys);
  for (const a of addresses.value) set.add(a.vsys);
  return [...set].sort().map((v) => ({ label: v, value: v }));
});

async function loadFirewalls() {
  try {
    firewalls.value = (await listPaloAlto()).items;
    if (!fwId.value && firewalls.value.length) fwId.value = firewalls.value[0].id;
  } catch (e) { msg.error(apiErrMsg(e)); }
}

async function loadData() {
  if (!fwId.value) return;
  loading.value = true;
  try {
    [policies.value, addresses.value] = await Promise.all([
      listPaloAltoPolicies(fwId.value, vsys.value ?? undefined),
      listPaloAltoAddresses(fwId.value, vsys.value ?? undefined),
    ]);
  } catch (e) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}

const policyFocus = useFocusRow(policies, (p, k) => p.id === k);
const policiesShown = computed(() => policyFocus.apply(policies.value));
watch(fwId, (_n, old) => { if (old != null) policyFocus.clear(); });   // 換了防火牆，那一筆就不在這裡了
watch([fwId, vsys], () => { void loadData(); });
onMounted(async () => { await loadFirewalls(); await loadData(); });

const policyCols = computed<DataTableColumns<PaloAltoPolicy>>(() => autoSort([
  { title: "vsys", key: "vsys", width: 100 },
  { title: "#", key: "position", width: 60 },
  { title: t("common.name"), key: "name", minWidth: 150, ellipsis: { tooltip: true } },
  { title: t("fortigate.col_action"), key: "action", width: 90,
    render: (r) => r.action
      ? { allow: "✔ allow", deny: "✘ deny", drop: "✘ drop" }[r.action] ?? r.action : "—" },
  { title: t("common.status"), key: "disabled", width: 90,
    render: (r) => r.disabled ? t("common.disabled") : t("common.enabled") },
  { title: t("fortigate.col_src"), key: "from_zone", minWidth: 150, ellipsis: { tooltip: true },
    render: (r) => `${r.from_zone ?? "—"} / ${r.source ?? "—"}` },
  { title: t("fortigate.col_dst"), key: "to_zone", minWidth: 150, ellipsis: { tooltip: true },
    render: (r) => `${r.to_zone ?? "—"} / ${r.destination ?? "—"}` },
  // App-ID 是 PAN-OS 規則的核心語意（服務埠只是輔助）→ 一定要顯示
  { title: t("paloalto.col_application"), key: "application", minWidth: 130,
    ellipsis: { tooltip: true }, render: (r) => r.application ?? "—" },
  { title: t("fortigate.col_service"), key: "service", minWidth: 110,
    ellipsis: { tooltip: true }, render: (r) => r.service ?? "—" },
  { title: t("sections.description"), key: "description", minWidth: 120,
    ellipsis: { tooltip: true }, render: (r) => r.description ?? "—" },
]));

const addrCols = computed<DataTableColumns<PaloAltoAddressObject>>(() => autoSort([
  { title: "vsys", key: "vsys", width: 100 },
  { title: t("common.name"), key: "name", minWidth: 160, ellipsis: { tooltip: true } },
  { title: t("common.type"), key: "kind", width: 120,
    render: (r) => r.kind === "group" ? t("fortigate.kind_group") : (r.obj_type ?? "—") },
  { title: t("fortigate.col_value"), key: "value", minWidth: 180, ellipsis: { tooltip: true },
    render: (r) => r.kind === "group"
      ? (r.members ?? []).join(", ") || "—"
      : (r.value ?? "—") },
  { title: t("sections.description"), key: "description", minWidth: 140,
    ellipsis: { tooltip: true }, render: (r) => r.description ?? "—" },
]));
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><FirewallIcon /></n-icon>
        <span>{{ t("paloalto.view_title") }}</span>
        <n-tag size="small" type="warning" :bordered="false">Beta</n-tag>
      </n-space>
    </template>

    <n-space style="margin-bottom: 12px" align="center">
      <n-select v-model:value="fwId" :options="fwOptions" style="width: 220px"
                :placeholder="t('paloalto.pick_firewall')" />
      <n-select v-model:value="vsys" :options="vsysOptions" clearable style="width: 180px"
                :placeholder="t('paloalto.all_vsys')" />
    </n-space>

    <n-empty v-if="!firewalls.length" :description="t('paloalto.none_configured')" />
    <n-tabs v-else type="line">
      <n-tab-pane name="policies" :tab="t('paloalto.policies')">
        <FocusRowBanner :ctl="policyFocus" :loading="loading" />
        <n-data-table :columns="policyCols" :data="policiesShown" :loading="loading"
                      :bordered="false" :scroll-x="1240" />
      </n-tab-pane>
      <n-tab-pane name="addresses" :tab="t('paloalto.addresses')">
        <n-data-table :columns="addrCols" :data="addresses" :loading="loading"
                      :bordered="false" :scroll-x="900" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>
