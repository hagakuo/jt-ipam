<script setup lang="ts">
/**
 * MikroTik RouterOS 檢視（唯讀）：防火牆規則 / address-list / 鄰居（LLDP/CDP/MNDP）。
 * 資料由 MikroTik 整合同步進來；本頁不呼叫路由器、也不修改任何設定。
 *
 * 規則依 `position` 排序，**而且不提供改排序** —— RouterOS 由上而下比對、
 * 第一條命中就決定結果，用別的順序看等於看不出行為。
 */
import { computed, h, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NDataTable, NSpace, NSelect, NIcon, NEmpty, NTabs, NTabPane, NTag, NInput,
  useMessage, type DataTableColumns,
} from "naive-ui";
import { FirewallIcon } from "@/icons";
import {
  listMikroTik, listMikroTikRules, listMikroTikAddressLists, listMikroTikNeighbors,
  type MikroTikRouter, type MikroTikRule, type MikroTikAddressListEntry, type MikroTikNeighbor,
} from "@/api/mikrotik";
import { RouterLink } from "vue-router";
import { fmtDateTime } from "@/utils/datetime";
import { autoSort } from "@/composables/useTableSort";
import { apiErrMsg } from "@/api/client";
import { useRoute } from "vue-router";
import { useFocusRow } from "@/composables/useFocusRow";
import FocusRowBanner from "@/components/FocusRowBanner.vue";

const { t } = useI18n();
const msg = useMessage();

const routers = ref<MikroTikRouter[]>([]);
const route = useRoute();
// IP 詳細頁點進來：?tab=rules|lists|neighbors&fw=<路由器 id>&focus=<規則 id／清單名稱>
const routerId = ref<string | null>(typeof route.query.fw === "string" ? route.query.fw : null);
type Tab = "rules" | "lists" | "neighbors";
const tab = ref<Tab>(["lists", "neighbors"].includes(String(route.query.tab))
  ? route.query.tab as Tab : "rules");
const table = ref<string | null>(null);
const listFilter = ref("");
const rules = ref<MikroTikRule[]>([]);
const entries = ref<MikroTikAddressListEntry[]>([]);
const neighbors = ref<MikroTikNeighbor[]>([]);
const loading = ref(false);

const routerOptions = computed(() => routers.value.map((r) => ({ label: r.name, value: r.id })));
const tableOptions = computed(() => ["filter", "nat", "mangle"].map((v) => ({ label: v, value: v })));

const filteredEntries = computed(() => {
  const q = listFilter.value.trim().toLowerCase();
  if (!q) return entries.value;
  return entries.value.filter((e) =>
    e.list_name.toLowerCase().includes(q) || e.address.toLowerCase().includes(q));
});

async function loadRouters() {
  try {
    routers.value = (await listMikroTik()).items;
    if (!routerId.value && routers.value.length) routerId.value = routers.value[0].id;
  } catch (e) { msg.error(apiErrMsg(e)); }
}

async function loadData() {
  if (!routerId.value) return;
  loading.value = true;
  try {
    [rules.value, entries.value, neighbors.value] = await Promise.all([
      listMikroTikRules(routerId.value, table.value ?? undefined),
      listMikroTikAddressLists(routerId.value),
      listMikroTikNeighbors(routerId.value),
    ]);
  } catch (e) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}

const ruleFocus = useFocusRow(rules, (r, k) => r.id === k, "rules");
const listFocus = useFocusRow(entries, (e, k) => e.list_name === k, "lists");
const rulesShown = computed(() => ruleFocus.apply(rules.value));
const entriesShown = computed(() => listFocus.apply(filteredEntries.value));
watch(routerId, (_n, old) => { if (old != null) { ruleFocus.clear(); listFocus.clear(); } });
watch([routerId, table], () => { void loadData(); });
onMounted(async () => { await loadRouters(); await loadData(); });

const ruleCols = computed<DataTableColumns<MikroTikRule>>(() => autoSort([
  { title: t("mikrotik.col_table"), key: "table_name", width: 90 },
  { title: t("mikrotik.col_chain"), key: "chain", width: 110,
    render: (r) => r.chain ?? "—" },
  { title: "#", key: "position", width: 60 },
  { title: t("fortigate.col_action"), key: "action", width: 110,
    render: (r) => r.action ?? "—" },
  { title: t("common.status"), key: "disabled", width: 90,
    render: (r) => r.disabled ? t("common.disabled") : t("common.enabled") },
  { title: t("fortigate.col_src"), key: "src_address", minWidth: 150,
    ellipsis: { tooltip: true },
    render: (r) => [r.src_address, r.src_port].filter(Boolean).join(":") || "—" },
  { title: t("fortigate.col_dst"), key: "dst_address", minWidth: 150,
    ellipsis: { tooltip: true },
    render: (r) => [r.dst_address, r.dst_port].filter(Boolean).join(":") || "—" },
  { title: t("mikrotik.col_proto"), key: "protocol", width: 90,
    render: (r) => r.protocol ?? "—" },
  { title: t("mikrotik.col_iface"), key: "in_interface", minWidth: 140,
    ellipsis: { tooltip: true },
    render: (r) => `${r.in_interface ?? "—"} → ${r.out_interface ?? "—"}` },
  { title: t("mikrotik.col_to"), key: "to_addresses", minWidth: 140,
    ellipsis: { tooltip: true },
    render: (r) => [r.to_addresses, r.to_ports].filter(Boolean).join(":") || "—" },
  { title: t("sections.description"), key: "comment", minWidth: 140,
    ellipsis: { tooltip: true }, render: (r) => r.comment ?? "—" },
]));

const entryCols = computed<DataTableColumns<MikroTikAddressListEntry>>(() => autoSort([
  { title: t("mikrotik.col_list"), key: "list_name", minWidth: 160,
    ellipsis: { tooltip: true } },
  { title: t("fortigate.col_value"), key: "address", minWidth: 180,
    ellipsis: { tooltip: true } },
  // 動態條目是規則自己加進去的（例如防掃描），不是人設定的 —— 分開看很重要
  { title: t("common.type"), key: "dynamic", width: 110,
    render: (r) => r.dynamic ? t("mikrotik.dynamic") : t("mikrotik.static") },
  { title: t("mikrotik.col_timeout"), key: "timeout", width: 120,
    render: (r) => r.timeout ?? "—" },
  { title: t("sections.description"), key: "comment", minWidth: 140,
    ellipsis: { tooltip: true }, render: (r) => r.comment ?? "—" },
]));

const neighborCols = computed<DataTableColumns<MikroTikNeighbor>>(() => autoSort([
  { title: t("mikrotik.col_local_port"), key: "interface", width: 130 },
  // 對方宣告的名稱；對到 jt-ipam 裝置時連過去（依宣告的位址或 MAC，對到多台不猜）
  { title: t("mikrotik.col_neighbor"), key: "identity", minWidth: 170, ellipsis: { tooltip: true },
    render: (r) => r.device_id
      ? h(RouterLink, { to: `/devices/${r.device_id}` }, () => r.device_name ?? r.identity ?? "—")
      : (r.identity ?? "—") },
  { title: t("mikrotik.col_remote_port"), key: "remote_interface", width: 140,
    render: (r) => r.remote_interface ?? "—" },
  { title: "IP", key: "address", width: 150, render: (r) => r.address ?? "—" },
  { title: "MAC", key: "mac", width: 160, render: (r) => r.mac ?? "—" },
  { title: t("mikrotik.col_platform"), key: "platform", minWidth: 180, ellipsis: { tooltip: true },
    render: (r) => [r.platform, r.board, r.version].filter(Boolean).join(" · ") || "—" },
  { title: t("mikrotik.col_discovered_by"), key: "discovered_by", width: 130,
    render: (r) => r.discovered_by ?? "—" },
  { title: t("cols.last_seen"), key: "last_seen_at", width: 165,
    render: (r) => fmtDateTime(r.last_seen_at) },
]));
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><FirewallIcon /></n-icon>
        <span>{{ t("mikrotik.view_title") }}</span>
        <n-tag size="small" type="warning" :bordered="false">Beta</n-tag>
      </n-space>
    </template>

    <n-space style="margin-bottom: 12px" align="center">
      <n-select v-model:value="routerId" :options="routerOptions" style="width: 220px"
                :placeholder="t('mikrotik.pick_router')" />
      <n-select v-model:value="table" :options="tableOptions" clearable style="width: 160px"
                :placeholder="t('mikrotik.all_tables')" />
      <n-input v-model:value="listFilter" clearable style="width: 200px"
               :placeholder="t('mikrotik.filter_lists')" />
    </n-space>

    <n-empty v-if="!routers.length" :description="t('mikrotik.none_configured')" />
    <n-tabs v-else v-model:value="tab" type="line">
      <n-tab-pane name="rules" :tab="t('mikrotik.rules')">
        <FocusRowBanner :ctl="ruleFocus" :loading="loading" />
        <n-data-table :columns="ruleCols" :data="rulesShown" :loading="loading"
                      :bordered="false" :scroll-x="1400" />
      </n-tab-pane>
      <n-tab-pane name="lists" :tab="t('mikrotik.address_lists')">
        <FocusRowBanner :ctl="listFocus" :loading="loading" />
        <n-data-table :columns="entryCols" :data="entriesShown" :loading="loading"
                      :bordered="false" :scroll-x="900"
                      :pagination="{ pageSize: 50, showSizePicker: false }" />
      </n-tab-pane>
      <n-tab-pane name="neighbors" :tab="t('mikrotik.neighbors')">
        <div class="nb-hint">{{ t("mikrotik.neighbors_hint") }}</div>
        <n-data-table :columns="neighborCols" :data="neighbors" :loading="loading"
                      :bordered="false" :scroll-x="1250" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>

<style scoped>
.nb-hint { font-size: 12px; opacity: .7; margin-bottom: 8px; }
</style>
