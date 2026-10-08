<script setup lang="ts">
/**
 * RustDesk 客戶端回報的稽核：連線（建立／驗證通過／結束）、檔案傳輸、告警、控制端備註。
 * 資料來自受控端自己（docs/SPEC_RUSTDESK_API_zh-TW.md），伺服器端分頁與搜尋（紀錄會很多）。
 */
import { computed, h, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";
import { NButton, NDataTable, NInput, NSelect, NSpace, NTag, NText, NTooltip, useMessage,
  type DataTableColumns, type DataTableSortState } from "naive-ui";
import { listRustDeskAudit, type RustDeskAudit } from "@/api/rustdesk";
import { apiErrMsg } from "@/api/client";
import { fmtDateTime } from "@/utils/datetime";
import CopyButton from "@/components/CopyButton.vue";
import ColumnPicker from "@/components/ColumnPicker.vue";
import ExportButton from "@/components/ExportButton.vue";
import { useColumnPrefs } from "@/composables/useColumnPrefs";
import { withExportValue } from "@/utils/tableExport";

const props = defineProps<{ serverId: string | null }>();
const { t, te } = useI18n();
const msg = useMessage();
const router = useRouter();

const rows = ref<RustDeskAudit[]>([]);
const total = ref(0);
const loading = ref(false);
const q = ref("");
const kind = ref<string | null>(null);
const page = ref(1);
const pageSize = ref(50);
// 伺服器端排序（紀錄會很多，只排畫面上這一頁沒有意義）；沒選就是新的在前
const sortKey = ref<string | null>(null);
const sortOrder = ref<"ascend" | "descend" | false>(false);
const SORTABLE = new Set(["occurred_at", "kind", "rustdesk_id", "device_hostname", "device_ip", "peer_id", "peer_name",
  "ip", "verified"]);

const COLS = ["occurred_at", "kind", "rustdesk_id", "device_hostname", "device_ip", "peer_id", "peer_name", "ip",
  "detail", "verified"];
const prefs = useColumnPrefs("rustdesk_audit", COLS, COLS);
const picker = computed(() => [
  { key: "occurred_at", label: t("rustdesk.audit_time") },
  { key: "kind", label: t("rustdesk.audit_kind") },
  { key: "rustdesk_id", label: t("rustdesk.col_device_id") },
  { key: "device_hostname", label: t("rustdesk.col_device_hostname") },
  { key: "device_ip", label: t("rustdesk.col_device_ip") },
  { key: "peer_id", label: t("rustdesk.col_peer_id") },
  { key: "peer_name", label: t("rustdesk.col_peer_name") },
  { key: "ip", label: t("rustdesk.col_peer_ip") },
  { key: "detail", label: t("rustdesk.audit_detail") },
  { key: "verified", label: t("rustdesk.unverified") },
]);

const kindOptions = computed(() => (["conn", "file", "alarm", "note"] as const).map((k) => ({
  label: t(`rustdesk.audit_kind_${k}`), value: k })));

function params() {
  return {
    q: q.value.trim() || undefined, kind: kind.value || undefined,
    sort: sortKey.value && sortOrder.value ? sortKey.value : undefined,
    order: sortOrder.value === "ascend" ? ("asc" as const) : ("desc" as const),
  };
}
async function load() {
  if (!props.serverId) { rows.value = []; total.value = 0; return; }
  loading.value = true;
  try {
    const r = await listRustDeskAudit(props.serverId, { ...params(), page: page.value, page_size: pageSize.value });
    rows.value = r.items;
    total.value = r.total;
  } catch (e) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}
let timer: ReturnType<typeof setTimeout> | undefined;
watch(q, () => { clearTimeout(timer); timer = setTimeout(() => { page.value = 1; void load(); }, 300); });
watch([() => props.serverId, kind], () => { page.value = 1; void load(); }, { immediate: true });
defineExpose({ reload: load });

/** NDataTable 的 @update:sorter：交給後端排，回到第一頁 */
function onSorter(st: DataTableSortState | DataTableSortState[] | null) {
  const one = Array.isArray(st) ? st[0] : st;
  sortKey.value = one && one.order ? String(one.columnKey) : null;
  sortOrder.value = one ? one.order : false;
  page.value = 1;
  void load();
}

// 匯出：照目前的篩選與排序整份抓（上限 20,000 筆，免得把瀏覽器拖垮）
const EXPORT_CAP = 20000;
async function fetchAll(): Promise<RustDeskAudit[]> {
  if (!props.serverId) return [];
  const all: RustDeskAudit[] = [];
  for (let p = 1; all.length < EXPORT_CAP; p++) {
    const r = await listRustDeskAudit(props.serverId, { ...params(), page: p, page_size: 500 });
    all.push(...r.items);
    if (r.items.length < 500 || all.length >= r.total) break;
  }
  return all.slice(0, EXPORT_CAP);
}

const pagination = computed(() => ({
  page: page.value, pageSize: pageSize.value, itemCount: total.value, showSizePicker: true,
  pageSizes: [50, 100, 200], prefix: () => t("common.total_n", { n: total.value }),
  onUpdatePage: (p: number) => { page.value = p; void load(); },
  onUpdatePageSize: (s: number) => { pageSize.value = s; page.value = 1; void load(); },
}));

function label(prefix: string, v: number | null | undefined): string {
  if (v == null) return "—";
  const key = `rustdesk.${prefix}_${v}`;
  return te(key) ? t(key) : String(v);
}

function kindTag(r: RustDeskAudit) {
  const type = r.kind === "alarm" ? "error" : r.kind === "file" ? "info" : r.kind === "note" ? "default" : "success";
  const text = r.kind === "conn" && r.action ? t(`rustdesk.audit_conn_${r.action}`) : t(`rustdesk.audit_kind_${r.kind}`);
  return h(NTag, { size: "small", bordered: false, type }, () => text);
}

function detail(r: RustDeskAudit) {
  const d = r.detail || {};
  if (r.kind === "conn") return r.action === "auth" ? label("conn_type", r.conn_type) : "—";
  if (r.kind === "alarm") return h("span", { style: r.alarm_type != null && [1, 2, 6].includes(r.alarm_type) ? "color:#d03050;font-weight:600" : "" },
    label("alarm", r.alarm_type));
  if (r.kind === "note") return d.note ?? "—";
  if (r.kind === "file") {
    const files: [string, number][] = Array.isArray(d.files) ? d.files : [];
    const head = `${d.direction === 1 ? t("rustdesk.file_from_device") : t("rustdesk.file_to_device")}：${d.path ?? ""}`;
    return h(NTooltip, { disabled: !files.length }, {
      trigger: () => h("span", null, `${head}（${t("rustdesk.n_files", { n: d.num ?? files.length })}）`),
      default: () => h("div", { style: "max-width:420px" }, files.map(([n, s]) => h("div", null, `${n}  ${s} B`))),
    });
  }
  return "—";
}

const deviceName = (r: RustDeskAudit) => r.device_reported_hostname || r.device_hostname;
const idCell = (v: string | null | undefined) => (v
  ? h("span", { class: "rd-nowrap" }, [h("span", { class: "mono" }, v), h(CopyButton, { text: v, label: t("rustdesk.copy_id") })])
  : "—");
const columnsAll = computed<DataTableColumns<RustDeskAudit>>(() => [
  { title: t("rustdesk.audit_time"), key: "occurred_at", width: 170, render: (r) => fmtDateTime(r.occurred_at) },
  withExportValue({ title: t("rustdesk.audit_kind"), key: "kind", width: 110, render: (r: RustDeskAudit) => kindTag(r) },
    (r: RustDeskAudit) => (r.kind === "conn" && r.action ? t(`rustdesk.audit_conn_${r.action}`) : t(`rustdesk.audit_kind_${r.kind}`))),
  withExportValue({ title: t("rustdesk.col_device_id"), key: "rustdesk_id", width: 150, render: (r: RustDeskAudit) => idCell(r.rustdesk_id) },
    (r: RustDeskAudit) => r.rustdesk_id),
  withExportValue({ title: t("rustdesk.col_device_hostname"), key: "device_hostname", width: 160, ellipsis: { tooltip: true },
    render: (r: RustDeskAudit) => deviceName(r) || "—" }, (r: RustDeskAudit) => deviceName(r)),
  withExportValue({
    title: t("rustdesk.col_device_ip"), key: "device_ip", width: 140,
    render: (r: RustDeskAudit) => (r.device_address_id && r.device_ip
      ? h(NButton, { text: true, type: "primary", class: "mono",
                     onClick: () => router.push({ name: "address-detail", params: { id: r.device_address_id! } }) },
          () => r.device_ip)
      : (r.device_ip ?? "—")),
  }, (r: RustDeskAudit) => r.device_ip),
  withExportValue({ title: t("rustdesk.col_peer_id"), key: "peer_id", width: 150, render: (r: RustDeskAudit) => idCell(r.peer_id) },
    (r: RustDeskAudit) => r.peer_id),
  { title: t("rustdesk.col_peer_name"), key: "peer_name", width: 140, ellipsis: { tooltip: true },
    render: (r) => r.peer_name || "—" },
  { title: t("rustdesk.col_peer_ip"), key: "ip", width: 140, render: (r) => (r.ip ? h("span", { class: "mono" }, r.ip) : "—") },
  withExportValue({ title: t("rustdesk.audit_detail"), key: "detail", minWidth: 240, width: 260, render: (r: RustDeskAudit) => detail(r) },
    (r: RustDeskAudit) => (r.kind === "note" ? r.detail?.note : r.kind === "alarm" ? label("alarm", r.alarm_type)
      : r.kind === "conn" && r.action === "auth" ? label("conn_type", r.conn_type)
        : r.kind === "file" ? r.detail?.path : null)),
  withExportValue({
    title: t("rustdesk.unverified"), key: "verified", width: 100,
    render: (r: RustDeskAudit) => (r.verified ? null : h(NTooltip, null, {
      trigger: () => h(NTag, { size: "tiny", type: "warning", bordered: false }, () => t("rustdesk.unverified")),
      default: () => t("rustdesk.unverified_hint"),
    })),
  }, (r: RustDeskAudit) => (r.verified ? "" : t("rustdesk.unverified"))),
]);
const columns = computed<DataTableColumns<RustDeskAudit>>(() => prefs.orderColumns(columnsAll.value
  .filter((c: any) => prefs.visibleKeys.value.includes(c.key)))
  .map((c: any) => (SORTABLE.has(c.key)
    ? { ...c, sorter: true, sortOrder: sortKey.value === c.key ? sortOrder.value : false }
    : c)));
const scrollX = computed(() => columns.value.reduce((sum, c: any) => sum + (Number(c.width) || Number(c.minWidth) || 120), 0));
</script>

<template>
  <div data-testid="rustdesk-audit">
    <n-space style="margin-bottom: 10px" align="center" :wrap="true">
      <n-input v-model:value="q" clearable :placeholder="t('rustdesk.audit_search_ph')" style="width: 260px"
               data-testid="rustdesk-audit-search" />
      <n-select v-model:value="kind" :options="kindOptions" clearable style="width: 160px"
                :placeholder="t('rustdesk.audit_kind')" data-testid="rustdesk-audit-kind" />
      <ColumnPicker :all="picker" :visible="prefs.visibleKeys.value"
                    @update:visible="prefs.setVisible" @reset="prefs.reset"
                    :order="prefs.order.value" @update:order="prefs.setOrder" />
      <ExportButton :columns="columns" :rows="rows" :fetch-all="fetchAll" filename="rustdesk-audit"
                    :title="t('rustdesk.audit')" />
    </n-space>
    <n-text v-if="!total && !loading" depth="3" style="font-size: 13px">{{ t("rustdesk.audit_empty") }}</n-text>
    <n-data-table v-else :columns="columns" :data="rows" :loading="loading" :bordered="false" :scroll-x="scrollX"
                  remote :pagination="pagination" :row-key="(r: RustDeskAudit) => r.id" data-testid="rustdesk-audit-table"
                  @update:sorter="onSorter" />
  </div>
</template>

<style scoped>
.rd-nowrap { display: inline-flex; align-items: center; white-space: nowrap; }
.mono { font-family: ui-monospace, monospace; }
</style>
