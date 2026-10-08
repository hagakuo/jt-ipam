<script setup lang="ts">
/**
 * MAC 歷程：以一個 MAC 為中心，串起它的所有故事（2026-10-01 使用者要求）。
 *
 * 「我有一個 MAC，但我不確定它用過哪些 IP」：以前只能從 IP 查。這一頁把 IP 異動記錄、ARP、
 * 交換器 MAC 表、DHCP 固定分配、裝置連接埠與虛擬機網卡都以 MAC 收在一起。
 * 入口：全域搜尋輸入完整 MAC、IP 詳細資料的 MAC、異動記錄與異常偵測裡的 MAC。
 */
import { computed, h, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { RouterLink, useRoute, useRouter } from "vue-router";
import {
  NAlert, NButton, NCard, NDataTable, NEmpty, NIcon, NInput, NSpace, NSpin, NTag, NTimeline, NTimelineItem,
  NTooltip, type DataTableColumns,
} from "naive-ui";
import { getMacHistory, type MacHistory, type MacIpRow } from "@/api/macs";
import { apiErrMsg } from "@/api/client";
import { fmtDateTime } from "@/utils/datetime";
import { normalizeMac } from "@/utils/mac";
import { autoSort } from "@/composables/useTableSort";
import LiveStatusDot from "@/components/LiveStatusDot.vue";
import { classifyAddressLiveness, type LivenessKind } from "@/composables/useLivenessSettings";
import { SearchIcon } from "@/icons";

const { t, te } = useI18n();
const route = useRoute();
const router = useRouter();

const input = ref(String(route.params.mac ?? ""));
const data = ref<MacHistory | null>(null);
const loading = ref(false);
const error = ref("");

async function load(mac: string) {
  error.value = "";
  data.value = null;
  if (!mac) return;
  loading.value = true;
  try { data.value = await getMacHistory(mac); }
  catch (e) { error.value = apiErrMsg(e); }
  finally { loading.value = false; }
}
watch(() => route.params.mac, (v) => { input.value = String(v ?? ""); void load(String(v ?? "")); },
      { immediate: true });

const inputMac = computed(() => normalizeMac(input.value));
function go() {
  if (!inputMac.value) return;
  void router.push({ name: "mac-history", params: { mac: inputMac.value } });
}

const empty = computed(() => {
  const d = data.value;
  return !!d && !d.ips.length && !d.events.length && !d.switch_ports.length && !d.device_ports.length
    && !d.dhcp_reservations.length && !d.vms.length;
});

// ── 小工具 ──
function srcLabel(v: string): string {
  const key = `addresses.source_${v}`;
  return te(key) ? t(key) : v;
}
const VENDOR: Record<string, string> = {
  opnsense: "OPNsense", pfsense: "pfSense", fortigate: "FortiGate", paloalto: "Palo Alto",
  mikrotik: "MikroTik", librenms: "LibreNMS",
};
/** 依據：ipam＝IP 記錄現在就是這個 MAC、change_log＝異動記錄、arp:<來源>＝ARP 觀測 */
function evidenceLabel(e: string): string {
  if (e === "ipam") return t("mac_history.ev_ipam");
  if (e === "change_log") return t("mac_history.ev_change_log");
  const src = e.startsWith("arp:") ? e.slice(4) : e;
  if (src === "scanner") return t("mac_history.ev_arp_scanner");
  const vendor = src.startsWith("arp:") ? src.slice(4) : src;
  return t("mac_history.ev_arp", { src: VENDOR[vendor] ?? vendor });
}
function macLink(mac: string | null, random = false) {
  if (!mac) return h("span", { style: "opacity:.6" }, t("mac_history.none"));
  return h(RouterLink, { to: { name: "mac-history", params: { mac } }, class: "mh-mac" }, () => [
    mac, random ? h("span", { class: "mh-rand" }, t("mac_history.random_short")) : null,
  ]);
}
function ipLink(ip: string, id: string | null, deleted = false) {
  if (id && !deleted) return h(RouterLink, { to: { name: "address-detail", params: { id } } }, () => ip);
  return h("span", null, [ip, deleted ? h("span", { class: "mh-note" }, t("mac_history.deleted")) : null]);
}
const RANK: Record<LivenessKind, number> = { online: 0, stale: 1, offline: 2, unknown: 3 };

const ipCols = computed<DataTableColumns<MacIpRow>>(() => autoSort([
  { title: t("anomaly.col.live"), key: "live", width: 78, align: "center", titleAlign: "center",
    sorter: (a, b) => (a.live ? RANK[classifyAddressLiveness(a.live)] : 4) - (b.live ? RANK[classifyAddressLiveness(b.live)] : 4),
    render: (r) => (r.live ? h(LiveStatusDot, { address: r.live as any }) : "—") },
  { title: "IP", key: "ip", width: 130, render: (r) => ipLink(r.ip, r.ip_id, r.deleted) },
  { title: t("mac_history.col_subnet"), key: "subnet_cidr", width: 130, render: (r) => r.subnet_cidr ?? "—" },
  { title: t("mac_history.col_hostname"), key: "hostname", width: 130, ellipsis: { tooltip: true },
    render: (r) => r.hostname ?? "—" },
  { title: t("mac_history.col_state"), key: "current", width: 100,
    render: (r) => h(NTag, { size: "small", bordered: false, type: r.current ? "success" : "default" },
      () => (r.current ? t("mac_history.in_use") : t("mac_history.moved_on"))) },
  { title: t("mac_history.col_first"), key: "first_seen", width: 150, render: (r) => fmtDateTime(r.first_seen) },
  { title: t("mac_history.col_last"), key: "last_seen", width: 150, render: (r) => fmtDateTime(r.last_seen) },
  // 最後一欄吃剩下的寬度、標籤自動換行。「IP 記錄」與「狀態：目前使用中」重複，不另外列
  { title: t("mac_history.col_evidence"), key: "evidence", minWidth: 190,
    render: (r) => h(NSpace, { size: 4, wrap: true }, () => r.evidence.filter((e) => e !== "ipam").map((e) =>
      h(NTag, { size: "tiny", bordered: false }, () => evidenceLabel(e)))) },
]));

const portCols = computed<DataTableColumns<MacHistory["switch_ports"][number]>>(() => autoSort([
  { title: t("mac_history.col_switch"), key: "switch", minWidth: 160,
    render: (r) => (r.switch_device_id
      ? h(RouterLink, { to: { name: "device-detail", params: { id: r.switch_device_id } } }, () => r.switch ?? "—")
      : (r.switch ?? "—")) },
  { title: t("mac_history.col_port"), key: "port", width: 140, render: (r) => r.port ?? "—" },
  { title: "VLAN", key: "vlan", width: 80, render: (r) => (r.vlan ?? "—") as any },
  { title: t("mac_history.col_first"), key: "first_seen", width: 165, render: (r) => fmtDateTime(r.first_seen) },
  { title: t("mac_history.col_last"), key: "last_seen", width: 165, render: (r) => fmtDateTime(r.last_seen) },
  { title: t("mac_history.col_source"), key: "source", width: 110,
    render: (r) => (VENDOR[r.source] ?? r.source) },
]));
</script>

<template>
  <!-- 用 flex＋gap 而不是 n-space：結果的幾張卡片包在 n-spin 裡，n-space 把整組當成一個項目，
       卡片之間就沒有間距（使用者回報三張卡片黏在一起）；spin 的內容層也要同樣排（見 style） -->
  <div class="mh-page">
    <n-card>
      <template #header>{{ t("mac_history.title") }}</template>
      <n-space align="center" :wrap="true" :size="10">
        <n-input v-model:value="input" clearable style="width: 280px" :placeholder="t('mac_history.placeholder')"
                 data-testid="mh-input" @keyup.enter="go" />
        <n-button type="primary" :disabled="!inputMac" @click="go">
          <template #icon><n-icon><SearchIcon /></n-icon></template>
          {{ t("mac_history.lookup") }}
        </n-button>
        <span class="mh-hint">{{ t("mac_history.hint") }}</span>
      </n-space>
    </n-card>

    <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>

    <n-spin :show="loading" class="mh-results">
      <template v-if="data">
        <n-card data-testid="mh-summary">
          <div class="mh-head">
            <span class="mh-big">{{ data.mac }}</span>
            <n-tag v-if="data.vendor" size="small" :bordered="false" type="info">{{ data.vendor }}</n-tag>
            <n-tooltip v-if="data.random">
              <template #trigger>
                <n-tag size="small" :bordered="false" type="warning" data-testid="mh-random">{{ t("mac_history.random") }}</n-tag>
              </template>
              {{ t("mac_history.random_tip") }}
            </n-tooltip>
          </div>
          <div class="mh-facts">
            <div>
              <span class="mh-k">{{ t("mac_history.now") }}</span>
              <template v-if="data.current.length">
                <span v-for="c in data.current" :key="c.ip_id" class="mh-v">
                  <RouterLink :to="{ name: 'address-detail', params: { id: c.ip_id } }">{{ c.ip }}</RouterLink>
                  <span v-if="c.hostname" class="mh-note">{{ c.hostname }}</span>
                </span>
              </template>
              <span v-else class="mh-v mh-dim">{{ t("mac_history.now_none") }}</span>
            </div>
            <div v-if="data.device_ports.length || data.vms.length">
              <span class="mh-k">{{ t("mac_history.belongs") }}</span>
              <span v-for="d in data.device_ports" :key="d.device_id + d.port" class="mh-v">
                <RouterLink :to="{ name: 'device-detail', params: { id: d.device_id } }">{{ d.device_name }}</RouterLink>
                <span class="mh-note">{{ d.port }}</span>
              </span>
              <span v-for="v in data.vms" :key="v.vm_id + v.interface" class="mh-v">
                {{ v.vm_name }}<span class="mh-note">{{ v.cluster }} · {{ v.interface }}</span>
              </span>
            </div>
            <div v-if="data.dhcp_reservations.length">
              <span class="mh-k">{{ t("mac_history.dhcp_fixed") }}</span>
              <span v-for="r in data.dhcp_reservations" :key="r.source_type + r.ip" class="mh-v">
                {{ r.ip }}<span class="mh-note">{{ r.source_name || r.source_type }}<template v-if="r.hostname"> · {{ r.hostname }}</template></span>
              </span>
            </div>
          </div>
          <n-alert v-if="data.random" type="info" :bordered="false" style="margin-top: 12px">
            {{ t("mac_history.random_note") }}
          </n-alert>
          <div v-if="data.restricted" class="mh-hint" style="margin-top: 10px">{{ t("mac_history.restricted") }}</div>
        </n-card>

        <n-empty v-if="empty" :description="t('mac_history.empty')" style="margin: 24px 0" />

        <n-card v-if="data.related.length" :title="t('mac_history.related_title')" data-testid="mh-related">
          <div class="mh-hint" style="margin-bottom: 8px">{{ t("mac_history.related_hint") }}</div>
          <div v-for="r in data.related" :key="r.mac" class="mh-rel">
            <component :is="macLink(r.mac, r.random)" />
            <span class="mh-note">{{ t("mac_history.related_line", { ip: r.ip, at: fmtDateTime(r.at) }) }}</span>
          </div>
        </n-card>

        <n-card v-if="data.ips.length" data-testid="mh-ips">
          <template #header>
            {{ t("mac_history.ips_title") }}
            <span class="mh-count">{{ data.ips_total > data.ips.length
              ? t("mac_history.shown_of", { n: data.ips.length, total: data.ips_total }) : data.ips_total }}</span>
          </template>
          <n-data-table :columns="ipCols" :data="data.ips" :bordered="false" size="small" :scroll-x="1060" />
        </n-card>

        <n-card v-if="data.switch_ports.length" data-testid="mh-ports">
          <template #header>{{ t("mac_history.ports_title") }}</template>
          <n-data-table :columns="portCols" :data="data.switch_ports" :bordered="false" size="small" :scroll-x="820" />
        </n-card>

        <n-card v-if="data.events.length" data-testid="mh-events">
          <template #header>
            {{ t("mac_history.events_title") }}
            <span class="mh-count">{{ data.events_total > data.events.length
              ? t("mac_history.shown_of", { n: data.events.length, total: data.events_total }) : data.events_total }}</span>
          </template>
          <n-timeline>
            <n-timeline-item v-for="e in data.events" :key="e.id" :time="fmtDateTime(e.at)"
                             :type="e.kind === 'assigned' ? 'success' : 'default'">
              <template #header>
                <n-space align="center" :size="6">
                  <strong>{{ e.kind === "assigned" ? t("mac_history.ev_assigned") : t("mac_history.ev_released") }}</strong>
                  <component :is="ipLink(e.ip, e.ip_id)" />
                  <n-tag size="tiny" :bordered="false">{{ srcLabel(e.source) }}</n-tag>
                </n-space>
              </template>
              <span class="mh-ev">
                {{ e.kind === "assigned" ? t("mac_history.ev_prev") : t("mac_history.ev_next") }}
                <component :is="macLink(e.other_mac, e.other_random)" />
              </span>
            </n-timeline-item>
          </n-timeline>
        </n-card>
      </template>
    </n-spin>
  </div>
</template>

<style scoped>
.mh-page { display: flex; flex-direction: column; gap: 14px; }
.mh-results :deep(.n-spin-content) { display: flex; flex-direction: column; gap: 14px; }
.mh-hint { font-size: 12px; opacity: .65; }
/* 連結用主題色（瀏覽器預設的藍色在深色主題下幾乎看不見） */
.mh-page :deep(a) { color: var(--primary-color, #18a058); text-decoration: none; }
.mh-page :deep(a:hover) { text-decoration: underline; }
.mh-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.mh-big { font-family: var(--jt-mono, monospace); font-size: 20px; font-weight: 600; }
.mh-facts { display: flex; flex-direction: column; gap: 6px; margin-top: 12px; font-size: 13.5px; }
.mh-k { display: inline-block; min-width: 110px; opacity: .65; }
.mh-v { margin-right: 14px; }
.mh-dim { opacity: .6; }
.mh-note { margin-left: 6px; font-size: 12px; opacity: .65; }
.mh-count { margin-left: 8px; font-size: 12.5px; font-weight: 400; opacity: .6; }
.mh-rel { display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap; padding: 3px 0; font-size: 13.5px; }
.mh-ev { font-size: 13px; }
:deep(.mh-mac) { font-family: var(--jt-mono, monospace); }
:deep(.mh-rand) { margin-left: 6px; font-family: inherit; font-size: 11px; padding: 0 5px; border-radius: 4px;
                  background: rgba(240, 160, 32, .18); color: #d08a12; }
@media (max-width: 640px) { .mh-k { min-width: 0; display: block; } }
</style>
