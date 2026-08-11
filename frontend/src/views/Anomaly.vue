<script setup lang="ts">
import { computed, ref, h } from "vue";
import { fmtDateTime } from "@/utils/datetime";
import { useI18n } from "vue-i18n";
import {
  NCard, NSpace, NIcon, NButton, NAlert, NStatistic, NGrid, NGi, NDataTable, NEmpty,
  NTabs, NTabPane, NModal, NSelect, useMessage, type DataTableColumns,
} from "naive-ui";
import { runAnomalyScan, type AnomalyReport } from "@/api/phase3";
import { AnomalyIcon, TestIcon, InfoIcon, SettingsIcon } from "@/icons";
import { listSubnets, setAnomalyScope } from "@/api/subnets";
import { apiErrMsg } from "@/api/client";
import { autoSort } from "@/composables/useTableSort";
import type { Subnet } from "@/types";
import { useTablePagination } from "@/composables/useTablePagination";
import { useColumnPrefs } from "@/composables/useColumnPrefs";
import ColumnPicker from "@/components/ColumnPicker.vue";

const { t, te } = useI18n();
const msg = useMessage();
const pg = useTablePagination();
const loading = ref(false);
const report = ref<AnomalyReport | null>(null);
const lastRunAt = ref<string | null>(null);

// 偵測範圍（寫的是 subnets.anomaly_enabled，跟子網路編輯頁同一個欄位）
const scopeShow = ref(false);
const scopeSaving = ref(false);
const scopeIds = ref<string[]>([]);
const subnets = ref<Subnet[]>([]);
const subnetsLoading = ref(false);
const subnetOptions = computed(() => subnets.value.map((s) => ({
  label: s.description ? `${s.cidr} — ${s.description}` : s.cidr,
  value: s.id,
})));

async function loadSubnets() {
  subnetsLoading.value = true;
  try {
    const r = await listSubnets({ pageSize: 500 });
    subnets.value = r.items;
    scopeIds.value = r.items.filter((s) => s.anomaly_enabled).map((s) => s.id);
  } catch { /* 沒權限就留空，不擋整頁 */ } finally { subnetsLoading.value = false; }
}

function openScope() {
  scopeShow.value = true;
  void loadSubnets();
}

async function saveScope() {
  scopeSaving.value = true;
  try {
    await setAnomalyScope(scopeIds.value);
    msg.success(t("common.saved"));
    scopeShow.value = false;
  } catch (e) { msg.error(apiErrMsg(e)); await loadSubnets(); }
  finally { scopeSaving.value = false; }
}
const activeTab = ref("ip_conflicts");

type CatKey = "ip_conflicts" | "mac_drifts" | "ghost_ips" | "unauthorized_ips"
  | "rogue_dhcp" | "external_exposure" | "dangling_dns" | "duplicate_ip_records" | "suspicious_changes";
const CATEGORIES: { key: CatKey; label: () => string }[] = [
  { key: "ip_conflicts", label: () => t("anomaly.ip_conflicts") },
  { key: "mac_drifts", label: () => t("anomaly.mac_drifts") },
  { key: "ghost_ips", label: () => t("anomaly.ghost_ips") },
  { key: "unauthorized_ips", label: () => t("anomaly.unauthorized") },
  { key: "rogue_dhcp", label: () => t("anomaly.rogue_dhcp") },
  { key: "external_exposure", label: () => t("anomaly.exposure") },
  { key: "dangling_dns", label: () => t("anomaly.dangling_dns") },
  { key: "duplicate_ip_records", label: () => t("anomaly.dup_ip") },
  { key: "suspicious_changes", label: () => t("anomaly.changes") },
];

const rogueTitle = computed(() =>
  t("anomaly.rogue_dhcp") + `（${report.value?.rogue_dhcp?.length ?? 0}）`);

const anyFindings = computed(() => {
  const r = report.value;
  return !!r && (r.ip_conflicts.length + r.mac_drifts.length + r.ghost_ips.length
    + r.unauthorized_ips.length + (r.rogue_dhcp?.length ?? 0)
    + (r.external_exposure?.length ?? 0) + (r.dangling_dns?.length ?? 0)
    + (r.duplicate_ip_records?.length ?? 0) + (r.suspicious_changes?.length ?? 0)) > 0;
});
function catRows(key: CatKey): Record<string, any>[] {
  return (report.value?.[key] as Record<string, any>[]) ?? [];
}

// 欄位標題（技術欄名在地化；其餘原樣）
const COLLBL: Record<string, string> = {
  mac: "MAC", macs: "MAC", ip: "IP", ips: "對應 IP / 主機名稱", hostname: "主機名稱",
  port: "埠", device_id: "裝置", last_seen_at: "最後出現", locations: "出現位置",
  last_seen_scanner: "最後出現（掃描）", last_seen_librenms: "最後出現（LibreNMS）",
  ip_address_id: "IP 物件 ID", reason: "原因", subnet: "子網路", state: "狀態",
  server_ip: "DHCP 伺服器 IP", subnet_cidr: "子網路", vendor: "廠商",
  offered_ip: "發出的 IP", router: "指定的閘道", first_seen_at: "首次發現",
  kind: "狀況", ports: "對外開放的埠", monitored: "監控涵蓋",
  name: "名稱", value: "指向", type: "型別", zone: "區域", server: "DNS 伺服器",
  records: "重複的紀錄", actor: "操作者", actor_ip: "來源 IP",
  action: "動作", count: "次數", first_at: "最早", object_type: "物件類型",
  effective_status: "存活狀態", names: "DNS 名稱", owner: "負責人", rules: "來源規則",
};
// 各類別的欄位（順序）＋預設隱藏（ip_address_id 是內部 UUID，預設不顯示，可在「欄位」勾選）
const CAT_KEYS: Record<CatKey, string[]> = {
  ip_conflicts: ["ip", "macs"],
  mac_drifts: ["mac", "ips", "locations"],
  ghost_ips: ["ip", "hostname", "last_seen_scanner", "last_seen_librenms", "ip_address_id"],
  unauthorized_ips: ["ip"],
  rogue_dhcp: ["server_ip", "subnet_cidr", "mac", "vendor", "offered_ip", "router",
               "first_seen_at", "last_seen_at"],
  external_exposure: ["kind", "ip", "hostname", "ports", "subnet", "monitored",
                      "effective_status", "names", "owner", "rules", "ip_address_id"],
  dangling_dns: ["name", "value", "type", "zone", "server"],
  duplicate_ip_records: ["ip", "records"],
  suspicious_changes: ["kind", "actor", "actor_ip", "object_type", "action",
                       "count", "first_at", "last_at"],
};
const CAT_HIDDEN: Partial<Record<CatKey, string[]>> = {
  ghost_ips: ["ip_address_id"],
  // owner 實務上幾乎沒人填、rules 是原始規則明細、ip_address_id 是內部 UUID：
  // 預設不顯示，需要的人可在「欄位」自行勾選
  external_exposure: ["ip_address_id", "owner", "rules"],
};

// 每個類別一份欄位顯示偏好
const prefs = {} as Record<CatKey, ReturnType<typeof useColumnPrefs>>;
for (const c of CATEGORIES) {
  const keys = CAT_KEYS[c.key];
  const hidden = CAT_HIDDEN[c.key] ?? [];
  prefs[c.key] = useColumnPrefs(`anomaly_${c.key}`, keys, keys.filter((k) => !hidden.includes(k)));
}
function pickerItems(key: CatKey) {
  return CAT_KEYS[key].map((k) => ({ key: k, label: COLLBL[k] ?? k }));
}

function pretty(k: string, val: any): string {
  if (val == null || val === "") return "";
  // kind 是分類代碼（exposed_unmonitored…），要翻成看得懂的字，不能把 enum 直接印給人看
  // kind 橫跨兩類（對外曝險 exp_* 與可疑變更 chg_*），找得到才翻，找不到就原樣顯示
  if (k === "kind") {
    for (const p of ["anomaly.exp_", "anomaly.chg_"]) {
      const key = `${p}${val}`;
      if (te(key)) return t(key);
    }
    return String(val);
  }
  if (k === "monitored") return val ? t("common.yes") : t("common.no");
  if (Array.isArray(val)) {
    return val.map((x) => (typeof x === "object" && x !== null ? objLine(x) : String(x)))
      .join("、");
  }
  if (k.includes("device_id")) return String(val).slice(0, 8);
  if (k.includes("last_seen") || k.includes("_at") || k.includes("time")) return fmtDateTime(String(val));   // 轉本地時區
  return String(val);
}
function objLine(o: Record<string, any>): string {
  return Object.entries(o)
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => `${COLLBL[k] ?? k}：${pretty(k, v)}`)
    .join("　·　");
}
function cell(label: string, val: string) {
  return h("span", { style: "white-space:nowrap;overflow:hidden;text-overflow:ellipsis" }, [
    h("span", { style: "opacity:.55;margin-right:4px" }, label),
    h("span", val || "—"),
  ]);
}
function renderLocation(o: Record<string, any>) {
  const dev = o.device_name || (o.device_id ? String(o.device_id).slice(0, 8) : "—");
  return h("div", {
    style: "display:grid;grid-template-columns:minmax(0,1fr) 110px 132px;gap:14px;font-size:12.5px;align-items:baseline",
  }, [
    cell(COLLBL.device_id, dev),
    cell(COLLBL.port, o.port ?? "—"),
    cell(COLLBL.last_seen_at, pretty("last_seen_at", o.last_seen_at)),
  ]);
}
function renderMac(o: Record<string, any>) {
  // 本地管理位址（虛擬機／容器／手機 MAC 隨機化）沒有 OUI 登記，查不到廠商是正常的。
  // 標出來才看得懂：同一 IP 上「真實 MAC + 隨機 MAC」多半是同一台裝置，不是兩台在搶。
  const tag = o.local
    ? h("span", { class: "mac-tag mac-tag--local" }, t("anomaly.mac_local"))
    : (o.vendor ? h("span", { class: "mac-tag" }, String(o.vendor)) : null);
  return h("div", { style: "display:flex;align-items:baseline;gap:8px;font-size:12.5px" }, [
    h("span", { style: "font-family:var(--jt-mono,monospace)" }, o.mac ?? "—"),
    tag,
    h("span", { style: "opacity:.55;margin-left:auto;white-space:nowrap" },
      pretty("last_seen_at", o.last_seen_at)),
  ]);
}
function renderVal(k: string, v: any) {
  if (v == null || v === "") return "—";
  if (k === "macs" && Array.isArray(v)) {
    return h("div", { style: "display:flex;flex-direction:column;gap:3px" }, v.map(renderMac));
  }
  if (k === "ips" && Array.isArray(v)) {
    if (!v.length) return h("span", { style: "opacity:.5" }, "—");
    return h("div", { style: "display:flex;flex-direction:column;gap:2px;font-size:12.5px" },
      v.map((it: any) => h("div", null, it.hostname ? `${it.ip}（${it.hostname}）` : it.ip)));
  }
  if (Array.isArray(v)) {
    return h("div", { style: "display:flex;flex-direction:column;gap:3px" },
      v.map((it: any) => k === "locations"
        ? renderLocation(it)
        : h("div", { style: "font-size:12.5px" }, it && typeof it === "object" ? objLine(it) : String(it))));
  }
  if (typeof v === "object") return objLine(v);
  return pretty(k, v);
}
// 依該類別的可見欄位（已套欄位偏好）組欄位
function catCols(key: CatKey): DataTableColumns<any> {
  const visible = prefs[key].visibleKeys.value;
  // autoSort：與全站表格一致，替沒有自訂 sorter 的欄位補上預設排序。
  // 這幾張表原本整排標頭都不能排 —— 十幾筆 MAC 變動想按時間或按網段看都做不到。
  return autoSort(CAT_KEYS[key].filter((k) => visible.includes(k)).map((k) => {
    const wide = k === "locations" || k === "macs";
    return {
      title: COLLBL[k] ?? k,
      key: k,
      minWidth: wide ? 420 : (k === "ips" ? 220 : 140),
      ellipsis: wide || k === "ips" ? false : { tooltip: true },
      render: (r: any) => renderVal(k, r[k]),
    };
  }));
}

async function run() {
  loading.value = true;
  try {
    report.value = await runAnomalyScan();
    lastRunAt.value = fmtDateTime(new Date());
  } catch (e: any) {
    msg.error(e?.response?.data?.detail ?? t("errors.server"));
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><AnomalyIcon /></n-icon>
        <span>{{ t("anomaly.title") }}</span>
      </n-space>
    </template>
    <n-space align="center" style="margin-bottom: 12px" :wrap-item="false">
      <n-button type="primary" :loading="loading" @click="run">
        <template #icon><n-icon><TestIcon /></n-icon></template>
        {{ t("anomaly.run_scan") }}
      </n-button>
      <span v-if="lastRunAt" style="opacity: 0.7; font-size: 13px">
        {{ t("anomaly.last_run") }}: {{ lastRunAt }}
      </span>
      <n-button size="small" quaternary @click="openScope">
        <template #icon><n-icon><SettingsIcon /></n-icon></template>
        {{ t("anomaly.scope_btn") }}
      </n-button>
    </n-space>

    <!-- 偵測範圍：訪客／實驗網段本來就會一堆異常，留著只會把真正該處理的埋掉 -->
    <n-modal v-model:show="scopeShow" preset="card" style="max-width: 620px"
             :title="t('anomaly.scope_title')">
      <n-alert type="info" :bordered="false" style="margin-bottom:12px">
        {{ t("anomaly.scope_hint") }}
      </n-alert>
      <n-select v-model:value="scopeIds" multiple filterable clearable
                :options="subnetOptions" :loading="subnetsLoading"
                :placeholder="t('anomaly.scope_none')" />
      <template #footer>
        <n-space justify="end">
          <n-button @click="scopeShow = false">{{ t("common.cancel") }}</n-button>
          <n-button type="primary" :loading="scopeSaving" @click="saveScope">
            {{ t("common.save") }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <n-alert v-if="!report" type="info">
      <template #icon><n-icon><InfoIcon /></n-icon></template>
      {{ t("anomaly.help") }}
    </n-alert>

    <template v-if="report">
      <!-- 非法 DHCP 一出現幾乎必定有事：它會把錯的位址跟閘道發給整個網段的機器。
           混在分頁裡跟其它異常一樣大小的話，看到的人不會知道這條要優先處理。 -->
      <n-alert v-if="report.rogue_dhcp?.length" type="error" :show-icon="true"
               style="margin-bottom: 16px" :title="rogueTitle">
        {{ t("anomaly.rogue_dhcp_warn") }}
        <div class="rogue-list">
          <span v-for="r in report.rogue_dhcp.slice(0, 8)" :key="r.server_ip" class="rogue-chip">
            {{ r.server_ip }}<template v-if="r.subnet_cidr"> · {{ r.subnet_cidr }}</template>
            <template v-if="r.vendor"> · {{ r.vendor }}</template>
          </span>
        </div>
      </n-alert>

      <n-grid :cols="4" x-gap="12" style="margin-bottom: 16px">
        <n-gi><n-statistic :label="t('anomaly.ip_conflicts')" :value="report.ip_conflicts.length" /></n-gi>
        <n-gi><n-statistic :label="t('anomaly.mac_drifts')" :value="report.mac_drifts.length" /></n-gi>
        <n-gi><n-statistic :label="t('anomaly.ghost_ips')" :value="report.ghost_ips.length" /></n-gi>
        <n-gi><n-statistic :label="t('anomaly.unauthorized')" :value="report.unauthorized_ips.length" /></n-gi>
      </n-grid>
      <n-empty v-if="!anyFindings" :description="t('anomaly.none_found')" style="margin: 24px 0" />

      <n-tabs v-else v-model:value="activeTab" type="line" animated>
        <n-tab-pane v-for="c in CATEGORIES" :key="c.key" :name="c.key"
                    :tab="`${c.label()} (${catRows(c.key).length})`">
          <!-- 每個類別先講清楚「這是什麼、為什麼會出現」，否則一長串 IP 沒人看得懂 -->
          <n-alert type="default" :bordered="false" :show-icon="false" class="cat-note">
            {{ t(`anomaly.explain_${c.key}`) }}
          </n-alert>
          <template v-if="catRows(c.key).length">
            <div style="display:flex;justify-content:flex-end;margin-bottom:8px">
              <ColumnPicker :all="pickerItems(c.key)" :visible="prefs[c.key].visibleKeys.value"
                            @update:visible="prefs[c.key].setVisible" @reset="prefs[c.key].reset" />
            </div>
            <n-data-table :columns="catCols(c.key)" :data="catRows(c.key)"
                          :bordered="false" size="small" :scroll-x="600" :pagination="pg" />
          </template>
          <n-empty v-else :description="t('anomaly.none_found')" style="margin: 16px 0" />
        </n-tab-pane>
      </n-tabs>
    </template>
  </n-card>
</template>

<style scoped>
.cat-note { margin: 4px 0 14px; font-size: 12.5px; line-height: 1.7; }
.rogue-list { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
.rogue-chip {
  font-family: var(--font-mono, monospace); font-size: 12px;
  padding: 2px 8px; border-radius: 4px; background: rgba(208, 48, 80, .12);
}
.mac-tag {
  font-size: 11px; padding: 0 6px; border-radius: 3px; white-space: nowrap;
  background: var(--n-color-embedded, rgba(128, 128, 128, .12));
  color: var(--n-text-color-disabled);
}
/* 本地管理／隨機位址：標成警示色，因為它是「多半不是真衝突」的主要線索 */
.mac-tag--local { background: rgba(240, 160, 32, .16); color: #b26a00; }
</style>
