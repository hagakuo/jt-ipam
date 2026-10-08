<script setup lang="ts">
/**
 * 對外開放服務清單：從外面可達的服務，每項配 IPAM 身分。
 *
 * 異常偵測的「對外曝險」是抓問題；這一頁是**清單**——資安稽核第一個要的東西。
 * 只列明確可判定的開口；未登錄的目標用紅色標出（對外開口指向不明主機，本身就是警訊）。
 * 欄位拆開（IP／埠／主機名稱／類型／名稱／防火牆各自獨立）才能排序與比對；
 * 欄位顯示走全站的欄位偏好，來源可依防火牆廠牌篩選。
 *
 * ⚠️ API 回的是巢狀物件（identity.ip 等），進表格前先攤平成 Row——
 * 欄位 key 對不到資料列的話，autoSort 的 sorter 取到的全是 undefined，
 * 點欄位標題永遠沒反應（使用者回饋）。排序／篩選／搜尋一律吃攤平後的欄位。
 */
import { computed, onMounted, ref, watch, h } from "vue";
import {
  NCard, NSpace, NIcon, NTag, NDataTable, NEmpty, NAlert, NButton, NSelect, NInput,
  NPopover, NTabs, NTabPane, useMessage, type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { apiClient, apiErrMsg } from "@/api/client";
import { FirewallIcon, RefreshIcon, SearchIcon } from "@/icons";
import { autoSort } from "@/composables/useTableSort";
import { useTablePagination } from "@/composables/useTablePagination";
import { useColumnPrefs } from "@/composables/useColumnPrefs";
import ColumnPicker from "@/components/ColumnPicker.vue";
import { useRouter } from "vue-router";
import { useEntityLinks } from "@/composables/useEntityLinks";
import { deviceKindColumn } from "@/utils/deviceKindCell";

const { t, te } = useI18n();
const msg = useMessage();
const pg = useTablePagination();
const links = useEntityLinks(useRouter());

interface Entry {
  via: string; source: string; firewall: string | null; name: string;
  protocol: string | null; port: number | string | null; descr: string;
  identity: { registered: boolean; ip?: string; ip_id?: string; hostname?: string | null;
              status?: string | null; subnet?: string | null;
              customer?: string | null; wazuh?: string | null; fqdns?: string[];
              device_kind?: string | null; device_model?: string | null };
}
/** 攤平後的表格列：欄位 key 與 column key 一一對應，排序／搜尋才有得比。 */
interface Row {
  ip: string | null; ip_id?: string; registered: boolean;
  port: number | null; portText: string;
  hostname: string | null; device_kind: string | null; device_model: string | null; via: string; name: string;
  firewall: string | null; source: string; protocol: string | null;
  owner: string | null; wazuh: string | null;
  status: string | null; online: boolean | null; statusSrc: string;
  descr: string; key: string; fqdns: string[];
  /** 這一列的穩定識別。**不可以用陣列索引** —— 過濾之後同一個索引會指到不同的列，
   *  表格會拿舊的列來重用，於是被篩掉的列還留在畫面上（實機遇過：搜尋 A 卻看到 B）。 */
  uid: string;
}
const items = ref<Entry[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const { data } = await apiClient.get("/api/v1/anomalies/attack-surface");
    items.value = data.items ?? [];
  } catch (e: any) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}
onMounted(load);

const rows = computed<Row[]>(() => items.value.map((i, idx) => {
  const ident = i.identity ?? { registered: false };
  const raw = ident.status ?? null;
  const online = raw ? raw.toLowerCase().startsWith("online") : null;
  const pn = Number(i.port);
  return {
    ip: ident.ip ?? null, ip_id: ident.ip_id, registered: !!ident.registered,
    // 埠轉成數字才能正確排序（來源混雜 int 與字串；空字串／區間視為無埠）
    port: i.port == null || i.port === "" || Number.isNaN(pn) ? null : pn,
    portText: i.port == null || i.port === "" ? "" : String(i.port),
    hostname: ident.hostname ?? null,
    device_kind: ident.device_kind ?? null, device_model: ident.device_model ?? null,
    via: i.via, name: i.name || "", firewall: i.firewall, source: i.source,
    // 協定統一大寫（NAT 同步存小寫、規則存大寫，混著顯示很刺眼——使用者回饋）
    protocol: i.protocol ? String(i.protocol).toUpperCase() : null,
    owner: ident.customer || ident.subnet || null,
    wazuh: ident.wazuh ?? null,
    status: raw ? (online ? t("surface.st_online") : t("surface.st_offline")) : null,
    online, statusSrc: raw ? ((raw.match(/\(([^)]+)\)/)?.[1]) ?? "") : "",
    descr: i.descr || "",
    fqdns: ident.fqdns ?? [],
    key: `${ident.ip ?? "?"}:${i.port ?? ""}`,
    // 在**未過濾**的來源清單裡的位置 —— 只有重新載入資料才會變
    uid: `r${idx}`,
  };
}));

// 篩選：選項一律由資料動態產生（新增廠牌／協定／單位都不必改程式）。
// 各下拉與搜尋框是「且」的關係，疊加過濾。
const sourceFilter = ref<string | null>(null);
// 防火牆「實例」的篩選。原本只能選類型（opnsense / pfsense…），但同一種類型底下
// 常常有好幾台，而使用者要問的是「**這一台**開了哪些對外服務」。
const firewallFilter = ref<string | null>(null);
const viaFilter = ref<string | null>(null);
const protoFilter = ref<string | null>(null);
const statusFilter = ref<string | null>(null);
const ownerFilter = ref<string | null>(null);
const searchText = ref("");

// 換了類型而原本選的那一台不屬於它時，把實例選擇清掉 —— 留著會得到一張空表格，
// 而畫面上沒有任何地方說明為什麼。
watch(sourceFilter, () => {
  if (!firewallFilter.value || firewallFilter.value === "__all__") return;
  const stillThere = rows.value.some(
    (r) => pick(sourceFilter.value, r.source) && r.firewall === firewallFilter.value);
  if (!stillThere) firewallFilter.value = null;
});

function opts(values: (string | null | undefined)[], allLabel: string) {
  const seen = [...new Set(values.filter((v): v is string => !!v))].sort();
  return [{ label: allLabel, value: "__all__" }, ...seen.map((v) => ({ label: v, value: v }))];
}
const sourceOptions = computed(() => opts(rows.value.map((r) => r.source), t("surface.all_sources")));
// 選了類型之後，實例清單只列那個類型底下的 —— 選項裡出現「不可能有結果」的組合，
// 使用者選下去只會看到空白表格而沒有任何解釋。
const firewallOptions = computed(() => opts(
  rows.value.filter((r) => pick(sourceFilter.value, r.source)).map((r) => r.firewall),
  t("surface.all_firewalls")));
const viaOptions = computed(() => [
  { label: t("surface.all_via"), value: "__all__" },
  { label: "NAT", value: "nat" }, { label: t("surface.rule"), value: "rule" },
]);
const protoOptions = computed(() => opts(rows.value.map((r) => r.protocol), t("surface.all_proto")));
const statusOptions = computed(() => opts(rows.value.map((r) => r.status), t("surface.all_status")));
const ownerOptions = computed(() => opts(rows.value.map((r) => r.owner), t("surface.all_owner")));

// NAT ↔ 規則配對：pfSense/OPNsense 的埠轉發常帶一條關聯放行規則。
// 同目標 IP＋同埠同時存在 NAT 列與規則列 → 兩列都標「配對」，一眼看出它們是一組。
// 純資料比對，不猜語意；對不上的（例如規則沒寫埠）就不標。
const pairedKeys = computed(() => {
  const nat = new Set<string>(), rule = new Set<string>();
  for (const r of rows.value) (r.via === "nat" ? nat : rule).add(r.key);
  return new Set([...nat].filter((k) => rule.has(k)));
});
const isPaired = (r: Row) => pairedKeys.value.has(r.key);

// 配對標籤要說得出「跟誰配對」（使用者回饋）：同鍵的其它列就是配對對象，
// hover／點擊標籤彈出卡片列出來（類型＋名稱＋防火牆）。
const pairMap = computed(() => {
  const m = new Map<string, Row[]>();
  for (const r of rows.value) {
    if (!pairedKeys.value.has(r.key)) continue;
    if (!m.has(r.key)) m.set(r.key, []);
    m.get(r.key)!.push(r);
  }
  return m;
});
const counterparts = (r: Row): Row[] =>
  (pairMap.value.get(r.key) ?? []).filter((x) => x !== r);

const pick = (f: string | null, v: string | null | undefined) =>
  !f || f === "__all__" || (v ?? "") === f;
const shown = computed(() => {
  let out = rows.value.filter((r) =>
    pick(sourceFilter.value, r.source)
    && pick(firewallFilter.value, r.firewall)
    && pick(viaFilter.value, r.via)
    && pick(protoFilter.value, r.protocol)
    && pick(statusFilter.value, r.status)
    && pick(ownerFilter.value, r.owner));
  const q = searchText.value.trim().toLowerCase();
  if (q) {
    out = out.filter((r) =>
      [r.ip, r.hostname, r.name, r.descr, r.portText, r.firewall, r.owner,
       r.fqdns.join(" ")]
        .some((v) => (v ?? "").toString().toLowerCase().includes(q)));
  }
  return out;
});

// ── FQDN 視角 ───────────────────────────────────────────────
// 稽核與對外服務盤點時，人記得的是名字不是位址（「meet 對外開了什麼」）。
// 名稱來自 IPAM 已同步的 DNS 記錄（A/AAAA 直接命中、CNAME 別名往上追），
// 不做即時解析 —— 清單要可重現，不能因為外部 DNS 變動而每次不同。
interface FqdnRow {
  fqdn: string; ip: string | null; ip_id?: string; registered: boolean;
  ports: string; portCount: number; owner: string | null;
  status: string | null; online: boolean | null;
  firewalls: string; names: string; key: string;
}
const fqdnRows = computed<FqdnRow[]>(() => {
  const by = new Map<string, Row[]>();
  for (const r of shown.value) {
    for (const f of r.fqdns) {
      if (!by.has(f)) by.set(f, []);
      by.get(f)!.push(r);
    }
  }
  return [...by.entries()].map(([fqdn, rs]) => {
    const ports = [...new Set(rs.map((r) => (r.protocol ? `${r.protocol.toLowerCase()}/` : "")
                                            + (r.portText || "—")))].sort();
    const first = rs[0];
    return {
      fqdn, ip: first.ip, ip_id: first.ip_id, registered: first.registered,
      ports: ports.join("、"), portCount: ports.length,
      owner: first.owner, status: first.status, online: first.online,
      firewalls: [...new Set(rs.map((r) => r.firewall).filter(Boolean))].join("、"),
      names: [...new Set(rs.map((r) => r.name).filter(Boolean))].join("、"),
      key: fqdn,
    };
  }).sort((a, b) => a.fqdn.localeCompare(b.fqdn));
});
// 有對外開口、卻沒有任何 DNS 名稱對應 —— FQDN 視角看不到它們，要明講有幾筆，
// 否則使用者會以為「FQDN 頁籤的筆數就是全部」。
const noFqdnCount = computed(() => shown.value.filter((r) => !r.fqdns.length).length);

const fqdnCols = computed<DataTableColumns<FqdnRow>>(() => autoSort([
  { title: () => t("surface.col_fqdn"), key: "fqdn", width: 260, ellipsis: { tooltip: true } },
  { title: () => t("surface.col_ip"), key: "ip", width: 150,
    render: (r: FqdnRow) => r.registered && r.ip_id
      ? links.ipById(r.ip_id, r.ip ?? "") : (r.ip ?? "—") },
  { title: () => t("surface.col_ports"), key: "ports", minWidth: 200,
    ellipsis: { tooltip: true }, render: (r: FqdnRow) => r.ports || "—" },
  { title: () => t("surface.col_name"), key: "names", minWidth: 200,
    ellipsis: { tooltip: true }, render: (r: FqdnRow) => r.names || "—" },
  { title: () => t("surface.col_firewall"), key: "firewalls", width: 180,
    render: (r: FqdnRow) => r.firewalls || "—" },
  { title: () => t("surface.col_owner"), key: "owner", width: 190,
    render: (r: FqdnRow) => r.owner || "—" },
  { title: () => t("surface.col_status"), key: "status", width: 130,
    render: (r: FqdnRow) => r.status
      ? h("span", { style: "display:inline-flex;align-items:center;gap:6px" }, [
          h("i", { style: `width:8px;height:8px;border-radius:50%;flex:none;background:${r.online ? "#22c55e" : "#ef4444"}` }),
          r.status,
        ])
      : "—" },
]));
const tab = ref<"ip" | "fqdn">("ip");

const ALL_KEYS = ["ip", "port", "hostname", "device_kind", "via", "name", "firewall",
                  "protocol", "owner", "wazuh", "status", "descr"];
const { visibleKeys, setVisible, reset, order, setOrder, orderColumns } =
  useColumnPrefs("attack_surface", ALL_KEYS, ALL_KEYS);
const pickerCols = computed(() => ALL_KEYS.map((k) => ({
  key: k, label: k === "device_kind" ? t("cols.device_kind") : t(`surface.col_${k}`) })));

const allCols: Record<string, any> = {
  ip: { title: () => t("surface.col_ip"), key: "ip", width: 150,
    render: (r: Row) => r.registered
      // IPAM 有這筆 → 點過去 IP 卡片（全站同一套 entity link）
      ? (r.ip_id ? links.ipById(r.ip_id, r.ip ?? "") : r.ip)
      : h("span", null, ["?", h(NTag, { size: "tiny", type: "error", style: "margin-left:6px" },
          { default: () => t("surface.unregistered") })]) },
  port: { title: () => t("surface.col_port"), key: "port", width: 90,
    render: (r: Row) => r.portText || "—" },
  hostname: { title: () => t("surface.col_hostname"), key: "hostname", width: 160,
    render: (r: Row) => r.hostname || "—" },
  // 對外開的是攝影機、NAS 還是伺服器（掃描代理判讀出的設備類型，滑過看型號）
  device_kind: deviceKindColumn(t, te),
  via: { title: () => t("surface.col_via"), key: "via", width: 130,
    render: (r: Row) => h("span", { style: "display:inline-flex;align-items:center;gap:6px" }, [
      r.via === "nat" ? "NAT" : t("surface.rule"),
      isPaired(r) ? h(NPopover, { trigger: "hover", placement: "right" }, {
        trigger: () => h(NTag, { size: "tiny", type: "info", bordered: false,
                                 style: "cursor: pointer" },
                         { default: () => t("surface.paired") }),
        default: () => h("div", { style: "max-width: 340px; font-size: 12.5px; line-height: 1.8" }, [
          h("div", { style: "opacity:.7; margin-bottom: 2px" }, t("surface.paired_with")),
          ...counterparts(r).map((c) => h("div",
            { style: "display:flex;align-items:center;gap:6px" }, [
              h(NTag, { size: "tiny", type: c.via === "nat" ? "warning" : "success",
                        bordered: false, style: "flex:none" },
                { default: () => c.via === "nat" ? "NAT" : t("surface.rule") }),
              h("span", null, c.name || "—"),
              c.firewall ? h("span", { style: "opacity:.6" }, `（${c.firewall}）`) : null,
            ])),
          h("div", { style: "opacity:.6; margin-top: 4px; font-size: 11.5px" },
            t("surface.paired_tip")),
        ]),
      }) : null,
    ]) },
  name: { title: () => t("surface.col_name"), key: "name", width: 220,
    ellipsis: { tooltip: true }, render: (r: Row) => r.name || "—" },
  firewall: { title: () => t("surface.col_firewall"), key: "firewall", width: 180,
    render: (r: Row) => h("span", null, [
      h(NTag, { size: "tiny", style: "margin-right:6px" }, { default: () => r.source }),
      r.firewall || "—",
    ]) },
  protocol: { title: () => t("surface.col_protocol"), key: "protocol", width: 90,
    render: (r: Row) => r.protocol || "—" },
  owner: { title: () => t("surface.col_owner"), key: "owner", width: 190,
    render: (r: Row) => r.owner || "—" },
  wazuh: { title: "Wazuh", key: "wazuh", width: 110,
    render: (r: Row) => r.registered
      ? (r.wazuh
          ? h(NTag, { size: "tiny", type: "success" }, { default: () => r.wazuh })
          : h("span", { style: "opacity:.6" }, t("surface.no_agent")))
      : "—" },
  status: { title: () => t("surface.col_status"), key: "status", width: 130,
    render: (r: Row) => {
      if (!r.status) return "—";
      return h("span", { style: "display:inline-flex;align-items:center;gap:6px" }, [
        h("i", { style: `width:8px;height:8px;border-radius:50%;flex:none;background:${r.online ? "#22c55e" : "#ef4444"}` }),
        r.status,
        r.statusSrc ? h("span", { style: "opacity:.55;font-size:11.5px" }, r.statusSrc) : null,
      ]);
    } },
  descr: { title: () => t("surface.col_descr"), key: "descr", minWidth: 200,
    ellipsis: { tooltip: true } },
};
const cols = computed<DataTableColumns<Row>>(
  () => autoSort(orderColumns(ALL_KEYS.filter((k) => visibleKeys.value.includes(k)).map((k) => allCols[k]))));
// 表格要在卡片內水平捲動，不能溢出卡片右緣（使用者截圖）：
// scroll-x 取「可見欄寬總和」，欄位少的時候不強撐寬度。
const scrollX = computed(() =>
  ALL_KEYS.filter((k) => visibleKeys.value.includes(k))
    .reduce((sum, k) => sum + (allCols[k].width ?? allCols[k].minWidth ?? 160), 0));
</script>

<template>
  <n-card :bordered="false">
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><FirewallIcon /></n-icon>
        <span>{{ t("surface.title") }}</span>
      </n-space>
    </template>
    <n-alert type="info" :bordered="false" style="margin-bottom: 12px">
      {{ t("surface.hint") }}<br>{{ t("surface.scope_note") }}
    </n-alert>
    <!-- 工具列與其它頁一致：放內文、不佔卡片標題列；全部 size=small 高度對齊 -->
    <n-space align="center" style="margin-bottom: 10px">
      <n-input v-model:value="searchText" clearable style="width: 220px"
               :placeholder="t('surface.search_ph')">
        <template #prefix><n-icon><SearchIcon /></n-icon></template>
      </n-input>
      <n-select v-model:value="sourceFilter" :options="sourceOptions"
                style="width: 150px"
                :placeholder="t('surface.all_sources')" clearable />
      <n-select v-model:value="firewallFilter" :options="firewallOptions" style="width: 170px"
                :placeholder="t('surface.all_firewalls')" filterable clearable />
      <n-select v-model:value="viaFilter" :options="viaOptions" style="width: 120px"
                :placeholder="t('surface.all_via')" clearable />
      <n-select v-model:value="protoFilter" :options="protoOptions" style="width: 120px"
                :placeholder="t('surface.all_proto')" clearable />
      <n-select v-model:value="statusFilter" :options="statusOptions" style="width: 140px"
                :placeholder="t('surface.all_status')" clearable />
      <n-select v-model:value="ownerFilter" :options="ownerOptions" style="width: 170px"
                :placeholder="t('surface.all_owner')" clearable />
      <ColumnPicker :all="pickerCols" :visible="visibleKeys"
                    @update:visible="setVisible" @reset="reset"
                    :order="order" @update:order="setOrder" />
      <n-button size="small" :loading="loading" @click="load">
        <template #icon><n-icon><RefreshIcon /></n-icon></template>
        {{ t("common.refresh") }}
      </n-button>
    </n-space>
    <n-tabs v-model:value="tab" type="line" animated size="small">
      <n-tab-pane name="ip" :tab="`${t('surface.tab_ip')} (${shown.length})`">
        <n-data-table :columns="cols" :data="shown" :loading="loading" size="small"
                      :scroll-x="scrollX"
                      :row-key="(r: Row) => r.uid"
                      :pagination="pg" :bordered="false" />
        <n-empty v-if="!loading && !shown.length" style="margin: 24px 0"
                 :description="t('surface.empty')" />
      </n-tab-pane>
      <n-tab-pane name="fqdn" :tab="`${t('surface.tab_fqdn')} (${fqdnRows.length})`">
        <!-- 沒有 DNS 名稱的開口在這個視角看不到 → 明講筆數，避免被當成全部 -->
        <n-alert v-if="noFqdnCount" type="warning" :bordered="false" size="small"
                 style="margin-bottom: 10px">
          {{ t("surface.no_fqdn_note", { n: noFqdnCount }) }}
        </n-alert>
        <n-data-table :columns="fqdnCols" :data="fqdnRows" :loading="loading" size="small"
                      :scroll-x="1110" :row-key="(r: FqdnRow) => r.key"
                      :pagination="pg" :bordered="false" />
        <n-empty v-if="!loading && !fqdnRows.length" style="margin: 24px 0"
                 :description="t('surface.empty_fqdn')" />
      </n-tab-pane>
    </n-tabs>
  </n-card>
</template>
