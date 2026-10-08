<script setup lang="ts">
/**
 * 全域 IP 異動記錄 (feature B)：搜尋 / 篩選 / 分頁。
 * 後端 GET /api/v1/ip-changes，依 subnet 可見性過濾。
 */
import { computed, h, onMounted, ref, watch } from "vue";
import {
  NButton, NCard, NDataTable, NInput, NPagination, NSelect, NSpace, NTag, NText,
} from "naive-ui";
import type { DataTableColumns } from "naive-ui";
import { useI18n } from "vue-i18n";
import {
  listIpChanges, IP_CHANGE_EVENT_TYPES, IP_CHANGE_SOURCES,
  type IPChangeLog,
} from "@/api/ip_history";
import { sourceLabel } from "@/utils/sourceLabel";
import { fmtDateTime } from "@/utils/datetime";
import { useChangeLogDim } from "@/composables/useChangeLogDim";
import ExportButton from "@/components/ExportButton.vue";
import { listSubnets } from "@/api/subnets";
import { listSections } from "@/api/sections";
import { useCustomers } from "@/composables/useCustomers";

const { t } = useI18n();

/** 沒有對應翻譯的事件型別（舊資料、未來新增的）直接顯示原值，
 *  不要把 `ipChanges.event.xxx` 這種鍵名露在畫面上。與 IPAddressEditModal 同一套作法。 */
function eventLabel(e: string): string {
  const key = `ipChanges.event.${e}`;
  const out = t(key);
  return out === key ? e : out;
}
const { isOld: isOldLog } = useChangeLogDim();

const rows = ref<IPChangeLog[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(50);
const loading = ref(false);

const q = ref("");
const eventType = ref<string | null>(null);
const source = ref<string | null>(null);
// 範圍篩選：區段 / 子網路 / 單位。三個各自獨立（後端是 AND），
// 因為現場的問法是「這個單位這週有什麼變動」也可能是「這個網段有什麼變動」。
const sectionId = ref<string | null>(null);
const subnetId = ref<string | null>(null);
const customerId = ref<string | null>(null);

const subnetOptions = ref<{ label: string; value: string; section_id: string }[]>([]);
const sectionOptions = ref<{ label: string; value: string }[]>([]);
const { options: customerOptions, ensureLoaded: loadCustomers } = useCustomers();

// 選了區段就只列該區段底下的子網路 —— 兩個下拉互相矛盾時，
// 使用者會以為篩選壞了（實際上是 AND 之後沒有交集）
const visibleSubnetOptions = computed(() => sectionId.value
  ? subnetOptions.value.filter((o) => o.section_id === sectionId.value)
  : subnetOptions.value);

async function loadFilterOptions() {
  try {
    // 一次抓完：清單頁只拿第一頁會讓下拉少東西，而且完全看不出來
    const [subs, secs] = await Promise.all([
      listSubnets({ page: 1, pageSize: 500 }),
      listSections(1, 500),
    ]);
    subnetOptions.value = subs.items.map((x) => ({
      label: x.description ? `${x.cidr} — ${x.description}` : x.cidr,
      value: x.id, section_id: x.section_id,
    }));
    sectionOptions.value = secs.items.map((x) => ({ label: x.name, value: x.id }));
  } catch { /* 下拉載不到不影響主要清單 */ }
  // 單位清單一般帳號也讀得到，但失敗就當作沒有這個篩選，不要讓整頁報錯
  try { await loadCustomers(); } catch { /* silent */ }
}

const eventOptions = computed(() => [
  { label: t("ipChanges.all_events"), value: "" },
  ...IP_CHANGE_EVENT_TYPES.map((e) => ({ label: eventLabel(e), value: e })),
]);
const sourceOptions = computed(() => [
  { label: t("ipChanges.all_sources"), value: "" },
  ...IP_CHANGE_SOURCES.map((s) => ({ label: sourceLabel(t, s), value: s })),
]);

// 事件 → tag 顏色
const EVENT_TYPE: Record<string, "default" | "info" | "success" | "warning" | "error"> = {
  created: "success", deleted: "error",
  online: "success", offline: "warning",
  hostname_changed: "info", mac_changed: "info", arp_changed: "info",
  os_changed: "warning", kind_changed: "warning",
  state_changed: "warning", edited: "default",
};

async function load() {
  loading.value = true;
  try {
    const r = await listIpChanges({
      q: q.value.trim() || undefined,
      event_type: eventType.value || undefined,
      source: source.value || undefined,
      section_id: sectionId.value || undefined,
      subnet_id: subnetId.value || undefined,
      customer_id: customerId.value || undefined,
      page: page.value,
      page_size: pageSize.value,
    });
    rows.value = r.items;
    total.value = r.total;
  } finally {
    loading.value = false;
  }
}

// 篩選改變 → 回到第一頁重查
let timer: ReturnType<typeof setTimeout> | null = null;
watch(sectionId, () => {
  // 換區段時，原本選的子網路可能不屬於它 —— 留著會變成「查不到任何資料」的無聲陷阱
  if (subnetId.value && !visibleSubnetOptions.value.some((o) => o.value === subnetId.value)) {
    subnetId.value = null;
  }
});
watch([q, eventType, source, sectionId, subnetId, customerId], () => {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => { page.value = 1; load(); }, 300);
});
watch([page, pageSize], load);
onMounted(() => { void load(); void loadFilterOptions(); });

const columns = computed<DataTableColumns<IPChangeLog>>(() => [
  {
    title: t("ipChanges.col_time"), key: "created_at", width: 170,
    render: (r) => fmtDateTime(r.created_at),
  },
  { title: t("ipChanges.col_ip"), key: "ip_text", width: 150, ellipsis: { tooltip: true } },
  {
    title: t("ipChanges.col_event"), key: "event_type", width: 130,
    render: (r) => h(NTag, { size: "small", type: EVENT_TYPE[r.event_type] ?? "default", bordered: false },
      { default: () => eventLabel(r.event_type) }),
  },
  { title: t("ipChanges.col_field"), key: "field", width: 110, render: (r) => r.field ?? "—" },
  {
    title: t("ipChanges.col_change"), key: "change", minWidth: 220,
    render: (r) => {
      if (r.old_value == null && r.new_value == null) return "—";
      return h("span", {}, [
        h(NText, { depth: 3, delete: true }, { default: () => r.old_value ?? "∅" }),
        " → ",
        h(NText, { strong: true }, { default: () => r.new_value ?? "∅" }),
      ]);
    },
  },
  {
    title: t("ipChanges.col_source"), key: "source", width: 100,
    render: (r) => h(NTag, { size: "small", bordered: false }, { default: () => sourceLabel(t, r.source) }),
  },
  {
    title: t("ipChanges.col_actor"), key: "actor", width: 120,
    render: (r) => r.actor_username ?? (r.source === "manual" ? "—" : sourceLabel(t, r.source)),
  },
]);
</script>

<template>
  <n-card :title="t('ipChanges.title')" :bordered="false">
    <!-- 卡片標題列只放標題。說明文字與動作都屬於內容區：
         說明自成一行，動作靠右與篩選同一列 —— 動作不會自己佔掉一整條空帶，
         也不會因為多加幾個篩選就被擠到下一行單獨一個。 -->
    <n-text depth="3" class="ipchg-subtitle">{{ t("ipChanges.subtitle") }}</n-text>

    <n-space align="center" class="ipchg-toolbar">
      <n-input
        v-model:value="q" clearable
        :placeholder="t('ipChanges.search_placeholder')"
        style="width: 280px"
      />
      <n-select
        v-model:value="eventType" :options="eventOptions"
        clearable style="width: 160px"
        :placeholder="t('ipChanges.all_events')"
      />
      <n-select
        v-model:value="source" :options="sourceOptions"
        clearable style="width: 140px"
        :placeholder="t('ipChanges.all_sources')"
      />
      <n-select
        v-model:value="sectionId" :options="sectionOptions"
        clearable filterable style="width: 160px"
        :placeholder="t('ipChanges.all_sections')"
      />
      <n-select
        v-model:value="subnetId" :options="visibleSubnetOptions"
        clearable filterable style="width: 200px"
        :placeholder="t('ipChanges.all_subnets')"
      />
      <n-select
        v-if="customerOptions.length"
        v-model:value="customerId" :options="customerOptions"
        clearable filterable style="width: 170px"
        :placeholder="t('ipChanges.all_customers')"
      />
      <!-- 兩顆動作綁成同一個 flex 子項：換行時要一起換，
           不然會出現「重新整理留在上一行、匯出自己掉到下一行」的破碎排法 -->
      <n-space align="center" :size="8" :wrap-item="false">
        <n-button @click="load" :loading="loading">{{ t("common.refresh") }}</n-button>
        <ExportButton :columns="columns" :rows="rows" filename="ip-changes"
                      :title="t('nav.ip_changes')" />
      </n-space>
    </n-space>

    <n-data-table
      :columns="columns"
      :data="rows"
      :loading="loading"
      :bordered="false"
      size="small"
      :scroll-x="1000"
      :row-class-name="(r:any) => isOldLog(r.created_at) ? 'log-dim' : ''"
    />

    <!-- 手機上放不下時分頁換到下一行，「共 N 筆」不被擠成直排 -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 12px; flex-wrap: wrap; gap: 8px">
      <span style="font-size: 13px; opacity: 0.7; white-space: nowrap">{{ t("common.total_rows", { n: total }) }}</span>
      <n-pagination
        v-model:page="page"
        v-model:page-size="pageSize"
        :item-count="total"
        :page-sizes="[20, 50, 100, 200]"
        show-size-picker
      />
    </div>
  </n-card>
</template>

<style scoped>
.ipchg-subtitle { display: block; font-size: 12px; margin-bottom: 10px; }
/* 篩選與動作在同一個會換行的群組裡，依序排下去。
   刻意不做「動作靠右」：靠右在寬度不夠時會自己換到一整列去，
   畫面上就多一條只有兩顆按鈕的空帶（拓樸圖原本就是這樣，使用者回報過）。 */
.ipchg-toolbar { flex-wrap: wrap; row-gap: 8px; margin-bottom: 12px; }

/* 異動記錄超過 N 天（系統設定）的列以淡色顯示 */
:deep(tr.log-dim td) { opacity: .45; }
</style>
