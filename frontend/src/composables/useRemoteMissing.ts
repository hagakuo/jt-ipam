/**
 * 「未裝 Agent 的 IP」伺服器端分頁（Wazuh 與 OCS 兩頁共用；2026-10-01 起取代瀏覽器端的 useScopeFilter）。
 *
 * 大站台 5 萬筆缺口時，整份清單一次抓回來要 27～42 MB、點進頁籤要等 8～10 秒，
 * 瀏覽器裡篩選又卡住主執行緒 2 秒。現在篩選、排序、分頁都在後端做，一次只拿一頁；
 * 篩選選項（區段／子網路／單位／上線狀態）也由後端從整份缺口算好一起回來，
 * 選了區段之後子網路選單只列那個區段底下的 —— 與以前的行為相同。
 * 上線狀態用的是與 IP 清單燈號同一套規則（後端 agent_scope.classify_liveness，有測試對照）。
 */
import { computed, reactive, ref, shallowRef, watch } from "vue";
import type { DataTableSortState } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useUiStore } from "@/stores/ui";

type Opt = { label: string; value: string };

export interface MissingFacets { sections: Opt[]; subnets: Opt[]; customers: Opt[]; statuses: Opt[] }
export interface MissingPage<T> { items: T[]; total: number; total_all: number; facets: MissingFacets }
export type MissingSort = "ip" | "hostname" | "subnet" | "section" | "customer" | "status" | "device_kind";
export interface MissingQuery {
  page: number;
  page_size: number;
  section_id?: string;
  subnet_id?: string;
  customer_id?: string;
  status?: string;
  q?: string;
  sort?: MissingSort;
  order?: "asc" | "desc";
}

/** 表格欄位 key → 後端的排序欄位（畫面的欄名與 API 不完全一樣） */
const SORT_OF: Record<string, MissingSort> = {
  ip: "ip", hostname: "hostname", subnet: "subnet", section: "section", customer: "customer", status: "status",
  device_kind: "device_kind",
};
const EMPTY: MissingFacets = { sections: [], subnets: [], customers: [], statuses: [] };
/** 匯出時一次拿多少筆（後端上限 100,000） */
const EXPORT_CHUNK = 20_000;

export function useRemoteMissing<T>(fetchPage: (q: MissingQuery) => Promise<MissingPage<T>>) {
  const ui = useUiStore();
  const { t } = useI18n();
  const section = ref<string | null>(null);
  const subnet = ref<string | null>(null);
  const customer = ref<string | null>(null);
  const status = ref<string | null>(null);
  const q = ref("");
  const sortKey = ref<string | null>(null);
  const sortOrder = ref<"ascend" | "descend" | false>(false);

  const rows = shallowRef<T[]>([]);
  const total = ref(0);
  const totalAll = ref(0);
  const facets = shallowRef<MissingFacets>(EMPTY);
  const loading = ref(false);
  const loaded = ref(false);

  function query(page: number, pageSize: number): MissingQuery {
    const out: MissingQuery = { page, page_size: pageSize };
    if (section.value) out.section_id = section.value;
    if (subnet.value) out.subnet_id = subnet.value;
    if (customer.value) out.customer_id = customer.value;
    if (status.value) out.status = status.value;
    if (q.value.trim()) out.q = q.value.trim();
    if (sortKey.value && sortOrder.value && SORT_OF[sortKey.value]) {
      out.sort = SORT_OF[sortKey.value];
      out.order = sortOrder.value === "descend" ? "desc" : "asc";
    }
    return out;
  }

  const pagination = reactive({
    page: 1,
    pageSize: ui.pageSize,
    itemCount: 0,
    showSizePicker: true,
    pageSizes: [10, 20, 50, 100, 200, 500],
    prefix: (info: { itemCount?: number }) => t("common.total_rows", { n: info.itemCount ?? 0 }),
    onUpdatePage: (p: number) => { pagination.page = p; void load(); },
    onUpdatePageSize: (ps: number) => {
      pagination.pageSize = ps;
      ui.setPageSize(ps);
      pagination.page = 1;
      void load();
    },
  });

  // 快速換篩選時可能有好幾個請求同時在路上：只採用最後送出的那個，畫面才不會跳回舊條件的結果
  let seq = 0;
  async function load(): Promise<void> {
    const mine = ++seq;
    loading.value = true;
    try {
      const d = await fetchPage(query(pagination.page, pagination.pageSize));
      if (mine !== seq) return;
      rows.value = d.items;
      total.value = d.total;
      totalAll.value = d.total_all;
      pagination.itemCount = d.total;
      facets.value = d.facets;
      loaded.value = true;
      // 換了區段、原本選的子網路不在新區段裡 → 清掉（會再查一次），免得篩出一片空白又看不出原因
      if (subnet.value && !d.facets.subnets.some((o) => o.value === subnet.value)) subnet.value = null;
    } finally {
      if (mine === seq) loading.value = false;
    }
  }

  function reload() { pagination.page = 1; void load(); }
  watch([section, subnet, customer, status], reload);
  let timer: ReturnType<typeof setTimeout> | undefined;
  watch(q, () => { clearTimeout(timer); timer = setTimeout(reload, 300); });

  /** NDataTable 的 @update:sorter */
  function onSorter(s: DataTableSortState | DataTableSortState[] | null) {
    const one = Array.isArray(s) ? s[0] : s;
    sortKey.value = one && one.order ? String(one.columnKey) : null;
    sortOrder.value = one ? one.order : false;
    reload();
  }

  /** 把欄位的排序交給後端：可排序的欄改成 sorter: true，並由這裡控制箭頭狀態 */
  function remoteSort<C extends Record<string, any>>(cols: C[]): C[] {
    return cols.map((c) => (c.key && SORT_OF[c.key]
      ? { ...c, sorter: true, sortOrder: sortKey.value === c.key ? sortOrder.value : false }
      : { ...c, sorter: undefined }));
  }

  /** 匯出用：依目前的篩選與排序抓整份（分批，每批 EXPORT_CHUNK 筆） */
  async function fetchAll(): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; page <= 1000; page++) {
      const d = await fetchPage(query(page, EXPORT_CHUNK));
      out.push(...d.items);
      if (d.items.length < EXPORT_CHUNK || out.length >= d.total) break;
    }
    return out;
  }

  const active = computed(() => !!(section.value || subnet.value || customer.value || status.value || q.value.trim()));

  return {
    section, subnet, customer, status, q, rows, total, totalAll, facets, loading, loaded, active,
    pagination, load, onSorter, remoteSort, fetchAll,
  };
}
