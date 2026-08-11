<template>
  <n-card>
    <template #header>
      <CardTitle :icon="AnomalyIcon" :text="t('ai_audit.title')">
        <n-tag v-if="summary" size="small" round :bordered="false">{{ summary.total }}</n-tag>
      </CardTitle>
    </template>
    <template #header-extra>
      <n-space :size="8">
        <n-button size="small" :loading="loading" @click="load">
          <template #icon><n-icon><RefreshIcon /></n-icon></template>{{ t("common.refresh") }}
        </n-button>
        <!-- 清除是刪除、不是全部忽略：忽略會留下指紋，往後同一件事都自動略過，
             跟「清掉再重新分析一次」正好相反。所以確認文字要把後果講明白。 -->
        <n-popconfirm v-if="canRun && (summary?.total ?? 0) > 0" @positive-click="clearAll">
          <template #trigger>
            <n-button size="small" :loading="clearing">
              <template #icon><n-icon><DeleteIcon /></n-icon></template>{{ t("ai_audit.clear_all") }}
            </n-button>
          </template>
          {{ t("ai_audit.clear_confirm") }}
        </n-popconfirm>
        <n-button v-if="canRun" size="small" type="primary" :loading="running" @click="runNow">
          <template #icon><n-icon><TestIcon /></n-icon></template>{{ t("ai_audit.run_now") }}
        </n-button>
      </n-space>
    </template>

    <!-- 這是 LLM 的推測，不是查核過的事實。放在最上面，不是藏在角落的小字。 -->
    <n-alert type="warning" :bordered="false" :show-icon="true" style="margin-bottom:14px">
      {{ t("ai_audit.disclaimer") }}
    </n-alert>

    <!-- 執行中的進度：巡檢會跑好幾分鐘、切成很多批，只有轉圈的按鈕等於什麼都沒說 -->
    <div v-if="running" class="run-box">
      <div class="run-head">
        <n-spin :size="14" />
        <span class="run-stage">{{ stageText }}</span>
        <span class="run-elapsed">{{ elapsedText }}</span>
      </div>
      <n-progress type="line" :percentage="percent" :height="8"
                  :processing="percent < 100" :show-indicator="percent > 0" />
      <!-- 講清楚可以走：不講的話，使用者會以為要一直停在這頁盯著 -->
      <div class="run-bg">{{ t("ai_audit.run_background") }}</div>
      <div v-if="progressHint" class="run-hint">
        {{ progressHint }}
        <span v-if="writing">
          · {{ t(writePhase === "thinking" ? "ai_audit.progress_thinking"
                                           : "ai_audit.progress_written", { n: writing }) }}
        </span>
      </div>
    </div>

    <!-- 上一次執行失敗要一直看得到。用 toast 的話，人不在畫面前就永遠不會知道出過事 -->
    <n-alert v-else-if="lastError" type="error" closable :bordered="false"
             style="margin-bottom:14px" @close="lastError = null">
      {{ t("ai_audit.run_failed") }}{{ lastError }}
    </n-alert>

    <!-- 跟儀表板同一組數字：從儀表板點進來之後，看到的第一眼要能對得起來 -->
    <div v-if="summary" class="sev-row">
      <div v-for="sv in (['high', 'medium', 'low'] as const)" :key="sv"
           class="sev-cell" :class="[`sev-${sv}`, { on: severity === sv }]"
           @click="toggleSeverity(sv)">
        <div class="sev-n">{{ summary.counts[sv] }}</div>
        <div class="sev-l">{{ t(`ai_audit.sev_${sv}`) }}</div>
      </div>
      <!-- 發現數不等於問題規模：一筆「命名不一致」可能點名 30 個位址 -->
      <div class="sev-cell sev-ips">
        <div class="sev-n">{{ summary.ip_count }}</div>
        <div class="sev-l">{{ t("ai_audit.related_ips") }}</div>
      </div>
    </div>

    <n-space :size="10" align="center" style="margin-bottom:14px" :wrap="true">
      <n-radio-group v-model:value="status" size="small" @update:value="load">
        <n-radio-button value="open">
          <n-icon :component="AnomalyIcon" class="rb-ic" />{{ t("ai_audit.st_open") }}
        </n-radio-button>
        <n-radio-button value="dismissed">
          <n-icon :component="DismissIcon" class="rb-ic" />{{ t("ai_audit.st_dismissed") }}
        </n-radio-button>
        <n-radio-button value="all">
          <n-icon :component="ListIcon" class="rb-ic" />{{ t("common.all") }}
        </n-radio-button>
      </n-radio-group>
      <n-select v-model:value="severity" size="small" clearable style="width:160px"
                :options="sevOptions" :placeholder="t('ai_audit.all_severity')"
                :render-label="renderSevLabel" :render-tag="renderSevTag"
                @update:value="load" />
      <!-- 分類（對外暴露／資料衝突…）：每則發現都掛著這個標籤，能看不能篩的話，
           一整頁高嚴重度裡要挑出「所有暴露的管理介面」只能用眼睛掃 -->
      <n-select v-model:value="category" size="small" clearable style="width:160px"
                :options="catOptions" :placeholder="t('ai_audit.all_category')"
                @update:value="load" />
      <span v-if="summary?.last_run_at" class="hint">
        {{ t("ai_audit.last_run", { at: fmtDateTime(summary.last_run_at) }) }}
      </span>
    </n-space>

    <n-empty v-if="!loading && !rows.length" :description="t('ai_audit.none')" style="margin:28px 0" />

    <n-spin :show="loading">
      <!-- 欄位標題：點一下換排序。發現是一則一則的長文，不適合塞進表格，
           但至少要能照嚴重度或時間排 —— 20 筆混在一起時，順序決定看不看得完 -->
      <div v-if="rows.length" class="fx-thead">
        <span v-for="c in COLS" :key="c.key" class="th"
              :class="[`th-${c.key}`, { on: sortKey === c.key, sortable: c.key !== 'action' }]"
              @click="toggleSort(c.key)">
          {{ t(c.i18n) }}
          <!-- 排序箭頭每一欄都在（未啟用時淡化），跟系統其他表格一致：
               只有目前排序欄才顯示箭頭的話，使用者不知道其他欄也可以點 -->
          <span v-if="c.key !== 'action'" class="th-sorter"
                :class="{ asc: sortKey === c.key && sortAsc, desc: sortKey === c.key && !sortAsc }">
            <i class="up" />
            <i class="down" />
          </span>
        </span>
      </div>

      <div v-for="f in sortedRows" :key="f.id" class="fx" :class="`fx-${f.severity}`">
        <div class="fx-head">
          <span class="fx-sev-cell" :class="f.severity">
            {{ t(`ai_audit.sev_${f.severity}`) }}
          </span>
          <span class="fx-what">
            <n-tag size="small" round :bordered="false">{{ t(`ai_audit.cat_${f.category}`) }}</n-tag>
            <!-- eslint-disable-next-line vue/no-v-html -->
            <h3 class="fx-title" v-html="renderInlineMarkdown(f.title)"></h3>
          </span>
          <span class="fx-when">
            <!-- 哪個模型寫的：巡檢是推測，換過模型之後要分得出哪幾條出自哪一個，
                 否則無從判斷新模型到底有沒有比較好 -->
            <span v-if="f.model" class="fx-model">{{ t("ai_audit.by_model", { m: f.model }) }}</span>
            <span class="fx-date">{{ fmtDateTime(f.created_at) }}</span>
          </span>
          <n-button v-if="canRun && f.status === 'open'" size="tiny" secondary
                    style="justify-self:end" @click="dismiss(f.id)">
            <template #icon><n-icon><DismissIcon /></n-icon></template>
            {{ t("ai_audit.dismiss") }}
          </n-button>
          <n-button v-else-if="canRun" size="tiny" secondary type="primary"
                    style="justify-self:end" @click="restore(f.id)">
            <template #icon><n-icon><RestoreIcon /></n-icon></template>
            {{ t("ai_audit.restore") }}
          </n-button>
        </div>
        <!-- 這三段都是模型寫的文字，會夾 `code`、**粗體** 這類語法 —— 當純文字印會
             把反引號直接顯示在畫面上。用行內版渲染器（跳脫在前、不產生區塊標籤）。 -->
        <!-- eslint-disable-next-line vue/no-v-html -->
        <p v-if="f.detail" class="fx-detail" v-html="renderInlineMarkdown(f.detail)"></p>
        <div v-if="f.recommendation" class="fx-rec">
          <span class="fx-rec-tag">{{ t("ai_audit.recommendation") }}</span>
          <!-- eslint-disable-next-line vue/no-v-html -->
          <span v-html="renderInlineMarkdown(f.recommendation)"></span>
        </div>
        <!-- 依據資料一定要看得到：沒有它，上面那段話就無從查證。
             IP 直接做成連結 —— 查證要能一鍵翻到那筆紀錄，不是叫人自己去搜尋。 -->
        <div v-if="f.evidence" class="fx-ev">
          <span class="fx-ev-label">{{ t("ai_audit.evidence") }}</span>
          <n-popover v-for="ip in evIps(f.evidence)" :key="ip" trigger="hover"
                     :delay="120" placement="top" @update:show="(v: boolean) => v && loadIp(ip)">
            <template #trigger>
              <span class="fx-ip" @click="goIp(ip)">{{ ip }}</span>
            </template>
            <IpPeek :ip="ip" :data="ipCache[ip]" />
          </n-popover>
          <!-- 裝置與子網路也要能點過去查證 —— 只印一個名字，還是要人自己去搜尋。
               主機名稱也要能懸停看摘要：同一列裡 IP 有、主機名稱沒有，
               使用者得先點進去才知道那台是什麼。 -->
          <n-popover v-for="d in evList(f.evidence, 'devices')" :key="`d-${d}`"
                     trigger="hover" :delay="120" placement="top"
                     @update:show="(v: boolean) => v && loadDev(d)">
            <template #trigger>
              <span class="fx-ref" @click="goDevice(d)">{{ d }}</span>
            </template>
            <DevicePeek :name="d" :data="devCache[d]" />
          </n-popover>
          <span v-for="n in evList(f.evidence, 'subnets')" :key="`s-${n}`"
                class="fx-ref" @click="goSubnet(n)">{{ n }}</span>
          <span v-for="[k, v] in evRest(f.evidence)" :key="k" class="fx-ev-kv">
            <b>{{ evKeyLabel(k) }}</b>{{ v }}
          </span>
        </div>
      </div>
    </n-spin>
  </n-card>
</template>

<script setup lang="ts">
import { computed, h, onBeforeUnmount, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import {
  NAlert, NButton, NCard, NEmpty, NIcon, NPopconfirm, NPopover, NProgress,
  NRadioButton, NRadioGroup, NSelect, NSpace, NSpin, NTag, useMessage,
  type SelectOption,
} from "naive-ui";
import {
  AnomalyIcon, DeleteIcon, DismissIcon, ListIcon, RefreshIcon, RestoreIcon, TestIcon,
} from "@/icons";
import IpPeek, { type IpPeekData } from "@/components/IpPeek.vue";
import DevicePeek, { type DevicePeekData } from "@/components/DevicePeek.vue";
import { listAddresses } from "@/api/addresses";
import { listDevices } from "@/api/basic";
import { listSubnets } from "@/api/subnets";
import CardTitle from "@/components/CardTitle.vue";
import { fmtDateTime } from "@/utils/datetime";
import { renderInlineMarkdown } from "@/utils/markdown";
import { apiErrMsg } from "@/api/client";
import {
  clearAIFindings, dismissAIFindings, getAIAuditStatus, getAIAuditSummary, listAIFindings,
  restoreAIFindings, runAIAudit,
  type AIAuditSummary, type AIAuditTask, type AIFinding,
} from "@/api/system";
import { useAuthStore } from "@/stores/auth";

const { t } = useI18n();
const msg = useMessage();
const auth = useAuthStore();
const router = useRouter();

const rows = ref<AIFinding[]>([]);
const summary = ref<AIAuditSummary | null>(null);
const loading = ref(false);
const running = ref(false);
const status = ref("open");
const severity = ref<string | null>(null);
const category = ref<string | null>(null);

// 執行進度
const stage = ref<string>("");
const progressHint = ref("");
const lastError = ref<string | null>(null);
const startedAt = ref(0);
const elapsed = ref(0);
const ipsSeen = ref(0);
const modelSeen = ref("");
const writing = ref(0);
const writePhase = ref("");

const stageText = computed(() => t(`ai_audit.stage_${stage.value || "collecting"}`));

// 百分比由後端算好寫進作業列 —— 前端自己再算一次的話，兩邊遲早不一致
const percent = ref(0);

const elapsedText = computed(() => {
  const s = elapsed.value;
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
});

// 執行與忽略是管理員操作（後端仍是唯一真相，這裡只是不要給看得到卻按不動的按鈕）
const canRun = computed(() => !!auth.me?.is_admin);

const clearing = ref(false);
/** 清空整份清單，讓下一次巡檢重新報告（包含先前判定為誤報而忽略的）。 */
async function clearAll() {
  clearing.value = true;
  try {
    const r = await clearAIFindings();
    msg.success(t("ai_audit.cleared", { n: r.deleted }));
    await load();
  } catch (e) { msg.error(apiErrMsg(e)); }
  finally { clearing.value = false; }
}

const sevOptions = computed(() => ["high", "medium", "low"].map((s) => ({
  label: t(`ai_audit.sev_${s}`), value: s,
})));

// 與後端 services/ai_audit.py 的 CATEGORIES 同一組；漏一個會出現沒有標籤的選項
// （backend/tests/test_ai_audit_category_filter.py 會檢查翻譯是否齊全）
const CATEGORIES = ["exposure", "stale", "conflict", "naming", "coverage", "policy", "other"];
const catOptions = computed(() => CATEGORIES.map((c) => ({
  label: t(`ai_audit.cat_${c}`), value: c,
})));

// 欄位標題（點一下排序）。發現本身是長文，用表格反而難讀 —— 只把「可以排序的那幾件事」
// 做成標題列。
const COLS = [
  { key: "severity", i18n: "ai_audit.col_severity" },
  { key: "what", i18n: "ai_audit.col_what" },
  { key: "created_at", i18n: "ai_audit.col_when" },
  { key: "action", i18n: "ai_audit.col_action" },
] as const;

type SortKey = (typeof COLS)[number]["key"];
const sortKey = ref<SortKey>("severity");
const sortAsc = ref(false);          // 預設嚴重度由高到低

const SEV_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 };

function toggleSort(k: SortKey) {
  if (k === "action") return;        // 「動作」沒有排序的意義
  if (sortKey.value === k) sortAsc.value = !sortAsc.value;
  else { sortKey.value = k; sortAsc.value = k === "what"; }
}

const sortedRows = computed(() => {
  const dir = sortAsc.value ? 1 : -1;
  return [...rows.value].sort((a, b) => {
    if (sortKey.value === "created_at") {
      return (Date.parse(a.created_at || "") - Date.parse(b.created_at || "")) * dir;
    }
    if (sortKey.value === "what") {
      // 先照分類、同分類再照標題 —— 同一類的問題排在一起才好一次處理完
      const c = t(`ai_audit.cat_${a.category}`).localeCompare(t(`ai_audit.cat_${b.category}`));
      return (c !== 0 ? c : a.title.localeCompare(b.title, undefined, { numeric: true })) * dir;
    }
    const d = (SEV_ORDER[a.severity] ?? 0) - (SEV_ORDER[b.severity] ?? 0);
    // 同嚴重度時用時間當第二順位，順序才穩定（否則每次重新整理都跳來跳去）
    return (d !== 0 ? d : Date.parse(a.created_at || "") - Date.parse(b.created_at || "")) * dir;
  });
});


const SEV_COLOR: Record<string, string> = {
  high: "#d03050", medium: "#f0a020", low: "#909399",
};

// 下拉裡的高／中／低也要有顏色 —— 選單跟清單上的標籤指的是同一件事，顏色不一致會讓人
// 以為是兩套分類
function sevDot(v: string) {
  return h("span", {
    style: `display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;`
      + `background:${SEV_COLOR[v] ?? "#909399"};flex:0 0 auto`,
  });
}

function renderSevLabel(opt: SelectOption) {
  return h("div", { style: "display:flex;align-items:center" },
    [sevDot(String(opt.value)), h("span", {}, String(opt.label))]);
}

function renderSevTag({ option }: { option: SelectOption }) {
  return h("div", { style: "display:flex;align-items:center" },
    [sevDot(String(option.value)), h("span", {}, String(option.label))]);
}

function toggleSeverity(sv: string) {
  severity.value = severity.value === sv ? null : sv;
  void load();
}

// evidence 的鍵名是模型產生的英文；常見的幾個翻成中文，其餘照原樣顯示
// （硬要翻不認得的鍵只會翻出更難懂的東西）
const EV_KEYS: Record<string, string> = {
  note: "ai_audit.ev_note", reason: "ai_audit.ev_reason",
  hostnames: "ai_audit.ev_hostnames", subnets: "ai_audit.ev_subnets",
  devices: "ai_audit.ev_devices", details: "ai_audit.ev_details",
};

function evKeyLabel(k: string) {
  const key = EV_KEYS[k.toLowerCase()];
  return key ? t(key) : k;
}

// IP 詳細卡片：滑過去才查，查過就快取（同一筆發現裡同一個 IP 只查一次）
const ipCache = ref<Record<string, IpPeekData | undefined>>({});
const devCache = ref<Record<string, DevicePeekData | undefined>>({});

/** 懸停時才抓裝置摘要（抓過就留著）。用伺服器端搜尋，不必把整份裝置清單拉下來。 */
async function loadDev(name: string) {
  if (name in devCache.value) return;
  devCache.value[name] = undefined;
  try {
    const r = await listDevices({ q: name, pageSize: 20 });
    const hit = r.items.find((d) => d.name === name)
      ?? r.items.find((d) => d.name?.toLowerCase() === name.toLowerCase());
    devCache.value[name] = hit
      ? {
          type: hit.type, ip: (hit as any).ip ?? null,
          vendor: (hit as any).vendor ?? null, model: (hit as any).model ?? null,
          serial: (hit as any).serial ?? null,
          location: (hit as any).location_name ?? null,
          description: hit.description ?? null,
        }
      : { missing: true };
  } catch {
    devCache.value[name] = { missing: true };
  }
}

async function loadIp(ip: string) {
  if (ipCache.value[ip] !== undefined) return;
  ipCache.value = { ...ipCache.value, [ip]: undefined };
  try {
    const r = await listAddresses({ q: ip, exact: true, pageSize: 1 });
    const a = r.items[0];
    ipCache.value = {
      ...ipCache.value,
      [ip]: a
        ? {
            hostname: a.hostname,
            state: a.state, effective_status: (a as any).effective_status ?? null,
            mac: a.mac, device_name: (a as any).device_name ?? null,
            description: a.description,
            is_gateway: (a as any).is_gateway ?? null,
            is_dhcp_server: (a as any).is_dhcp_server ?? null,
            in_dhcp_range: (a as any).in_dhcp_range ?? null,
            last_seen: (a as any).last_seen_scanner ?? (a as any).last_seen_librenms ?? null,
          }
        : { missing: true },
    };
  } catch {
    ipCache.value = { ...ipCache.value, [ip]: { missing: true } };
  }
}

// evidence 的內容是模型產生的，鍵名不保證是哪些 —— IP 清單挑出來做成連結，
// 其餘一律照原樣列出。看不懂的形狀也要顯示出來，不能因為不認得就藏起來。
function evIps(ev: Record<string, unknown> | null): string[] {
  const v = ev?.ips;
  return Array.isArray(v) ? v.map((x) => String(x)).slice(0, 30) : [];
}

/** evidence 裡的字串陣列（devices / subnets…）。 */
function evList(ev: Record<string, unknown> | null, key: string): string[] {
  const v = ev?.[key];
  if (Array.isArray(v)) return v.map((x) => String(x)).slice(0, 20);
  return typeof v === "string" && v.trim() ? [v.trim()] : [];
}

// 已經做成可點連結的鍵不再重複列一次純文字
const LINKED_KEYS = new Set(["ips", "devices", "subnets"]);

function evRest(ev: Record<string, unknown> | null): [string, string][] {
  if (!ev) return [];
  return Object.entries(ev)
    .filter(([k]) => !LINKED_KEYS.has(k))
    .map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]);
}

function goIp(ip: string) {
  router.push({ name: "addresses", query: { q: ip, exact: "1" } }).catch(() => {});
}

/** 裝置名稱 → 直接開該裝置的詳細資料；找不到才退回清單並說明。
 *  只把人帶到未篩選的整份清單，等於沒有幫上忙。 */
async function goDevice(name: string) {
  try {
    const r = await listDevices({ q: name, pageSize: 20 });
    const hit = r.items.find((d) => d.name === name)
      ?? r.items.find((d) => d.name?.toLowerCase() === name.toLowerCase());
    if (hit) {
      await router.push({ name: "device-detail", params: { id: hit.id } });
      return;
    }
  } catch { /* 查不到就往下走 */ }
  msg.warning(t("ai_audit.ref_not_found", { name }));
  router.push({ name: "devices" }).catch(() => {});
}

/** 子網路 CIDR → 直接開該子網路。 */
async function goSubnet(cidr: string) {
  try {
    const r = await listSubnets({ pageSize: 500 });
    const hit = r.items.find((x) => String(x.cidr) === cidr);
    if (hit) {
      await router.push({ name: "subnet-detail", params: { id: hit.id } });
      return;
    }
  } catch { /* 查不到就往下走 */ }
  msg.warning(t("ai_audit.ref_not_found", { name: cidr }));
  router.push({ name: "subnets" }).catch(() => {});
}

async function load() {
  loading.value = true;
  try {
    const [f, s] = await Promise.all([
      listAIFindings({
        status: status.value,
        severity: severity.value || undefined,
        category: category.value || undefined,
        page_size: 200,
      }),
      getAIAuditSummary(),
    ]);
    rows.value = f.items;
    summary.value = s;
  } catch (e) { msg.error(apiErrMsg(e)); } finally { loading.value = false; }
}

let pollTimer: number | undefined;

function tick() {
  if (startedAt.value) elapsed.value = Math.floor((Date.now() - startedAt.value) / 1000);
}

/** 把作業狀態畫到進度區。作業列是唯一真相 —— 頁面只是在看它。 */
function applyTask(task: AIAuditTask | null) {
  if (!task || (task.status !== "running" && task.status !== "pending")) {
    running.value = false;
    stopPolling();
    if (task?.status === "failed") {
      lastError.value = task.error ?? t("ai_audit.run_unknown_error");
    } else if (task?.summary?.error) {
      // 部分批次失敗但仍有發現 → 作業算成功，可是結果不完整，這件事一定要講
      lastError.value = task.summary.error;
    }
    return false;
  }
  running.value = true;
  lastError.value = null;
  percent.value = task.progress;
  if (task.started_at) startedAt.value = new Date(task.started_at).getTime();
  const live = task.summary?.live;
  if (live) {
    stage.value = live.stage ?? "analyzing";
    if (live.ips) ipsSeen.value = live.ips;
    if (live.model) modelSeen.value = live.model;
    if (live.total) {
      progressHint.value = t("ai_audit.progress_hint", {
        batch: `${live.batch ?? (live.current ?? 0) + 1}/${live.total}`,
        ips: ipsSeen.value, model: modelSeen.value, found: live.found ?? 0,
      });
    }
    writing.value = live.written ?? 0;
    writePhase.value = live.phase ?? "";
  }
  return true;
}

function startPolling() {
  stopPolling();
  tick();
  pollTimer = window.setInterval(async () => {
    tick();
    try {
      const { task } = await getAIAuditStatus();
      const stillRunning = applyTask(task);
      if (!stillRunning) {
        // 跑完了 —— 把發現抓回來，並照實回報結果（成功幾筆 / 失敗原因）
        await load();
        if (task?.status === "succeeded") {
          msg.success(t("ai_audit.run_done", { n: task.summary?.findings ?? 0 }));
        }
      }
    } catch { /* 暫時抓不到狀態不必中斷輪詢 */ }
  }, 2000);
}

function stopPolling() {
  if (pollTimer) window.clearInterval(pollTimer);
  pollTimer = undefined;
}

async function runNow() {
  running.value = true;
  lastError.value = null;
  stage.value = "collecting";
  percent.value = 2;
  progressHint.value = "";
  writing.value = 0;
  startedAt.value = Date.now();
  elapsed.value = 0;
  try {
    await runAIAudit();
    startPolling();
  } catch (e) {
    running.value = false;
    lastError.value = apiErrMsg(e);
  }
}

async function dismiss(id: string) {
  try {
    await dismissAIFindings([id]);
    // 講清楚這一按的影響範圍：之後同一件事都不會再跳出來，不是只藏這一次
    msg.success(t("ai_audit.dismiss_done"), { duration: 4000 });
    await load();
  } catch (e) { msg.error(apiErrMsg(e)); }
}

async function restore(id: string) {
  try {
    await restoreAIFindings([id]);
    await load();
  } catch (e) { msg.error(apiErrMsg(e)); }
}

onMounted(async () => {
  await load();
  // 進來就先問一次作業狀態：巡檢是背景跑的，可能是別人（或上一個分頁）觸發的
  try {
    const { task } = await getAIAuditStatus();
    if (applyTask(task)) startPolling();
  } catch { /* 沒權限或還沒跑過 */ }
});

onBeforeUnmount(stopPolling);
</script>

<style scoped>
.hint { font-size: 12px; color: var(--n-text-color-disabled); }
.rb-ic { vertical-align: -2px; margin-right: 5px; }

/* 嚴重度統計：跟儀表板那塊同一組數字、同一組顏色。點一下＝篩選 */
.sev-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
/* 跟儀表板的 KPI 卡片一致：有框線才看得出這是四個獨立的數字 */
.sev-cell {
  padding: 12px; border-radius: 8px; cursor: pointer; text-align: center;
  background: var(--n-color, #fff);
  border: 1px solid var(--n-border-color, rgba(0, 0, 0, .09));
  transition: transform .12s ease, box-shadow .12s ease, border-color .12s ease;
}
.sev-cell:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0, 0, 0, .08); }
/* 被選為篩選條件時邊框轉成該嚴重度的顏色，看得出目前在篩什麼 */
.sev-cell.on { border-color: currentColor; box-shadow: 0 0 0 1px currentColor inset; }
.sev-n {
  font-size: 24px; font-weight: 700; line-height: 1.2;
  font-variant-numeric: tabular-nums;
}
.sev-l { font-size: 12px; color: var(--n-text-color-disabled); margin-top: 2px; }
.sev-high { color: #d03050; }
.sev-medium { color: #f0a020; }
.sev-low { color: var(--n-text-color-3); }
.sev-ips { cursor: default; color: var(--n-text-color-3); }
.sev-ips:hover { opacity: 1; }
.sev-high .sev-n { color: #d03050; }
.sev-medium .sev-n { color: #f0a020; }
.run-box {
  margin-bottom: 14px; padding: 12px 14px; border-radius: 6px;
  background: var(--n-color-embedded, rgba(128, 128, 128, .06));
}
.run-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.run-stage { font-size: 13px; font-weight: 600; }
.run-elapsed {
  margin-left: auto; font-size: 12px; font-variant-numeric: tabular-nums;
  color: var(--n-text-color-disabled);
}
.run-hint { margin-top: 6px; font-size: 12px; color: var(--n-text-color-disabled); }
.run-bg { margin-top: 6px; font-size: 12px; color: var(--n-color-target, #36ad6a); }
.fx {
  position: relative; padding: 16px 12px 18px 14px;
  border-bottom: 1px solid var(--n-border-color);
}
.fx:last-child { border-bottom: none; }
/* 嚴重度直接用那一格的底色表示，不再另外畫左側色條 ——
   同一件事講兩次，色條還會讓每一列的左緣看起來對不齊。 */
.fx-sev-cell { display: flex; align-items: center; justify-content: center;
  align-self: stretch; border-radius: 6px; padding: 4px 0; font-size: 12.5px; }
.fx-sev-cell.high { background: rgba(208, 48, 80, 0.14); color: #d03050; font-weight: 600; }
.fx-sev-cell.medium { background: rgba(240, 160, 32, 0.16); color: #b3760f; font-weight: 600; }
.fx-sev-cell.low { background: rgba(128, 128, 128, 0.12); color: var(--n-text-color-disabled); }
/* 標題列與資料列共用同一組欄寬，才會對得齊 */
.fx-thead, .fx-head {
  display: grid;
  grid-template-columns: 52px minmax(0, 1fr) minmax(150px, max-content) 92px;
  align-items: center; gap: 8px;
}
/* 底色與圓角跟其他頁的表格表頭一致（子網路、IP 位址…都是 n-data-table）。
   顏色取自 App.vue 送下來的 --table-th-color，不在這裡複製一份色碼 —— 複製的話
   主題一改就會有一個地方沒跟上。 */
.fx-thead {
  padding: 9px 12px 9px 14px; margin: 4px 0 0;
  background: var(--table-th-color, rgba(128, 128, 128, .06));
  border-top: 1px solid var(--n-border-color);
  border-bottom: 1px solid var(--n-border-color);
  font-size: 13px; font-weight: 500; color: var(--n-text-color-2);
}
.th {
  display: inline-flex; align-items: center; gap: 4px;
  user-select: none; white-space: nowrap;
}
.th.sortable { cursor: pointer; }
.th.sortable:hover { color: var(--n-text-color); }
.th.on { color: var(--n-color-target, #36ad6a); font-weight: 600; }
/* 排序箭頭：上下兩個小三角，未選中時兩個都淡；選中時對應方向那個亮起來
   （跟 n-data-table 的 sorter 一樣的視覺語彙） */
.th-sorter { display: inline-flex; flex-direction: column; gap: 1px; line-height: 0; }
.th-sorter i {
  width: 0; height: 0; border-left: 3.5px solid transparent; border-right: 3.5px solid transparent;
  opacity: .3;
}
.th-sorter i.up { border-bottom: 4px solid currentColor; }
.th-sorter i.down { border-top: 4px solid currentColor; }
.th-sorter.asc i.up, .th-sorter.desc i.down { opacity: 1; }
.th-created_at, .th-action { justify-content: flex-end; }
.th-severity { justify-content: center; }
.fx-head { margin-bottom: 8px; }
/* 「狀況」欄：分類標籤 + 標題 */
.fx-what { display: flex; align-items: center; gap: 8px; min-width: 0; }
/* 標籤只包到字，並在欄位裡置中 —— 預設會被拉成整欄寬，看起來像色塊而不是標籤 */
.th-severity { text-align: center; }
/* 標題自己一級，不跟標籤和時間擠在同一個字級 */
.fx-title {
  margin: 0; font-size: 15px; font-weight: 600; line-height: 1.4;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
/* 模型與日期各自一行：擠在同一行會把這一欄撐寬，溢出去蓋到右邊的動作按鈕上
   （實機截圖看到「忽略」被日期壓住）。模型名稱可能很長，所以獨立一行並可縮排。 */
.fx-when {
  font-size: 12px; color: var(--n-text-color-disabled);
  text-align: right; display: flex; flex-direction: column; align-items: flex-end;
  gap: 1px; min-width: 0;
}
.fx-when .fx-date { white-space: nowrap; }
/* 不設 max-width：中文一個字約等於兩個 ch，78ch 換算成中文只有 39 個字，
   在寬螢幕上右邊會空一大片、每兩三個字就折一次，比長行更難讀 */
/* 內文從「狀況」欄的位置開始，跟標題對齊 */
.fx-detail {
  margin: 0 0 8px 60px; font-size: 13.5px; line-height: 1.9;
  color: var(--n-text-color-2);
}
.fx-rec {
  display: flex; gap: 8px; align-items: baseline;
  margin: 0 0 8px 60px; font-size: 13.5px; line-height: 1.9;
}
.fx-rec-tag {
  flex: 0 0 auto; font-size: 11.5px; padding: 1px 8px; border-radius: 4px;
  background: rgba(24, 160, 88, .12); color: var(--n-color-target, #36ad6a);
  position: relative; top: -1px;
}
.fx-ev {
  margin: 8px 0 0 60px; padding: 6px 10px; border-radius: 4px;
  background: var(--n-color-embedded, rgba(128, 128, 128, .08));
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 8px;
  font-size: 12px; line-height: 1.7;
}
.fx-ev-label { color: var(--n-text-color-disabled); }
.fx-ip {
  font-family: var(--font-mono, monospace); cursor: pointer;
  color: var(--n-color-target, #36ad6a); text-decoration: underline dotted;
}
.fx-ip:hover { text-decoration: underline; }
/* 裝置 / 子網路：同樣可點，但用一般字體區分於位址（位址是等寬） */
.fx-ref {
  cursor: pointer; color: var(--n-color-target, #36ad6a);
  text-decoration: underline dotted;
}
.fx-ref:hover { text-decoration: underline; }
.fx-ev-kv { color: var(--n-text-color-3); word-break: break-word; }
.fx-ev-kv b { font-weight: 500; color: var(--n-text-color-disabled); margin-right: 4px; }
.fx-model { opacity: .55; font-size: 11.5px; max-width: 220px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
