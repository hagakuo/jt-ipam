<script setup lang="ts">
/**
 * 系統診斷（管理）：把後端查得到的狀況一次列出來，每一項都附「該怎麼修」。
 *
 * 由來（2026-09-05 客戶回報）：儀表板數得出 55 台裝置、點進裝置清單卻是
 * 「Internal Server Error」加一片空白。原因是資料庫結構落後於程式 —— 系統其實
 * 查得出來，卻沒有任何地方講，只能請客戶去伺服器上跑 CLI 版的 doctor。
 * 這一頁就是把那件事搬到畫面上。
 *
 * 系統層的檢查（systemd、nginx、備份檔、掃描代理）後端看不到，頁面上會明講，
 * 不會讓人以為「這裡全綠就等於一切正常」。
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NSpace, NButton, NIcon, NTag, NAlert, NSpin, NEmpty, useMessage,
} from "naive-ui";
import { apiClient, apiErrMsg } from "@/api/client";
import { RefreshIcon, ExportIcon, TestIcon } from "@/icons";
import { fmtDateTime } from "@/utils/datetime";

const { t } = useI18n();
const msg = useMessage();

interface Check {
  key: string; title: string; status: "ok" | "warn" | "bad";
  detail?: string; fix?: string;
  // 後端只給代碼與參數；句子在這裡組。沒有代碼（舊後端）才退回上面那三個字串。
  title_key?: string; detail_key?: string; fix_key?: string;
  params?: Record<string, unknown>;
}

/** 有代碼就翻譯，沒有就用後端寫好的字 —— 後端沒有「當前語言」可言。
 *  時間參數後端給 ISO（UTC），這裡換成觀看者的時區：以前直接印 UTC，「最後一筆 13:33」其實是本地 21:33。 */
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
function field(c: Check, which: "title" | "detail" | "fix"): string {
  const key = c[`${which}_key` as const];
  if (!key) return c[which] ?? "";
  const params: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(c.params || {})) {
    params[k] = typeof v === "string" && ISO_RE.test(v) ? fmtDateTime(v) : v;
  }
  return t(key, params);
}
interface Report {
  generated_at: string; ok: number; warn: number; bad: number; checks: Check[];
}

const report = ref<Report | null>(null);
const loading = ref(false);

// 資料統計：各類資料各有幾筆（只在本機算，不回傳）。逾時的大表是估計值，前面加「約」
interface StatItem { key: string; count: number | null; approx: boolean }
interface StatGroup { key: string; items: StatItem[] }
const stats = ref<StatGroup[]>([]);
const nf = new Intl.NumberFormat();
function statText(i: StatItem): string {
  if (i.count == null) return "—";
  return (i.approx ? t("doctor.stats_approx") + " " : "") + nf.format(i.count);
}

async function run() {
  loading.value = true;
  try {
    const [{ data }, st] = await Promise.all([
      apiClient.get<Report>("/api/v1/system/doctor"),
      apiClient.get<{ groups: StatGroup[] }>("/api/v1/system/doctor/stats").catch(() => null),
    ]);
    report.value = data;
    stats.value = st?.data.groups ?? [];
  } catch (e) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}

/** 下載純文字報告 —— 直接貼進工單用（不是給機器讀的 JSON）。
 *
 * 從畫面上已經翻好的內容組，不打後端的 /doctor/report：那一支是在伺服器上組字串的，
 * 沒有「當前語言」可言，下載下來會是中文。工單要貼給誰看，就該是那個人的語言。
 * （伺服器端那支仍保留：curl 與 CLI 會用到。） */
function download() {
  try {
    const r = report.value;
    if (!r) return;
    const icon = { ok: "[ OK ]", warn: "[WARN]", bad: "[FAIL]" } as const;
    const lines = [`jt-ipam self-check — ${r.generated_at}`, ""];
    for (const c of r.checks) {
      lines.push(`${icon[c.status]} ${field(c, "title")}`);
      const d = field(c, "detail");
      if (d) lines.push(`        ${d}`);
      const fx = field(c, "fix");
      if (fx && c.status !== "ok") lines.push(`        → ${fx}`);
    }
    lines.push("", t("doctor.report_counts", { bad: r.bad, warn: r.warn, ok: r.ok }), "");
    lines.push(t("doctor.cli_note"));
    lines.push("  sudo bash /opt/jt-ipam/scripts/jt-ipam.sh doctor");
    const data = lines.join("\n");
    const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
    const url = URL.createObjectURL(new Blob([data], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `jt-ipam-doctor-${stamp}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { msg.error(apiErrMsg(e)); }
}

const overall = computed<"ok" | "warn" | "bad">(() => {
  const r = report.value;
  if (!r) return "ok";
  return r.bad ? "bad" : r.warn ? "warn" : "ok";
});
const TYPE = { ok: "success", warn: "warning", bad: "error" } as const;

onMounted(() => { void run(); });
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><TestIcon /></n-icon>
        <span>{{ t("doctor.title") }}</span>
      </n-space>
    </template>

    <n-space align="center" class="doc-bar">
      <n-button type="primary" @click="run" :loading="loading">
        <template #icon><n-icon><RefreshIcon /></n-icon></template>
        {{ t("doctor.run") }}
      </n-button>
      <n-button :disabled="!report" @click="download">
        <template #icon><n-icon><ExportIcon /></n-icon></template>
        {{ t("doctor.download") }}
      </n-button>
      <span v-if="report" class="doc-time">
        {{ t("doctor.generated_at") }}：{{ fmtDateTime(report.generated_at) }}
      </span>
    </n-space>

    <n-spin :show="loading">
      <n-alert v-if="report" :type="TYPE[overall]" :bordered="false" style="margin-bottom: 12px">
        {{ t("doctor.summary", { bad: report.bad, warn: report.warn, ok: report.ok }) }}
      </n-alert>

      <n-empty v-if="!report && !loading" :description="t('doctor.not_run')" />

      <div v-for="c in report?.checks ?? []" :key="c.key" class="doc-row" :data-status="c.status">
        <n-tag :type="TYPE[c.status]" size="small" :bordered="false" class="doc-badge">
          {{ t(`doctor.status_${c.status}`) }}
        </n-tag>
        <div class="doc-body">
          <div class="doc-title">{{ field(c, "title") }}</div>
          <div v-if="field(c, 'detail')" class="doc-detail">{{ field(c, "detail") }}</div>
          <!-- 每個非 ok 的項目都要講「怎麼修」——只說壞了等於沒說 -->
          <div v-if="field(c, 'fix') && c.status !== 'ok'" class="doc-fix">
            <span class="doc-fix-label">{{ t("doctor.fix") }}</span>
            <code>{{ field(c, "fix") }}</code>
          </div>
        </div>
      </div>

      <n-alert v-if="report" type="default" :bordered="false" style="margin-top: 14px">
        {{ t("doctor.cli_note") }}
        <code>sudo bash /opt/jt-ipam/scripts/jt-ipam.sh doctor</code>
      </n-alert>

      <!-- 資料統計（使用者 2026-10-06，比照 LibreNMS 的統計頁；但只在本機算，不回傳、不蒐集） -->
      <section v-if="stats.length" class="doc-stats" data-testid="doctor-stats">
        <div class="doc-stats-head">
          <span class="doc-stats-title">{{ t("doctor.stats_title") }}</span>
          <span class="doc-stats-hint">{{ t("doctor.stats_hint") }}</span>
        </div>
        <div v-for="g in stats" :key="g.key" class="doc-stats-group">
          <div class="doc-stats-gname">{{ t(`doctor.stats_group.${g.key}`) }}</div>
          <div class="doc-stats-grid">
            <div v-for="i in g.items" :key="i.key" class="doc-stat" :data-key="i.key">
              <span class="doc-stat-k">{{ t(`doctor.stats.${i.key}`) }}</span>
              <span class="doc-stat-v">{{ statText(i) }}</span>
            </div>
          </div>
        </div>
      </section>
    </n-spin>
  </n-card>
</template>

<style scoped>
.doc-bar { margin-bottom: 12px; flex-wrap: wrap; row-gap: 8px; }
.doc-time { font-size: 12px; opacity: .7; }

.doc-row {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid var(--n-border-color, rgba(0, 0, 0, .06));
  margin-bottom: 8px;
}
/* 有問題的列要一眼看得出來，不能跟通過的長一樣 */
.doc-row[data-status="bad"] { border-color: rgba(208, 48, 80, .45); background: rgba(208, 48, 80, .06); }
.doc-row[data-status="warn"] { border-color: rgba(240, 160, 32, .45); background: rgba(240, 160, 32, .06); }

.doc-badge { flex: 0 0 auto; margin-top: 1px; }
.doc-body { min-width: 0; flex: 1 1 auto; }
.doc-title { font-weight: 600; }
.doc-detail { font-size: 13px; opacity: .8; margin-top: 2px; word-break: break-word; }
.doc-fix { font-size: 12px; margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap; }
.doc-fix-label { opacity: .7; flex: 0 0 auto; }
.doc-fix code, .doc-row code { word-break: break-all; }

.doc-stats { margin-top: 22px; }
.doc-stats-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
.doc-stats-title { font-weight: 600; font-size: 15px; }
.doc-stats-hint { font-size: 12px; opacity: .65; }
.doc-stats-group { margin-top: 10px; }
.doc-stats-gname { font-size: 12px; opacity: .7; margin-bottom: 4px; }
.doc-stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); column-gap: 24px; }
.doc-stat { display: flex; justify-content: space-between; gap: 12px; padding: 6px 2px;
            border-bottom: 1px solid var(--n-border-color, rgba(0, 0, 0, .06)); font-size: 13px; }
.doc-stat-v { font-variant-numeric: tabular-nums; font-weight: 600; white-space: nowrap; }
</style>
