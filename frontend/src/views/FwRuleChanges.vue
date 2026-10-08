<script setup lang="ts">
/**
 * 防火牆規則異動歷史（異動偵測快照）。
 *
 * 異動通知只給摘要，並說「細節到快照裡看」—— 這一頁就是那個「快照裡」。
 * 沒有這頁的話，通知等於指向一個不存在的地方。admin 限定（規則內容屬純管理資料）。
 */
import { onMounted, ref, h } from "vue";
import {
  NCard, NSpace, NIcon, NTag, NDataTable, NEmpty, NAlert, NButton, NModal, NInput,
  useMessage, type DataTableColumns,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { apiClient, apiErrMsg } from "@/api/client";
import { fmtDateTime } from "@/utils/datetime";
import { AiAuditIcon, DownloadIcon, EyeIcon, FirewallIcon, OkIcon, RefreshIcon, renderIcon } from "@/icons";
import { autoSort } from "@/composables/useTableSort";
import { renderMarkdown } from "@/utils/markdown";
import { downloadTextFile } from "@/utils/investigateReport";

const { t } = useI18n();
const msg = useMessage();

interface Change {
  id: string; source_type: string; instance_name: string; taken_at: string;
  rule_count: number; is_baseline: boolean;
  diff: { added: any[]; removed: any[]; changed: any[] } | null;
  ack: { at: string; note: string } | null;
}
const items = ref<Change[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const { data } = await apiClient.get("/api/v1/anomalies/fw-rule-changes");
    items.value = data.items ?? [];
  } catch (e: any) { msg.error(apiErrMsg(e)); }
  finally { loading.value = false; }
}
onMounted(load);

/** 廠牌顯示名稱：`source_type` 是內部鍵，直接印出來會是全小寫的 paloalto／pfsense。 */
const VENDOR_LABEL: Record<string, string> = {
  opnsense: "OPNsense", pfsense: "pfSense", fortigate: "FortiGate", paloalto: "Palo Alto",
};

function ruleLine(r: any): string {
  const port = r.dst_port ? `:${r.dst_port}` : "";
  const descr = r.descr ? `（${r.descr}）` : "";
  return `${r.action || "?"} ${r.src || "any"} → ${r.dst || "any"}${port}${descr}`;
}

type DiffKind = "add" | "del" | "chg";
const KIND_TAG: Record<DiffKind, "error" | "default" | "warning"> = {
  add: "error", del: "default", chg: "warning",
};

/** 把一筆快照的 diff 攤成「一列一條規則」。類型與文字分開回傳，兩個欄位才對得齊。 */
function diffLines(row: Change): { kind: DiffKind; text: string }[] {
  const d = row.diff;
  if (row.is_baseline || !d) return [];
  const out: { kind: DiffKind; text: string }[] = [];
  for (const r of (d.added ?? [])) out.push({ kind: "add", text: ruleLine(r) });
  for (const r of (d.removed ?? [])) out.push({ kind: "del", text: ruleLine(r) });
  for (const c of (d.changed ?? [])) {
    out.push({ kind: "chg", text: `${c.descr || c.key}：${(c.fields ?? []).map(
      (f: string) => `${f} ${c.old?.[f] ?? ""} → ${c.new?.[f] ?? ""}`).join("、")}` });
  }
  return out;
}

/** 每一列的高度要與「異動內容」那欄的同一列對齊 —— 兩欄用一樣的 line-height 與 gap。 */
const LINE_STYLE = "font-size:12.5px;line-height:1.7;min-height:22px";

/** 異動類型欄：只有標籤，靠上對齊，與右側規則文字一列一列對應。 */
function renderKinds(row: Change) {
  if (row.is_baseline) return h("span", { style: "opacity:.55;font-size:12.5px" }, "—");
  return h("div", { style: "display:flex;flex-direction:column;gap:3px;padding:4px 0" },
    diffLines(row).map((l) => h("div", { style: LINE_STYLE },
      h(NTag, { size: "tiny", type: KIND_TAG[l.kind] },
        { default: () => t(`fw_changes.d_${l.kind}`) }))));
}

/** 異動內容欄；規則描述是不可信文字，一律以純文字 render（不進 v-html）。 */
function renderDiff(row: Change) {
  if (row.is_baseline) {
    return h("span", { style: "opacity:.65" }, t("fw_changes.baseline"));
  }
  return h("div", { style: "display:flex;flex-direction:column;gap:3px;padding:4px 0" },
    diffLines(row).map((l) => h("div", { style: LINE_STYLE }, l.text)));
}

/** AI 解讀：偵測是確定性的，解讀層按需觸發 —— 帶上目標位址的全系統整合證據。
 *  LLM 要跑幾十秒，所以按下去是**背景執行**：使用者可以繼續看表格、
 *  同時解讀多筆；完成後該列長出「檢視結果」按鈕（結果留在頁面裡可重看）。 */
const aiBusy = ref<Set<string>>(new Set());
const aiResults = ref<Record<string, { card: string; disclaimer: string; model?: string }>>({});
const aiShow = ref<string | null>(null);

/** 下載解讀報告：.md 保留原始 markdown；.txt 去掉標記符號成純文字。 */
function downloadAi(fmt: "md" | "txt") {
  const id = aiShow.value;
  const res = id ? aiResults.value[id] : null;
  if (!id || !res) return;
  const row = items.value.find((i) => i.id === id);
  const header = [
    `# ${t("fw_changes.ai_title")}`,
    "",
    `- ${t("fw_changes.firewall")}：${row?.instance_name ?? ""}（${row?.source_type ?? ""}）`,
    `- ${t("fw_changes.when")}：${row ? fmtDateTime(row.taken_at) : ""}`,
    `- ${t("fw_changes.ai_model")}：${res.model ?? "—"}`,
    "",
    `> ${res.disclaimer}`,
    "",
  ].join("\n");
  const body = header + res.card + "\n";
  const text = fmt === "md" ? body : body
    .replace(/\*\*([^*]+)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1")
    .replace(/^#{1,6}\s+/gm, "").replace(/^>\s?/gm, "");
  const stamp = (row?.taken_at ?? "").slice(0, 19).replace(/[T:]/g, "-");
  downloadTextFile(text, `fw-change-ai-${row?.instance_name ?? "report"}-${stamp}.${fmt}`, fmt);
}
async function analyze(row: Change) {
  aiBusy.value.add(row.id); aiBusy.value = new Set(aiBusy.value);
  try {
    const { data } = await apiClient.post(`/api/v1/anomalies/fw-rule-changes/${row.id}/analyze`);
    aiResults.value = { ...aiResults.value, [row.id]: data };
    msg.success(t("fw_changes.ai_done"));
  } catch (e: any) { msg.error(apiErrMsg(e)); }
  finally { aiBusy.value.delete(row.id); aiBusy.value = new Set(aiBusy.value); }
}

/** 認可：把異動標記為「已知變更＋說明」。沒被認可的異動＝稽核上無人說明的變更。 */
const ackTarget = ref<Change | null>(null);
const ackNote = ref("");
const ackBusy = ref(false);
async function submitAck() {
  if (!ackTarget.value) return;
  ackBusy.value = true;
  try {
    await apiClient.post(`/api/v1/anomalies/fw-rule-changes/${ackTarget.value.id}/ack`,
                         { note: ackNote.value.trim() });
    ackTarget.value = null; ackNote.value = "";
    await load();
  } catch (e: any) { msg.error(apiErrMsg(e)); }
  finally { ackBusy.value = false; }
}

const cols: DataTableColumns<Change> = autoSort([
  { title: t("fw_changes.when"), key: "taken_at", width: 170,
    render: (r) => fmtDateTime(r.taken_at) },
  { title: t("fw_changes.firewall"), key: "instance_name", width: 200,
    render: (r) => h("span", null, [
      h(NTag, { size: "tiny", style: "margin-right:6px" },
        { default: () => VENDOR_LABEL[r.source_type] ?? r.source_type }),
      r.instance_name,
    ]) },
  { title: t("fw_changes.rules"), key: "rule_count", width: 90 },
  // 類型獨立一欄：混在異動內容裡時，標籤寬度不一會讓每一列的規則文字起點不同
  //（使用者回報「很不整齊」）。
  { title: t("fw_changes.kind"), key: "_kind", width: 84, render: (r) => renderKinds(r) },
  { title: t("fw_changes.diff"), key: "diff", render: (r) => renderDiff(r) },
  // 單一「操作」欄：欄位標題若與裡面的按鈕同名（認可／AI 解讀）會像重複貼了兩次
  //（使用者回饋）；認可後按鈕原位換成狀態文字。
  // 寬度只留到剛好放下兩顆按鈕（使用者回饋：多餘寬度優先給異動內容），
  // 「檢視結果」長出來或認可說明較長時靠 flex-wrap 換行。
  { title: t("common.actions"), key: "_actions", width: 185, className: "col-actions",
    render: (r) => r.is_baseline ? null : h("span",
      { style: "display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap" }, [
        r.ack
          ? h("span", { style: "font-size:12px;opacity:.75" },
              `✓ ${t("fw_changes.acked")}${r.ack.note ? "：" + r.ack.note.slice(0, 40) : ""}`)
          : h(NButton, { size: "tiny", secondary: true,
                         onClick: () => { ackTarget.value = r; ackNote.value = ""; } },
              { icon: renderIcon(OkIcon, 15), default: () => t("fw_changes.ack_btn") }),
        h(NButton, {
          size: "tiny", secondary: true, loading: aiBusy.value.has(r.id),
          disabled: aiBusy.value.has(r.id),
          onClick: () => analyze(r),
        }, { icon: renderIcon(AiAuditIcon, 15), default: () => t("fw_changes.ai_btn") }),
        aiResults.value[r.id]
          ? h(NButton, { size: "tiny", type: "primary", secondary: true,
                         onClick: () => { aiShow.value = r.id; } },
              { icon: renderIcon(EyeIcon, 15), default: () => t("fw_changes.ai_view") })
          : null,
      ]) },
]);
</script>

<template>
  <n-card :bordered="false">
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><FirewallIcon /></n-icon>
        <span>{{ t("fw_changes.title") }}</span>
      </n-space>
    </template>
    <!-- 控制列：自標題列搬到內文最上方 -->
    <n-space align="center" justify="end" style="margin-bottom: 10px">
      <n-button size="small" :loading="loading" @click="load">
        <template #icon><n-icon><RefreshIcon /></n-icon></template>
        {{ t("common.refresh") }}
      </n-button>
    </n-space>
    <n-alert type="info" :bordered="false" style="margin-bottom: 12px">
      {{ t("fw_changes.hint") }}
    </n-alert>
    <n-data-table :columns="cols" :data="items" :loading="loading" size="small"
                  :row-key="(r: Change) => r.id" :bordered="false" />
    <n-empty v-if="!loading && !items.length" style="margin: 24px 0"
             :description="t('fw_changes.empty')" />
  </n-card>

  <!-- 認可：合規證據鏈（誰確認了這筆變更、為什麼） -->
  <n-modal :show="!!ackTarget" preset="card" style="width: 460px; max-width: 92vw"
           :title="t('fw_changes.ack_title')"
           @update:show="(v: boolean) => { if (!v) ackTarget = null; }">
    <n-input v-model:value="ackNote" type="textarea" :rows="3"
             :placeholder="t('fw_changes.ack_ph')" />
    <template #footer>
      <n-space justify="end">
        <n-button @click="ackTarget = null">{{ t("common.cancel") }}</n-button>
        <n-button type="primary" :loading="ackBusy" @click="submitAck">
          {{ t("common.confirm") }}
        </n-button>
      </n-space>
    </template>
  </n-modal>

  <!-- AI 解讀卡：走全站共用的零相依 markdown 渲染器（先跳脫再產標籤，無注入面）——
       原本 pre-wrap 純文字會把 **粗體** 的星號原樣露出（使用者截圖） -->
  <n-modal :show="!!aiShow" preset="card" style="width: 560px; max-width: 94vw"
           :title="t('fw_changes.ai_title')"
           @update:show="(v: boolean) => { if (!v) aiShow = null; }">
    <n-alert type="warning" :bordered="false" style="margin-bottom: 10px">
      {{ aiShow ? aiResults[aiShow]?.disclaimer : "" }}
    </n-alert>
    <!-- eslint-disable-next-line vue/no-v-html -->
    <div class="fwai-body" v-html="renderMarkdown(aiShow ? aiResults[aiShow]?.card ?? '' : '')" />
    <template #footer>
      <div class="fwai-foot">
        <span class="fwai-model">{{ t("fw_changes.ai_model") }}：{{
          (aiShow ? aiResults[aiShow]?.model : "") || "—" }}</span>
        <n-space :size="8">
          <n-button size="small" secondary @click="downloadAi('md')">
            <template #icon><n-icon><DownloadIcon /></n-icon></template>
            {{ t("fw_changes.ai_dl_md") }}
          </n-button>
          <n-button size="small" secondary @click="downloadAi('txt')">
            <template #icon><n-icon><DownloadIcon /></n-icon></template>
            {{ t("fw_changes.ai_dl_txt") }}
          </n-button>
        </n-space>
      </div>
    </template>
  </n-modal>
</template>

<style scoped>
.fwai-body { font-size: 13px; line-height: 1.85; }
.fwai-body :deep(code) { background: rgba(128, 128, 128, .14); border-radius: 4px;
  padding: 1px 5px; font-size: 12px; }
.fwai-body :deep(p) { margin: 6px 0; }
.fwai-body :deep(ul), .fwai-body :deep(ol) { margin: 4px 0; padding-left: 20px; }
.fwai-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.fwai-model { font-size: 12px; opacity: .65; }
</style>
