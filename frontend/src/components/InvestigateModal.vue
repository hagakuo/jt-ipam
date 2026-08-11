<template>
  <n-modal :show="show" preset="card" style="width: 860px; max-width: 94vw"
           :title="() => `${t('investigate.title')}　${ip}`" @update:show="$emit('update:show', $event)">
    <n-spin :show="loading">
      <div v-if="d && !d.found" class="inv-empty">{{ t("investigate.not_found") }}</div>

      <template v-else-if="d">
        <!-- 矛盾之處放最上面：這個功能存在的理由就是「線索散在各處、彼此對不上」 -->
        <n-alert v-if="conflicts.length" type="warning" :bordered="false"
                 :show-icon="true" style="margin-bottom: 12px">
          <div v-for="c in conflicts" :key="c">{{ c }}</div>
        </n-alert>

        <div class="inv-grid">
          <div class="inv-k">{{ t("addresses.hostname") }}</div>
          <div class="inv-v">{{ d.address.hostname || "—" }}</div>
          <div class="inv-k">{{ t("common.status") }}</div>
          <div class="inv-v">
            {{ d.address.state }} ／ {{ d.address.effective_status || "—" }}
          </div>
          <div class="inv-k">{{ t("nav.subnets") }}</div>
          <div class="inv-v">{{ d.address.subnet }}
            <span v-if="d.address.subnet_description" style="opacity:.6">
              （{{ d.address.subnet_description }}）</span>
          </div>
          <div class="inv-k">MAC</div>
          <div class="inv-v mono">{{ d.address.mac || "—" }}</div>
          <div class="inv-k">DHCP</div>
          <div class="inv-v">
            <n-tag v-if="d.address.dhcp_reserved" size="small" type="success" :bordered="false">
              {{ t("addresses.dhcp_reserved_tag") }}
            </n-tag>
            <n-tag v-else-if="d.address.in_dhcp_lease" size="small" type="warning" :bordered="false">
              DHCP
            </n-tag>
            <span v-else>—</span>
          </div>
        </div>

        <n-collapse :default-expanded-names="defaultOpen" style="margin-top: 12px">
          <n-collapse-item v-if="d.other_records.length"
                           :title="`${t('investigate.other_records')}（${d.other_records.length}）`"
                           name="other">
            <div v-for="o in d.other_records" :key="o.ip_address_id" class="inv-row">
              {{ o.subnet }} · {{ o.hostname || "—" }} · {{ o.effective_status || "—" }}
            </div>
          </n-collapse-item>

          <n-collapse-item v-if="d.hostname_sources.length"
                           :title="`${t('hostnameSrc.sources')}（${d.hostname_sources.length}）`"
                           name="names">
            <div v-for="h in d.hostname_sources" :key="h.source + h.hostname" class="inv-row">
              <b>{{ h.source }}</b>：{{ h.hostname }}
            </div>
          </n-collapse-item>

          <n-collapse-item v-if="osList.length" :title="t('cols.os')" name="os">
            <div v-for="o in osList" :key="o" class="inv-row">{{ o }}</div>
          </n-collapse-item>

          <n-collapse-item v-if="monitorList.length" :title="t('investigate.monitoring')" name="mon">
            <div v-for="m in monitorList" :key="m" class="inv-row">{{ m }}</div>
          </n-collapse-item>

          <n-collapse-item v-if="d.arp.length" :title="`ARP（${d.arp.length}）`" name="arp">
            <div v-for="a in d.arp" :key="a.mac + a.last_seen_at" class="inv-row mono">
              {{ a.mac }} · {{ fmtDateTime(a.last_seen_at) }}
            </div>
          </n-collapse-item>

          <n-collapse-item v-if="d.dns.length" :title="`DNS（${d.dns.length}）`" name="dns">
            <div v-for="r in d.dns" :key="r.name" class="inv-row">{{ r.type }} {{ r.name }}</div>
          </n-collapse-item>

          <n-collapse-item v-if="d.nat.length" :title="`NAT（${d.nat.length}）`" name="nat">
            <div v-for="n in d.nat" :key="n.name + n.port" class="inv-row">
              {{ n.name }} · {{ n.protocol }}/{{ n.port }} · {{ n.interface }}
              <n-tag v-if="n.disabled" size="tiny" :bordered="false">{{ t("common.disabled") }}</n-tag>
            </div>
          </n-collapse-item>

          <n-collapse-item v-if="d.firewall_rules.length"
                           :title="`${t('nav.firewall')}（${d.firewall_rules.length}）`" name="fw">
            <div v-for="(r, i) in d.firewall_rules" :key="i" class="inv-row">
              {{ r.action }} {{ r.interface }} {{ r.protocol }}/{{ r.port }} — {{ r.description }}
            </div>
          </n-collapse-item>

          <n-collapse-item v-if="d.changes.length"
                           :title="`${t('nav.ip_changes')}（${d.changes.length}）`" name="chg">
            <div v-for="(c, i) in d.changes" :key="i" class="inv-row">
              {{ fmtDateTime(c.at) }} · {{ c.field || c.event }}
              <span v-if="c.old || c.new">：<ChangeValue :field="c.field" :value="c.old" />
                → <ChangeValue :field="c.field" :value="c.new" /></span>
            </div>
          </n-collapse-item>
        </n-collapse>

        <!-- 模型的判讀與上面的事實分開放，而且標明是推測 -->
        <!-- 匯出報告：把這一頁的事實與 AI 判讀一起帶走（交接、報修單、稽核附件都會用到）。
             四種格式都是瀏覽器端產生，沒有新的相依套件。 -->
        <div class="inv-export">
          <span class="inv-export-k">{{ t("investigate.export") }}</span>
          <n-button v-for="f in (['md', 'txt', 'html', 'csv'] as ReportFormat[])" :key="f"
                    size="tiny" secondary @click="doExport(f)">.{{ f }}</n-button>
        </div>
        <div class="inv-ai">
          <n-button v-if="!narrative" size="small" :loading="asking" @click="ask">
            <template #icon><n-icon><TestIcon /></n-icon></template>
            {{ t("investigate.ask_ai") }}
          </n-button>
          <template v-else>
            <div class="inv-ai-hd">
              {{ t("investigate.ai_reading") }}
              <!-- 秒數與字數：跑很久的時候，這是唯一能看出「它還活著」的東西 -->
              <span v-if="asking || elapsed" class="inv-ai-prog">
                {{ t("investigate.ai_progress", {
                     s: elapsed, n: narrative.length,
                     think: thinkChars }) }}
              </span>
            </div>
            <div class="inv-ai-note">{{ t("investigate.ai_note") }}</div>
            <div class="inv-ai-body" v-html="renderMarkdown(narrative)" />
          </template>
          <div v-if="narrativeError" class="inv-ai-err">{{ narrativeError }}</div>
        </div>
      </template>
    </n-spin>
  </n-modal>
</template>

<script setup lang="ts">
/**
 * 調查模式：把一個位址散落在各處的線索攤在同一頁。
 *
 * 事實與推測分開：上半部全是查得到的事實，模型的判讀要按了才出現，而且標明是推測。
 * 模型不可用時這個視窗仍然完整可用 —— 真正省時間的是把線索收在一起，不是那段敘述。
 */
import { computed, ref, watch } from "vue";
import {
  NAlert, NButton, NCollapse, NCollapseItem, NIcon, NModal, NSpin, NTag,
} from "naive-ui";
import { useI18n } from "vue-i18n";
import { investigate } from "@/api/investigate";
import { narrativeStream } from "@/api/investigate";
import { TestIcon } from "@/icons";
import { fmtDateTime } from "@/utils/datetime";
import { renderMarkdown } from "@/utils/markdown";
import { downloadReport, type ReportFormat, type ReportSection } from "@/utils/investigateReport";
import ChangeValue from "@/components/ChangeValue.vue";

const props = defineProps<{ show: boolean; ip: string }>();
defineEmits<{ (e: "update:show", v: boolean): void }>();
const { t, locale } = useI18n();

const d = ref<any>(null);
const loading = ref(false);
const asking = ref(false);
const narrative = ref<string>("");
const narrativeError = ref<string>("");

const defaultOpen = ["other", "names", "mon"];

const osList = computed(() =>
  Object.entries(d.value?.os_candidates ?? {}).map(([k, v]) => `${k}：${v}`));

const monitorList = computed(() => {
  const m = d.value?.monitoring ?? {};
  const out: string[] = [];
  if (m.wazuh) {
    out.push(`Wazuh ${m.wazuh.name ?? m.wazuh.agent_id}（${m.wazuh.status}）`
      + (m.wazuh.sca_score != null ? ` · SCA ${m.wazuh.sca_score}` : ""));
  }
  if (m.librenms) out.push(`LibreNMS ${m.librenms.hostname ?? ""}（${m.librenms.status ?? "—"}）`);
  return out;
});

/** 一眼看得出的矛盾。這是整個功能的重點，所以放在最上面而不是埋在分頁裡。 */
const conflicts = computed<string[]>(() => {
  const v = d.value;
  if (!v?.found) return [];
  const out: string[] = [];
  const names = new Set(
    (v.hostname_sources ?? []).map((h: any) => String(h.hostname || "").toLowerCase())
      .filter(Boolean));
  if (names.size > 1) out.push(t("investigate.conflict_names", { n: names.size }));
  if (v.monitoring?.wazuh && v.monitoring.wazuh.still_represents_this_ip === false) {
    out.push(t("investigate.conflict_stale_agent", { name: v.monitoring.wazuh.name ?? "" }));
  }
  if (v.other_records?.length) {
    out.push(t("investigate.conflict_duplicate", { n: v.other_records.length + 1 }));
  }
  const macs = new Set((v.arp ?? []).map((a: any) => a.mac));
  if (macs.size > 2) out.push(t("investigate.conflict_macs", { n: macs.size }));
  return out;
});

async function load() {
  loading.value = true;
  narrative.value = "";
  narrativeError.value = "";
  try {
    const r = await investigate(props.ip, false, locale.value);
    d.value = r.dossier;
  } finally { loading.value = false; }
}

// 判讀進度：秒數與字數。會思考的模型前幾分鐘只吐思考內容，所以兩者分開計數 ——
// 只顯示「處理中」的話，使用者分不出模型在想、卡住、還是壞了。
const elapsed = ref(0);
const thinkChars = ref(0);
let ticker: ReturnType<typeof setInterval> | null = null;

async function ask() {
  asking.value = true;
  narrative.value = "";
  narrativeError.value = "";
  elapsed.value = 0;
  thinkChars.value = 0;
  ticker = setInterval(() => { elapsed.value += 1; }, 1000);
  try {
    await narrativeStream(props.ip, locale.value, (ev) => {
      if (ev.type === "thinking") thinkChars.value += (ev.text ?? "").length;
      else if (ev.type === "content") narrative.value += ev.text ?? "";
      else if (ev.type === "done") { if (ev.text) narrative.value = ev.text; }
      else if (ev.type === "error") narrativeError.value = ev.detail ?? "";
      if (ev.elapsed != null) elapsed.value = Math.round(ev.elapsed);
    });
  } catch (e: any) {
    narrativeError.value = e?.message ?? String(e);
  } finally {
    asking.value = false;
    if (ticker) { clearInterval(ticker); ticker = null; }
  }
}

// ── 匯出報告（.md / .txt / .html / .csv）
// 純瀏覽器端，零相依 —— 安裝與升級不必追加任何套件。中文編碼見 investigateReport.ts。
function sectionsForReport(): ReportSection[] {
  // **照畫面上實際渲染的欄位取值**。第一版是照記憶猜的（v.hostname、r.rtype、
  // v.firewall、c.summary），結果匯出的摘要整排「—」、DNS 每行 undefined、
  // 異動記錄倒出原始 JSON —— 匯出跟畫面必須是同一份資料的同一種讀法。
  const v = d.value ?? {};
  const fmtChange = (c: any) => {
    const head = `${fmtDateTime(c.at)} · ${c.field || c.event}`;
    return (c.old || c.new) ? `${head}：${c.old ?? "—"} → ${c.new ?? "—"}` : head;
  };
  return [
    { title: t("investigate.sec_names"),
      lines: (v.hostname_sources ?? []).map((h: any) => `${h.source}：${h.hostname}`) },
    { title: "OS", lines: osList.value },
    { title: t("investigate.sec_mon"), lines: monitorList.value },
    { title: "ARP",
      lines: (v.arp ?? []).map((a: any) => `${a.mac} · ${fmtDateTime(a.last_seen_at)}`) },
    { title: "DNS",
      lines: (v.dns ?? []).map((r: any) => `${r.type} ${r.name}`) },
    { title: "NAT",
      lines: (v.nat ?? []).map((n: any) =>
        [n.name, `${n.protocol ?? ""}/${n.port ?? ""}`, n.interface,
         n.disabled ? t("common.disabled") : ""].filter(Boolean).join(" · ")) },
    { title: t("investigate.sec_fw"),
      lines: (v.firewall_rules ?? []).map((r: any) =>
        `${r.action} ${r.interface} ${r.protocol}/${r.port}`
        + (r.description ? ` — ${r.description}` : "")) },
    { title: t("investigate.sec_other"),
      lines: (v.other_records ?? []).map((o: any) =>
        `${o.subnet} · ${o.hostname ?? "—"} · ${o.effective_status ?? "—"}`) },
    { title: t("investigate.sec_changes"),
      lines: (v.changes ?? []).map(fmtChange) },
  ];
}

function doExport(fmt: ReportFormat) {
  const a = d.value?.address ?? {};
  downloadReport({
    ip: props.ip,
    generatedAt: fmtDateTime(new Date().toISOString()),
    summary: [
      [t("addresses.hostname"), a.hostname ?? "—"],
      [t("nav.subnets"), a.subnet ? (a.subnet_description
        ? `${a.subnet}（${a.subnet_description}）` : a.subnet) : "—"],
      [t("common.status"), `${a.state ?? "—"} / ${a.effective_status ?? "—"}`],
      ["MAC", a.mac ?? "—"],
      [t("addresses.switch_port"), a.switch_port ?? "—"],
    ] as [string, string][],
    conflicts: conflicts.value,
    sections: sectionsForReport(),
    narrative: narrative.value || undefined,
    narrativeNote: narrative.value ? t("investigate.ai_note") : undefined,
    // HTML 版把判讀的 markdown 真的渲染出來（**粗體**、`code`、清單），
    // 不要把原始標記直接印在報告上
    narrativeHtml: narrative.value ? renderMarkdown(narrative.value) : undefined,
  }, fmt);
}

watch(() => [props.show, props.ip], ([s]) => { if (s) void load(); }, { immediate: true });
</script>

<style scoped>
.inv-empty { opacity: .6; padding: 18px 0; }
.inv-grid { display: grid; grid-template-columns: 96px minmax(0, 1fr) 96px minmax(0, 1fr); gap: 6px 10px; font-size: 13px; }
.inv-k { opacity: .55; }
.inv-v { word-break: break-word; }
.inv-row { font-size: 12.5px; line-height: 1.9; }
.mono { font-family: var(--jt-mono, monospace); }
.inv-ai { margin-top: 14px; border-top: 1px solid var(--n-border-color, #eee); padding-top: 12px; }
.inv-ai-hd { font-weight: 600; margin-bottom: 2px; }
.inv-ai-note { font-size: 11.5px; opacity: .6; margin-bottom: 8px; }
.inv-ai-body { font-size: 13px; line-height: 1.85; }
.inv-ai-err { color: #d03050; font-size: 12.5px; margin-top: 6px; }
.inv-export { display: flex; align-items: center; gap: 6px; margin-top: 14px;
  padding-top: 12px; border-top: 1px solid var(--n-border-color, #eee); }
.inv-export-k { font-size: 12.5px; opacity: .7; margin-right: 2px; }
.inv-ai-prog { font-weight: 400; font-size: 12px; opacity: .6; margin-left: 8px; }
</style>
