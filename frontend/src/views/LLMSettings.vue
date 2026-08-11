<script setup lang="ts">
/**
 * LLM / AI 全域設定 (管理員)。
 *
 * 設定會覆寫環境變數，寫入 system_settings 表。所有 user 共用。
 */
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NSpace, NIcon, NAlert, NSwitch, NInput, NInputNumber, NSelect, NButton, NTag, NTimePicker,
  NPopconfirm, NModal, useMessage,
} from "naive-ui";
import {
  getLLMConfig, patchLLMConfig, listOllamaModels, revealMcpKey, rotateMcpKey, checkEmbedding,
  reindexEmbeddings,
  type LLMConfig, type LLMConfigPatch, type OllamaModel, type EmbeddingCheck,
  type ReindexResult,
} from "@/api/system";
import { listMcpTools, type McpTool } from "@/api/chat";
import { listSubnets, setAIAuditScope } from "@/api/subnets";
import type { Subnet } from "@/types";
import { SettingsIcon, RefreshIcon, ToolsIcon, KeyIcon, CopyIcon, EyeIcon, EyeOffIcon, AnomalyIcon, PlusIcon, DeleteIcon } from "@/icons";
import { apiErrMsg } from "@/api/client";

const { t } = useI18n();
const msg = useMessage();
const llm = ref<LLMConfig | null>(null);
const models = ref<OllamaModel[]>([]);
const modelsLoading = ref(false);
const modelsError = ref<string | null>(null);

const modelOptions = computed(() => {
  // 已 pull 的 model；若目前設定的不在清單裡也補上去避免變空
  const opts = models.value.map((m) => ({
    label: m.parameter_size ? `${m.name} (${m.parameter_size})` : m.name,
    value: m.name,
  }));
  for (const v of [llm.value?.chat_model, llm.value?.embedding_model]) {
    if (v && !opts.find((o) => o.value === v)) {
      opts.push({ label: t("llm_settings.model_not_found", { model: v }), value: v });
    }
  }
  return opts;
});

// 嵌入模型名稱慣例含 "embed"（qwen3-embedding / nomic-embed-text / mxbai-embed…）
const isEmbedModel = (name: string) => /embed/i.test(name);
// 嵌入模型下拉：只有嵌入模型可選，其餘反灰（目前已選的仍保留可見）
const embeddingModelOptions = computed(() =>
  modelOptions.value.map((o) => ({
    ...o,
    disabled: !isEmbedModel(o.value) && o.value !== llm.value?.embedding_model,
  })));
// 對話模型下拉：反過來把嵌入模型反灰
const chatModelOptions = computed(() =>
  modelOptions.value.map((o) => ({
    ...o,
    disabled: isEmbedModel(o.value) && o.value !== llm.value?.chat_model,
  })));
// 巡檢模型下拉：同樣排除嵌入模型；清空＝沿用對話模型（不是「沒有模型」）
const auditModelOptions = computed(() =>
  modelOptions.value.map((o) => ({
    ...o,
    disabled: isEmbedModel(o.value) && o.value !== llm.value?.ai_audit_model,
  })));

// 巡檢範圍。存的是每個子網路的 ai_audit_enabled 欄位（跟子網路編輯頁同一個），
// 不是另外存一份清單 —— 存兩份遲早會出現「這裡看是開的、那裡看是關的」。
const subnets = ref<Subnet[]>([]);
const subnetsLoading = ref(false);
const auditScope = ref<string[]>([]);
const subnetOptions = computed(() => subnets.value.map((s) => ({
  label: s.description ? `${s.cidr} — ${s.description}` : s.cidr,
  value: s.id,
})));

async function loadSubnets() {
  subnetsLoading.value = true;
  try {
    const r = await listSubnets({ pageSize: 500 });
    subnets.value = r.items;
    auditScope.value = r.items.filter((s) => s.ai_audit_enabled).map((s) => s.id);
  } catch { /* 沒權限或載入失敗 → 這一格留空，不擋整頁 */ } finally { subnetsLoading.value = false; }
}

async function saveScope(ids: string[]) {
  try {
    await setAIAuditScope(ids);
    msg.success(t("common.saved"));
  } catch (e) { msg.error(apiErrMsg(e)); await loadSubnets(); }
}

// 排程時刻。n-time-picker 吃毫秒時間戳，設定存的是 "HH:MM" —— 兩邊在這裡轉換。
const auditTimes = computed(() => llm.value?.ai_audit_times?.length
  ? [...llm.value.ai_audit_times] : ["03:30"]);

function hhmmToMs(hhmm: string): number {
  const [h, m] = hhmm.split(":").map((x) => Number(x) || 0);
  const d = new Date();
  d.setHours(h, m, 0, 0);
  return d.getTime();
}

function setTime(index: number, formatted: string | null) {
  if (!formatted) return;
  const next = [...auditTimes.value];
  next[index] = formatted;
  patch({ ai_audit_times: next });
}

function addTime() {
  patch({ ai_audit_times: [...auditTimes.value, "12:00"] });
}

function removeTime(index: number) {
  const next = auditTimes.value.filter((_, i) => i !== index);
  // 一個都不留等於安靜地把排程關掉，但開關還是開著 —— 後端也會擋，這裡先不讓它發生
  if (next.length) patch({ ai_audit_times: next });
}

async function loadModels() {
  modelsLoading.value = true;
  modelsError.value = null;
  try {
    const res = await listOllamaModels();
    models.value = res.models;
    if (res.error) modelsError.value = res.error;
  } catch (e: any) {
    modelsError.value = e?.response?.data?.detail ?? String(e);
  } finally {
    modelsLoading.value = false;
  }
}

const providerOptions = computed(() => [
  { label: t("llm_settings.provider_ollama"), value: "ollama" },
  { label: t("llm_settings.provider_openai"), value: "openai" },
]);

// 嵌入維度檢查：模型回幾維、資料庫要幾維、通不通
const embedBusy = ref(false);
const embedResult = ref<EmbeddingCheck | null>(null);
const reindexBusy = ref(false);
const reindexResult = ref<ReindexResult | null>(null);
async function doReindex() {
  reindexBusy.value = true;
  reindexResult.value = null;
  try { reindexResult.value = await reindexEmbeddings(); }
  catch (e) { msg.error(apiErrMsg(e)); }
  finally { reindexBusy.value = false; }
}

async function doCheckEmbedding() {
  embedBusy.value = true;
  try { embedResult.value = await checkEmbedding(); }
  catch (e) { msg.error(apiErrMsg(e)); }
  finally { embedBusy.value = false; }
}

async function load() {
  try { llm.value = await getLLMConfig(); }
  catch (e) { msg.error(apiErrMsg(e)); }
  // 未啟用連接時不要自動去抓清單（否則會冒出「無法連上 LLM 伺服器」錯誤）
  if (llm.value?.enabled) { void loadModels(); void doCheckEmbedding(); }
}

// URL 改了也重新拉 model 清單 (換 LLM 伺服器時可能不同)；僅在已啟用時
watch(() => llm.value?.url, () => { if (llm.value?.url && llm.value?.enabled) void loadModels(); });
// 換供應商等於換端點（/api/tags ↔ /v1/models），清單一定要重拉，否則下拉會留著上一家的模型
watch(() => llm.value?.provider, () => { if (llm.value?.url && llm.value?.enabled) void loadModels(); });
// 啟用切換：開啟才去抓清單；關閉時清掉清單與錯誤（避免殘留「無法連」）
watch(() => llm.value?.enabled, (en) => {
  if (en) { if (llm.value?.url) void loadModels(); }
  else { models.value = []; modelsError.value = null; }
});

let debounce: ReturnType<typeof setTimeout> | null = null;
function patch(p: LLMConfigPatch) {
  if (!llm.value) return;
  llm.value = { ...llm.value, ...p } as LLMConfig;
  if (debounce) clearTimeout(debounce);
  debounce = setTimeout(async () => {
    try {
      llm.value = await patchLLMConfig(p);
      msg.success(t("common.saved"));
    } catch (e: any) {
      msg.error(e?.response?.data?.detail ?? t("errors.server"));
    }
  }, 600);
}

// 對外提供 MCP（讓其它系統呼叫）
const mcpKey = ref<string | null>(null);   // 已揭示的明文（null＝未揭示）
const mcpKeyBusy = ref(false);
const mcpUrl = computed(() => `${window.location.origin}/api/mcp`);
async function doRevealKey() {
  mcpKeyBusy.value = true;
  try { mcpKey.value = await revealMcpKey(); }
  catch { msg.error(t("errors.server")); }
  finally { mcpKeyBusy.value = false; }
}
async function doRotateKey() {
  mcpKeyBusy.value = true;
  try {
    mcpKey.value = await rotateMcpKey();
    if (llm.value) llm.value.mcp_api_key_set = true;
    msg.success(t("common.saved"));
  } catch { msg.error(t("errors.server")); }
  finally { mcpKeyBusy.value = false; }
}
async function copyText(s: string | null) {
  if (!s) return;
  try { await navigator.clipboard.writeText(s); msg.success(t("common.copied_clipboard")); }
  catch { /* ignore */ }
}

// 產生各用戶端的 MCP 設定（方便對方直接貼上）
const cfgShow = ref(false);
async function openClientConfigs() {
  // 已設金鑰但尚未揭示 → 先揭示，讓產生的設定直接帶上真正的金鑰
  if (!mcpKey.value && llm.value?.mcp_api_key_set) await doRevealKey();
  cfgShow.value = true;
}
const clientConfigs = computed(() => {
  const url = mcpUrl.value;
  const key = mcpKey.value || "<API KEY>";
  return [
    {
      id: "claude", name: "Claude Desktop", file: "claude_desktop_config.json",
      code: JSON.stringify({ mcpServers: { "jt-ipam": {
        command: "npx", args: ["-y", "mcp-remote", url, "--header", `X-Auth-Token: ${key}`],
      } } }, null, 2),
    },
    {
      id: "opencode", name: "opencode", file: "opencode.json",
      code: JSON.stringify({ mcp: { "jt-ipam": {
        type: "remote", url, enabled: true, headers: { "X-Auth-Token": key },
      } } }, null, 2),
    },
    {
      id: "mcpo", name: "mcpo", file: "config.json（mcpo --config config.json）",
      code: JSON.stringify({ mcpServers: { "jt-ipam": {
        type: "streamablehttp", url, headers: { "X-Auth-Token": key },
      } } }, null, 2),
    },
    {
      id: "generic", name: "Cursor / Cline / VS Code", file: "mcp.json",
      code: JSON.stringify({ mcpServers: { "jt-ipam": { url, headers: { "X-Auth-Token": key } } } }, null, 2),
    },
  ];
});

// MCP / AI 工具清單
const mcpTools = ref<McpTool[]>([]);
const mcpMutating = ref(0);
async function loadTools() {
  try { const r = await listMcpTools(); mcpTools.value = r.tools; mcpMutating.value = r.mutating_count; }
  catch { /* ignore */ }
}

onMounted(() => { void load(); void loadTools(); void loadSubnets(); });
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><SettingsIcon /></n-icon>
        <span>{{ t("llm_settings.title") }}</span>
      </n-space>
    </template>
    <!-- 不限寬：說明文字在寬螢幕上只佔一半版面、右邊整片空白，讀起來被硬折行 -->
    <n-space v-if="llm" vertical :size="16" style="width: 100%">
      <n-alert type="info" size="small">
        <span v-html="t('llm_settings.admin_note', { strong: `<strong>${t('llm_settings.admin_global_settings')}</strong>` })" />
      </n-alert>
      <div>
        <label>{{ t("llm_settings.enable_ollama") }}</label>
        <n-switch :value="llm.enabled" @update:value="(v: boolean) => patch({ enabled: v })" />
      </div>
      <div>
        <label>{{ t("llm_settings.provider") }}</label>
        <n-select
          :value="llm.provider ?? 'ollama'"
          :options="providerOptions"
          @update:value="(v: string) => patch({ provider: v })"
        />
        <p class="hint">{{ t("llm_settings.provider_hint") }}</p>
      </div>
      <!-- 選了外部供應商就要講清楚資料會離開自己的網路。
           這個專案的賣點是「自架 LLM、資料不外流」，改成雲端是使用者的選擇，
           但不能讓它悄悄發生。 -->
      <n-alert v-if="(llm.provider ?? 'ollama') === 'openai'" type="warning"
               :bordered="false" :show-icon="true">
        {{ t("llm_settings.provider_egress_warn") }}
      </n-alert>
      <div>
        <label>{{ (llm.provider ?? 'ollama') === 'openai' ? t("llm_settings.api_base") : "Ollama URL" }}</label>
        <n-input
          :value="llm.url"
          :placeholder="(llm.provider ?? 'ollama') === 'openai'
            ? 'https://api.openai.com/v1' : 'http://127.0.0.1:11434'"
          @update:value="(v: string) => patch({ url: v })"
        />
        <p v-if="(llm.provider ?? 'ollama') === 'openai'" class="hint">
          {{ t("llm_settings.api_base_hint") }}
        </p>
      </div>
      <div v-if="(llm.provider ?? 'ollama') === 'openai'">
        <label>{{ t("llm_settings.api_key") }}</label>
        <n-input type="password" show-password-on="click"
                 :placeholder="llm.api_key_set ? t('llm_settings.api_key_set') : 'sk-…'"
                 @update:value="(v: string) => patch({ api_key: v })" />
        <p class="hint">{{ t("llm_settings.api_key_hint") }}</p>
      </div>
      <div>
        <n-space align="center" style="margin-bottom: 4px">
          <label style="margin: 0">{{ t("llm_settings.chat_model") }}</label>
          <n-button text size="tiny" @click="loadModels" :loading="modelsLoading">
            <template #icon><n-icon><RefreshIcon /></n-icon></template>
            {{ t("llm_settings.reload_list") }}
          </n-button>
          <span v-if="modelsError" style="color: var(--err-color, #e88080); font-size: 11px;">
            {{ t("llm_settings.ollama_unreachable", { err: modelsError.slice(0, 80) }) }}
          </span>
        </n-space>
        <n-select
          :value="llm.chat_model"
          :options="chatModelOptions"
          :loading="modelsLoading"
          :placeholder="t('llm_settings.pick_model')"
          filterable
          @update:value="(v: string) => patch({ chat_model: v })"
        />
      </div>
      <div>
        <n-space align="center" style="margin-bottom: 4px">
          <label style="margin: 0">{{ t("llm_settings.embedding_model") }}</label>
          <n-button text size="tiny" :loading="embedBusy" @click="doCheckEmbedding">
            <template #icon><n-icon><RefreshIcon /></n-icon></template>
            {{ t("llm_settings.embed_check") }}
          </n-button>
        </n-space>
        <n-select
          :value="llm.embedding_model"
          :options="embeddingModelOptions"
          :loading="modelsLoading"
          :placeholder="t('llm_settings.pick_model')"
          filterable
          @update:value="(v: string) => patch({ embedding_model: v })"
        />
        <!-- 選錯嵌入模型時唯一的症狀是「語意搜尋永遠沒有結果」，畫面上沒有任何線索
             指向維度不合 —— 所以要能當場問一次、把實際維度講出來。 -->
        <p v-if="embedResult" class="hint" :style="embedResult.ok ? 'color:#18a058' : 'color:#e88080'">
          {{ embedResult.ok
            ? t("llm_settings.embed_ok", { dim: embedResult.dim })
            : embedResult.dim
              ? t("llm_settings.embed_dim_mismatch", { dim: embedResult.dim, expected: embedResult.expected })
              : t("llm_settings.embed_failed", { err: String(embedResult.error).slice(0, 120) }) }}
        </p>
        <p class="hint">{{ t("llm_settings.embed_hint", { expected: embedResult?.expected ?? 768 }) }}</p>
        <!-- 換過模型之後，既有物件的向量還是空的 —— 沒有這顆按鈕，使用者無從讓
             語意搜尋真的開始運作（端點一直都在，只是畫面上沒有入口）。 -->
        <n-space align="center" style="margin-top:8px">
          <n-button size="small" :loading="reindexBusy" @click="doReindex">
            <template #icon><n-icon><RefreshIcon /></n-icon></template>
            {{ t("llm_settings.reindex") }}
          </n-button>
          <span v-if="reindexResult" class="hint" style="margin:0"
                :style="reindexResult.failed ? 'color:#e88080' : 'color:#18a058'">
            {{ reindexResult.failed
              ? t("llm_settings.reindex_failed", { n: reindexResult.failed,
                    err: String(reindexResult.error).slice(0, 100) })
              : t("llm_settings.reindex_ok", { n: reindexResult.subnets
                    + reindexResult.ip_addresses + reindexResult.devices }) }}
          </span>
        </n-space>
        <p class="hint">{{ t("llm_settings.reindex_hint") }}</p>
      </div>
      <div>
        <label>{{ t("llm_settings.timeout_sec") }}</label>
        <n-input-number
          :value="llm.timeout"
          :min="1"
          :max="600"
          @update:value="(v: any) => patch({ timeout: v })"
        />
      </div>
      <div>
        <label>{{ t("llm_settings.num_ctx") }}</label>
        <n-input-number
          :value="llm.num_ctx ?? null"
          :min="0"
          :max="131072"
          :step="1024"
          clearable
          :placeholder="t('llm_settings.num_ctx_placeholder')"
          style="width: 220px"
          @update:value="(v: any) => patch({ num_ctx: v ?? 0 })"
        />
        <p class="hint">{{ t("llm_settings.num_ctx_hint") }}</p>
      </div>
    </n-space>
    <p v-else style="opacity: 0.7">{{ t("common.loading") }}</p>
  </n-card>

  <!-- AI 巡檢排程 -->
  <n-card v-if="llm" style="margin-top:16px">
    <template #header>
      <n-space align="center" :size="8">
        <n-icon :size="18" :component="AnomalyIcon" />
        <span>{{ t("llm_settings.audit_title") }}</span>
      </n-space>
    </template>
    <n-alert type="warning" :bordered="false" :show-icon="true" style="margin-bottom:14px">
      {{ t("llm_settings.audit_warning") }}
    </n-alert>
    <n-space vertical :size="14">
      <div>
        <n-switch :value="llm.ai_audit_enabled"
                  @update:value="(v: boolean) => patch({ ai_audit_enabled: v })" />
        <span style="margin-left:10px">{{ t("llm_settings.audit_enabled") }}</span>
        <p class="hint">{{ t("llm_settings.audit_enabled_hint") }}</p>
      </div>
      <div>
        <label>{{ t("llm_settings.audit_model") }}</label>
        <n-select
          :value="llm.ai_audit_model"
          :options="auditModelOptions"
          :loading="modelsLoading"
          :disabled="!llm.ai_audit_enabled"
          :placeholder="t('llm_settings.audit_model_inherit', { model: llm.chat_model })"
          clearable
          filterable
          style="width: 100%"
          @update:value="(v: string | null) => patch({ ai_audit_model: v ?? '' })"
        />
        <p class="hint">{{ t("llm_settings.audit_model_hint") }}</p>
      </div>
      <div>
        <label>{{ t("llm_settings.audit_num_ctx") }}</label>
        <n-input-number :value="llm.ai_audit_num_ctx" :min="0" :max="131072" :step="2048"
                        :disabled="!llm.ai_audit_enabled" clearable style="width: 220px"
                        :placeholder="String(llm.num_ctx ?? 4096)"
                        @update:value="(v: number | null) => patch({ ai_audit_num_ctx: v ?? 0 })" />
        <p class="hint">{{ t("llm_settings.audit_num_ctx_hint", { n: llm.num_ctx ?? 4096 }) }}</p>
      </div>
      <div>
        <label>{{ t("llm_settings.audit_scope") }}</label>
        <n-select v-model:value="auditScope" multiple filterable clearable
                  :options="subnetOptions" :loading="subnetsLoading"
                  :disabled="!llm.ai_audit_enabled"
                  :placeholder="t('llm_settings.audit_scope_none')"
                  style="width: 100%" @update:value="saveScope" />
        <p class="hint">{{ t("llm_settings.audit_scope_hint") }}</p>
      </div>
      <div>
        <label>{{ t("llm_settings.audit_times") }}</label>
        <div class="times">
          <div v-for="(tm, i) in auditTimes" :key="i" class="time-row">
            <n-time-picker :value="hhmmToMs(tm)" format="HH:mm" :disabled="!llm.ai_audit_enabled"
                           style="width: 130px"
                           @update:formatted-value="(v: string | null) => setTime(i, v)" />
            <n-button quaternary size="small" :disabled="!llm.ai_audit_enabled || auditTimes.length <= 1"
                      @click="removeTime(i)">
              <template #icon><n-icon><DeleteIcon /></n-icon></template>
            </n-button>
          </div>
          <n-button size="small" dashed :disabled="!llm.ai_audit_enabled || auditTimes.length >= 12"
                    @click="addTime">
            <template #icon><n-icon><PlusIcon /></n-icon></template>
            {{ t("llm_settings.audit_add_time") }}
          </n-button>
        </div>
        <p class="hint">
          {{ t("llm_settings.audit_times_hint", { tz: llm.server_timezone || "—" }) }}
        </p>
      </div>
    </n-space>
  </n-card>

  <!-- 對外提供 MCP：讓其它系統（外部 LLM 客戶端 / 自動化）以 HTTP 呼叫本站 MCP -->
  <n-card v-if="llm" style="margin-top:16px">
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="20"><KeyIcon /></n-icon>
        <span>{{ t("llm_settings.mcp_ext_title") }}</span>
      </n-space>
    </template>

    <div class="row">
      <label>{{ t("llm_settings.mcp_ext_enable") }}</label>
      <n-switch :value="llm.mcp_external_enabled"
                @update:value="(v: boolean) => patch({ mcp_external_enabled: v })" />
    </div>
    <p class="hint">{{ t("llm_settings.mcp_ext_hint") }}</p>

    <template v-if="llm.mcp_external_enabled">
      <!-- 連線資訊：外部系統要填的 URL / 傳輸 / 認證標頭 -->
      <div class="mcp-info">
        <div class="mcp-info-row">
          <span class="mcp-k">{{ t("llm_settings.mcp_url") }}</span>
          <code class="mcp-v">{{ mcpUrl }}</code>
          <n-button size="tiny" @click="copyText(mcpUrl)">
            <template #icon><n-icon :component="CopyIcon" /></template>{{ t("common.copy") }}
          </n-button>
        </div>
        <div class="mcp-info-row">
          <span class="mcp-k">{{ t("llm_settings.mcp_transport") }}</span>
          <code class="mcp-v">Streamable HTTP（JSON-RPC 2.0, POST）</code>
          <span class="mcp-or">{{ t("llm_settings.mcp_transport_note") }}</span>
        </div>
        <div class="mcp-info-row mcp-auth-hd">
          <span class="mcp-k">{{ t("llm_settings.mcp_auth_header") }}</span>
          <span class="mcp-or">{{ t("llm_settings.mcp_auth_choose") }}</span>
        </div>
        <!-- 兩種寫法各一列，名稱與值各自對齊成欄；原本擠在同一行讀起來像一串亂碼 -->
        <div class="mcp-auth-grid">
          <span class="mcp-kn">{{ t("llm_settings.mcp_header_name") }}</span>
          <code class="mcp-v">X-Auth-Token</code>
          <span class="mcp-kn">{{ t("llm_settings.mcp_header_value") }}</span>
          <code class="mcp-v">&lt;API KEY&gt;</code>

          <span class="mcp-kn">{{ t("llm_settings.mcp_header_name") }}</span>
          <code class="mcp-v">Authorization</code>
          <span class="mcp-kn">{{ t("llm_settings.mcp_header_value") }}</span>
          <code class="mcp-v">Bearer &lt;API KEY&gt;</code>
        </div>
        <div class="mcp-info-row mcp-gen-row">
          <n-button size="small" type="primary" ghost @click="openClientConfigs">
            <template #icon><n-icon :component="CopyIcon" /></template>{{ t("llm_settings.mcp_gen_config") }}
          </n-button>
          <span class="mcp-or">{{ t("llm_settings.mcp_gen_inline_hint") }}</span>
        </div>
      </div>

      <!-- API 金鑰（唯讀範圍）：標籤獨立一行，下方為金鑰值與操作 -->
      <div class="mcp-key">
        <label>{{ t("llm_settings.mcp_key") }}</label>
        <n-space align="center" :size="8" :wrap-item="false" style="flex-wrap:wrap">
          <code v-if="mcpKey" class="mcp-keybox mcp-keybox--val">{{ mcpKey }}</code>
          <span v-else-if="llm.mcp_api_key_set" class="mcp-keybox">••••••••••••（{{ t("llm_settings.mcp_key_hidden") }}）</span>
          <span v-else class="mcp-keybox mcp-keybox--none">{{ t("llm_settings.mcp_key_none") }}</span>

          <n-button v-if="llm.mcp_api_key_set && !mcpKey" size="small" :loading="mcpKeyBusy" @click="doRevealKey">
            <template #icon><n-icon :component="EyeIcon" /></template>{{ t("llm_settings.mcp_key_reveal") }}
          </n-button>
          <n-button v-if="mcpKey" size="small" @click="copyText(mcpKey)">
            <template #icon><n-icon :component="CopyIcon" /></template>{{ t("common.copy") }}
          </n-button>
          <n-button v-if="mcpKey" size="small" @click="mcpKey = null">
            <template #icon><n-icon :component="EyeOffIcon" /></template>{{ t("llm_settings.mcp_key_hide") }}
          </n-button>

          <n-popconfirm v-if="llm.mcp_api_key_set" @positive-click="doRotateKey">
            <template #trigger>
              <n-button size="small" type="warning" ghost :loading="mcpKeyBusy">
                <template #icon><n-icon :component="RefreshIcon" /></template>{{ t("llm_settings.mcp_key_rotate") }}
              </n-button>
            </template>
            {{ t("llm_settings.mcp_key_rotate_confirm") }}
          </n-popconfirm>
          <n-button v-else size="small" type="primary" :loading="mcpKeyBusy" @click="doRotateKey">
            <template #icon><n-icon :component="KeyIcon" /></template>{{ t("llm_settings.mcp_key_generate") }}
          </n-button>
        </n-space>
        <p class="hint">{{ t("llm_settings.mcp_key_hint") }}</p>
      </div>
    </template>

    <n-modal v-model:show="cfgShow" preset="card"
             :title="t('llm_settings.mcp_gen_title')" style="width: 760px; max-width: 94vw">
      <p class="hint" style="margin-top:0">{{ t("llm_settings.mcp_gen_hint") }}</p>
      <div v-for="cc in clientConfigs" :key="cc.id" class="cfg-block">
        <div class="cfg-head">
          <span class="cfg-name">{{ cc.name }}</span>
          <code class="cfg-file">{{ cc.file }}</code>
          <n-button size="tiny" @click="copyText(cc.code)">
            <template #icon><n-icon :component="CopyIcon" /></template>{{ t("common.copy") }}
          </n-button>
        </div>
        <pre class="cfg-code">{{ cc.code }}</pre>
      </div>
    </n-modal>
  </n-card>

  <n-card style="margin-top:16px">
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="20"><ToolsIcon /></n-icon>
        <span>{{ t("llm_settings.tools_title") }}</span>
      </n-space>
    </template>
    <p class="tools-cap">{{ t("llm_settings.tools_intro", { n: mcpTools.length, m: mcpMutating }) }}</p>
    <div class="tool-list">
      <div v-for="tool in mcpTools" :key="tool.name" class="tool-item">
        <div class="tool-head">
          <code class="tool-name">{{ tool.name }}</code>
          <n-tag v-if="tool.mutating" size="tiny" type="warning" :bordered="false">
            {{ t("llm_settings.tools_mutating") }}
          </n-tag>
          <n-tag v-else size="tiny" type="success" :bordered="false">
            {{ t("llm_settings.tools_readonly") }}
          </n-tag>
        </div>
        <div class="tool-desc">{{ tool.description }}</div>
        <div v-if="tool.params.length" class="tool-params">
          <span v-for="p in tool.params" :key="p.name" class="tool-param"
                :title="p.description">
            {{ p.name }}<span v-if="p.required" class="req">*</span>
            <em>{{ p.type }}</em>
          </span>
        </div>
      </div>
    </div>
  </n-card>
</template>

<style scoped>
label {
  display: block;
  font-size: 12px;
  margin-bottom: 4px;
  opacity: 0.8;
}
.times { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.time-row { display: flex; align-items: center; gap: 2px; }
.hint { margin: 4px 0 0; font-size: 12px; opacity: 0.6; line-height: 1.5; }
.tools-cap { margin: 0 0 12px; font-size: 13px; opacity: 0.7; }
.tool-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
.tool-item { border: 1px solid var(--n-border-color, #eee); border-radius: 8px; padding: 10px 12px; }
.tool-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.tool-name { font-weight: 700; font-size: 13px; }
.tool-desc { font-size: 12.5px; opacity: 0.85; line-height: 1.5; }
.tool-params { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
.tool-param { font-size: 11px; background: rgba(128,128,128,0.1); border-radius: 5px; padding: 1px 6px; font-family: ui-monospace, monospace; }
.tool-param .req { color: #d03050; margin-left: 1px; }
.tool-param em { opacity: 0.55; font-style: normal; margin-left: 4px; }
/* 對外 MCP 卡片 */
.row { display: flex; align-items: center; gap: 12px; }
.row > label { margin-bottom: 0; }
.mcp-info { margin: 14px 0 4px; border: 1px solid var(--n-border-color, #eee); border-radius: 8px;
  padding: 10px 12px; background: rgba(128,128,128,0.04); }
.mcp-info-row { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; padding: 4px 0; font-size: 13px; }
.mcp-auth-hd { margin-bottom: 2px; }
/* 名稱／值 兩組欄位；auto 讓標籤只佔文字寬度，值欄可伸展 */
.mcp-auth-grid {
  display: grid; grid-template-columns: auto auto auto minmax(0, 1fr);
  gap: 6px 8px; align-items: center; margin: 2px 0 8px 12px;
}
.mcp-k { min-width: 96px; opacity: 0.65; font-size: 12.5px; }
.mcp-v { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px;
  background: rgba(128,128,128,0.12); border-radius: 5px; padding: 2px 7px; word-break: break-all; }
.mcp-or { opacity: 0.5; font-size: 12px; }
.mcp-info-sub { padding-left: 14px; }
.mcp-kn { opacity: 0.6; font-size: 11.5px; }
.mcp-key { margin-top: 14px; }
/* 金鑰值/狀態框：與旁邊 small 按鈕同高（28px） */
.mcp-keybox { display: inline-flex; align-items: center; min-height: 28px; box-sizing: border-box;
  padding: 0 10px; border: 1px solid var(--n-border-color, rgba(128,128,128,0.3)); border-radius: 6px;
  background: rgba(128,128,128,0.06); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12.5px; line-height: 1.4; word-break: break-all; }
.mcp-keybox--val { background: rgba(24,160,88,0.12); border-color: rgba(24,160,88,0.35); }
.mcp-keybox--none { color: #d0a215; background: rgba(208,162,21,0.08); border-color: rgba(208,162,21,0.4); }
.mcp-gen-row { margin-top: 8px; padding-top: 10px; align-items: center; gap: 10px;
  border-top: 1px dashed var(--n-border-color, rgba(128,128,128,.22)); }
.mcp-gen-row .mcp-or { font-size: 12px; opacity: .6; }
.cfg-block { margin-bottom: 14px; }
.cfg-head { display: flex; align-items: center; gap: 10px; margin-bottom: 5px; }
.cfg-name { font-weight: 600; font-size: 13px; }
.cfg-file { font-size: 11.5px; opacity: .6; }
.cfg-head .n-button { margin-left: auto; }
.cfg-code { margin: 0; padding: 10px 12px; border-radius: 8px; font-size: 12px; line-height: 1.5;
  background: rgba(128,128,128,.1); overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
