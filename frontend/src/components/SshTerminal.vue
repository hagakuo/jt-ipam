<script setup lang="ts">
import { wsErrorText } from "@/utils/wsError";
import ConnElapsed from "@/components/ConnElapsed.vue";
import ConsoleRouteNote from "@/components/ConsoleRouteNote.vue";
/**
 * SSH 終端機（xterm.js）。先換 ticket → 開 WebSocket → 橋接後端 asyncssh。
 * 憑證（密碼/私鑰）只在連線時送出，前端不保存。Host key 採 TOFU：首次顯示指紋確認後由後端釘選。
 */
import { nextTick, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import {
  NForm, NFormItem, NInput, NInputNumber, NRadioGroup, NRadio, NButton,
  NSpace, NModal, NAlert, NIcon, NSpin, NTag, NButtonGroup, NSelect, NSwitch,
  NPopconfirm, NCard, useMessage,
} from "naive-ui";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useTerminalLinks } from "@/composables/useTerminalLinks";
import "@xterm/xterm/css/xterm.css";
import {
  requestSshTicket, buildSshWsUrl,
  listSshCredentials, createSshCredential, deleteSshCredential, type SshCredential,
} from "@/api/ssh";
import { TerminalIcon, CancelIcon, RefreshIcon, DeleteIcon } from "@/icons";
import ConsoleDisconnectedOverlay from "@/components/ConsoleDisconnectedOverlay.vue";
import GuacView from "@/components/GuacView.vue";
import { consoleEngineLabel } from "@/utils/consoleEngine";

const props = withDefaults(defineProps<{
  addressId: string;
  ip: string;
  hostname?: string | null;
  deviceName?: string | null;
  defaultPort?: number;
  fullHeight?: boolean;
}>(), { defaultPort: 22, fullHeight: false, hostname: null, deviceName: null });

const FONT_MIN = 9;
const FONT_MAX = 24;
// 字級（px）記住：換頁、重連、換引擎都沿用
const FONT_KEY = "jt.sshFontSize";
const fontSize = ref(13);
try {
  const v = Number(localStorage.getItem(FONT_KEY));
  if (v >= FONT_MIN && v <= FONT_MAX) fontSize.value = v;
} catch { /* 隱私模式讀不到就用預設 */ }
/** guacd 的字級單位是 pt（96 DPI 下 1pt＝4/3 px） */
const fontPt = () => Math.round(fontSize.value * 0.75);

const { t } = useI18n();
const msg = useMessage();

// 已存帳密（by-user）：選一筆 → 以 reference 連線；或勾「記住」存新的
const savedCreds = ref<SshCredential[]>([]);
const selectedCredId = ref<string | null>(null);
const remember = ref(false);
const rememberLabel = ref("");
const credOptions = ref<{ label: string; value: string }[]>([]);

async function loadCreds() {
  try {
    savedCreds.value = await listSshCredentials(props.addressId);
    credOptions.value = [
    { label: t('ssh.cred_manual'), value: null as unknown as string },
    ...savedCreds.value.map((c) => ({
      label: `${c.label}（${c.username}・${c.auth_type === "key" ? t("ssh.auth_key") : t("ssh.auth_password")}）`,
      value: c.id,
    }))];
    // 有已存帳密就預設選最近一筆 → 不必再輸入，直接按連線（要改用其他帳密可清空下拉）
    if (!selectedCredId.value && savedCreds.value.length) {
      selectedCredId.value = savedCreds.value[0].id;
    }
  } catch { /* 靜默：沒有已存帳密不影響手動連線 */ }
}
async function delSelectedCred() {
  if (!selectedCredId.value) return;
  try {
    await deleteSshCredential(selectedCredId.value);
    selectedCredId.value = null;
    await loadCreds();
    msg.success(t("common.ok"));
  } catch { msg.error(t("errors.server")); }
}
onMounted(loadCreds);

type Phase = "form" | "connecting" | "connected" | "closed" | "error";
const phase = ref<Phase>("form");
const errorMsg = ref("");

const form = reactive({
  username: "",
  port: props.defaultPort,
  auth: "password" as "password" | "key",
  password: "",
  privateKey: "",
  passphrase: "",
});

const termEl = ref<HTMLElement | null>(null);
let term: Terminal | null = null;
let fit: FitAddon | null = null;
let detachLinks: (() => void) | null = null;
const { hoveredUrl, attachTerminalLinks } = useTerminalLinks();
let ws: WebSocket | null = null;
let ro: ResizeObserver | null = null;
// heartbeat：每 20s 送 ping；45s 內沒收到任何訊息（含 pong）→ 判定斷線
let pingTimer: ReturnType<typeof setInterval> | null = null;
let watchdogTimer: ReturnType<typeof setInterval> | null = null;
let lastRecv = 0;
const PING_MS = 20_000;
const DEAD_MS = 45_000;

// host key TOFU 確認
const hostKeyAsk = ref(false);
const hostKeyFp = ref("");
// 這條連線是否經由跳板（後端在連線前送 status/via_jump）
const viaJump = ref("");
const viaKind = ref("jump");   // "jump"／"agent"（經由掃描代理中繼，issue #24 階段二）
// guacd 引擎（系統設定選的）：終端機由 guacd 在伺服器端畫，這個元件只留表單、工具列與金鑰確認
const guacRef = ref<InstanceType<typeof GuacView> | null>(null);
// 狀態列的「引擎」標示（這次連線實際用的引擎，來自票證）
const engineLabel = ref("");
const guacSession = ref<{ key: number; url: string; config: Record<string, unknown> } | null>(null);

function clearCreds() {
  form.password = "";
  form.privateKey = "";
  form.passphrase = "";
}

function wsSend(obj: Record<string, unknown>) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function disposeTerm() {
  ro?.disconnect(); ro = null;
  term?.dispose(); term = null; fit = null;
}

function onVisibility() {
  // 分頁切回前景：重置計時窗，避免背景期間 lastRecv 變舊 → 一回前景就被 watchdog 誤判斷線
  if (!document.hidden) lastRecv = Date.now();
}
function stopHeartbeat() {
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
  if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null; }
  document.removeEventListener("visibilitychange", onVisibility);
}
function startHeartbeat() {
  stopHeartbeat();
  lastRecv = Date.now();
  document.addEventListener("visibilitychange", onVisibility);
  pingTimer = setInterval(() => wsSend({ type: "ping" }), PING_MS);
  watchdogTimer = setInterval(() => {
    // 背景分頁：瀏覽器會節流 setInterval、應用層 heartbeat 不準 → 不判定斷線。
    // 連線由 WS 傳輸層維持（uvicorn ws-ping/pong，背景分頁也會回 protocol pong），
    // 真正斷線走 ws.onclose。使用者切走再切回不會被誤斷。
    if (document.hidden) return;
    if (phase.value === "connected" && Date.now() - lastRecv > DEAD_MS) {
      // 45s 沒收到任何訊息（含 pong）→ 視為斷線（靜默斷線：拔線/睡眠/對端斷電）
      term?.write(`\r\n\x1b[33m${t("ssh.disconnected")}\x1b[0m\r\n`);
      teardown();
      phase.value = "closed";
    }
  }, 5_000);
}

function teardown() {
  if (detachLinks) { detachLinks(); detachLinks = null; }
  stopHeartbeat();
  guacRef.value?.disconnect();
  try { ws?.close(); } catch { /* noop */ }
  ws = null;
  disposeTerm();
}

function doFit() {
  try {
    fit?.fit();
    if (term) wsSend({ type: "resize", cols: term.cols, rows: term.rows });
  } catch { /* noop */ }
}

// 文字大小快速調整
function setFont(delta: number) {
  fontSize.value = Math.min(FONT_MAX, Math.max(FONT_MIN, fontSize.value + delta));
  try { localStorage.setItem(FONT_KEY, String(fontSize.value)); } catch { /* 忽略 */ }
  if (term) { term.options.fontSize = fontSize.value; doFit(); }
  // guacd 引擎：連線中改字級（argv 串流），工作階段不中斷
  if (guacSession.value) guacRef.value?.setArgument("font-size", String(fontPt()));
}

async function connect() {
  errorMsg.value = "";
  if (!selectedCredId.value && !form.username.trim()) { errorMsg.value = t("ssh.err_username"); return; }
  phase.value = "connecting";

  // 決定憑證 reference：用已選的，或勾「記住」→ 先存後以 reference 連線
  let credId: string | null = selectedCredId.value;
  if (!credId && remember.value) {
    try {
      const saved = await createSshCredential({
        label: rememberLabel.value.trim() || `${form.username.trim()}@${props.ip}`,
        username: form.username.trim(),
        auth_type: form.auth,
        target_ip_id: props.addressId,
        password: form.auth === "password" ? form.password : undefined,
        private_key: form.auth === "key" ? form.privateKey : undefined,
        passphrase: form.auth === "key" ? form.passphrase : undefined,
      });
      credId = saved.id;
      // 記進本地狀態 → 同一分頁內「重新連線」直接沿用剛存的憑證，不再跳帳密輸入。
      // （原本只在重新整理頁面時 loadCreds 才撿得到，故同頁重連仍要求輸入帳密。）
      selectedCredId.value = saved.id;
      remember.value = false;
      void loadCreds();
    } catch (e: any) {
      phase.value = "error";
      errorMsg.value = e?.response?.data?.detail || t("ssh.err_save_cred");
      return;
    }
  }

  let ticket;
  try {
    ticket = await requestSshTicket(props.addressId);
  } catch (e: any) {
    phase.value = "error";
    errorMsg.value = e?.response?.data?.detail || t("ssh.err_ticket");
    return;
  }

  engineLabel.value = consoleEngineLabel(ticket.engine || "builtin");
  if (ticket.engine === "guacd") {
    guacSession.value = {
      key: Date.now(), url: buildSshWsUrl(ticket.ws_path, ticket.ticket),
      config: credId
        ? { credential_id: credId, port: form.port, font_size: fontPt() }
        : { username: form.username.trim(), port: form.port, auth: form.auth, font_size: fontPt(),
            password: form.auth === "password" ? form.password : undefined,
            private_key: form.auth === "key" ? form.privateKey : undefined,
            passphrase: form.auth === "key" ? form.passphrase : undefined },
    };
    clearCreds();
    return;
  }
  guacSession.value = null;
  await nextTick();
  if (!termEl.value) { phase.value = "error"; errorMsg.value = t("ssh.err_ticket"); return; }
  term = new Terminal({ cursorBlink: true, fontSize: fontSize.value, scrollback: 5000,
    allowProposedApi: true,   // Unicode 11 寬度表需要
    theme: { background: "#1e1e1e" } });
  fit = new FitAddon();
  term.loadAddon(fit);
  term.open(termEl.value);
  detachLinks = attachTerminalLinks(term, termEl.value);
  doFit();
  ro = new ResizeObserver(() => doFit());
  ro.observe(termEl.value);
  term.onData((d) => wsSend({ type: "data", data: d }));

  ws = new WebSocket(buildSshWsUrl(ticket.ws_path, ticket.ticket));
  ws.onopen = () => {
    if (credId) {
      // 以已存憑證連線：前端只送 reference，明文不經過 WS
      wsSend({ type: "config", credential_id: credId, port: form.port,
               cols: term?.cols ?? 80, rows: term?.rows ?? 24 });
    } else {
      wsSend({
        type: "config",
        username: form.username.trim(),
        port: form.port,
        auth: form.auth,
        password: form.auth === "password" ? form.password : undefined,
        private_key: form.auth === "key" ? form.privateKey : undefined,
        passphrase: form.auth === "key" ? form.passphrase : undefined,
        cols: term?.cols ?? 80,
        rows: term?.rows ?? 24,
      });
    }
    clearCreds(); // 送出後即清空，前端不留
    startHeartbeat();
  };
  ws.onmessage = (ev) => {
    lastRecv = Date.now();   // 收到任何訊息（含 pong）即視為仍存活
    let payload: any;
    try { payload = JSON.parse(ev.data); } catch { return; }
    switch (payload.type) {
      case "pong": break;   // heartbeat 回應，僅更新 lastRecv（上方已做）
      case "data": term?.write(payload.data); break;
      case "status":
        if (payload.state === "connected") phase.value = "connected";
        else if (payload.state === "disconnected") phase.value = "closed";
        // 經跳板時要講出來：使用者看到的位址是目標，實際路徑卻多了一跳，
        // 出問題時（例如跳板掛了）知道這件事才查得下去
        else if (payload.state === "via_jump") { viaJump.value = payload.via || ""; viaKind.value = payload.via_kind || "jump"; }
        break;
      case "hostkey":
        hostKeyFp.value = payload.fingerprint;
        hostKeyAsk.value = true;
        break;
      case "error":
        phase.value = "error";
        errorMsg.value = wsErrorText(payload, t("ssh.err_generic"));
        break;
    }
  };
  ws.onclose = () => {
    if (phase.value !== "error") {
      phase.value = "closed";
      term?.write(`\r\n\x1b[33m${t("ssh.disconnected")}\x1b[0m\r\n`);
    }
  };
  ws.onerror = () => {
    if (phase.value !== "error" && phase.value !== "connected") {
      phase.value = "error";
      errorMsg.value = t("ssh.err_ws");
    }
  };
}

function acceptHostKey() {
  hostKeyAsk.value = false;
  if (guacSession.value) { guacRef.value?.acceptHostKey(); return; }
  wsSend({ type: "hostkey_accept" });
}
function rejectHostKey() {
  hostKeyAsk.value = false;
  if (guacSession.value) guacRef.value?.rejectHostKey();
  else wsSend({ type: "hostkey_reject" });
  teardown();
  guacSession.value = null;
  phase.value = "form";
}
function onGuacHostKey(fp: string) { hostKeyFp.value = fp; hostKeyAsk.value = true; }
function onGuacError(text: string) { phase.value = "error"; errorMsg.value = text; }

function disconnect() {
  wsSend({ type: "close" });
  teardown();
  phase.value = "closed";
}
function backToForm() {
  teardown();
  guacSession.value = null;
  phase.value = "form";
}

onBeforeUnmount(teardown);
</script>

<template>
  <div class="ssh-wrap" :class="{ 'ssh-full': fullHeight, 'ssh-center': fullHeight && phase === 'form' }">
    <!-- 連線設定表單 -->
    <div v-if="phase === 'form'" class="ssh-form">
      <n-card size="small" :bordered="true">
        <template #header>
          <span style="display:flex;align-items:center;gap:8px">
            <n-icon :component="TerminalIcon" :size="18" />
            <span>{{ t("ssh.connect_to", { ip }) }}</span>
          </span>
        </template>
      <!-- 已存帳密（個人保管）：選一筆即以 reference 連線。獨立 flex 列確保 label 與下拉垂直置中 -->
      <div v-if="savedCreds.length" class="ssh-saved-row">
        <span class="ssh-saved-label">{{ t("ssh.saved_cred") }}</span>
        <n-select v-model:value="selectedCredId" :options="credOptions" clearable size="small"
                  :placeholder="t('ssh.saved_cred_ph')" style="flex:1" />
        <n-popconfirm v-if="selectedCredId" @positive-click="delSelectedCred">
          <template #trigger>
            <n-button quaternary type="error" size="small">
              <template #icon><n-icon :component="DeleteIcon" /></template>
            </n-button>
          </template>
          {{ t("ssh.saved_cred_del_confirm") }}
        </n-popconfirm>
      </div>

      <n-form label-placement="left" :label-width="92" size="small">
        <!-- 手動輸入（未選已存帳密時才顯示）-->
        <template v-if="!selectedCredId">
          <n-form-item :label="t('ssh.auth_method')">
            <n-radio-group v-model:value="form.auth">
              <n-radio value="password">{{ t("ssh.auth_password") }}</n-radio>
              <n-radio value="key">{{ t("ssh.auth_key") }}</n-radio>
            </n-radio-group>
          </n-form-item>
          <n-form-item :label="t('ssh.username')">
            <n-input v-model:value="form.username" placeholder="root" autofocus
                     @keyup.enter="connect" />
          </n-form-item>
          <n-form-item v-if="form.auth === 'password'" :label="t('ssh.password')">
            <n-input v-model:value="form.password" type="password" show-password-on="click"
                     @keyup.enter="connect" />
          </n-form-item>
          <template v-else>
            <n-form-item :label="t('ssh.private_key')">
              <n-input v-model:value="form.privateKey" type="textarea"
                       :autosize="{ minRows: 4, maxRows: 8 }"
                       placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
            </n-form-item>
            <n-form-item :label="t('ssh.passphrase')">
              <n-input v-model:value="form.passphrase" type="password" show-password-on="click" />
            </n-form-item>
          </template>
        </template>

        <n-form-item :label="t('ssh.port')">
          <n-input-number v-model:value="form.port" :min="1" :max="65535" style="width:140px" />
        </n-form-item>

        <!-- 記住此帳密（僅手動模式）-->
        <n-form-item v-if="!selectedCredId" :label="t('ssh.remember')">
          <n-space vertical :size="4" style="width:100%">
            <n-switch v-model:value="remember" />
            <n-input v-if="remember" v-model:value="rememberLabel" size="small"
                     :placeholder="t('ssh.remember_label_ph')" />
          </n-space>
        </n-form-item>

        <!-- 按連線之前就看得到會走哪條路（直連／跳板／掃描代理）、走不通的話原因 -->

        <ConsoleRouteNote :address-id="props.addressId" />

        <n-alert :show-icon="false" type="info" style="margin-bottom:10px">
          {{ selectedCredId ? t("ssh.use_saved_hint") : (remember ? t("ssh.store_hint") : t("ssh.no_store_hint")) }}
        </n-alert>
        <n-space justify="end">
          <n-button type="primary" @click="connect">
            <template #icon><n-icon :component="TerminalIcon" /></template>
            {{ t("ssh.connect") }}
          </n-button>
        </n-space>
      </n-form>
      </n-card>
    </div>

    <!-- 終端機 -->
    <div v-show="phase !== 'form'" class="ssh-term-area" :class="{ 'ssh-full': fullHeight }">
      <div class="ssh-toolbar">
        <span class="ssh-status" :data-state="phase">
          <n-spin v-if="phase === 'connecting'" :size="12" />
          <span v-else class="ssh-dot" />
          <span class="ssh-state-label">{{ t(`ssh.state_${phase}`) }}</span>
          <span class="ssh-ip">{{ ip }}</span>
          <n-tag v-if="hostname" size="small" :bordered="false" round>{{ hostname }}</n-tag>
          <span class="conn-proto conn-proto--ssh">SSH</span>
          <!-- 位址顯示的是目標，但實際路徑多了一跳 —— 不講出來，跳板掛掉時會查錯方向 -->
          <n-tag v-if="viaJump" size="small" type="warning" :bordered="false" round>
            {{ viaKind === "agent" ? t("relay.via_agent") : t("jump_hosts.via") }}：{{ viaJump }}
          </n-tag>
          <n-tag v-if="deviceName" size="small" type="info" :bordered="false" round>{{ deviceName }}</n-tag>
          <n-tag v-if="engineLabel" size="small" :bordered="false" round class="conn-engine"
                 :title="t('common.console_engine_title')">{{ engineLabel }}</n-tag>
          <ConnElapsed :active="phase === 'connected'" />
        </span>
        <n-space :size="8" align="center">
          <!-- 文字大小快速調整 -->
          <n-button-group v-if="phase === 'connected'" size="tiny">
            <n-button :disabled="fontSize <= FONT_MIN" :title="t('ssh.font_smaller')" @click="setFont(-1)">A−</n-button>
            <n-button :disabled="fontSize >= FONT_MAX" :title="t('ssh.font_larger')" @click="setFont(1)">A+</n-button>
          </n-button-group>
          <n-button v-if="phase === 'connected'" size="tiny" type="error" ghost @click="disconnect">
            <template #icon><n-icon :component="CancelIcon" /></template>{{ t("ssh.disconnect") }}
          </n-button>
          <n-button v-if="phase === 'closed' || phase === 'error'" size="tiny" @click="backToForm">
            <template #icon><n-icon :component="RefreshIcon" /></template>{{ t("ssh.reconnect") }}
          </n-button>
        </n-space>
      </div>
      <n-alert v-if="phase === 'error'" type="error" :show-icon="true" style="margin:8px 0">
        {{ errorMsg }}
      </n-alert>
      <div class="ssh-disp" :class="{ 'ssh-full': fullHeight }">
        <div class="term-host">
          <GuacView v-if="guacSession" :key="guacSession.key" ref="guacRef" class="ssh-term ssh-guac"
                    :class="{ 'ssh-full': fullHeight, 'term-dim': phase === 'closed' }"
                    :ws-url="guacSession.url" :config="guacSession.config" protocol="ssh"
                    scale-mode="native" :resize-remote="true" :sync-clipboard="true"
                    @connected="phase = 'connected'" @closed="phase = 'closed'" @error="onGuacError"
                    @hostkey="onGuacHostKey" @via-jump="(v: string, k: string) => { viaJump = v; viaKind = k || 'jump'; }" />
          <div v-else ref="termEl" class="ssh-term" :class="{ 'ssh-full': fullHeight, 'term-dim': phase === 'closed' }" />
          <div v-if="hoveredUrl" class="term-linkbar" :title="hoveredUrl">{{ hoveredUrl }}</div>
        </div>
        <ConsoleDisconnectedOverlay :show="phase === 'closed' || phase === 'error'" :error="phase === 'error'" />
      </div>
    </div>

    <!-- host key TOFU 確認 -->
    <n-modal v-model:show="hostKeyAsk" preset="dialog" :title="t('ssh.hostkey_title')"
             :positive-text="t('ssh.hostkey_trust')" :negative-text="t('common.cancel')"
             @positive-click="acceptHostKey" @negative-click="rejectHostKey"
             :mask-closable="false">
      <div style="line-height:1.6">
        <div>{{ t("ssh.hostkey_body", { ip }) }}</div>
        <code class="ssh-fp">{{ hostKeyFp }}</code>
        <div style="opacity:.7;font-size:12px">{{ t("ssh.hostkey_hint") }}</div>
      </div>
    </n-modal>
  </div>
</template>

<style scoped>
.ssh-wrap { width: 100%; }
.ssh-wrap.ssh-full { height: 100%; display: flex; flex-direction: column; }
/* 全頁模式且尚未連線：把連線表單置中（頁面很大時不要黏左上角） */
.ssh-wrap.ssh-center { justify-content: center; align-items: center; }
.ssh-wrap.ssh-center .ssh-form { width: 560px; max-width: 92vw; }
.ssh-form { max-width: 560px; }
.ssh-title { font-weight: 600; display: flex; align-items: center; gap: 6px; margin-bottom: 12px; }
.ssh-term-area { display: flex; flex-direction: column; }
.ssh-disp { position: relative; }
.ssh-disp.ssh-full { flex: 1; min-height: 0; display: flex; flex-direction: column; }
.ssh-term-area.ssh-full { flex: 1; min-height: 0; }
.ssh-toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; padding: 4px 2px; gap: 8px; }
.ssh-status { font-size: 13px; display: inline-flex; align-items: center; gap: 7px;
  padding: 3px 11px; border-radius: 999px; font-weight: 500;
  background: rgba(128, 128, 128, .12); color: #888; }
/* 手機：內容放不下時整顆標籤換到下一行，不要把「連線錯誤」擠成直排、也不要超出畫面 */
.ssh-status { flex-wrap: wrap; row-gap: 4px; max-width: 100%; min-width: 0; }
.ssh-status > * { flex: none; max-width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
@media (max-width: 640px) { .ssh-status { border-radius: 14px; } }
.ssh-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; flex: none; }
.ssh-ip { opacity: .7; font-variant-numeric: tabular-nums; }
.ssh-status[data-state="connected"] { color: #18a058; background: rgba(24, 160, 88, .14); }
.ssh-status[data-state="connected"] .ssh-dot { animation: ssh-pulse 1.8s infinite; }
.ssh-status[data-state="connecting"] { color: #d99812; background: rgba(217, 152, 18, .14); }
.ssh-status[data-state="error"] { color: #d03050; background: rgba(208, 48, 80, .14); }
.ssh-status[data-state="closed"] { color: #888; background: rgba(128, 128, 128, .14); }
@keyframes ssh-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(24, 160, 88, .5); }
  70%  { box-shadow: 0 0 0 6px rgba(24, 160, 88, 0); }
  100% { box-shadow: 0 0 0 0 rgba(24, 160, 88, 0); }
}
.ssh-term { height: 420px; background: #1e1e1e; padding: 8px; border-radius: 8px;
  border: 1px solid #2b2b30; box-shadow: 0 1px 3px rgba(0,0,0,.18); overflow: hidden; }
.ssh-term.ssh-full { flex: 1; height: auto; min-height: 0; }
/* guacd：終端機由伺服器端畫成圖，不要 padding（尺寸要跟 guacd 算的欄列數對齊） */
.ssh-term.ssh-guac { padding: 0; }
/* 卡片標題 icon+文字垂直置中（覆蓋主題預設，避免內容偏上） */
:deep(.n-card > .n-card-header) { display: flex; align-items: center; padding-top: 12px; padding-bottom: 12px; }
/* 「已存帳密」列：flex 列，label 與下拉/刪除鈕保證垂直置中；label 寬度對齊表單 92px 欄 */
.ssh-saved-row { display: flex; align-items: center; margin-bottom: 18px; }
.ssh-saved-label { width: 92px; flex: none; box-sizing: border-box; text-align: right;
  padding-right: 12px; font-size: 14px; }
.ssh-saved-row :deep(.n-button) { margin-left: 6px; }
/* 協定標籤（主機名稱右邊）：SSH */
.conn-proto { font-weight: 700; font-size: 11px; letter-spacing: .4px; line-height: 1;
  padding: 2px 7px; border-radius: 999px; }
.conn-proto--ssh { color: #18a058; background: rgba(24,160,88,.16); }
.ssh-fp { display: block; margin: 8px 0; padding: 6px 8px; background: rgba(128,128,128,.12);
  border-radius: 4px; word-break: break-all; font-size: 13px; }
/* 已斷線：整個畫面反灰並停用互動，讓使用者一眼看出已中斷 */
.term-dim { filter: grayscale(1) brightness(.45); pointer-events: none; transition: filter .25s; }

/* 懸停連結預覽：終端機文字是遠端主機控制的，點下去之前要看得到完整目標 */
.term-host { position: relative; height: 100%; min-height: 0; display: flex; flex-direction: column; }
.term-linkbar {
  position: absolute; left: 0; bottom: 0; max-width: 100%;
  padding: 2px 10px; font-size: 12px; line-height: 1.6;
  background: rgba(0, 0, 0, .82); color: #9ecbff;
  border-top-right-radius: 6px; pointer-events: none;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
</style>
