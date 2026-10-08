<script setup lang="ts">
/**
 * guacd 引擎的畫面（RDP／VNC／SSH 共用）。
 *
 * 流程跟其他引擎前半段一樣：開 WebSocket → 送 config（帳密或已存帳密 id、尺寸）→ 收 JSON 狀態。
 * 後端跟 guacd 握手、等到第一個畫面後回 `{"type":"status","state":"connected","engine":"guacd"}`，
 * **從下一則訊息起這條 WebSocket 改講 Guacamole 協定**，交給 guacamole-common-js 處理。
 * 所以這裡用一個自訂的 tunnel 接在同一條 WebSocket 上，而不是 guacamole 內建的 WebSocketTunnel
 * （那個要自己開連線、而且第一則就要是 Guacamole 協定，接不上我們的票證與錯誤格式）。
 *
 * 父元件（RdpScreen／VncScreen／SshTerminal）保留自己的表單與工具列，只把畫面換成這個。
 */
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import Guacamole from "@/vendor/guacamole/guacamole-common.js";
import { wsErrorText } from "@/utils/wsError";

const props = withDefaults(defineProps<{
  wsUrl: string;
  /** 第一則 config 訊息的內容（帳密或 credential_id…）；尺寸、DPI、時區由這裡補上 */
  config: Record<string, unknown>;
  protocol: "rdp" | "vnc" | "ssh";
  scaleMode?: "fit" | "native";
  /** 固定尺寸（RDP 選了解析度時）；不給就量容器 */
  fixedSize?: [number, number] | null;
  /** 容器大小改變時要不要請遠端跟著改（RDP 的 display-update、SSH 的終端機大小；VNC 由伺服器決定） */
  resizeRemote?: boolean;
  /** 在 guacd 的剪貼簿與瀏覽器之間同步（SSH：複製、貼上都可以） */
  syncClipboard?: boolean;
}>(), { scaleMode: "fit", fixedSize: null, resizeRemote: false, syncClipboard: false });

const emit = defineEmits<{
  (e: "connecting"): void;
  (e: "connected", size: { width: number; height: number }): void;
  (e: "closed"): void;
  (e: "error", text: string): void;
  (e: "via-jump", via: string, kind: string): void;
  (e: "hostkey", fingerprint: string): void;
  (e: "notice", text: string): void;
}>();

const { t } = useI18n();
const boxEl = ref<HTMLElement | null>(null);
const hostEl = ref<HTMLElement | null>(null);
// 鍵盤的接收點：一個看不見的 textarea。guacamole 的鍵盤模組自己會處理輸入法（組字中的按鍵略過、
// 組好的字從 compositionend／input 送出），但那兩種事件只有可輸入的元素收得到 ——
// 接在 div 上的話，注音、倉頡打的中文全部送不出去（2026-09-25 實測）。
const imeEl = ref<HTMLTextAreaElement | null>(null);
// 按鍵依序送出：貼上快捷鍵要先等瀏覽器剪貼簿讀完，後面的按鍵（包括 V 本身與修飾鍵的放開）
// 都要排在它後面，否則 V 會在 Ctrl／Shift 放開之後才送到，變成打出一個「V」
let keyChain: Promise<void> = Promise.resolve();
function queueKey(pressed: 0 | 1, keysym: number) {
  keyChain = keyChain.then(() => { client?.sendKeyEvent(pressed, keysym); });
}

let ws: WebSocket | null = null;
let tunnel: any = null;
let client: any = null;
let keyboard: any = null;
let mouse: any = null;
let ro: ResizeObserver | null = null;
let resizeTimer: ReturnType<typeof setTimeout> | null = null;
let finished = false;       // 已經回報過 closed／error，之後的事件不再改狀態

// ───────── 自訂 tunnel：接在已經開好的 WebSocket 上 ─────────
function JtTunnel(this: any, socket: WebSocket) {
  Guacamole.Tunnel.call(this);
  // guacamole 的 Tunnel 是舊式建構函式（prototype 繼承），回呼裡要拿得到這個實例
  // eslint-disable-next-line @typescript-eslint/no-this-alias
  const self = this;
  const parser = new Guacamole.Parser();
  parser.oninstruction = (opcode: string, args: string[]) => {
    if (self.oninstruction) self.oninstruction(opcode, args);
  };
  const len = (s: string) => (Guacamole.Parser.codePointCount ? Guacamole.Parser.codePointCount(s) : s.length);
  this.receive = (text: string) => {
    try { parser.receive(text); }
    catch (err: any) {
      if (self.onerror) self.onerror(new Guacamole.Status(Guacamole.Status.Code.SERVER_ERROR, String(err?.message || err)));
    }
  };
  this.connect = () => { self.setState(Guacamole.Tunnel.State.OPEN); };
  this.disconnect = () => {
    self.setState(Guacamole.Tunnel.State.CLOSED);
    try { socket.close(); } catch { /* noop */ }
  };
  this.sendMessage = (...elements: unknown[]) => {
    if (!elements.length || socket.readyState !== WebSocket.OPEN) return;
    const msg = elements.map((v) => { const s = String(v); return `${len(s)}.${s}`; }).join(",") + ";";
    socket.send(msg);
  };
}
(JtTunnel as any).prototype = new Guacamole.Tunnel();

// ───────── 尺寸與縮放 ─────────
/**
 * 高解析度螢幕（Retina 等）的像素倍率。遠端畫面要用**裝置像素**算尺寸、DPI 跟著乘，
 * 顯示時再縮回 CSS 像素 —— 跟官方 guacamole-client 的作法一樣。以前只把 DPI 乘上倍率、
 * 尺寸卻用 CSS 像素：guacd 依 DPI 把 SSH 字型畫成兩倍大，1:1 顯示出來字就大一倍（使用者回報）。
 * 使用者指定固定解析度時就照那個解析度、DPI 96，不乘倍率。
 */
const density = Math.min(3, Math.max(1, window.devicePixelRatio || 1));
function boxSize(): [number, number] {
  const b = boxEl.value;
  const w = Math.max(320, Math.floor(b?.clientWidth || window.innerWidth - 24));
  const h = Math.max(200, Math.floor(b?.clientHeight || window.innerHeight - 120));
  return [Math.round(w * density), Math.round(h * density)];
}
function applyScale() {
  const display = client?.getDisplay();
  const b = boxEl.value;
  if (!display || !b) return;
  const dw = display.getWidth(), dh = display.getHeight();
  if (!dw || !dh) return;
  if (props.scaleMode === "native") { display.scale(props.fixedSize ? 1 : 1 / density); return; }
  display.scale(Math.min(b.clientWidth / dw, b.clientHeight / dh));
}
function onBoxResize() {
  applyScale();
  if (!props.resizeRemote || !client || props.fixedSize) return;
  if (resizeTimer) clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const [w, h] = boxSize();
    client?.sendSize(w, h);
  }, 300);
}

// ───────── 剪貼簿 ─────────
function setRemoteClipboard(text: string) {
  if (!client) return;
  const stream = client.createClipboardStream("text/plain");
  const writer = new Guacamole.StringWriter(stream);
  writer.sendText(text);
  writer.sendEnd();
}
/** 讀瀏覽器剪貼簿寫進遠端剪貼簿；讀不到回 false（沒給權限、或剪貼簿是空的） */
async function paste(): Promise<"ok" | "denied" | "empty"> {
  let text = "";
  try { text = await navigator.clipboard.readText(); }
  catch { return "denied"; }
  if (!text) return "empty";
  setRemoteClipboard(text);
  return "ok";
}

// ───────── 按鍵 ─────────
const KEYSYMS: Record<string, number> = {
  Escape: 0xff1b, Tab: 0xff09, Control: 0xffe3, Alt: 0xffe9, Shift: 0xffe1, Delete: 0xffff,
  Meta: 0xffeb, " ": 0x20, Enter: 0xff0d, Backspace: 0xff08,
};
for (let i = 1; i <= 12; i++) KEYSYMS[`F${i}`] = 0xffbe + i - 1;
/** 送出組合鍵（useSendKeys 的 token）：依序按下、反序放開 */
function sendCombo(tokens: string[]) {
  if (!client) return;
  const syms = tokens.map((k) => KEYSYMS[k] ?? (k.length === 1 ? k.codePointAt(0)! : 0)).filter(Boolean);
  syms.forEach((s) => queueKey(1, s));
  [...syms].reverse().forEach((s) => queueKey(0, s));
  focus();
}

function focus() { (imeEl.value ?? boxEl.value)?.focus({ preventScroll: true }); }
function onBoxMouseDown(e: MouseEvent) { e.preventDefault(); focus(); }

// ───────── 連線 ─────────
function fail(text: string) {
  if (finished) return;
  finished = true;
  emit("error", text);
  teardown();
}
function closed() {
  if (finished) return;
  finished = true;
  emit("closed");
  teardown();
}

function statusText(status: any): string {
  // guacd 的狀態碼 → 跟後端同一組錯誤代碼（errors.guacd_*），原文當 reason
  const code = Number(status?.code);
  const map: Record<number, string> = {
    0x0200: "guacd_server_error", 0x0201: "guacd_server_busy", 0x0202: "guacd_upstream_timeout",
    0x0203: "guacd_upstream_error", 0x0204: "guacd_resource_not_found", 0x0207: "guacd_upstream_not_found",
    0x0208: "guacd_upstream_unavailable", 0x0209: "guacd_session_conflict", 0x020A: "guacd_session_timeout",
    0x020B: "guacd_session_closed", 0x0300: "guacd_bad_request", 0x0301: "guacd_unauthorized",
    0x0303: "guacd_forbidden", 0x0308: "guacd_client_timeout", 0x031D: "guacd_too_many",
  };
  const reason = String(status?.message || "");
  return wsErrorText({ code: map[code] || "guacd_upstream_error", params: { reason }, message: reason },
    t("rdp.err_generic"));
}

function startGuac() {
  if (!ws || !hostEl.value) return;
  tunnel = new (JtTunnel as any)(ws);
  client = new Guacamole.Client(tunnel);
  const display = client.getDisplay();
  hostEl.value.appendChild(display.getElement());
  display.onresize = () => applyScale();

  client.onerror = (status: any) => fail(statusText(status));
  client.onstatechange = (state: number) => {
    if (state === Guacamole.Client.State.DISCONNECTED) closed();
  };
  if (props.syncClipboard) {
    // 遠端複製（選取文字、Ctrl+Shift+C）→ 瀏覽器剪貼簿
    client.onclipboard = (stream: any, mimetype: string) => {
      if (!/^text\//.test(mimetype)) return;
      const reader = new Guacamole.StringReader(stream);
      let data = "";
      reader.ontext = (s: string) => { data += s; };
      reader.onend = () => { navigator.clipboard?.writeText(data).catch(() => { /* 沒給權限就算了 */ }); };
    };
  }

  mouse = new Guacamole.Mouse(display.getElement());
  mouse.onEach(["mousedown", "mouseup", "mousemove"], (e: any) => {
    if (e.type === "mousedown") focus();
    client?.sendMouseState(e.state, true);
  });

  const ime = imeEl.value!;
  keyboard = new Guacamole.Keyboard(ime);
  // guacamole 處理完 input 之後把輸入框清空（它不會自己清，內容會一直累積）
  ime.addEventListener("input", () => { if (!(ime as any)._composing) ime.value = ""; });
  ime.addEventListener("compositionstart", () => { (ime as any)._composing = true; });
  ime.addEventListener("compositionend", () => { (ime as any)._composing = false; ime.value = ""; });
  keyboard.onkeydown = (keysym: number) => {
    // SSH 貼上（Ctrl+Shift+V／Cmd+V）：guacd 貼的是它自己的剪貼簿，
    // 所以 V 送出去之前先把瀏覽器剪貼簿同步過去
    const m = keyboard.modifiers;
    if (props.syncClipboard && ((keysym === 0x56 && m.ctrl) || (keysym === 0x76 && m.meta))) {
      keyChain = keyChain.then(() => paste().then(() => undefined));
    }
    queueKey(1, keysym);
    return false;
  };
  keyboard.onkeyup = (keysym: number) => { queueKey(0, keysym); };

  client.connect("");
  ro = new ResizeObserver(onBoxResize);
  if (boxEl.value) ro.observe(boxEl.value);
  nextTick(() => { applyScale(); focus(); });
}

async function connect() {
  finished = false;
  emit("connecting");
  await nextTick();
  const [w, h] = props.fixedSize ?? boxSize();
  let tz = "";
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { /* noop */ }
  ws = new WebSocket(props.wsUrl);
  ws.onopen = () => {
    ws?.send(JSON.stringify({ type: "config", ...props.config, width: w, height: h,
      dpi: props.fixedSize ? 96 : Math.round(96 * density), timezone: tz || undefined }));
  };
  ws.onmessage = (ev) => {
    if (tunnel) { tunnel.receive(ev.data); return; }    // 已經切到 Guacamole 協定
    let payload: any;
    try { payload = JSON.parse(ev.data); } catch { return; }
    switch (payload.type) {
      case "status":
        if (payload.state === "connected") {
          startGuac();
          emit("connected", { width: Number(payload.width) || w, height: Number(payload.height) || h });
        } else if (payload.state === "via_jump") emit("via-jump", payload.via || "", payload.via_kind || "jump");
        else if (payload.state === "disconnected") closed();
        break;
      case "hostkey": emit("hostkey", payload.fingerprint || ""); break;
      case "notice": emit("notice", wsErrorText(payload)); break;
      case "error": fail(wsErrorText(payload, t("rdp.err_generic"))); break;
    }
  };
  ws.onclose = () => { if (!finished) closed(); };
  ws.onerror = () => { if (!tunnel && !finished) fail(t("rdp.err_ws")); };
}

function acceptHostKey() { ws?.send(JSON.stringify({ type: "hostkey_accept" })); }
function rejectHostKey() {
  try { ws?.send(JSON.stringify({ type: "hostkey_reject" })); } catch { /* noop */ }
  finished = true;
  teardown();
}

function teardown() {
  if (resizeTimer) { clearTimeout(resizeTimer); resizeTimer = null; }
  ro?.disconnect(); ro = null;
  if (keyboard) { keyboard.onkeydown = null; keyboard.onkeyup = null; try { keyboard.reset(); } catch { /* noop */ } }
  if (mouse) mouse.offEach?.(["mousedown", "mouseup", "mousemove"]);
  const c = client; client = null;
  if (c) { c.onstatechange = null; c.onerror = null; try { c.disconnect(); } catch { /* noop */ } }
  const s = ws; ws = null; tunnel = null;
  if (s) { s.onclose = null; s.onmessage = null; s.onerror = null; try { s.close(); } catch { /* noop */ } }
}

function disconnect() {
  finished = true;
  teardown();
}

onMounted(connect);
watch(() => props.scaleMode, () => nextTick(applyScale));
onBeforeUnmount(() => { finished = true; teardown(); });

/** 連線中修改連線參數（guacd 的 argv 串流），例如 SSH 終端機的 font-size —— 不必重新連線 */
function setArgument(name: string, value: string) {
  if (!client) return;
  const writer = new Guacamole.StringWriter(client.createArgumentValueStream("text/plain", name));
  writer.sendText(value);
  writer.sendEnd();
}

defineExpose({ disconnect, sendCombo, paste, focus, acceptHostKey, rejectHostKey, setArgument,
  refit: onBoxResize });
</script>

<template>
  <!-- 外框不可聚焦：鍵盤一律由下面的 textarea 接。按下滑鼠時擋掉瀏覽器預設的焦點轉移，
       否則焦點會跑到外框（或 body），打字全部沒反應、中文也打不出來 -->
  <div ref="boxEl" class="guac-box" :class="{ 'guac-native': scaleMode === 'native' }"
       @mousedown.capture="onBoxMouseDown" @contextmenu.prevent>
    <div ref="hostEl" class="guac-host" />
    <textarea ref="imeEl" class="guac-ime" tabindex="-1" autocomplete="off" autocorrect="off"
              autocapitalize="off" spellcheck="false" :aria-label="t('rdp.keyboard_input')" />
  </div>
</template>

<style scoped>
.guac-box { position: relative; width: 100%; height: 100%; min-height: 0; overflow: hidden;
  display: flex; align-items: center; justify-content: center; background: #000; outline: none; }
.guac-box.guac-native { overflow: auto; align-items: flex-start; justify-content: flex-start; }
.guac-host { line-height: 0; }
/* 看不見、點不到（滑鼠事件要給畫面），但拿得到焦點、輸入法的候選窗也跟著它出現 */
.guac-ime { position: absolute; left: 8px; top: 8px; width: 1px; height: 1px; opacity: 0;
  border: 0; padding: 0; resize: none; overflow: hidden; pointer-events: none; }
/* guacamole 的游標層與畫布都在 guac-host 底下，滑鼠要能點到 */
.guac-host :deep(canvas) { display: block; }
</style>
