/**
 * SFTP 傳輸路徑測試（2026-09-26）：從瀏覽器實際上傳、下載一段資料，看整條路
 * （瀏覽器 → 前端反向代理 → IPAM 的 nginx → 後端）吃不吃得下。
 *
 * 為什麼要實測、為什麼只能從瀏覽器測：見 backend/app/services/sftp_probe.py。
 * 走的是跟 SFTP 同一條 WebSocket 路徑，上傳的節奏也跟 SftpBrowser 一樣
 * （16 KiB 的框、從小窗開始、收到確認就加倍）—— 測的是 SFTP 真正會做的事。
 */

export type ProbeProblem =
  | "ws_blocked"      // WebSocket 連不上這條路徑（代理沒替它開 WebSocket）
  | "msg_too_big"     // 被以「訊息太大」斷線（1009）
  | "closed"          // 傳到一半連線被切斷
  | "no_data_up"      // 上傳的資料送不過去（伺服器收不到新資料）
  | "no_data_down"    // 下載的資料收不到
  | "error";          // 其他（伺服器回錯誤等）

export interface ProbeResult {
  ok: boolean;
  problem?: ProbeProblem;
  closeCode?: number;
  /** 出問題時完成了多少／總共多少（位元組） */
  done?: number;
  total?: number;
  /** 多久沒有新資料（秒），no_data_* 用 */
  stallSec?: number;
  detail?: string;
  upBps?: number;
  downBps?: number;
}

// 與 SftpBrowser 的上傳相同（改那邊時這裡要一起改）
const CHUNK = 16 * 1024;
const WINDOW_START = 32 * 1024;
const WINDOW_MAX = 4 * 1024 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const FIRST_ACK_TIMEOUT = 15_000;
const STALL_TIMEOUT = 20_000;
const OPEN_TIMEOUT = 10_000;

class ProbeError extends Error {
  constructor(public result: ProbeResult) { super(result.problem); }
}

export async function runSftpProbe(opts: {
  url: string; upBytes: number; downBytes: number;
  onProgress?: (stage: "up" | "down", done: number, total: number) => void;
}): Promise<ProbeResult> {
  const { url, upBytes, downBytes, onProgress } = opts;
  const ws = new WebSocket(url);
  ws.binaryType = "arraybuffer";
  let opened = false;
  let closed: CloseEvent | null = null;
  // 目前在等什麼：收到訊息時交給它；連線被關時用 onClose 讓它失敗
  let onText: ((m: any) => void) | null = null;
  let onBinary: ((n: number) => void) | null = null;
  let onClose: ((e: CloseEvent) => void) | null = null;
  ws.onmessage = (ev) => {
    if (typeof ev.data === "string") {
      try { onText?.(JSON.parse(ev.data)); } catch { /* 不是 JSON，忽略 */ }
    } else {
      onBinary?.((ev.data as ArrayBuffer).byteLength);
    }
  };
  ws.onclose = (e) => { closed = e; onClose?.(e); };

  const closeProblem = (e: CloseEvent, done: number, total: number): ProbeResult =>
    ({ ok: false, problem: e.code === 1009 ? "msg_too_big" : "closed", closeCode: e.code, done, total });

  try {
    // ── 連線與 ready ──
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new ProbeError({ ok: false, problem: "ws_blocked", closeCode: 0 })), OPEN_TIMEOUT);
      ws.onopen = () => { opened = true; };
      onText = (m) => { if (m.type === "ready") { clearTimeout(timer); resolve(); } };
      onClose = (e) => { clearTimeout(timer); reject(new ProbeError({ ok: false, problem: opened ? "closed" : "ws_blocked", closeCode: e.code })); };
    });

    // ── 上傳：跟 SftpBrowser 同樣的流量控制 ──
    const block = new Uint8Array(CHUNK);
    crypto.getRandomValues(block);        // 隨機內容：路上若有壓縮，量到的才不會失真
    const upStart = performance.now();
    await new Promise<void>((resolve, reject) => {
      let acked = 0, win = WINDOW_START, sent = 0, lastProgress = performance.now();
      let ready = false;
      let waiter: (() => void) | null = null;
      const fail = (r: ProbeResult) => { clearInterval(watch); reject(new ProbeError(r)); };
      const watch = setInterval(() => {
        const idle = performance.now() - lastProgress;
        const limit = acked === 0 && ready ? FIRST_ACK_TIMEOUT : STALL_TIMEOUT;
        if (idle > limit) fail({ ok: false, problem: "no_data_up", done: acked, total: upBytes, stallSec: Math.round(idle / 1000) });
      }, 500);
      onClose = (e) => fail(closeProblem(e, acked, upBytes));
      onText = (m) => {
        if (m.type === "put_ready") { ready = true; lastProgress = performance.now(); void pump(); }
        else if (m.type === "put_ack") {
          if (m.bytes > acked) {
            acked = m.bytes; lastProgress = performance.now();
            if (win < WINDOW_MAX) win = Math.min(win * 2, WINDOW_MAX);
            onProgress?.("up", acked, upBytes);
            waiter?.();
          }
        } else if (m.type === "ok") { clearInterval(watch); resolve(); }
        else if (m.type === "error") fail({ ok: false, problem: "error", detail: m.message || m.code });
      };
      const pump = async () => {
        while (sent < upBytes) {
          if (ws.readyState !== WebSocket.OPEN) return;
          while (sent - acked >= win || ws.bufferedAmount > HIGH_WATER) {
            await new Promise<void>((r) => { waiter = r; setTimeout(r, 50); });
            waiter = null;
            if (ws.readyState !== WebSocket.OPEN) return;
          }
          const n = Math.min(CHUNK, upBytes - sent);
          ws.send(n === CHUNK ? block : block.slice(0, n));
          sent += n;
        }
      };
      ws.send(JSON.stringify({ type: "put", size: upBytes, id: 1 }));
    });
    const upBps = upBytes / Math.max(0.001, (performance.now() - upStart) / 1000);

    // ── 下載 ──
    let downStart = 0;
    await new Promise<void>((resolve, reject) => {
      let got = 0, lastProgress = performance.now();
      const fail = (r: ProbeResult) => { clearInterval(watch); reject(new ProbeError(r)); };
      const watch = setInterval(() => {
        const idle = performance.now() - lastProgress;
        if (idle > STALL_TIMEOUT) fail({ ok: false, problem: "no_data_down", done: got, total: downBytes, stallSec: Math.round(idle / 1000) });
      }, 500);
      onClose = (e) => fail(closeProblem(e, got, downBytes));
      onBinary = (n) => { got += n; lastProgress = performance.now(); onProgress?.("down", got, downBytes); };
      onText = (m) => {
        if (m.type === "file_begin") { downStart = performance.now(); lastProgress = downStart; }
        else if (m.type === "file_end") {
          clearInterval(watch);
          if (got < downBytes) fail({ ok: false, problem: "no_data_down", done: got, total: downBytes, stallSec: 0 });
          else resolve();
        } else if (m.type === "error") fail({ ok: false, problem: "error", detail: m.message || m.code });
      };
      ws.send(JSON.stringify({ type: "get", size: downBytes, id: 2 }));
    });
    const downBps = downBytes / Math.max(0.001, (performance.now() - downStart) / 1000);
    return { ok: true, upBps, downBps };
  } catch (e) {
    if (e instanceof ProbeError) return e.result;
    return { ok: false, problem: "error", detail: String(e) };
  } finally {
    onClose = null; onText = null; onBinary = null;
    if (!closed && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ type: "bye" })); } catch { /* 已經斷了 */ }
    }
    try { ws.close(); } catch { /* 已經斷了 */ }
  }
}

/** 位元組／秒 → 顯示用字串 */
export function fmtRate(bps: number): string {
  if (bps >= 1024 * 1024) return `${(bps / 1024 / 1024).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bps / 1024))} KB`;
}

/** 秒數 → 「約 3 分鐘」之類的粗略時間（給估算用） */
export function roughDuration(sec: number, t: (k: string, p?: Record<string, unknown>) => string): string {
  if (sec < 60) return t("common.duration_sec", { n: Math.max(1, Math.round(sec)) });
  if (sec < 3600) return t("common.duration_min", { n: Math.round(sec / 60) });
  return t("common.duration_hour", { n: (sec / 3600).toFixed(1) });
}
