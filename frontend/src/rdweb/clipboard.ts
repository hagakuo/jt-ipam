/**
 * 相容 RustDesk 的網頁連線：雙向剪貼簿（規格附錄 F；訊息格式見 §12、F.1）。
 *
 * - 受控端 → 瀏覽器：`multi_clipboards (28)`（也接受舊式 `clipboard (16)`），取第一個純文字項目；
 *   只有 HTML 時轉成純文字，HTML 本身也一起交出去（瀏覽器支援時以 text/html 寫入本機剪貼簿）。
 * - 瀏覽器 → 受控端：`multi_clipboards`，一個 Text 項目。超過 64 KB 時規格建議改送 zstd 壓縮；
 *   目前沒有可以在瀏覽器裡跑、授權合適的純 JavaScript zstd 壓縮器（WebAssembly 版被站台的 CSP 擋下），
 *   所以預設一律不壓縮送出（F.1 第 5 點：未壓縮的 multi_clipboards 受控端一樣會寫入）。
 *   ClipboardSync 留了 compress 的掛鉤，之後有壓縮器時直接接上。
 * - 文字上限 1 MB（UTF-8 bytes），收到壓縮的內容時解壓後也一樣（F.2）。
 * - 開關（登入時的 disable_clipboard、執行中的 Misc.option）由 RdSession 管；這裡只問它「現在能不能送」。
 */
import { concat, fBool, fBytes, fMsg, fVarint, getBool, getBytes, getInt, getMsgs, parse, type Fields } from "./pb";
import { BoolOption, encodeMessage } from "./messages";
import { zstdDecompress } from "./zstd";

/** ClipboardFormat：F.1 第 2 點實測過的兩種；其他格式（圖片等）忽略 */
export const ClipboardFormat = { Text: 0, Html: 2 } as const;
/** F.2：送出與接收的文字上限 */
export const MAX_CLIPBOARD_BYTES = 1 << 20;
/** F.2：超過這個大小時改送壓縮的內容（要有壓縮器才會壓） */
export const COMPRESS_THRESHOLD = 64 << 10;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

export interface ClipItem { compress: boolean; content: Uint8Array; format: number }

function toItem(f: Fields): ClipItem {
  return { compress: getBool(f, 1), content: getBytes(f, 2), format: getInt(f, 5) };
}

/** Clipboard { compress (1), content (2), width (3), height (4), format (5), special_name (6) } */
export function parseClipboard(body: Uint8Array): ClipItem {
  return toItem(parse(body));
}

/** MultiClipboards { clipboards (1): repeated Clipboard } */
export function parseMultiClipboards(body: Uint8Array): ClipItem[] {
  return getMsgs(parse(body), 1).map(toItem);
}

export type Incoming =
  | { kind: "text"; text: string; html?: string }
  | { kind: "too_large" }
  | { kind: "none" };          // 沒有文字或 HTML、或內容解不開

/** HTML → 純文字（F.2：DOMParser 的 textContent）。解析出來的文件是惰性的：不執行指令碼、不載入圖片。 */
export function htmlToText(html: string): string {
  if (typeof DOMParser === "undefined") return html.replace(/<[^>]*>/g, "");
  const doc = new DOMParser().parseFromString(html, "text/html");
  doc.querySelectorAll("script, style, template").forEach((n) => n.remove());
  return doc.body?.textContent ?? "";
}

/** 一個項目的內容（壓縮的先解壓），超過上限回 "too_large"、解不開回 null。 */
function itemText(it: ClipItem, maxBytes: number): string | "too_large" | null {
  let raw = it.content;
  if (it.compress) {
    const r = zstdDecompress(raw, maxBytes);
    if (!r.ok) return r.reason === "too_large" ? "too_large" : null;
    raw = r.data;
  } else if (raw.length > maxBytes) {
    return "too_large";
  }
  return dec.decode(raw);
}

/** F.2：取第一個 Text 項目；沒有的話取第一個 Html 項目轉成純文字。只解要用的那一個。 */
export function readIncoming(items: ClipItem[], maxBytes = MAX_CLIPBOARD_BYTES,
                             toText: (html: string) => string = htmlToText): Incoming {
  const textItem = items.find((i) => i.format === ClipboardFormat.Text);
  const pick = textItem ?? items.find((i) => i.format === ClipboardFormat.Html);
  if (!pick) return { kind: "none" };
  const s = itemText(pick, maxBytes);
  if (s === "too_large") return { kind: "too_large" };
  if (s === null) return { kind: "none" };
  if (textItem) return { kind: "text", text: s };
  return { kind: "text", text: toText(s), html: s };
}

export type Compressor = (raw: Uint8Array) => Uint8Array;

/** 送給受控端的剪貼簿：multi_clipboards，一個 Text 項目（format 0 是預設值，不寫）。 */
export function encodeClipboardBytes(raw: Uint8Array, compress?: Compressor): Uint8Array {
  const zipped = compress && raw.length > COMPRESS_THRESHOLD ? compress(raw) : null;
  const item = zipped ? concat(fBool(1, true), fBytes(2, zipped)) : fBytes(2, raw);
  return encodeMessage("multi_clipboards", fMsg(1, item));
}

/** 執行中切換剪貼簿：Misc { option (7): OptionMessage { disable_clipboard (8) } }；其他欄位不填＝不變（§7.4）。 */
export function encodeClipboardOption(enabled: boolean): Uint8Array {
  return encodeMessage("misc", fMsg(7, fVarint(8, enabled ? BoolOption.No : BoolOption.Yes)));
}

export interface ClipboardTransport {
  /** 現在能不能送（已登入、開關開著、不是唯讀檢視） */
  enabled(): boolean;
  /** 送出一則已編好的 Message；沒送出回 false */
  send(msg: Uint8Array): boolean;
}

export type SendResult = "sent" | "duplicate" | "disabled" | "empty" | "too_large";

/** 一條連線的剪貼簿狀態：上限、略過重複、收到的內容怎麼解讀。 */
export class ClipboardSync {
  /** 已知對方剪貼簿目前的文字（我們送過去的、或對方送來的）；不確定時是 null */
  private peerText: string | null = null;

  constructor(private readonly transport: ClipboardTransport,
              private readonly opts: { compress?: Compressor; maxBytes?: number } = {}) {}

  private get max(): number {
    return this.opts.maxBytes ?? MAX_CLIPBOARD_BYTES;
  }

  /**
   * 把文字送到對方的剪貼簿。對方剪貼簿已經是這段內容時略過（F.2 第 3 點，免得每次 Ctrl+V 都重送）；
   * force＝使用者明確按了「傳送文字」，照送。
   */
  send(text: string, force = false): SendResult {
    if (!this.transport.enabled()) return "disabled";
    if (!text) return "empty";
    const raw = enc.encode(text);
    if (raw.length > this.max) return "too_large";
    if (!force && text === this.peerText) return "duplicate";
    if (!this.transport.send(encodeClipboardBytes(raw, this.opts.compress))) return "disabled";
    this.peerText = text;
    return "sent";
  }

  /** 收到對方的剪貼簿。不管這則能不能用，之前記的「對方剪貼簿內容」都不再成立。 */
  receive(kind: "clipboard" | "multi_clipboards", body: Uint8Array): Incoming {
    const items = kind === "clipboard" ? [parseClipboard(body)] : parseMultiClipboards(body);
    const r = readIncoming(items, this.max);
    this.peerText = r.kind === "text" ? r.text : null;
    return r;
  }

  /** 開關重新打開、或重新連線：這段期間對方的剪貼簿可能變過（關著時對方不會通知）。 */
  reset(): void {
    this.peerText = null;
  }
}

// ── 瀏覽器端（本機剪貼簿）──

/**
 * Ctrl+V 的按鍵（F.2）：Ctrl+V；控制端是 macOS 時也接受 Cmd+V。
 * Shift 不排除（Linux 終端機的貼上是 Ctrl+Shift+V），Alt 排除。
 */
export function isPasteKey(e: { code: string; ctrlKey: boolean; metaKey: boolean; altKey: boolean },
                           macController: boolean): boolean {
  return e.code === "KeyV" && !e.altKey && (e.ctrlKey || (macController && e.metaKey));
}

/**
 * 剪貼簿送出後要送給受控端的按鍵（KeyboardEvent.code 與按下／放開）。
 * - Ctrl+V：Ctrl 已經照常送過去了，只補 V 的按下（放開照一般流程）。
 * - macOS 的 Cmd+V、受控端不是 macOS：對方要收到 Ctrl+V。先放開已經送過去的 Meta、按一下 Ctrl+V，
 *   再把 Meta 按回去（使用者手還按著 Cmd，之後的放開照一般流程送）。受控端是 macOS 時 Cmd+V 本來就是貼上，照送。
 */
export function pasteKeys(cmdToCtrl: boolean, held: Iterable<string>): Array<{ code: string; down: boolean }> {
  if (!cmdToCtrl) return [{ code: "KeyV", down: true }];
  const metas = [...held].filter((c) => c === "MetaLeft" || c === "MetaRight");
  return [
    ...metas.map((code) => ({ code, down: false })),
    { code: "ControlLeft", down: true }, { code: "KeyV", down: true },
    { code: "KeyV", down: false }, { code: "ControlLeft", down: false },
    ...metas.map((code) => ({ code, down: true })),
  ];
}

/**
 * 取得本機剪貼簿的文字：等 Ctrl+V 的預設動作觸發的 paste 事件（不需要權限），waitMs 內等不到再試
 * navigator.clipboard.readText()（瀏覽器可能跳出權限詢問，最多等 readTimeoutMs）。拿不到回 null、沒有文字回 ""。
 * 要在 keydown 的處理函式裡同步呼叫：paste 事件緊接在 keydown 之後觸發，晚一步掛上就收不到。
 */
export function waitForPaste(target: EventTarget, o: {
  waitMs?: number; readTimeoutMs?: number; readText?: () => Promise<string>;
} = {}): Promise<string | null> {
  return new Promise((resolve) => {
    let done = false;
    let readTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (v: string | null) => {
      if (done) return;
      done = true;
      target.removeEventListener("paste", onPaste, true);
      clearTimeout(waitTimer);
      clearTimeout(readTimer);
      resolve(v);
    };
    const onPaste = (e: Event) => {
      e.preventDefault();                        // 不讓內容真的貼進看不見的輸入框
      finish((e as ClipboardEvent).clipboardData?.getData("text/plain") ?? "");
    };
    target.addEventListener("paste", onPaste, true);
    // finish 只會在事件或計時器觸發後才被呼叫，那時 waitTimer 已經有值
    const waitTimer = setTimeout(() => {
      target.removeEventListener("paste", onPaste, true);
      const read = o.readText ?? (() => navigator.clipboard.readText());
      readTimer = setTimeout(() => finish(null), o.readTimeoutMs ?? 5000);
      try {
        read().then((s) => finish(s), () => finish(null));
      } catch {
        finish(null);
      }
    }, o.waitMs ?? 100);
  });
}

/** 寫入本機剪貼簿；有 HTML 時一起寫 text/html（瀏覽器支援時）。瀏覽器拒絕（沒有焦點、沒有使用者手勢）回 false。 */
export async function writeLocalClipboard(text: string, html?: string): Promise<boolean> {
  const cb = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
  if (!cb) return false;
  if (html && typeof ClipboardItem !== "undefined" && typeof cb.write === "function") {
    try {
      await cb.write([new ClipboardItem({
        "text/plain": new Blob([text], { type: "text/plain" }),
        "text/html": new Blob([html], { type: "text/html" }),
      })]);
      return true;
    } catch { /* 改寫純文字 */ }
  }
  try {
    await cb.writeText(text);
    return true;
  } catch {
    return false;
  }
}
