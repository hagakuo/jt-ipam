/**
 * 相容 RustDesk 的網頁連線：「傳送文字」的直接打字輸入（規格附錄 F.4）。
 *
 * 把文字逐字換成按鍵，用 §9.2 的 map 模式送 down/up（附錄 A 的按鍵代碼，keymap.ts），不需要新的協定訊息。
 * - 只接受美式鍵盤配置打得出的字元：可列印的 ASCII（0x20～0x7E）、換行（送 Enter）、Tab
 * - 需要 Shift 的（大寫字母、!@#$%^&*()_+{}|:"<>?~）前後加送 Shift down/up
 * - 文字裡有其他字元（中文、全形、emoji…）就整段不打，畫面提示改用「放到對方剪貼簿」
 * - 每個按鍵之間約 8 毫秒，一次最多 2000 個字元；送的期間可以取消，取消時把按著的鍵放開（不讓對方卡鍵）
 */

/** F.4：一次最多幾個字元 */
export const TYPE_TEXT_MAX = 2000;
/** F.4：每個按鍵（down 或 up）之間的間隔（毫秒） */
export const TYPE_TEXT_INTERVAL_MS = 8;

export interface KeyStroke {
  /** KeyboardEvent.code（keymap.ts 換成受控端平台的按鍵代碼） */
  code: string;
  down: boolean;
}

/** 美式鍵盤：不用 Shift 的符號 */
const PLAIN: Readonly<Record<string, string>> = {
  " ": "Space", "`": "Backquote", "-": "Minus", "=": "Equal", "[": "BracketLeft", "]": "BracketRight",
  "\\": "Backslash", ";": "Semicolon", "'": "Quote", ",": "Comma", ".": "Period", "/": "Slash",
  "\n": "Enter", "\t": "Tab",
};
/** 美式鍵盤：要 Shift 的符號 */
const SHIFTED: Readonly<Record<string, string>> = {
  "!": "Digit1", "@": "Digit2", "#": "Digit3", "$": "Digit4", "%": "Digit5", "^": "Digit6", "&": "Digit7",
  "*": "Digit8", "(": "Digit9", ")": "Digit0", "_": "Minus", "+": "Equal", "{": "BracketLeft",
  "}": "BracketRight", "|": "Backslash", ":": "Semicolon", "\"": "Quote", "<": "Comma", ">": "Period",
  "?": "Slash", "~": "Backquote",
};

const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** 一個字元（換行已正規化成 \n）在美式鍵盤上是哪個鍵、要不要 Shift；打不出來回 null。 */
export function charKey(ch: string): { code: string; shift: boolean } | null {
  if (/^[a-z]$/.test(ch)) return { code: `Key${ch.toUpperCase()}`, shift: false };
  if (/^[A-Z]$/.test(ch)) return { code: `Key${ch}`, shift: true };
  if (/^[0-9]$/.test(ch)) return { code: `Digit${ch}`, shift: false };
  if (own(PLAIN, ch)) return { code: PLAIN[ch], shift: false };
  if (own(SHIFTED, ch)) return { code: SHIFTED[ch], shift: true };
  return null;
}

export type TypingPlan =
  | { ok: true; chars: number; strokes: KeyStroke[] }
  | { ok: false; reason: "empty" | "too_long" }
  | { ok: false; reason: "unsupported"; bad: string[] };

/** 文字 → 按鍵序列。CRLF 與單獨的 CR 都算一個換行。 */
export function planTyping(text: string, max = TYPE_TEXT_MAX): TypingPlan {
  const chars = Array.from(text.replace(/\r\n?/g, "\n"));
  if (!chars.length) return { ok: false, reason: "empty" };
  const bad: string[] = [];
  for (const ch of chars) {
    if (!charKey(ch) && !bad.includes(ch)) {
      bad.push(ch);
      if (bad.length >= 5) break;
    }
  }
  if (bad.length) return { ok: false, reason: "unsupported", bad };
  if (chars.length > max) return { ok: false, reason: "too_long" };
  const strokes: KeyStroke[] = [];
  for (const ch of chars) {
    const k = charKey(ch)!;
    if (k.shift) strokes.push({ code: "ShiftLeft", down: true });
    strokes.push({ code: k.code, down: true }, { code: k.code, down: false });
    if (k.shift) strokes.push({ code: "ShiftLeft", down: false });
  }
  return { ok: true, chars: chars.length, strokes };
}

export interface TypeOptions {
  /** 送一個按鍵；送不出去（連線結束、唯讀、對方關閉控制權）回 false */
  send(s: KeyStroke): boolean;
  /** 測試可以換掉 */
  sleep?(ms: number): Promise<void>;
  /** 使用者按了取消 */
  cancelled(): boolean;
  /** 已經打完幾個字元 */
  progress?(chars: number): void;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * 依序送出按鍵，每個之間隔 TYPE_TEXT_INTERVAL_MS。取消或送不出去時停下來，把還按著的鍵放開
 * （先放開最後按下的；送不出去時盡量送，不保證）。chars＝完整打完的字元數。
 */
export async function typeStrokes(strokes: KeyStroke[], o: TypeOptions):
    Promise<{ result: "done" | "cancelled" | "failed"; chars: number }> {
  const sleep = o.sleep ?? defaultSleep;
  const held: string[] = [];
  let chars = 0;
  const release = () => {
    for (const code of held.splice(0).reverse()) o.send({ code, down: false });
  };
  for (const [i, s] of strokes.entries()) {
    if (o.cancelled()) {
      release();
      return { result: "cancelled", chars };
    }
    if (!o.send(s)) {
      release();
      return { result: "failed", chars };
    }
    if (s.down) {
      held.push(s.code);
    } else {
      const at = held.lastIndexOf(s.code);
      if (at >= 0) held.splice(at, 1);
      if (!held.length) {                 // 一個字元的按鍵（含 Shift）都放開了＝打完一個字元
        chars += 1;
        o.progress?.(chars);
      }
    }
    if (i < strokes.length - 1) await sleep(TYPE_TEXT_INTERVAL_MS);
  }
  return { result: "done", chars };
}
