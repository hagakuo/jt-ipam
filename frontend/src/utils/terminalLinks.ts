/**
 * 終端機裡的網址 → 可點連結（SSH / BMC 序列主控台共用）。
 *
 * 為什麼不用官方的 web-links 套件：它只跟著 `isWrapped` 走，也就是**只處理終端機自己折的行**。
 * 但 TUI 程式（Claude Code、k9s、lazygit 這類走 Ink／ncurses 的）是自己算好寬度、
 * 一列一列寫出來再換行的 —— 那些列在緩衝區裡是各自獨立的邏輯行，`isWrapped` 是 false。
 * 結果就是一條網址被切成好幾段，既不能點、選取複製起來還會夾帶換行（實測過，兩種情況差異很大）。
 *
 * 所以這裡兩種都處理：
 *   1. 軟折行：沿著 `isWrapped` 往前後把整個邏輯行接起來（跟官方套件一樣）
 *   2. 硬斷行：上一列**寫滿到最後一欄**、下一列從第 0 欄開始又是網址允許的字元 → 視為續行
 *
 * 第 2 條是啟發式的，不可能百分之百正確，因此刻意收得很緊：只有「填滿整列」才續接、
 * 只吃網址字元、遇到空白就停、有長度上限，而且**滑過去會把完整網址顯示出來**，
 * 讓使用者在點下去之前就看得到實際目標，而不是靜靜地開一個拼錯的網址。
 */

import type { IBufferLine, ILink, ILinkProvider, Terminal } from "@xterm/xterm";

/** 網址字元集：終端機文字裡不會有 HTML 跳脫，用「排除法」比列舉安全 */
const URL_CHARS = /[^\s"'`<>\\^{}|　-〿＀-￯]/;
const URL_RE = /\bhttps?:\/\/[^\s"'`<>\\^{}|　-〿＀-￯]+/g;
/** 句尾標點不該算進網址（「請看 https://x/y。」的句號） */
const TRAILING_PUNCT = /[.,;:!?)\]}'"]+$/;

const MAX_URL_LEN = 2048;
/** 硬斷行最多往下接幾列 —— 網址再長也不會超過這個數量 */
const MAX_CONT_ROWS = 24;

/** 組出來的字串：每個字元都記得它來自哪一列、哪一欄（寬字元會佔兩欄，不能用字串索引推算） */
interface Assembled {
  text: string;
  row: number[];   // 每個字元所在的緩衝區列（0-based）
  col: number[];   // 每個字元所在的欄（0-based）
}

function readRow(line: IBufferLine, cols: number): Assembled {
  const out: Assembled = { text: "", row: [], col: [] };
  for (let x = 0; x < cols; x++) {
    const cell = line.getCell(x);
    if (!cell) continue;
    // 寬字元（CJK）佔兩格，第二格寬度為 0 —— 跳過，否則欄位對應會整條偏掉
    if (cell.getWidth() === 0) continue;
    const chars = cell.getChars() || " ";
    for (let i = 0; i < chars.length; i++) {
      out.text += chars[i];
      out.col.push(x);
    }
  }
  return out;
}

function trimRight(a: Assembled): Assembled {
  let end = a.text.length;
  while (end > 0 && a.text[end - 1] === " ") end--;
  return { text: a.text.slice(0, end), row: a.row.slice(0, end), col: a.col.slice(0, end) };
}

function push(dst: Assembled, src: Assembled, rowIndex: number): void {
  dst.text += src.text;
  for (let i = 0; i < src.text.length; i++) {
    dst.row.push(rowIndex);
    dst.col.push(src.col[i]);
  }
}

/** 這一列是不是「寫滿到最後一欄」（＝可能是被硬斷行切開的） */
function fillsRow(a: Assembled, cols: number): boolean {
  return a.text.length > 0 && a.col[a.col.length - 1] === cols - 1;
}

/**
 * 把某一列所屬的「整條邏輯網址文字」組出來。
 * 先沿 isWrapped 收軟折行，再視情況往下吃硬斷行的續行。
 */
export function assembleLogicalLine(term: Terminal, y: number): Assembled | null {
  const buf = term.buffer.active;
  const cols = term.cols;
  const rowAt = (r: number) => {
    const line = buf.getLine(r);
    return line ? readRow(line, cols) : null;
  };
  const softStart = (r: number) => {
    while (r > 0 && buf.getLine(r)?.isWrapped) r--;
    return r;
  };
  const softEnd = (r: number) => {
    while (buf.getLine(r + 1)?.isWrapped) r++;
    return r;
  };

  let start = softStart(y);
  const end = softEnd(y);

  // ── 往上接硬斷行：本列從第 0 欄開始且是網址字元、上一列寫滿且結尾也是網址字元 → 續行
  for (let n = 0; n < MAX_CONT_ROWS; n++) {
    if (start === 0) break;
    const cur = rowAt(start);
    if (!cur || !cur.text || cur.col[0] !== 0 || !URL_CHARS.test(cur.text[0])) break;
    const prev = rowAt(start - 1);
    if (!prev) break;
    const prevTrim = trimRight(prev);
    // 中間的續行沒有 https:// 首碼，所以這裡只能要求「寫滿 + 結尾是網址字元」，
    // 真正的把關是最後組出來的字串必須含有協定首碼（見 provideLinks 的比對）
    if (!fillsRow(prevTrim, cols)) break;
    if (!URL_CHARS.test(prevTrim.text[prevTrim.text.length - 1])) break;
    start = softStart(start - 1);
  }

  const acc: Assembled = { text: "", row: [], col: [] };
  for (let r = start; r <= end; r++) {
    const raw = rowAt(r);
    if (!raw) return null;
    push(acc, r === end ? trimRight(raw) : raw, r);
  }

  // ── 往下接硬斷行
  let lastRow = end;
  for (let n = 0; n < MAX_CONT_ROWS && acc.text.length < MAX_URL_LEN; n++) {
    const lastRaw = rowAt(lastRow);
    if (!lastRaw || !fillsRow(trimRight(lastRaw), cols)) break;
    if (!endsWithUrl(acc.text)) break;

    const nextLine = buf.getLine(lastRow + 1);
    if (!nextLine || nextLine.isWrapped) break;      // 軟折行上面已經收過
    const nextRaw = readRow(nextLine, cols);
    if (!nextRaw.text || nextRaw.col[0] !== 0) break;  // 續行一定從第 0 欄開始
    let take = 0;
    while (take < nextRaw.text.length && URL_CHARS.test(nextRaw.text[take])) take++;
    if (take === 0) break;
    // 沒吃滿整列時，剩下的必須是空白 —— 否則那是「另一段文字」，不是網址的續行。
    // 少了這條，滿版的一行後面接一句話就會被黏成一條假網址。
    if (take < nextRaw.text.length && nextRaw.text.slice(take).trim() !== "") break;

    push(acc, {
      text: nextRaw.text.slice(0, take),
      row: [],
      col: nextRaw.col.slice(0, take),
    }, lastRow + 1);
    lastRow++;
    if (take < nextRaw.text.length) break;            // 網址在這一列結束
  }

  return acc.text ? acc : null;
}

/** 目前累積的文字是不是以一條網址作結（決定要不要再往下接一列） */
function endsWithUrl(text: string): boolean {
  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  let last: RegExpExecArray | null = null;
  while ((m = URL_RE.exec(text)) !== null) last = m;
  return !!last && last.index + last[0].length === text.length;
}

export interface TerminalLinkOptions {
  /** 滑鼠移到連結上（帶完整網址）／離開（null）—— 讓呼叫端顯示實際目標 */
  onHover?: (url: string | null) => void;
  /** 點下去要做什麼；預設開新分頁 */
  onActivate?: (url: string) => void;
}

/** 只放行 http/https —— 終端機文字是遠端主機控制的，不可以讓它決定要開什麼協定 */
export function isSafeUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export function openUrlSafely(url: string): void {
  if (!isSafeUrl(url)) return;
  window.open(url, "_blank", "noopener,noreferrer");
}

export function createLinkProvider(
  term: Terminal, opts: TerminalLinkOptions = {},
): ILinkProvider {
  return {
    provideLinks(bufferLineNumber: number, callback: (links: ILink[] | undefined) => void): void {
      const y = bufferLineNumber - 1;                  // xterm 給的是 1-based
      const acc = assembleLogicalLine(term, y);
      if (!acc) { callback(undefined); return; }

      const links: ILink[] = [];
      URL_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = URL_RE.exec(acc.text)) !== null) {
        let raw = m[0];
        const trimmed = raw.replace(TRAILING_PUNCT, "");
        if (trimmed) raw = trimmed;
        if (raw.length > MAX_URL_LEN || !isSafeUrl(raw)) continue;

        const s = m.index;
        const e = s + raw.length - 1;
        if (acc.row[s] === undefined || acc.row[e] === undefined) continue;
        // 這條連結有沒有經過被詢問的那一列（xterm 是逐列詢問的）
        if (y < acc.row[s] || y > acc.row[e]) continue;

        links.push({
          text: raw,
          range: {
            start: { x: acc.col[s] + 1, y: acc.row[s] + 1 },
            end: { x: acc.col[e] + 1, y: acc.row[e] + 1 },
          },
          activate: (event: MouseEvent) => {
            event.preventDefault();
            if (opts.onActivate) opts.onActivate(raw);
            else openUrlSafely(raw);
          },
          hover: () => opts.onHover?.(raw),
          leave: () => opts.onHover?.(null),
        });
      }
      callback(links.length ? links : undefined);
    },
  };
}

/**
 * 選取複製的補救：被硬斷行切開的網址，選起來會夾帶換行，貼出去就是壞的。
 *
 * 只在「拿掉換行之後正好是一條完整網址、而且中間沒有其他空白」時才改寫剪貼簿內容——
 * 這種情況下使用者的意圖沒有別的解釋。其餘一律原樣，不去動使用者複製到的東西。
 */
export function joinIfBrokenUrl(selection: string): string | null {
  if (!selection.includes("\n")) return null;
  // TUI 會把每一列補白到滿版，整列選取時那些尾端空白會跟著進來 —— 先去掉再判斷，
  // 但「中間」只要還有任何空白就放棄：那表示選到的不只是一條網址。
  const joined = selection.split(/\r?\n/).map((ln) => ln.replace(/[ \t]+$/, "")).join("");
  if (/\s/.test(joined)) return null;
  if (joined.length > MAX_URL_LEN) return null;
  if (!/^https?:\/\/\S+$/.test(joined) || !isSafeUrl(joined)) return null;
  return joined;
}
