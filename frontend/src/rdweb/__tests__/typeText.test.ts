/**
 * 相容 RustDesk 的網頁連線：「傳送文字」的直接打字輸入（規格附錄 F.4 的單元測試）。
 * 只接受美式鍵盤打得出的字元：可列印的 ASCII、換行（Enter）、Tab；需要 Shift 的字元前後加送 Shift down/up；
 * 含其他字元就不打；一次最多 2000 個字元；按鍵之間約 8 毫秒；可以取消（取消時不留下按著的鍵）。
 */
import { describe, expect, it } from "vitest";
import { charKey, planTyping, typeStrokes, TYPE_TEXT_INTERVAL_MS, TYPE_TEXT_MAX, type KeyStroke } from "../typeText";
import { keyCodeFor } from "../keymap";

const press = (code: string): KeyStroke[] => [{ code, down: true }, { code, down: false }];
const shifted = (code: string): KeyStroke[] => [{ code: "ShiftLeft", down: true }, ...press(code),
                                                 { code: "ShiftLeft", down: false }];

describe("字元 → 按鍵（美式鍵盤配置）", () => {
  it("小寫、數字、空白不用 Shift；大寫用 Shift", () => {
    expect(charKey("a")).toEqual({ code: "KeyA", shift: false });
    expect(charKey("Z")).toEqual({ code: "KeyZ", shift: true });
    expect(charKey("7")).toEqual({ code: "Digit7", shift: false });
    expect(charKey(" ")).toEqual({ code: "Space", shift: false });
  });

  it("符號：!@#$%^&*()_+{}|:\"<>?~ 要 Shift，其他不用", () => {
    const withShift: Record<string, string> = {
      "!": "Digit1", "@": "Digit2", "#": "Digit3", "$": "Digit4", "%": "Digit5", "^": "Digit6", "&": "Digit7",
      "*": "Digit8", "(": "Digit9", ")": "Digit0", "_": "Minus", "+": "Equal", "{": "BracketLeft",
      "}": "BracketRight", "|": "Backslash", ":": "Semicolon", "\"": "Quote", "<": "Comma", ">": "Period",
      "?": "Slash", "~": "Backquote",
    };
    for (const [ch, code] of Object.entries(withShift)) expect(charKey(ch)).toEqual({ code, shift: true });
    const plain: Record<string, string> = {
      "`": "Backquote", "-": "Minus", "=": "Equal", "[": "BracketLeft", "]": "BracketRight", "\\": "Backslash",
      ";": "Semicolon", "'": "Quote", ",": "Comma", ".": "Period", "/": "Slash",
    };
    for (const [ch, code] of Object.entries(plain)) expect(charKey(ch)).toEqual({ code, shift: false });
  });

  it("每個可列印的 ASCII（0x20～0x7E）都對得到附錄 A 有的按鍵", () => {
    for (let c = 0x20; c <= 0x7e; c++) {
      const k = charKey(String.fromCharCode(c));
      expect(k, String.fromCharCode(c)).not.toBeNull();
      for (const p of ["Windows", "Linux", "Mac OS"]) expect(keyCodeFor(k!.code, p)).not.toBeNull();
    }
  });

  it("換行送 Enter、Tab 送 Tab；其他控制字元、中文、全形、emoji 都沒有對應", () => {
    expect(charKey("\n")).toEqual({ code: "Enter", shift: false });
    expect(charKey("\t")).toEqual({ code: "Tab", shift: false });
    for (const ch of ["\u0007", "\u007f", "中", "Ａ", "，", "é", "😀", " "]) expect(charKey(ch)).toBeNull();
  });
});

describe("打字計畫", () => {
  it("大小寫與符號的 Shift 處理：每個需要 Shift 的字元前後各送一次 Shift down/up", () => {
    const p = planTyping("aB!");
    expect(p).toEqual({ ok: true, chars: 3, strokes: [...press("KeyA"), ...shifted("KeyB"), ...shifted("Digit1")] });
  });

  it("換行（CRLF、CR 也算一個換行）送 Enter，Tab 送 Tab", () => {
    const p = planTyping("ls\r\n\tx\ry");
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    expect(p.chars).toBe(7);
    expect(p.strokes).toEqual([...press("KeyL"), ...press("KeyS"), ...press("Enter"), ...press("Tab"),
                               ...press("KeyX"), ...press("Enter"), ...press("KeyY")]);
  });

  it("含美式鍵盤打不出的字元：整段不打，列出是哪些字（最多 5 個、不重複）", () => {
    expect(planTyping("echo 你好，世界 😀 é ü ö ä")).toEqual({
      ok: false, reason: "unsupported", bad: ["你", "好", "，", "世", "界"] });
    expect(planTyping("café")).toEqual({ ok: false, reason: "unsupported", bad: ["é"] });
  });

  it("上限 2000 個字元（以字元數算，換行算一個）；空的不打", () => {
    expect(TYPE_TEXT_MAX).toBe(2000);
    expect(planTyping("a".repeat(2000)).ok).toBe(true);
    expect(planTyping("a".repeat(1999) + "\r\n").ok).toBe(true);
    expect(planTyping("a".repeat(2001))).toEqual({ ok: false, reason: "too_long" });
    expect(planTyping("")).toEqual({ ok: false, reason: "empty" });
  });
});

describe("送出", () => {
  function recorder(failAt = -1) {
    const sent: KeyStroke[] = [];
    const sleeps: number[] = [];
    return {
      sent, sleeps,
      send: (s: KeyStroke) => { if (sent.length === failAt) return false; sent.push(s); return true; },
      sleep: async (ms: number) => { sleeps.push(ms); },
    };
  }

  it("照順序送出，每個按鍵之間約 8 毫秒；回報進度（字元數）", async () => {
    const r = recorder();
    const progress: number[] = [];
    const plan = planTyping("Hi");
    if (!plan.ok) throw new Error("plan");
    const out = await typeStrokes(plan.strokes, { send: r.send, sleep: r.sleep, cancelled: () => false,
                                                  progress: (n) => progress.push(n) });
    expect(out).toEqual({ result: "done", chars: 2 });
    expect(r.sent).toEqual(plan.strokes);
    expect(TYPE_TEXT_INTERVAL_MS).toBe(8);
    expect(r.sleeps).toEqual(Array(plan.strokes.length - 1).fill(8));
    expect(progress[progress.length - 1]).toBe(2);
  });

  it("取消：停在下一個按鍵之前，按著的鍵（含 Shift）一定送放開，不讓對方卡鍵", async () => {
    const r = recorder();
    const plan = planTyping("AB");
    if (!plan.ok) throw new Error("plan");
    let n = 0;
    // 送到「Shift 按下、A 按下」之後取消
    const out = await typeStrokes(plan.strokes, { send: (s) => { n += 1; return r.send(s); }, sleep: r.sleep,
                                                  cancelled: () => n >= 2 });
    expect(out.result).toBe("cancelled");
    expect(out.chars).toBe(0);
    expect(r.sent).toEqual([{ code: "ShiftLeft", down: true }, { code: "KeyA", down: true },
                            { code: "KeyA", down: false }, { code: "ShiftLeft", down: false }]);
  });

  it("送不出去（連線結束、對方關閉控制權）：停止並回報 failed", async () => {
    const r = recorder(3);
    const plan = planTyping("abc");
    if (!plan.ok) throw new Error("plan");
    const out = await typeStrokes(plan.strokes, { send: r.send, sleep: r.sleep, cancelled: () => false });
    expect(out).toEqual({ result: "failed", chars: 1 });
    expect(r.sent).toHaveLength(3);
  });
});
