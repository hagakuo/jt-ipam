import { describe, expect, it } from "vitest";
import type { Terminal } from "@xterm/xterm";
import {
  assembleLogicalLine, isSafeUrl, joinIfBrokenUrl,
} from "@/utils/terminalLinks";

/**
 * 用假的緩衝區驅動 —— 這裡要守的是「網址被切成好幾列」時還原得對不對，
 * 那跟畫面渲染無關，用假緩衝區反而能把邊界情況寫清楚。
 *
 * 兩種切法差很多，測試必須分開涵蓋：
 *   - 軟折行：終端機自己折的，續行 isWrapped = true
 *   - 硬斷行：TUI 自己算寬度寫出來的，每列都是獨立邏輯行（Claude Code、k9s 這類）
 */
function fakeTerm(rows: { text: string; wrapped?: boolean }[], cols = 40): Terminal {
  const lines = rows.map((r) => ({
    isWrapped: !!r.wrapped,
    getCell: (x: number) => {
      const ch = r.text[x];
      if (ch === undefined) return { getChars: () => "", getWidth: () => 1 };
      return { getChars: () => ch, getWidth: () => 1 };
    },
  }));
  return {
    cols,
    buffer: { active: { getLine: (y: number) => lines[y] } },
  } as unknown as Terminal;
}

/** 把字串補白到滿版（TUI 就是這樣寫出來的） */
const pad = (s: string, cols = 40) => s + " ".repeat(Math.max(0, cols - s.length));

const URL = "https://example.com/oauth/authorize?code=abc123&state=xyz789&scope=read";

describe("assembleLogicalLine", () => {
  it("軟折行：沿著 isWrapped 把整條網址接回來", () => {
    const term = fakeTerm([
      { text: pad("start") },
      { text: URL.slice(0, 40) },
      { text: URL.slice(40), wrapped: true },
    ]);
    for (const y of [1, 2]) {
      expect(assembleLogicalLine(term, y)?.text).toContain(URL);
    }
  });

  it("硬斷行：每列都是獨立邏輯行，一樣要接得回來", () => {
    const term = fakeTerm([
      { text: pad("start") },
      { text: URL.slice(0, 40) },
      { text: pad(URL.slice(40)) },
    ]);
    expect(assembleLogicalLine(term, 1)?.text).toContain(URL);
  });

  it("硬斷行時從續行那一列問也要認得（滑鼠可能停在網址的第三列）", () => {
    const term = fakeTerm([
      { text: URL.slice(0, 40) },
      { text: pad(URL.slice(40)) },
    ]);
    expect(assembleLogicalLine(term, 1)?.text).toContain(URL);
  });

  it("滿版一行後面接另一段文字時，不可以黏成假網址", () => {
    const line = "See the guide at https://example.com/do";   // 正好 40 欄，且結尾就是網址
    expect(line).toHaveLength(39);
    const term = fakeTerm([
      { text: line + "c" },
      { text: pad("Important: read it before continuing") },
    ]);
    const text = assembleLogicalLine(term, 0)?.text ?? "";
    expect(text).toContain("https://example.com/doc");
    expect(text).not.toContain("Important");
  });

  it("續行沒有從第 0 欄開始（有縮排）就不算續行", () => {
    const term = fakeTerm([
      { text: URL.slice(0, 40) },
      { text: pad("  " + URL.slice(40)) },
    ]);
    expect(assembleLogicalLine(term, 0)?.text).not.toContain(URL);
  });
});

describe("joinIfBrokenUrl", () => {
  it("被換行切開的網址接回來", () => {
    expect(joinIfBrokenUrl("https://example.com/a\nbcdef")).toBe("https://example.com/abcdef");
  });

  it("容忍 TUI 補在行尾的空白（整列選取時會一起被選到）", () => {
    expect(joinIfBrokenUrl("https://example.com/a   \nbcdef    ")).toBe("https://example.com/abcdef");
  });

  it("中間還有空白就不動它 —— 那表示選到的不只是一條網址", () => {
    expect(joinIfBrokenUrl("https://example.com/a b\ncdef")).toBeNull();
  });

  it("一般多行文字原樣保留", () => {
    expect(joinIfBrokenUrl("line one\nline two")).toBeNull();
  });

  it("單行不需要處理", () => {
    expect(joinIfBrokenUrl("https://example.com/abc")).toBeNull();
  });

  it("不是 http/https 一律不碰", () => {
    expect(joinIfBrokenUrl("javascript:alert(1)\n//x")).toBeNull();
    expect(joinIfBrokenUrl("file:///etc/pas\nswd")).toBeNull();
  });
});

describe("isSafeUrl", () => {
  it("只放行 http 與 https", () => {
    expect(isSafeUrl("https://example.com")).toBe(true);
    expect(isSafeUrl("http://example.com")).toBe(true);
    // 終端機文字由遠端主機控制，不可以讓它決定開什麼協定
    expect(isSafeUrl("javascript:alert(1)")).toBe(false);
    expect(isSafeUrl("data:text/html,<script>1</script>")).toBe(false);
    expect(isSafeUrl("file:///etc/passwd")).toBe(false);
    expect(isSafeUrl("not a url")).toBe(false);
  });
});
