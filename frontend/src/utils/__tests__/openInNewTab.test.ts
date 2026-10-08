/**
 * 從 IP 頁／連線清單開主控台分頁時一定要 noopener。
 *
 * 少了它，新分頁留著 window.opener → Chrome 讓兩個分頁共用同一個渲染程序與主執行緒。
 * 使用者回報（macOS Chrome）：點「SSH 連線」開新分頁、再切回原本的 IP 頁，整頁變黑。
 * 主控台頁完全不需要 opener，拆開程序後原分頁的重繪就不再受主控台分頁影響。
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { openInNewTab } from "../openInNewTab";

afterEach(() => vi.restoreAllMocks());

describe("openInNewTab", () => {
  it("用 _blank 並帶 noopener", () => {
    const spy = vi.spyOn(window, "open").mockReturnValue(null);
    openInNewTab("/ssh/abc");
    expect(spy).toHaveBeenCalledWith("/ssh/abc", "_blank", "noopener");
  });
});

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== "__tests__") walk(p, out); }
    else if (/\.(vue|ts)$/.test(n)) out.push(p);
  }
  return out;
}

describe("守門：開新分頁不可留 opener", () => {
  it("src 裡沒有不帶 noopener 的 window.open(…, \"_blank\")", () => {
    const root = join(__dirname, "..", "..");
    const files = walk(root);
    expect(files.length).toBeGreaterThan(50);            // 走訪真的有掃到東西
    const bad: string[] = [];
    for (const f of files) {
      const src = readFileSync(f, "utf-8");
      // 抓整個呼叫（可能跨行），到第一個對應的右括號為止夠用
      for (const m of src.matchAll(/window\.open\(([\s\S]*?)\);/g)) {
        if (/["']_blank["']/.test(m[1]) && !/noopener/.test(m[1])) bad.push(`${f}: ${m[0].replace(/\s+/g, " ")}`);
      }
    }
    expect(bad, bad.join("\n")).toEqual([]);
  });
});
