import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * 不用「白名單／黑名單」（使用者 2026-10-05）：改寫「允許清單／封鎖清單」，英文 allowlist／denylist，
 * 日文 許可リスト／拒否リスト。畫面文案、後端訊息、程式註解、公開文件都算。
 * 外部系統的原文照抄不算（例如 TigerVNC 日誌裡的 `blacklisted`，要照原文去搜尋）。
 */
const BANNED = /白名單|黑名單|白名单|黑名单|ホワイトリスト|ブラックリスト|white-?list|black-?list/gi;
const EXTERNAL_LITERALS = ["`blacklisted`"];

function offences(text: string): string[] {
  let t = text;
  for (const lit of EXTERNAL_LITERALS) t = t.split(lit).join("");
  return [...t.matchAll(BANNED)].map((m) => {
    const i = m.index ?? 0;
    return t.slice(Math.max(0, i - 12), i + m[0].length + 12).replace(/\s+/g, " ");
  });
}

const ROOT = resolve(__dirname, "../../../..");
const SKIP_DIRS = new Set(["node_modules", ".venv", "__pycache__", "dist", ".git", "shots"]);
const EXTS = /\.(?:vue|ts|js|json|py|md|html|sh|ps1)$/;

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (EXTS.test(name)) out.push(p);
  }
  return out;
}

describe("不用白名單／黑名單", () => {
  it("規則本身抓得到、外部原文不誤抓", () => {
    expect(offences("IP 不在白名單")).toHaveLength(1);
    expect(offences("whitelist violation")).toHaveLength(1);
    expect(offences("Black-list")).toHaveLength(1);
    expect(offences("看日誌有沒有 `blacklisted`")).toEqual([]);
    expect(offences("允許清單、封鎖清單、allowlist")).toEqual([]);
  });

  it("前端、後端、代理、腳本與文件都不出現", () => {
    const dirs = ["frontend/src", "frontend/e2e", "backend/app", "backend/tests", "backend/alembic", "agent", "scripts", "docs"]
      .map((d) => resolve(ROOT, d));
    const files = [...dirs.flatMap((d) => walk(d)),
      ...["README.md", "README_zh-TW.md", "CHANGELOG.md", "CHANGELOG_zh-TW.md", "TEST_CHECKLIST.md", "TEST_CHECKLIST_zh-TW.md"]
        .map((f) => resolve(ROOT, f))];
    const self = resolve(__dirname, "inclusiveTerms.test.ts");
    const found = files.filter((f) => f !== self)
      .flatMap((f) => offences(readFileSync(f, "utf8")).map((o) => `${f.slice(ROOT.length + 1)}: ${o}`));
    expect(found).toEqual([]);
  });
});
