/**
 * 守門：每個用到「欄位」選單的地方都要接上拖拉排序。
 *
 * 使用者要求的是「所有頁面」（2026-10-05）。功能做在 ColumnPicker／useColumnPrefs，
 * 但順序要由各頁自己的 columns computed 套上去 —— 新頁面照舊寫法複製一份，就會出現
 * 「選單裡拖得動、表格卻不跟著變」或「根本沒有把手」，型別檢查抓不到。
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const SRC = resolve(__dirname, "../..");

function vueFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return name === "__tests__" ? [] : vueFiles(p);
    return name.endsWith(".vue") ? [p] : [];
  });
}

const files = vueFiles(SRC).filter((p) => !p.endsWith("components/ColumnPicker.vue"));

describe("欄位選單都接上拖拉排序", () => {
  it("每個 <ColumnPicker> 都有 :order 與 @update:order", () => {
    const missing: string[] = [];
    let count = 0;
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      for (const m of src.matchAll(/<ColumnPicker\b([\s\S]*?)\/>/g)) {
        count += 1;
        if (!/\s:order="/.test(m[1]) || !/\s@update:order="/.test(m[1])) {
          missing.push(`${relative(SRC, f)}: <ColumnPicker${m[1].slice(0, 60).replace(/\s+/g, " ")}…`);
        }
      }
    }
    expect(count).toBeGreaterThan(50);   // 找不到任何一個＝這個守門自己壞了
    expect(missing).toEqual([]);
  });

  it("每個用 useColumnPrefs 的檔案都把順序套到表格欄位（orderColumns／orderKeys）", () => {
    const missing = files
      .filter((f) => {
        const src = readFileSync(f, "utf8");
        return src.includes("useColumnPrefs(") && !/\borderColumns\b|\borderKeys\(/.test(src);
      })
      .map((f) => relative(SRC, f));
    expect(missing).toEqual([]);
  });
});
