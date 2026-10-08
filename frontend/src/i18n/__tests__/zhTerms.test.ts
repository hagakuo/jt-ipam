import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import zh from "../zh-TW.json";

/**
 * 繁中（台灣）用詞的守門測試。
 *
 * pool 一律寫「集區」（DHCP 集區、位址集區、連線集區），不寫「池」—— 使用者說
 * 「這講過很多次了」。IP 的 address 是「位址」；「地址」只用在實體地點的地址。
 * 畫面文案之外，公開文件（文件站、README、changelog）也算。
 */
type Dict = Record<string, unknown>;
function values(obj: Dict): string[] {
  return Object.values(obj).flatMap((v) => (v && typeof v === "object" ? values(v as Dict) : [String(v)]));
}

/** 回傳違規的片段（前後各留幾個字，方便找） */
function offences(text: string): string[] {
  const out: string[] = [];
  const rules: RegExp[] = [/(?<!電)池/g, /地址池/g, /IP\s*地址/g];
  for (const re of rules) {
    for (const m of text.matchAll(re)) {
      const i = m.index ?? 0;
      out.push(text.slice(Math.max(0, i - 8), i + m[0].length + 8).replace(/\s+/g, " "));
    }
  }
  return out;
}

describe("繁中用詞", () => {
  it("規則本身抓得到、不誤抓", () => {
    expect(offences("DHCP 池被反覆重用")).toHaveLength(1);
    expect(offences("地址池")).not.toHaveLength(0);
    expect(offences("IP 地址")).toHaveLength(1);
    expect(offences("切換到電池供電")).toEqual([]);
    expect(offences("記錄地點的地址與經緯度")).toEqual([]);
  });

  it("畫面文案不寫「池」「地址池」「IP 地址」", () => {
    expect(values(zh as Dict).flatMap(offences)).toEqual([]);
  });

  it("公開文件也一樣", () => {
    const root = resolve(__dirname, "../../../..");
    const files = ["docs/index.html", "docs/features.html", "docs/adoption.html", "README_zh-TW.md", "CHANGELOG_zh-TW.md"];
    const found = files.flatMap((f) => offences(readFileSync(resolve(root, f), "utf8")).map((o) => `${f}: ${o}`));
    expect(found).toEqual([]);
  });
});
