import { describe, expect, it } from "vitest";

import en from "../en-US.json";
import ja from "../ja-JP.json";
import zh from "../zh-TW.json";

/**
 * IP 詳細資料裡「最後出現」那一組欄位是並排顯示的，所以標籤必須長得一樣。
 *
 * 2026-09-18 使用者指出 Wazuh 那一格寫成「Wazuh 代理 keep-alive」，與旁邊的
 * 「最後出現 (掃描代理)」「最後出現 (LibreNMS)」放在一起很突兀 —— 同一組資料
 * （各來源最後看到這個 IP 的時間）卻有兩種句型，讀的人會以為它是別的東西。
 */
const SOURCES = ["scanner", "librenms", "dns", "arp", "wazuh"] as const;

const LOCALES = {
  "zh-TW": { dict: zh, prefix: "最後出現" },
  "en-US": { dict: en, prefix: "Last seen" },
  "ja-JP": { dict: ja, prefix: "最終確認" },
} as const;

describe("最後出現的標籤", () => {
  for (const [name, { dict, prefix }] of Object.entries(LOCALES)) {
    const addresses = (dict as Record<string, any>).addresses as Record<string, string>;

    it(`${name}：每一個來源都用同一個句型`, () => {
      for (const src of SOURCES) {
        const label = addresses[`last_seen_${src}`];
        expect(label, `缺少 last_seen_${src}`).toBeTruthy();
        expect(label.startsWith(prefix), `${src} 的標籤是 ${JSON.stringify(label)}`).toBe(true);
      }
    });

    it(`${name}：來源名稱都放在括號裡`, () => {
      for (const src of SOURCES) {
        expect(addresses[`last_seen_${src}`]).toMatch(/[(（].+[)）]$/);
      }
    });
  }

  it("繁體中文用全形括號（專案的標點慣例）", () => {
    const addresses = (zh as Record<string, any>).addresses as Record<string, string>;
    for (const src of SOURCES) {
      const label = addresses[`last_seen_${src}`];
      expect(label, `${src} 用了半形括號：${label}`).not.toMatch(/[()]/);
      expect(label).toMatch(/（.+）$/);
    }
  });
});
