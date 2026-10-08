import { describe, expect, it } from "vitest";

import { IP_CHANGE_SOURCES } from "@/api/ip_history";
import en from "../en-US.json";
import ja from "../ja-JP.json";
import zh from "../zh-TW.json";

/**
 * 異動記錄的「來源」篩選與標籤用 addresses.source_<來源> 翻譯；沒有鍵就原樣顯示英文代碼。
 *
 * 2026-10-07 使用者在 IP 詳情的異動記錄看到「system」「user」夾在「掃描代理」「LibreNMS」中間 ——
 * 後端一直有寫這兩種來源，只是從沒補翻譯。新增來源時這裡會擋下。
 */
const LOCALES = { "zh-TW": zh, "en-US": en, "ja-JP": ja } as const;

describe("異動記錄的來源都有翻譯", () => {
  for (const [name, dict] of Object.entries(LOCALES)) {
    const addresses = (dict as Record<string, any>).addresses as Record<string, string>;
    it(`${name}：IP_CHANGE_SOURCES 每一項都有 addresses.source_*`, () => {
      const missing = IP_CHANGE_SOURCES.filter((s) => !addresses[`source_${s}`]);
      expect(missing).toEqual([]);
    });
  }
});
