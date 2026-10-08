/** 作業系統分類的顯示名稱依介面語言挑（日文以前一律退回英文）。 */
import { describe, expect, it } from "vitest";
import { osFamilyLabel, type OsFamily } from "../scanProbes";

const fams: OsFamily[] = [
  { key: "network", label_en: "Network device", label_zh: "網路裝置", label_ja: "ネットワーク機器" },
  { key: "linux", label_en: "Linux", label_zh: "Linux" },
];

describe("osFamilyLabel", () => {
  it("依語言挑名稱", () => {
    expect(osFamilyLabel(fams, "network", "zh-TW")).toBe("網路裝置");
    expect(osFamilyLabel(fams, "network", "en-US")).toBe("Network device");
    expect(osFamilyLabel(fams, "network", "ja-JP")).toBe("ネットワーク機器");
  });
  it("後端沒給日文時退回英文", () => {
    expect(osFamilyLabel(fams, "linux", "ja-JP")).toBe("Linux");
  });
});
