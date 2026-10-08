/**
 * AI 工具名稱的在地化。
 *
 * 重點不是「有沒有翻」，而是**組裝方式也會變**：中文黏在一起、英文要空格、
 * 日文動詞擺在最後。把順序寫死在程式裡，日文就會變成「照会IP詳細」那種不成話的東西。
 */
import { describe, expect, it } from "vitest";
import { humanToolName } from "../toolLabel";
import zh from "../../i18n/zh-TW.json";
import en from "../../i18n/en-US.json";
import ja from "../../i18n/ja-JP.json";

function harness(msgs: Record<string, any>) {
  const get = (key: string): unknown =>
    key.split(".").reduce<any>((o, k) => (o && typeof o === "object" ? o[k] : undefined), msgs);
  const te = (key: string) => typeof get(key) === "string";
  const t = (key: string, params: Record<string, unknown> = {}) =>
    String(get(key) ?? key).replace(/\{(\w+)\}/g, (_, p) => String(params[p] ?? ""));
  return { t, te };
}
const ZH = harness(zh), EN = harness(en), JA = harness(ja);

describe("AI 工具名稱", () => {
  it("動詞＋名詞組合成看得懂的說明", () => {
    expect(humanToolName("get_ip_detail", ZH.t, ZH.te)).toBe("查詢IP詳細資料");
    expect(humanToolName("list_devices", ZH.t, ZH.te)).toBe("列出裝置");
    expect(humanToolName("get_subnet_usage", ZH.t, ZH.te)).toBe("查詢子網路使用率");
  });

  it("英文用空格分隔，不是黏成一團", () => {
    expect(humanToolName("list_devices", EN.t, EN.te)).toBe("List devices");
    expect(humanToolName("get_subnet_usage", EN.t, EN.te)).toBe("Look up subnet usage");
  });

  it("日文的動詞在最後", () => {
    const s = humanToolName("list_devices", JA.t, JA.te);
    expect(s).toBe("機器を一覧表示");
    expect(s.endsWith("一覧表示"), "日文把動詞放到前面就不成話了").toBe(true);
  });

  it("三種語言都不會漏掉動詞或名詞", () => {
    for (const h of [ZH, EN, JA]) {
      const s = humanToolName("get_ip_detail", h.t, h.te);
      expect(s).toContain("IP");
      expect(s.length).toBeGreaterThan(3);
    }
  });

  it("不認得的字保留原樣，不是空白 —— 寧可顯示代號也不要什麼都不說", () => {
    expect(humanToolName("frobnicate_widget", ZH.t, ZH.te)).toBe("frobnicatewidget");
    expect(humanToolName("", ZH.t, ZH.te)).toBe("");
  });

  it("只有動詞沒有名詞時就只回動詞", () => {
    expect(humanToolName("list", ZH.t, ZH.te)).toBe("列出");
  });
});
