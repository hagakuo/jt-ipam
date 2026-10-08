import { describe, expect, it } from "vitest";
import zh from "../zh-TW.json";
import ja from "../ja-JP.json";

/**
 * 日文語系的守門測試。
 *
 * 為什麼需要：少一個鍵、或整段沒翻到，vue-i18n 都**不會報錯** —— 它安靜地退回
 * en-US，畫面看起來只是「有些地方是英文」，沒有人會發現是漏翻。三語並存之後，
 * 這件事只會更容易發生（改一個功能要動三個檔）。
 *
 * `scripts/check-i18n.mjs` 已經守住鍵集合一致；這裡守的是**內容真的是日文**。
 */
type Dict = Record<string, unknown>;

function flatten(obj: Dict, prefix = ""): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object") Object.assign(out, flatten(v as Dict, key));
    else out[key] = String(v);
  }
  return out;
}

const fz = flatten(zh as Dict);
const fj = flatten(ja as Dict);

// 只列**日文不會用**的繁體字（日文有對應的新字體，例如 實→実、說→説、會→会）。
// 不能把 有、個、選、際、請 這類兩邊共用的字放進來 —— 第一版就是這樣寫的，
// 結果 200 多則正確的日文被判成「沒翻到」。
const CHINESE_ONLY = /[這們麼嗎呢您臺灣沒裡哪樣點體實說讓會國學關與將從區發處屬單當]/;

describe("ja-JP", () => {
  it("鍵集合與 zh-TW 完全一致", () => {
    expect(Object.keys(fj).sort()).toEqual(Object.keys(fz).sort());
  });

  it("沒有整段沒翻到的中文", () => {
    const leaked = Object.entries(fj)
      .filter(([, v]) => CHINESE_ONLY.test(v))
      .map(([k]) => k);
    expect(leaked, `這些鍵看起來還是中文：${leaked.slice(0, 10).join(", ")}`).toEqual([]);
  });

  it("插值參數與 zh-TW 一模一樣", () => {
    // {n}、{ip} 這類參數漏掉或打錯，畫面會直接印出 {n}；翻譯最常見的錯就是這個。
    const bad: string[] = [];
    for (const [k, zhv] of Object.entries(fz)) {
      const want = (zhv.match(/\{[a-zA-Z_][a-zA-Z0-9_]*\}/g) ?? []).sort();
      const got = (fj[k].match(/\{[a-zA-Z_][a-zA-Z0-9_]*\}/g) ?? []).sort();
      if (want.join(",") !== got.join(",")) bad.push(`${k}: 期望 ${want} 實得 ${got}`);
    }
    expect(bad, bad.slice(0, 10).join(" | ")).toEqual([]);
  });

  it("幾個一定會看到的字串確實是日文", () => {
    expect(fj["nav.dashboard"]).toBe("ダッシュボード");
    expect(fj["common.save"]).toBe("保存");
    expect(fj["login.submit"]).toBe("サインイン");
  });
});
