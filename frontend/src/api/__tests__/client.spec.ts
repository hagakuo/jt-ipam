import { describe, expect, it } from "vitest";
import { apiErrMsg } from "@/api/client";

describe("apiErrMsg", () => {
  it("字串 detail 直接顯示", () => {
    expect(apiErrMsg({ response: { data: { detail: "名稱重複" } } })).toBe("名稱重複");
  });

  it("結構化 detail 取 message —— 否則會顯示成 [object Object]", () => {
    const e = { response: { data: { detail: {
      code: "ip_in_cooldown", until: "2026-09-25T00:00:00Z", message: "此位址仍在冷卻期內",
    } } } };
    expect(apiErrMsg(e)).toBe("此位址仍在冷卻期內");
  });

  it("認不得的形狀退回通用訊息，不會丟出例外", () => {
    expect(typeof apiErrMsg({})).toBe("string");
    expect(typeof apiErrMsg(null)).toBe("string");
    expect(typeof apiErrMsg({ response: { data: { detail: { code: "x" } } } })).toBe("string");
  });
});
