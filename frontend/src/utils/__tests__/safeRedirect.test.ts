import { describe, expect, it } from "vitest";
import { safeNextPath } from "@/utils/safeRedirect";

const ORIGIN = "https://ipam.example.test";

describe("safeNextPath（登入後的 ?next= 只接受本站路徑）", () => {
  it("本站路徑原樣保留（含查詢與錨點）", () => {
    expect(safeNextPath("/addresses?q=198.51.100.7#x", ORIGIN)).toBe("/addresses?q=198.51.100.7#x");
    expect(safeNextPath("/devices", ORIGIN)).toBe("/devices");
  });

  it.each([
    "//evil.example/phish",          // protocol-relative：瀏覽器當成別的網站
    "/\\evil.example/phish",         // 反斜線被瀏覽器當成斜線
    "https://evil.example/",
    "javascript:alert(1)",
    "evil.example",
    "",
    "/login",
  ])("不接受 %s", (bad) => {
    expect(safeNextPath(bad, ORIGIN)).toBe("/");
  });

  it("不是字串（陣列參數）也退回首頁", () => {
    expect(safeNextPath(["/a", "/b"], ORIGIN)).toBe("/");
    expect(safeNextPath(undefined, ORIGIN)).toBe("/");
  });
});
