/**
 * 下載類請求（responseType: "blob"）出錯時，錯誤內容也是一個 Blob。
 *
 * 不先轉回 JSON 的話，`detail` 讀不到，畫面只剩「伺服器錯誤」——後端講的原因（例如
 * 「PFX 密碼不可以放在網址參數」）使用者永遠看不到。所有下載共用同一個攔截器，在那裡轉一次。
 */
import { describe, expect, it } from "vitest";
import { unwrapBlobError } from "../client";

function errWith(data: unknown) {
  return { response: { status: 400, data } } as any;
}

describe("unwrapBlobError", () => {
  it("JSON 型態的 Blob 轉回物件", async () => {
    const body = { detail: { code: "cert_export_password_in_url", params: {}, message: "x" } };
    const e = errWith(new Blob([JSON.stringify(body)], { type: "application/json" }));
    await unwrapBlobError(e);
    expect(e.response.data).toEqual(body);
  });

  it("不是 JSON 的 Blob 原樣保留（真的檔案內容不要亂動）", async () => {
    const blob = new Blob(["PK\u0003\u0004"], { type: "application/octet-stream" });
    const e = errWith(blob);
    await unwrapBlobError(e);
    expect(e.response.data).toBe(blob);
  });

  it("壞掉的 JSON 不丟例外", async () => {
    const e = errWith(new Blob(["{not json"], { type: "application/json" }));
    await expect(unwrapBlobError(e)).resolves.toBeUndefined();
  });

  it("本來就是物件的錯誤不受影響", async () => {
    const e = errWith({ detail: "x" });
    await unwrapBlobError(e);
    expect(e.response.data).toEqual({ detail: "x" });
  });
});
