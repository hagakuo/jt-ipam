/**
 * 憑證匯出 PFX：先問保護密碼，密碼走 POST body、不進網址。
 *
 * 以前兩個問題：
 * 1. 畫面匯出 PFX 一律**不加密碼** —— 後端支援密碼，畫面從來沒給地方填，匯出的 PFX 內含
 *    私鑰、任何人拿到都打得開。
 * 2. 密碼的傳法是 `?password=`，會原封不動寫進 nginx 存取日誌與瀏覽器歷史（0.6.43 ZAP 抓到）。
 */
import { execFileSync } from "node:child_process";
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const r = await fetch(path, { method, headers: { "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("access_token")}` },
      body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, json: r.status === 204 ? null : await r.json().catch(() => null) };
  }, { method, path, body });
}

test("PFX 匯出先問密碼、走 POST，下載的檔案用那個密碼打得開", async ({ page }) => {
  await login(page);
  const name = `e2e-pfx-${Date.now()}`;
  const c = await api(page, "POST", "/api/v1/certificates", { name, description: "e2e" });
  expect(c.status).toBe(201);
  const ss = await api(page, "POST", `/api/v1/certificates/${c.json.id}/self-signed`,
    { common_name: "pfx.example.net", sans: ["pfx.example.net"], days: 30 });
  expect(ss.status).toBe(201);

  const fileRequests: { method: string; url: string }[] = [];
  page.on("request", (r) => { if (r.url().includes("/file")) fileRequests.push({ method: r.method(), url: r.url() }); });
  try {
    await page.goto("/certificates");
    const row = page.locator("tr", { hasText: name }).first();
    await row.getByLabel("憑證資訊 / 檔案").click();
    await page.getByRole("button", { name: "下載" }).first().click();
    await page.locator(".n-dropdown-option", { hasText: "PFX" }).click();

    const dlg = page.locator(".n-modal").filter({ hasText: "PFX 匯出密碼" });
    await expect(dlg).toBeVisible();
    await expect(dlg).toContainText("沒有設定密碼");            // 留空時要警告
    const [pw1, pw2] = [dlg.locator("input").nth(0), dlg.locator("input").nth(1)];
    await pw1.fill("E2e-pfx-Pass");
    await pw2.fill("E2e-pfx-typo");
    await expect(dlg.getByRole("button", { name: "下載" })).toBeDisabled();   // 兩次不一樣不給下載
    await pw2.fill("E2e-pfx-Pass");
    const [dl] = await Promise.all([page.waitForEvent("download"), dlg.getByRole("button", { name: "下載" }).click()]);
    const path = await dl.path();
    expect(dl.suggestedFilename()).toMatch(/\.pfx$/);

    // 用那個密碼打得開、而且裡面真的有私鑰
    const out = execFileSync("openssl", ["pkcs12", "-in", path!, "-nocerts", "-nodes", "-passin", "pass:E2e-pfx-Pass"],
      { encoding: "utf-8" });
    expect(out).toContain("PRIVATE KEY");

    expect(fileRequests.length).toBeGreaterThan(0);
    for (const r of fileRequests) {
      expect(r.method).toBe("POST");
      expect(r.url).not.toContain("password");
    }
  } finally {
    await api(page, "DELETE", `/api/v1/certificates/${c.json.id}`);
  }
});
