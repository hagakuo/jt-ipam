/**
 * 登入後的 ?next= 只接受本站路徑（CodeQL 標出的開放式轉址，2026-09-29）。
 * `//evil.example/…` 與 `/\evil.example/…` 也以 / 開頭，瀏覽器卻會當成別的網站。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function loginVia(page: Page, next: string) {
  await page.goto(`/login?next=${encodeURIComponent(next)}`);
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

for (const bad of ["//evil.example/phish", "/\\evil.example/phish", "https://evil.example/"]) {
  test(`登入後不會被帶去別的網站：${bad}`, async ({ page, baseURL }) => {
    await loginVia(page, bad);
    const url = new URL(page.url());
    expect(url.origin).toBe(new URL(baseURL!).origin);
    expect(url.pathname).not.toContain("evil");
  });
}

test("本站路徑照常帶回去", async ({ page }) => {
  await loginVia(page, "/devices");
  await expect(page).toHaveURL(/\/devices$/);
});
