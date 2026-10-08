/**
 * 超大規模：裝置超過一次能畫的上限時，後端不建圖、只回裝置數 —— 畫面要講清楚並請使用者篩選，
 * 而不是一張空白的圖（2026-09-29 超大規模測試：兩萬台裝置時後端要算上十幾秒，瀏覽器也畫不動）。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("裝置太多：顯示裝置數與上限，請使用者用子網路篩選", async ({ page }) => {
  await page.route(/\/api\/v1\/topology(\?.*)?$/, (route) => route.fulfill({ json: {
    nodes: [], edges: [], too_large: { devices: 20501, limit: 2000 },
  } }));
  await login(page);
  await page.goto("/topology");
  const alert = page.getByTestId("topology-too-large");
  await expect(alert).toBeVisible({ timeout: 20_000 });
  await expect(alert).toContainText("20,501");
  await expect(alert).toContainText("2,000");
  await expect(alert).toContainText("子網路");
});
