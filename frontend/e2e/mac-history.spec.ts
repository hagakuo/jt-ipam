/**
 * MAC 歷程（以一個 MAC 為中心）：全域搜尋輸入完整 MAC → 「查看完整歷程」→ 用過的 IP、時間軸。
 *
 * 種子資料（tests/seed_e2e.py）：00:00:5e:00:53:12 以前在 app-01（10.20.0.11），12 天前被別的 MAC
 * 取代，現在在 db-01（10.20.0.12）。
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

test("全域搜尋輸入 MAC（任何寫法）→ MAC 歷程：用過的 IP、狀態、時間軸", async ({ page }) => {
  await login(page);
  const box = page.getByPlaceholder(/搜尋/).first();
  await box.click();
  await box.fill("00-00-5E-00-53-12");
  await expect(page.locator(".n-base-select-option", { hasText: "查看 00:00:5e:00:53:12 的完整歷程" })).toBeVisible();
  await box.press("Enter");
  await expect(page).toHaveURL(/\/mac\/00:00:5e:00:53:12$/);
  await expect(box).toHaveValue("");                       // 選完不留選項文字
  const ips = page.getByTestId("mh-ips");
  await expect(ips).toContainText("10.20.0.12");
  await expect(ips).toContainText("10.20.0.11");
  await expect(ips.locator("tr", { hasText: "10.20.0.12" })).toContainText("目前使用中");
  await expect(ips.locator("tr", { hasText: "10.20.0.11" })).toContainText("已換手");
  const ev = page.getByTestId("mh-events");
  await expect(ev).toContainText("離開");
  await expect(ev).toContainText("00:00:5e:00:53:11");      // 被誰取代
});

test("IP 詳細資料的 MAC 點下去到 MAC 歷程；不是 MAC 講清楚", async ({ page }) => {
  await login(page);
  await page.goto("/mac/not-a-mac");
  await expect(page.getByText("不是有效的 MAC 位址")).toBeVisible();
  await page.goto("/addresses?q=10.20.0.12");
  await page.locator("tr", { hasText: "10.20.0.12" }).first().getByText("10.20.0.12").first().click();
  const link = page.locator("a.mac-history-link");
  await expect(link).toHaveText("00:00:5e:00:53:12", { timeout: 15_000 });
  await link.click();
  await expect(page).toHaveURL(/\/mac\/00:00:5e:00:53:12$/);
  await expect(page.getByTestId("mh-summary")).toContainText("10.20.0.12");
});
