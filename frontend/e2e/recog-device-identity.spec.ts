/**
 * Recog 的其他用途（2026-10-01）：掃描代理定期偵測判讀出的設備類型。
 *   ② 異常偵測多一類「類型或 OS 突變」（印表機變成 Windows 主機）
 *   ③ IP 清單有「設備類型」欄（圖示＋類型，滑過去看型號）；IP 詳細資料顯示類型與型號
 * 資料來自 seed_e2e：db-01＝NAS（Synology DS920+）、app-01＝印表機 → Windows。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("異常偵測：類型或 OS 突變列出從什麼變成什麼，並有說明", async ({ page }) => {
  await login(page);
  await page.goto("/anomaly?tab=identity_changes");
  await page.getByRole("button", { name: /執行偵測/ }).click();
  const pane = page.locator(".n-tab-pane:visible");
  await expect(pane).toContainText("掃描代理的定期偵測判讀出的設備類型或 OS 家族變了", { timeout: 20_000 });
  const row = pane.locator(".n-data-table-tr", { hasText: "10.20.0.11" });
  await expect(row).toContainText("設備類型：印表機 → Windows 主機");
  await expect(row).toContainText(/OS：Linux → Windows/);
  await expect(page.locator(".n-tabs-tab", { hasText: "類型或 OS 突變" })).toBeVisible();
});

test("IP 清單的設備類型欄與 IP 詳細資料", async ({ page }) => {
  await login(page);
  await page.goto("/addresses");
  // 新欄位：從「欄位」打開（既有使用者的欄位偏好裡還沒有它）
  // 等表格畫完再判斷有沒有這一欄（欄位偏好會存著，上一輪可能已經打開了）
  await expect(page.locator(".n-data-table-tr", { hasText: "10.20.0.12" })).toBeVisible({ timeout: 15_000 });
  const header = page.locator(".n-data-table-th", { hasText: "設備類型" });
  if (!(await header.count())) {
    await page.getByRole("button", { name: /欄位/ }).first().click();
    await page.locator(".n-popover").getByText("設備類型", { exact: true }).click();
    await page.keyboard.press("Escape");
  }
  await expect(header).toBeVisible();
  const nas = page.locator(".n-data-table-tr", { hasText: "10.20.0.12" });
  await expect(nas).toContainText("儲存設備");
  await expect(nas.locator('[title="儲存設備 · Synology DS920+"]')).toHaveCount(1);
  await page.getByText("10.20.0.12", { exact: true }).first().click();
  await expect(page.getByTestId("ip-device-kind")).toContainText("Synology DS920+");
});
