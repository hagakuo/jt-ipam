import { test, expect, type Page } from "@playwright/test";

/**
 * 系統診斷（管理 → 系統診斷）。
 *
 * 由來（2026-09-05 客戶回報）：儀表板數得出 55 台裝置、裝置清單卻是 Internal Server Error。
 * 診斷過程中請客戶跑指令與貼 SQL 的每一件事，都是我們自己該做的 —— 所以有了這一頁。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test.describe("系統診斷", () => {
  test("列出檢查項目，且每個非正常項目都講得出怎麼修", async ({ page }) => {
    await login(page);
    await page.goto("/doctor");
    await expect(page.getByText("系統診斷").first()).toBeVisible({ timeout: 10_000 });
    // 資料庫結構是最重要的一項（客戶那次的第一嫌疑），一定要在
    await expect(page.getByText("資料庫結構")).toBeVisible({ timeout: 20_000 });
    // 資料健檢：拿正式讀取 schema 驗每一列，綠燈才代表清單頁畫得出來
    await expect(page.getByText("資料健檢")).toBeVisible();

    // 有問題的項目一定要附「怎麼修」——只說壞了等於沒說
    const problems = page.locator('.doc-row[data-status="bad"], .doc-row[data-status="warn"]');
    for (let i = 0; i < await problems.count(); i++) {
      await expect(problems.nth(i).locator(".doc-fix")).toBeVisible();
    }

    // 後端看不到系統層的東西，頁面要明講，不能讓人以為全綠＝一切正常
    await expect(page.getByText(/jt-ipam\.sh doctor/)).toBeVisible();
  });

  test("資料統計：各類資料的筆數都是數字，並寫明不會傳送出去", async ({ page }) => {
    await login(page);
    await page.goto("/doctor");
    const st = page.getByTestId("doctor-stats");
    await expect(st).toBeVisible({ timeout: 20_000 });
    await expect(st).toContainText("不會傳送到任何地方");
    for (const key of ["subnets", "ipv4", "devices", "audit_logs"]) {
      await expect(st.locator(`.doc-stat[data-key="${key}"] .doc-stat-v`)).toHaveText(/^(約 )?[\d,]+$/);
    }
    // 時間參數換成觀看者的時區（以前直接印 UTC）：背景作業那一列不可以有 T 或 +00:00
    const jobs = page.locator(".doc-row", { hasText: "背景作業" });
    if (await jobs.count()) await expect(jobs.first()).not.toContainText(/\dT\d|\+00:00/);
  });

  test("可以下載純文字記錄檔", async ({ page }) => {
    await login(page);
    await page.goto("/doctor");
    await expect(page.getByText("資料庫結構")).toBeVisible({ timeout: 20_000 });
    const dl = page.waitForEvent("download");
    await page.getByRole("button", { name: "下載記錄檔" }).click();
    const file = await dl;
    expect(file.suggestedFilename()).toMatch(/^jt-ipam-doctor-.*\.txt$/);
  });

  test("窄視窗時不會橫向溢出", async ({ page }) => {
    await page.setViewportSize({ width: 900, height: 900 });
    await login(page);
    await page.goto("/doctor");
    await expect(page.getByText("資料庫結構")).toBeVisible({ timeout: 20_000 });
    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, "頁面出現橫向捲動").toBeLessThanOrEqual(1);
  });
});
