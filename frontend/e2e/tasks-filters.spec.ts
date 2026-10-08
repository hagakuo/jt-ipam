/**
 * 作業頁：跟其他清單頁一樣能搜尋、篩選；代理回報與資料庫更新看得到；探測、代理回報、資料庫更新
 * 的結果直接顯示結論（以前四個數字永遠是 0）。樣本：seed_e2e 的 rd-e2e／Wireshark manuf／e2e-probe。
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

test("作業歷史：搜尋與篩選送到後端；代理回報與資料庫更新顯示結論", async ({ page }) => {
  await login(page);
  await page.goto("/tasks");
  await page.locator(".n-tabs-tab", { hasText: "歷史" }).click();
  const table = page.locator(".n-tab-pane:visible .n-data-table");

  // 搜尋：只剩符合的列
  await page.getByTestId("tasks-search").locator("input").fill("rd-e2e");
  await expect(table.locator("tbody tr")).toHaveCount(1, { timeout: 10_000 });
  const row = table.locator("tbody tr").first();
  await expect(row).toContainText("rustdesk.sync");
  await expect(row.getByTestId("task-summary-text")).toContainText("上線 2");

  // 資料庫更新：結論是幾個廠商前綴，不是四個數字
  await page.getByTestId("tasks-search").locator("input").fill("Wireshark");
  await expect(table.locator("tbody tr").first().getByTestId("task-summary-text"))
    .toContainText("39000", { timeout: 10_000 });

  // 沒有錯誤訊息的失敗探測：講清楚是失敗
  await page.getByTestId("tasks-search").locator("input").fill("e2e-probe");
  await expect(table.locator("tbody tr").first()).toContainText("沒有錯誤訊息", { timeout: 10_000 });

  // 篩選：清掉搜尋，只看手動 → 不會出現排程的 rustdesk.sync
  await page.getByTestId("tasks-search").locator("input").fill("");
  await page.getByTestId("tasks-filter-trigger").click();
  await page.locator(".n-base-select-option", { hasText: "手動" }).click();
  await expect(table).not.toContainText("rustdesk.sync", { timeout: 10_000 });

  // 類型選項來自後端（看得到的作業裡出現過的類型）
  await page.getByTestId("tasks-filter-kind").click();
  await expect(page.locator(".n-base-select-option", { hasText: "oui.refresh" })).toBeVisible();
});
