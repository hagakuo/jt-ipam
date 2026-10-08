import { test, expect, type Page } from "@playwright/test";

// Palo Alto 整合（Beta）：新增 → 測試連線（連不到必須回可讀診斷／錯誤）→ 刪除。
// 沒有實機，所以這裡驗的是「畫面真的做得出這些事」——型別檢查看不到渲染成功但內容錯。
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

test.describe("Palo Alto 整合（Beta）", () => {
  test("新增 → 測試連線 → 刪除", async ({ page }) => {
    await login(page);
    await page.goto("/paloalto");

    await expect(page.getByText("Beta", { exact: true }).first()).toBeVisible();

    const name = `e2e-pan-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await expect(dialog).toBeVisible();

    const boxes = dialog.getByRole("textbox");
    await boxes.nth(0).fill(name);                     // 名稱
    await boxes.nth(1).fill("https://192.0.2.241");    // API URL（TEST-NET，必連不到）
    await dialog.locator('input[type="password"]').fill("dummy-key");
    await dialog.getByRole("button", { name: "儲存" }).click();

    const row = page.locator(".n-data-table-tr", { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });

    // 測試連線：連不到時要回可讀訊息（診斷視窗或錯誤 toast），不可整頁爆掉
    await row.locator("button").nth(1).click();
    await expect(page.locator(".n-message, .n-modal").last()).toBeVisible({ timeout: 30_000 });
    await page.keyboard.press("Escape");

    // 刪除（tooltip 會蓋住 popconfirm → 直接對按鈕送 click 事件）
    await row.locator("button.n-button--error-type").click();
    const confirmBtn = page.locator(".n-popconfirm__action button").last();
    await expect(confirmBtn).toBeVisible();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/paloalto/"),
    );
    await confirmBtn.dispatchEvent("click");
    await deleted;
    await expect(page.locator(".n-data-table-tr", { hasText: name })).toHaveCount(0, { timeout: 10_000 });
  });

  test("唯讀檢視頁可開啟", async ({ page }) => {
    await login(page);
    await page.goto("/paloalto-fw");
    await expect(page.getByText(/防火牆 \(Palo Alto\)|Firewall \(Palo Alto\)/).last()).toBeVisible();
  });
});
