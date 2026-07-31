import { test, expect, type Page } from "@playwright/test";

// FortiGate 整合（Beta）：新增 → 測試連線（連不到必須回可讀診斷／錯誤）→ 刪除。
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

test.describe("FortiGate 整合（Beta）", () => {
  test("新增 → 測試連線 → 刪除", async ({ page }) => {
    await login(page);
    await page.goto("/fortigate");

    await expect(page.getByText("Beta", { exact: true }).first()).toBeVisible();

    const name = `e2e-fgt-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await expect(dialog).toBeVisible();

    const boxes = dialog.getByRole("textbox");
    await boxes.nth(0).fill(name);                     // 名稱
    await boxes.nth(1).fill("https://192.0.2.240");    // API URL（TEST-NET，必連不到）
    await dialog.locator('input[type="password"]').fill("dummy-token");
    await dialog.getByRole("button", { name: "儲存" }).click();

    const row = page.locator(".n-data-table-tr", { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });

    // 測試連線：連不到時要回可讀訊息（診斷視窗或錯誤 toast），不可整頁爆掉
    await row.locator("button").nth(1).click();
    await expect(page.locator(".n-message, .n-modal").last()).toBeVisible({ timeout: 30_000 });
    await page.keyboard.press("Escape");

    // 刪除
    await row.locator("button.n-button--error-type").click();
    const confirmBtn = page.locator(".n-popconfirm__action button").last();
    await expect(confirmBtn).toBeVisible();
    // 用 dispatchEvent 直接送到按鈕本身：刪除鈕的 tooltip 會蓋在 popconfirm 上，
    // 走座標的點擊（即使 force）仍會被 tooltip 接走。
    const deleted = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/fortigate/"),
    );
    await confirmBtn.dispatchEvent("click");
    await deleted;
    await expect(page.locator(".n-data-table-tr", { hasText: name })).toHaveCount(0, { timeout: 10_000 });
  });

  test("唯讀檢視頁可開啟", async ({ page }) => {
    await login(page);
    await page.goto("/fortigate-fw");
    await expect(page.getByText(/防火牆 \(FortiGate\)|Firewall \(FortiGate\)/).last()).toBeVisible();
  });
});
