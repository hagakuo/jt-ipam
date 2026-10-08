import { test, expect, type Page } from "@playwright/test";

// Zabbix 整合：新增（帳密／token 兩種認證）→ 測試連線（連不到要回可讀訊息）→ 刪除。
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

test.describe("Zabbix 整合", () => {
  test("新增 → 測試連線 → 主機清單 → 涵蓋缺口 → 刪除", async ({ page }) => {
    await login(page);
    await page.goto("/zabbix");
    await expect(page.getByText("整合 Zabbix").first()).toBeVisible();

    const name = `e2e-zbx-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await expect(dialog).toBeVisible();

    const boxes = dialog.getByRole("textbox");
    await boxes.nth(0).fill(name);
    await boxes.nth(1).fill("https://192.0.2.241");   // TEST-NET，必連不到
    await dialog.locator('input[type="password"]').fill("dummy-token");

    // 切到帳密模式要出現帳號欄，切回 token 要收起來 —— 兩個分支不可互相蓋掉
    await dialog.getByText("帳號密碼", { exact: true }).click();
    await expect(dialog.getByText("帳號", { exact: true })).toBeVisible();
    await dialog.getByText("API token", { exact: true }).first().click();
    await expect(dialog.getByText("帳號", { exact: true })).toHaveCount(0);

    await dialog.getByRole("button", { name: "儲存" }).click();

    const row = page.locator(".n-data-table-tr", { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });

    // 測試連線（連不到）→ 必須是可讀訊息，不可整頁爆掉
    await row.locator("button").nth(1).click();
    await expect(page.locator(".n-message, .n-modal").last()).toBeVisible({ timeout: 30_000 });
    await page.keyboard.press("Escape");

    // 主機清單與涵蓋缺口：尚未同步也要開得起來（空狀態，不是錯誤）
    await row.locator("button").nth(2).click();
    await expect(page.locator(".n-modal").last()).toBeVisible({ timeout: 10_000 });
    await page.keyboard.press("Escape");
    await row.locator("button").nth(3).click();
    await expect(page.locator(".n-modal").last()).toBeVisible({ timeout: 15_000 });
    await page.keyboard.press("Escape");

    // 刪除（比照 FortiGate spec：tooltip 會蓋住 popconfirm，要用 dispatchEvent）
    await row.locator("button.n-button--error-type").click();
    const confirmBtn = page.locator(".n-popconfirm__action button").last();
    await expect(confirmBtn).toBeVisible();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/zabbix/"),
    );
    await confirmBtn.dispatchEvent("click");
    await deleted;
    await expect(page.locator(".n-data-table-tr", { hasText: name })).toHaveCount(0, { timeout: 10_000 });
  });
});
