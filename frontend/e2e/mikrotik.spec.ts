import { test, expect, type Page } from "@playwright/test";

// MikroTik RouterOS 整合（Beta）：新增 → 測試連線 → 刪除，外加這個整合特有的兩件事：
//  1. **保護參數要真的存得下來**（CPU 門檻／區段間隔／回應上限）—— 它們是這個整合的重點，
//     不是可有可無的進階選項。
//  2. **重的區段預設關**（ARP）。預設值跑掉的話，第一次同步就會去讀一台主力路由器的整張
//     ARP 表 —— 而且沒有人會發現，因為畫面看起來一切正常。
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

test.describe("MikroTik 整合（Beta）", () => {
  test("新增（含保護參數）→ 測試連線 → 刪除", async ({ page }) => {
    await login(page);
    await page.goto("/mikrotik");
    await expect(page.getByText("Beta", { exact: true }).first()).toBeVisible();

    const name = `e2e-mt-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await expect(dialog).toBeVisible();

    const boxes = dialog.getByRole("textbox");
    await boxes.nth(0).fill(name);                     // 名稱
    await boxes.nth(1).fill("https://192.0.2.241");    // TEST-NET：必連不到
    await boxes.nth(2).fill("ipam-readonly");          // 帳號
    await dialog.locator('input[type="password"]').fill("dummy-password");

    // 重的區段預設關：ARP 那一格不可以是勾起來的
    const arp = dialog.locator(".n-checkbox", { hasText: "ARP" }).first();
    await expect(arp).not.toHaveClass(/n-checkbox--checked/);

    // 保護參數：把 CPU 門檻改掉，存完再開回來看有沒有真的存進去
    const numbers = dialog.locator(".n-input-number input");
    await numbers.nth(0).fill("55");                   // CPU 門檻
    await dialog.getByRole("button", { name: "儲存" }).click();

    const row = page.locator(".n-data-table-tr", { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });

    // 存回來的值要對（PATCH 掉欄位是這類表單最常見的無聲失敗）
    await row.locator("button").nth(0).click();
    await expect(dialog).toBeVisible();
    await expect(dialog.locator(".n-input-number input").nth(0)).toHaveValue("55");
    await dialog.getByRole("button", { name: "取消" }).click();

    // 測試連線：連不到時要回可讀訊息，不可整頁爆掉
    await row.locator("button").nth(1).click();
    await expect(page.locator(".n-message, .n-modal").last()).toBeVisible({ timeout: 40_000 });
    await page.keyboard.press("Escape");

    // 刪除（tooltip 會蓋住 popconfirm，直接送 click 事件）
    await row.locator("button.n-button--error-type").click();
    const confirmBtn = page.locator(".n-popconfirm__action button").last();
    await expect(confirmBtn).toBeVisible();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/mikrotik/"),
    );
    await confirmBtn.dispatchEvent("click");
    await deleted;
    await expect(page.locator(".n-data-table-tr", { hasText: name })).toHaveCount(0, { timeout: 10_000 });
  });

  test("唯讀檢視頁可開啟", async ({ page }) => {
    await login(page);
    await page.goto("/mikrotik-fw");
    await expect(page.getByText(/路由器 \(MikroTik\)|Router \(MikroTik\)/).last()).toBeVisible();
  });

  test("窄視窗時設定表單不會橫向溢出", async ({ page }) => {
    // v0.6.2 起的規定：版面問題要量、不要用看的（使用者回報過「選項跑出卡片外」）
    await page.setViewportSize({ width: 900, height: 900 });
    await login(page);
    await page.goto("/mikrotik");
    await page.getByRole("button", { name: "新增" }).first().click();
    await expect(page.locator(".n-modal")).toBeVisible();

    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, "頁面出現橫向捲動").toBeLessThanOrEqual(1);

    const modal = page.locator(".n-modal").first();
    const box = await modal.boundingBox();
    expect(box!.width, "設定視窗比視窗還寬").toBeLessThanOrEqual(900);
  });
});
