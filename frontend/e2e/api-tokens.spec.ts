import { test, expect, type Page } from "@playwright/test";

// API 權杖自助頁：建立（唯讀）→ 明文只顯示一次 → 撤銷。
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

test.describe("API 權杖", () => {
  test("建立唯讀權杖 → 明文顯示一次 → 撤銷", async ({ page }) => {
    await login(page);
    await page.goto("/account/api-tokens");

    const name = `e2e-token-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("textbox").first().fill(name);
    // 選「唯讀」
    await dialog.getByText("唯讀（禁止任何會改資料的操作）").click();
    await dialog.getByRole("button", { name: "儲存" }).click();

    // 一次性明文視窗：要真的出現一個 jt_ 開頭的權杖
    const created = page.locator(".n-modal", { hasText: "權杖已建立" });
    await expect(created).toBeVisible({ timeout: 10_000 });
    const shown = await created.locator("textarea").inputValue();
    expect(shown).toMatch(/^jt_[a-z]+_/);
    await created.getByRole("button", { name: "我已保存好" }).click();
    await expect(created).toBeHidden();

    // 列表出現該權杖，且標記為唯讀
    const row = page.locator(".n-data-table-tr", { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row).toContainText("唯讀");

    // 撤銷
    await row.locator("button").last().click();
    const confirmBtn = page.locator(".n-popconfirm__action button").last();
    await expect(confirmBtn).toBeVisible();
    const revoked = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/api-tokens/"),
    );
    await confirmBtn.dispatchEvent("click");
    await revoked;
    await expect(row).toContainText("已撤銷", { timeout: 10_000 });
  });

  test("唯讀權杖不能寫入（403）", async ({ page, request }) => {
    await login(page);
    await page.goto("/account/api-tokens");

    // 用 UI 建一把唯讀權杖，拿到明文後直接打 API 驗證 scope 真的生效
    const name = `e2e-scope-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await dialog.getByRole("textbox").first().fill(name);
    await dialog.getByText("唯讀（禁止任何會改資料的操作）").click();
    await dialog.getByRole("button", { name: "儲存" }).click();

    const created = page.locator(".n-modal", { hasText: "權杖已建立" });
    await expect(created).toBeVisible({ timeout: 10_000 });
    const token = await created.locator("textarea").inputValue();
    await created.getByRole("button", { name: "我已保存好" }).click();

    const base = process.env.E2E_BASE_URL || "http://localhost:5173";
    const auth = { Authorization: `Bearer ${token}` };

    // 讀取通
    const ok = await request.get(`${base}/api/v1/subnets`, { headers: auth });
    expect(ok.status()).toBe(200);

    // 寫入被擋成 403（不是 401、不是 201）
    const denied = await request.post(`${base}/api/v1/sections`, {
      headers: auth,
      data: { name: `should-not-exist-${Date.now()}` },
    });
    expect(denied.status()).toBe(403);
    expect(await denied.text()).toContain("read-only");
  });
});
