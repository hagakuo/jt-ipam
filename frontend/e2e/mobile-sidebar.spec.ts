/**
 * 手機版側欄（使用者要求，2026-09-27）：
 *   窄螢幕時側欄不是縮成一排圖示，而是整個收起（寬度 0）；左上角的按鈕叫出來、疊在內容上；
 *   點選功能後、或點旁邊暗掉的地方就收回。桌機維持原樣。
 * 量幾何，不看截圖（TEST_CHECKLIST §5c）。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username|ユーザー名/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password|パスワード/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /^(登入|Sign in|サインイン)$/ }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

const siderWidth = async (page: Page) => (await page.locator(".app-sider").boundingBox())?.width ?? 0;

test.describe("手機版側欄", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("收成一條線，左上角叫出來，點選功能後收回", async ({ page }) => {
    await login(page);
    const btn = page.locator(".mobile-menu-btn");
    await expect(btn).toBeVisible();
    // 收起：寬度 0，內容從最左邊開始，也沒有桌機那顆「›」
    await expect.poll(() => siderWidth(page)).toBeLessThan(2);
    const content = await page.locator(".topbar").boundingBox();
    expect(content!.x).toBeLessThan(2);
    await expect(page.locator(".app-sider .n-layout-toggle-button")).toHaveCount(0);

    // 叫出來：疊在內容上（內容不被推開），後面暗掉
    await btn.click();
    await expect.poll(() => siderWidth(page)).toBeGreaterThan(200);
    await expect(page.locator(".sider-mask")).toBeVisible();
    expect((await page.locator(".topbar").boundingBox())!.x).toBeLessThan(2);

    // 點選功能 → 換頁、收回
    await page.locator(".app-sider .n-menu-item-content", { hasText: /IP 位址|IP addresses|IP アドレス/ }).first().click();
    await expect(page).toHaveURL(/addresses/);
    await expect.poll(() => siderWidth(page)).toBeLessThan(2);
    await expect(page.locator(".sider-mask")).toHaveCount(0);

    // 點暗掉的地方也收回
    await btn.click();
    await expect.poll(() => siderWidth(page)).toBeGreaterThan(200);
    await page.locator(".sider-mask").click({ position: { x: 370, y: 400 } });
    await expect.poll(() => siderWidth(page)).toBeLessThan(2);
  });
});

test("桌機維持原樣：側欄在、沒有左上角按鈕", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await login(page);
  await expect.poll(() => siderWidth(page)).toBeGreaterThan(150);
  await expect(page.locator(".mobile-menu-btn")).toHaveCount(0);
});
