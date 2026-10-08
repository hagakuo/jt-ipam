/**
 * 手機上的機櫃圖（使用者回報，2026-09-27）：
 *   ① 機櫃比螢幕寬時要能左右拖拉看到右半邊（以前整張溢出卡片、頁面又不能橫向捲）
 *   ② 「正面／背面」按鈕不可以凸出卡片左邊（工具列靠右又不換行 → 放不下的往左溢出）
 * 量幾何，不看截圖。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");
test.use({ viewport: { width: 390, height: 844 } });

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username|ユーザー名/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password|パスワード/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /^(登入|Sign in|サインイン)$/ }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function api(page: Page, path: string) {
  return page.evaluate(async (p) => {
    const r = await fetch(p, { headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } });
    return r.json();
  }, path);
}

test("機櫃圖可以左右捲、工具列不凸出卡片", async ({ page }) => {
  await login(page);
  const racks = await api(page, "/api/v1/racks?page_size=500");
  const list = (racks.items ?? racks) as { id: string; u_height: number | null }[];
  const rack = list.find((r) => (r.u_height ?? 0) > 0);
  test.skip(!rack, "沒有可以畫的機櫃");
  await page.goto(`/racks?rack=${rack!.id}`);

  const card = page.locator(".rack-diagram-card").filter({ has: page.locator(".rd-toolbar") }).first();
  await expect(card.locator(".rack-scroll")).toBeVisible({ timeout: 15_000 });
  const cardBox = (await card.boundingBox())!;

  // ② 工具列每個項目都在卡片裡
  const items = card.locator(".rd-toolbar > *");
  for (let i = 0; i < await items.count(); i++) {
    const b = (await items.nth(i).boundingBox())!;
    expect(b.x, `工具列第 ${i + 1} 項凸出卡片左邊`).toBeGreaterThanOrEqual(cardBox.x - 0.5);
    expect(b.x + b.width).toBeLessThanOrEqual(cardBox.x + cardBox.width + 0.5);
  }

  // ① 卡片不超出畫面；機櫃比卡片寬時，捲動層真的捲得動
  expect(cardBox.x + cardBox.width).toBeLessThanOrEqual(390 + 0.5);
  const scroll = card.locator(".rack-scroll");
  const dims = await scroll.evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth }));
  if (dims.sw > dims.cw + 1) {
    await scroll.evaluate((el) => { el.scrollLeft = el.scrollWidth; });
    const left = await scroll.evaluate((el) => el.scrollLeft);
    expect(left, "機櫃比卡片寬卻捲不動").toBeGreaterThan(0);
  }
});
