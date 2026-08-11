/**
 * 主版面的幾何：側欄 logo 欄與頂端列的底邊必須切齊。
 *
 * 兩者原本各自由內容撐高（logo 欄 14+32+14、頂端列 8+內容+8），底邊差幾 px，
 * 在左上角形成一道對不齊的缺口 —— 實機回報，截圖乍看不明顯，用量的才確定。
 */
import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

test("側欄 logo 欄與頂端列的底邊要切齊", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));

  const brand = await page.locator(".brand").boundingBox();
  const topbar = await page.locator(".topbar").boundingBox();
  expect(brand && topbar, "抓不到 logo 欄或頂端列").toBeTruthy();
  const brandBottom = brand!.y + brand!.height;
  const topbarBottom = topbar!.y + topbar!.height;
  expect(Math.abs(brandBottom - topbarBottom),
    `底邊沒切齊：logo 欄 ${brandBottom} vs 頂端列 ${topbarBottom}`).toBeLessThanOrEqual(1);
});
