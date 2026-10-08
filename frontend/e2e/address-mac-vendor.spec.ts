/**
 * IP 清單的 MAC 欄要看得到 OUI 廠商（GitHub issue #38）。
 * 以前只有詳細頁有，清單上一眼看不出是哪家的設備。樣本：seed_e2e 的 db-01
 * （10.20.0.12，MAC 在 RFC 7042 文件保留範圍，OUI 00005E 登記給 IANA）。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

test("IP 清單的 MAC 欄顯示廠商，而且不撐寬欄位", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/addresses?q=10.20.0.12");
  const cell = page.locator(".mac-cell", { hasText: "00:00:5e:00:53:12" }).first();
  await expect(cell).toBeVisible({ timeout: 20_000 });
  await expect(cell.locator(".mac-cell__vendor")).toContainText(/IANA/);
  // 廠商在第二行：MAC 與廠商上下排列，不是同一行擠寬
  const m = (await cell.locator(".mac-cell__mac").boundingBox())!;
  const v = (await cell.locator(".mac-cell__vendor").boundingBox())!;
  expect(v.y).toBeGreaterThanOrEqual(m.y + m.height - 1);
});
