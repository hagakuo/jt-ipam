import { test, expect } from "@playwright/test";
// 與其他 spec 一致：帳號有預設值，沒給密碼就跳過 —— 否則會 fill(undefined)，
// 錯在「expected string, got undefined」，看起來跟登入毫無關係
const U = process.env.E2E_ADMIN_USER || "admin";
const P = process.env.E2E_ADMIN_PASS || "";
test.skip(!P, "需要 E2E_ADMIN_PASS");
test("AI 巡檢：日期與忽略按鈕不可重疊", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(U);
  await page.getByPlaceholder(/密碼|Password/).fill(P);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));
  await page.goto("/ai-audit");
  await expect(page.locator(".fx-date").first()).toBeVisible();
  // 幾何比對：日期的右緣不可以越過動作按鈕的左緣
  const d = await page.locator(".fx-date").first().boundingBox();
  const b = await page.locator(".fx .n-button").first().boundingBox();
  expect(d && b, "抓不到元素").toBeTruthy();
  expect(d!.x + d!.width, `日期右緣 ${d!.x + d!.width} 蓋到按鈕左緣 ${b!.x}`)
    .toBeLessThanOrEqual(b!.x + 1);
  await page.screenshot({ path: "test-results/overlap-check.png" });
});
