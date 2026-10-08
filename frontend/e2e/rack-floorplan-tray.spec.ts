/**
 * 平面圖編輯模式的「未擺放機櫃」托盤要在平面圖**上方**。
 *
 * 以前它在平面圖最下面、灰色虛線小按鈕 —— 平面圖一高，托盤就在捲軸外，使用者只會覺得
 * 「平面圖少了一台」，根本不知道還有機櫃等著被放上去。用量的：托盤底邊要在平面圖頂邊之上。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

// 1x1 PNG，平面圖只要是張圖就好
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

// 淺色主題下文字對比要夠（琥珀字配淺琥珀底很容易只剩 2:1）
function lum(rgb: string) {
  const [r, g, b] = rgb.match(/\d+(\.\d+)?/g)!.slice(0, 3).map(Number).map((v) => {
    v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

for (const theme of ["light", "dark"] as const) test(`未擺放托盤在平面圖上方、並顯示數量（${theme}）`, async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  // 主題以後端偏好為準（登入後 hydrate 會蓋掉 localStorage）→ 用右上角選單切，並確認生效
  await page.getByText(/^(淺色|深色|跟隨系統)$/).first().click();
  await page.locator(".n-dropdown-option").filter({ hasText: theme === "light" ? "淺色" : "深色" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  await page.goto("/racks");
  await page.waitForTimeout(600);
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  await page.locator(".n-base-selection").first().click();       // 選機房
  await page.locator(".n-base-select-option").first().click();

  // 上傳平面圖 → 元件會自動進入編輯模式
  await page.locator('input[type="file"]').first().setInputFiles(
    { name: "plan.png", mimeType: "image/png", buffer: PNG });

  const tray = page.locator(".tray");
  await expect(tray).toBeVisible({ timeout: 20_000 });
  await expect(tray.locator(".tray-label")).toContainText(/未擺放機櫃（\d+）：/);

  const plan = page.locator(".plan");
  await expect(plan).toBeVisible();
  const t = (await tray.boundingBox())!;
  const p = (await plan.boundingBox())!;
  expect(t.y + t.height, `托盤底 ${t.y + t.height} / 平面圖頂 ${p.y}`).toBeLessThanOrEqual(p.y);

  // 對比：文字色 vs 實際畫出來的托盤底色（半透明疊在卡片上 → 用畫面取樣）
  const fg = await tray.locator(".tray-label").evaluate((e) => getComputedStyle(e).color);
  await page.screenshot({ path: `test-results/rack-floorplan-tray-${theme}.png`, fullPage: false });
  const shot = await page.screenshot({ clip: { x: t.x + t.width - 12, y: t.y + t.height / 2, width: 1, height: 1 } });
  const px = await page.evaluate(async (b64) => {
    const img = new Image(); img.src = `data:image/png;base64,${b64}`; await img.decode();
    const c = document.createElement("canvas"); c.width = c.height = 1;
    const x = c.getContext("2d")!; x.drawImage(img, 0, 0); const d = x.getImageData(0, 0, 1, 1).data;
    return `rgb(${d[0]},${d[1]},${d[2]})`;
  }, shot.toString("base64"));
  const [a, b] = [lum(fg), lum(px)].sort((m, n) => n - m);
  const ratio = (a + 0.05) / (b + 0.05);
  expect(ratio, `文字 ${fg} / 底 ${px}`).toBeGreaterThanOrEqual(4.5);

  // 收尾：移除底圖，別影響其他 spec
  await page.getByRole("button", { name: /取消/ }).first().click();
  await page.getByRole("button", { name: /移除底圖/ }).click();
  await page.locator(".n-popconfirm__action .n-button--primary-type").click();
  await expect(page.locator(".plan")).toHaveCount(0);
});
