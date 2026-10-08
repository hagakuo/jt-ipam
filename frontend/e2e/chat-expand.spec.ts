/**
 * AI 對話面板的放大切換：X 右邊有「放大視窗」鈕，按下往左、往上擴到約 2/3 畫面，
 * 再按一次還原原本大小。純 UI 幾何驗證，不打 AI 端點（不碰 Ollama）。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";

test("AI 對話放大／還原切換", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  // 浮動按鈕只在 me.ai_enabled 時掛載；測試環境沒開 LLM → 攔截 /me 補旗標
  await page.route("**/api/v1/auth/me", async (route) => {
    const resp = await route.fetch();
    const body = await resp.json();
    body.ai_enabled = true;
    await route.fulfill({ response: resp, body: JSON.stringify(body) });
  });
  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });

  await page.locator(".chat-fab").click();
  const shell = page.locator(".chat-shell");
  await expect(shell).toBeVisible();
  const before = (await shell.boundingBox())!;
  expect(before.width).toBeLessThanOrEqual(500);

  // 放大：右下角不動，往左與上擴到約 2/3 畫面
  const expandBtn = page.locator(".chat-expand-btn");
  await expect(expandBtn).toHaveAttribute("title", "放大視窗");
  await expandBtn.click();
  const big = (await shell.boundingBox())!;
  expect(big.width).toBeGreaterThanOrEqual(1440 * 0.6);
  expect(big.height).toBeGreaterThanOrEqual(900 * 0.6);
  // 右下角錨定不變（右邊界位置差 < 2px）
  expect(Math.abs(big.x + big.width - (before.x + before.width))).toBeLessThan(2);

  // 還原
  await expect(expandBtn).toHaveAttribute("title", "還原大小");
  await expandBtn.click();
  const after = (await shell.boundingBox())!;
  expect(after.width).toBeLessThanOrEqual(500);
});
