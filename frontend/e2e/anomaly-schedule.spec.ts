import { test, expect } from "@playwright/test";

/**
 * 異常偵測可以排程執行。
 *
 * 偵測邏輯早就寫好了，但原本只能靠人按「執行掃描」—— IP 衝突、非法 DHCP
 * 不會挑上班時間發生。這裡驗設定存得下去、讀得回來，以及「每隔 N 分鐘」
 * 這個給營運監控用的模式真的可選。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("排程設定：開啟、選每隔 N 分鐘、存得住", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  await page.goto("/anomaly");
  await page.getByRole("button", { name: "排程" }).click();
  const dialog = page.locator(".n-modal", { hasText: "異常偵測排程" });
  await expect(dialog).toBeVisible();

  // 預設關閉 —— 排程會發通知給所有管理員，升級不該自己開始發信
  const sw = dialog.locator(".n-switch");
  await expect(sw).not.toHaveClass(/n-switch--active/);

  await sw.click();
  await dialog.locator(".n-base-selection").first().click();
  await page.locator(".n-base-select-option", { hasText: "每隔 N 分鐘" }).first().click();

  // 間隔輸入框出現，且下限是 5（背景排程本身約 5 分鐘一輪）
  const num = dialog.locator(".n-input-number input").first();
  await expect(num).toBeVisible();
  await num.fill("15");
  await num.press("Enter");
  await page.waitForTimeout(600);

  // 存得住：關掉重開仍是同一組設定（讀回來的是伺服器的值，不是畫面殘留）
  await dialog.getByRole("button", { name: /關閉|Close/ }).click();
  await page.getByRole("button", { name: "排程" }).click();
  const again = page.locator(".n-modal", { hasText: "異常偵測排程" });
  await expect(again.locator(".n-switch")).toHaveClass(/n-switch--active/);
  await expect(again.locator(".n-input-number input").first()).toHaveValue("15");

  // 收尾：把排程關掉，別讓測試環境留著會發通知的設定
  await again.locator(".n-switch").click();
  await page.waitForTimeout(400);
});
