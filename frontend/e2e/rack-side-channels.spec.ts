/**
 * 機櫃兩側的走線空間：從立柱的孔位中心線（EIA-310 左右孔距 465.1mm）量到外緣，
 * 600mm 各約 67mm、800mm 各約 167mm。畫面要畫出來，而且設備區不能跟著外寬放大
 * （以前 800mm 的機櫃把設備畫成 1.66 倍寬）。
 * 樣本：seed_e2e 的 RACK-01（沒填寬度＝600）與 RACK-800。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

test("800mm 機櫃外框比 600mm 寬、寬在兩側，設備區一樣寬", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/racks");
  await page.waitForTimeout(800);
  await page.locator(".n-base-selection").first().click();
  await page.locator(".n-base-select-option").first().click();
  await page.locator(".rack-row .rack-frame").first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);

  async function measure(name: string) {
    const card = page.locator(".rack-row > *").filter({ hasText: new RegExp(`${name}（|${name} \\(`) }).first();
    const frame = card.locator(".rack-frame").first();
    const row = frame.locator(".u-row").first();
    const f = (await frame.boundingBox())!;
    const r = (await row.boundingBox())!;
    return { frame: f.width, area: r.width, leftGap: r.x - f.x, rightGap: f.x + f.width - (r.x + r.width) };
  }
  const a = await measure("RACK-01");
  const b = await measure("RACK-800");
  expect(Math.abs(a.area - b.area), `設備區寬 ${a.area} vs ${b.area}`).toBeLessThan(1);
  // 兩側各多 (800-600)/2 = 100mm → 100 × 250/482.6 ≈ 51.8px，外框共多約 103.6px
  expect(b.frame - a.frame).toBeGreaterThan(95);
  expect(b.frame - a.frame).toBeLessThan(112);
  expect(Math.abs(b.leftGap - b.rightGap), "兩側走線空間要對稱").toBeLessThan(1);
  // 從孔位中心線（左右孔距 465.1mm）量到外緣：(600 − 465.1) ÷ 2 ≈ 67mm ≈ 35px，再加上導軌
  expect(a.leftGap, "600mm 也有走線空間，不是一條細縫").toBeGreaterThan(40);
});
