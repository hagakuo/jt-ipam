import { test, expect } from "@playwright/test";

/**
 * 版本資訊頁要講出授權條款。
 *
 * 這是 AGPL 專案 —— 散佈與修改的義務跟著授權走，使用者不該為了知道自己在用什麼
 * 授權而跑去翻原始碼。字串由後端給（與 pyproject / package.json / LICENSE 綁在一起，
 * 見 backend/tests/test_license_declaration.py），這裡驗的是「畫面上真的看得到」。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("版本資訊頁顯示授權條款，且連得到授權全文", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  await page.goto("/version");
  const tile = page.locator(".ver-tile", { hasText: "授權條款" });
  await expect(tile).toBeVisible({ timeout: 15_000 });
  // 值要是實際的 SPDX 識別字，不是空白或 "—"
  await expect(tile).toContainText("AGPL-3.0-or-later");

  const link = tile.getByRole("link", { name: "檢視授權全文" });
  await expect(link).toHaveAttribute("href", /github\.com\/.+\/LICENSE$/);
  // 對外連結一律另開分頁，且要有 noopener
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link).toHaveAttribute("rel", /noopener/);

  // 版面：授權字串比版本號長，不可以撐破格子，也不可以被折成兩行
  // （實際踩過：「AGPL-3.0-or-」＋「later」，看起來像壞掉）
  const box = (await tile.boundingBox())!;
  const valueLoc = tile.locator(".ver-tile__value");
  const value = (await valueLoc.boundingBox())!;
  expect(value.x + value.width, "授權字串溢出卡片").toBeLessThanOrEqual(box.x + box.width + 1);
  const lines = await valueLoc.evaluate((el) => {
    const cs = getComputedStyle(el);
    const lh = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.4;
    return el.getBoundingClientRect().height / lh;
  });
  expect(lines, "授權字串被折行了").toBeLessThan(1.6);

  await page.screenshot({ path: "test-results/version-license.png", fullPage: false });
});
