/**
 * 機櫃圖：裝置名稱要跨**整台**垂直置中，與它占幾 U 無關。
 *
 * 客戶回報：2U 的裝置名稱偏高半格。原因是名稱本來畫在「中間那一格」，
 * 而偶數 U 沒有正中間的一格 —— `Math.floor((len-1)/2)` 會取到上面那一格。
 *
 * 這種問題**只能量幾何**：截圖看起來「差不多置中」，但 1U 正常、2U 偏半格，
 * 肉眼在小圖上分不出來。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
/** 一台在機櫃裡的裝置 id；該機櫃需同時有 1U / 2U / 3U 的裝置（dev-1u / dev-2u / dev-3u，
 *  seed_e2e 放在 RACK-800）。 */
const DEV = process.env.E2E_RACK_DEVICE_ID || "";
test.skip(!ADMIN_PASS || !DEV, "需要 E2E_ADMIN_PASS 與 E2E_RACK_DEVICE_ID");

test("裝置名稱跨整台垂直置中（1U / 2U / 3U 都要對）", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto(`/devices/${DEV}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });

  // 名稱畫在最上面那一格；跨 n 格置中的話，名稱中心要比那一格的中心再往下 (n-1)/2 格
  for (const [name, run] of [["dev-1u", 1], ["dev-2u", 2], ["dev-3u", 3]] as const) {
    const label = page.locator(".d-name", { hasText: name }).first();
    const lb = (await label.boundingBox())!;
    // 量「最上面那一格」（.u-part），不是名稱的直接父層：.d-name-span 本身就撐滿整台的高度，
    // 拿它當基準的話偏移永遠是 0，偏半格也照樣過關
    const rb = (await label.locator("xpath=ancestor::div[contains(@class,'u-part')][1]").boundingBox())!;
    const want = ((run - 1) * rb.height) / 2;
    const got = lb.y + lb.height / 2 - (rb.y + rb.height / 2);
    expect(Math.abs(got - want),
      `${name}（${run}U）的名稱沒有落在整台的中心：應往下 ${want}px，實際 ${got}px`)
      .toBeLessThan(2);
  }
});
