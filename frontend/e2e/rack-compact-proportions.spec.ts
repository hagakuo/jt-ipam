/**
 * 裝置頁的機櫃縮圖要跟機櫃頁**同一個比例**。
 *
 * 客戶回報「側架的比例怪怪的」：縮圖模式以前只把**列高**壓扁，寬度、層板厚度、立柱寬、
 * 調整孔間距全都留在原尺寸 —— 層板變成很粗的橫條、一層只剩一個孔。量長寬比就看得出來
 * （當時是 1.45 對 3.94），截圖用看的只會覺得「好像有點怪」。
 *
 * 另一項：頂板**上面**那一列沒有層板也沒有導軌，橫向分隔線在那裡沒有東西可以分，
 * 而且那一列比放上去的裝置高，線會一路畫到半空中。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const RACK = process.env.E2E_SHELF_RACK_ID || "";
const DEV = process.env.E2E_SHELF_DEVICE_ID || "";
test.skip(!ADMIN_PASS || !RACK || !DEV,
  "需要 E2E_ADMIN_PASS / E2E_SHELF_RACK_ID / E2E_SHELF_DEVICE_ID");

async function login(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function frameRatio(page: any, url: string): Promise<number> {
  await page.goto(url);
  const f = page.locator(".rack-frame").first();
  await f.waitFor({ timeout: 20_000 });
  await page.waitForTimeout(300);          // 等 ResizeObserver 量完自然尺寸
  const b = (await f.boundingBox())!;
  return b.height / b.width;
}

test("縮圖與完整檢視是同一個長寬比（縮圖只能等比縮，不能只壓高度）", async ({ page }) => {
  await login(page);
  const full = await frameRatio(page, `/racks?rack=${RACK}`);
  const thumb = await frameRatio(page, `/devices/${DEV}`);
  expect(full).toBeGreaterThan(2);         // 這台層架本來就是高瘦的，量錯就不會有這個值
  expect(Math.abs(thumb - full), `縮圖 ${thumb.toFixed(2)} vs 完整 ${full.toFixed(2)}`)
    .toBeLessThan(0.15);
});

test("頂板上方那一列不畫橫向分隔線", async ({ page }) => {
  await login(page);
  await page.goto(`/racks?rack=${RACK}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });
  const top = page.locator(".u-row.is-top").first();
  await expect(top).toBeVisible();
  const styles = await top.locator(".u-part").evaluateAll(
    (els: Element[]) => els.map((e) => getComputedStyle(e).borderLeftStyle));
  expect(styles.length).toBeGreaterThan(1);       // 至少要有兩塊才分得出有沒有線
  // 分隔線是**虛線**；裝置自己的外框是實線，不能一起算進來
  expect(styles.every((v) => v !== "dashed"), `頂列的分隔線：${styles.join(",")}`).toBe(true);
});

test("裝置頁的縮圖就是縮圖：沒有工具列，點下去帶到機櫃頁", async ({ page }) => {
  await login(page);
  await page.goto(`/devices/${DEV}`);
  await page.locator(".dev-head-rack .rack-frame").waitFor({ timeout: 20_000 });
  // 正面／背面、縮放、匯出都留在機櫃頁 —— 縮圖上不該有工具列
  await expect(page.locator(".dev-head-rack .rd-toolbar")).toHaveCount(0);

  await page.locator(".dev-head-rack").click({ position: { x: 5, y: 5 } });
  await page.waitForURL(/\/racks\?rack=/, { timeout: 10_000 });
  // 少了 rack 這個 query 會停在「上次看的那一櫃」，看起來像點錯了
  expect(new URL(page.url()).searchParams.get("rack")).toBe(RACK);
});
