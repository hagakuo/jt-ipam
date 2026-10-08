/**
 * 「層數調整」放在機櫃設定視窗裡（以前在頁首，使用者說不該放那裡）。
 *
 * 除了按鈕的位置，還要守一件事：層數調整會在伺服器端改掉層數與逐層高度，
 * 設定視窗若還留著舊值，接著按「儲存」就會把剛做的調整蓋回去 —— 所以做完要看到新的層數。
 * 樣本：seed_e2e 的 ANGLE-90（角鋼 3 層）。做完會復原，不留下改動。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

const levelsInput = (page: Page) =>
  page.locator(".n-modal .n-form-item").filter({ has: page.locator(".n-form-item-label", { hasText: /^層數/ }) })
    .first().locator("input").first();

test("層數調整在設定視窗裡；做完表單就是新的層數，復原也回得去", async ({ page }) => {
  await login(page);
  const racks = await page.evaluate(async () => (await fetch("/api/v1/racks?page_size=500", {
    headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } })).json());
  const id = racks.items.find((r: any) => r.name === "ANGLE-90").id;
  await page.goto(`/racks?rack=${id}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });
  // 頁首不再有這顆按鈕
  await expect(page.locator(".n-card-header, .rack-head").getByRole("button", { name: "層數調整" })).toHaveCount(0);

  const row = page.locator("tr", { hasText: "ANGLE-90" }).first();
  await row.locator("td").last().locator("button").nth(1).click();      // 釘選、編輯、刪除
  const edit = page.locator(".n-modal").first();
  await edit.waitFor();
  await expect(levelsInput(page)).toHaveValue("3");
  await edit.getByRole("button", { name: "層數調整" }).click();

  const ops = page.locator(".n-modal").filter({ hasText: /刪除一層|插入/ }).last();
  await ops.getByText("插入一層").click();
  await ops.locator("input").last().fill("4");                           // 在最上面插入
  await ops.locator("input").last().press("Tab");
  await page.waitForTimeout(600);                                          // 等預覽
  await ops.getByRole("button", { name: /執行|套用/ }).click();
  await expect(levelsInput(page)).toHaveValue("4", { timeout: 10_000 });   // 表單換成新的層數

  await page.locator(".n-modal").first().getByRole("button", { name: /復原/ }).click();
  await expect(levelsInput(page)).toHaveValue("3", { timeout: 10_000 });
});
