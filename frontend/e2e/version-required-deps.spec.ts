/**
 * 版本資訊的「必要相依」卡片（0.6.49 實機回報）：
 *   guacd 的版本字串很長（「1.6.1-pre.d9ec474 (build 3) for Ubuntu 24.04.4 LTS (amd64)」），
 *   整串放在卡片右邊時把名稱欄擠成一行一個字。改成右邊只放狀態、版本放名稱下面。
 * 用真實站台的那一串覆寫 API 回應來量，開發機的 guacd 不是打包版、沒有版本字串。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

const LONG = "1.6.1-pre.d9ec474 (build 3) for Ubuntu 24.04.4 LTS (amd64)";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username|ユーザー名/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password|パスワード/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /^(登入|Sign in|サインイン)$/ }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

for (const width of [1440, 390]) {
  test(`必要相依的卡片不會被長版本字串擠扁（寬 ${width}）`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route("**/api/v1/system/version", async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      body.host.required_tools = { guacd: {
        present: true, running: true, version: LONG, package: "jt-ipam-guacd",
        used_by: "RDP / VNC console (default engine); SSH when selected", protocols: {}, address: "127.0.0.1:4822", error: "" } };
      await route.fulfill({ response: res, json: body });
    });
    await login(page);
    await page.goto("/version");
    const card = page.locator(".ver-pkg", { hasText: "guacd" }).first();
    await expect(card).toContainText("1.6.1-pre.d9ec474 (build 3)", { timeout: 15_000 });
    await expect(card).not.toContainText("for Ubuntu");
    await expect(card).toContainText(/執行中|Running|動作中/);
    const name = (await card.locator(".ver-pkg__name").boundingBox())!;
    expect(name.width, "名稱欄被擠扁").toBeGreaterThan(120);
    expect(name.height, "名稱欄被擠成一行一個字（壞掉時約 700px 高）").toBeLessThan(160);
  });
}
