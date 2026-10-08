/**
 * Wazuh／OCS 頁的「未裝 Agent 的 IP」點進頁籤才抓（2026-09-30 大量資料測試：5 萬筆缺口、
 * 回應四十幾 MB，以前一打開頁面就全抓，光載入就 10～17 秒）。Wazuh 的完整代理清單也是，
 * 但頁籤上的台數要一打開就看得到（只取一筆拿總數）。
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

for (const [path, agentsRe] of [["/wazuh", /代理/], ["/ocs", /代理數/]] as const) {
  test(`${path}：缺口清單點進頁籤才抓`, async ({ page }) => {
    await login(page);
    const hits: string[] = [];
    page.on("request", (r) => { if (/missing-agents|wazuh\/agents\?.*limit=500/.test(r.url())) hits.push(r.url()); });
    await page.goto(path);
    await expect(page.locator(".n-tabs-tab", { hasText: agentsRe }).first()).toHaveText(/\(\d+\)/, { timeout: 20_000 });
    await page.waitForLoadState("networkidle");
    expect(hits, "一打開頁面就抓了缺口清單或完整代理清單").toEqual([]);
    const got = page.waitForRequest((r) => r.url().includes("missing-agents"));
    await page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ }).click();
    await got;
  });
}
