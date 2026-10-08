import { test, expect } from "@playwright/test";

/**
 * 「東西壞了卻沒人知道」三類，要能在通知發送設定頁逐項開關。
 *
 * 整合同步失敗、代理失聯、系統檢查未通過 —— 這三類的資料本來就在資料庫裡
 * （last_error / last_seen_at / 系統診斷），只是要有人主動去點才看得到。
 * 接進通知之後，也必須能關掉：不同站台在意的東西不一樣。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("三類健康告警都在通知矩陣裡，而且存得住", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  await page.goto("/notification-channels");
  const table = page.locator("table").first();
  await expect(table).toBeVisible({ timeout: 15_000 });

  // 事件代碼要看得到 —— 使用者要能對照文件與 webhook 的事件名
  for (const ev of ["integration.sync_failed", "agent.offline", "system.health",
                    "dhcp.pool_exhausted", "jump_host.key_changed", "cert.fetch_failed",
                    "audit.chain_broken", "ip.stale",
                    "security.privilege_changed", "security.brute_force"]) {
    await expect(table).toContainText(ev);
  }
  // 以及看得懂的名稱，不是只有代碼
  await expect(table).toContainText("整合同步失敗");
  await expect(table).toContainText("代理失聯");
  await expect(table).toContainText("跳板主機的金鑰改變");
  // 動態組出來的 i18n 鍵（notify_ch.ev.<事件>）靜態檢查掃不到 ——
  // 漏翻時畫面上會直接印出鍵名，只有這裡看得到
  await expect(table).not.toContainText("notify_ch.ev.");

  // 關掉一項並儲存 → 重新載入後仍是關的
  const row = page.locator("tr", { hasText: "integration.sync_failed" });
  const cell = row.locator("td").nth(1);
  await cell.click();
  await page.getByRole("button", { name: /儲存|Save/ }).first().click();
  await page.waitForTimeout(800);
  await page.reload();
  await expect(page.locator("tr", { hasText: "integration.sync_failed" })).toBeVisible();
});
