/**
 * 掃描一律走代理：沒有指派代理的子網路不會被掃 —— 這件事必須在畫面上講出來。
 *
 * 客戶回報「設定好了但沒有掃」：當時那個選項寫著「本機直接掃（jt-ipam 主機）」，
 * 但後端沒有任何排程會執行本機掃描，前端也沒有觸發入口。畫面看起來設定完成，
 * 實際上永遠不會有結果 —— 沒有任何一種型別檢查或 API 測試看得出這件事。
 */
import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

test("子網路啟用掃描但未指派代理時，要明講不會被掃描", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));

  await page.goto("/subnets");
  await page.locator("tbody tr").first().click();
  const edit = page.getByRole("button", { name: /^編輯$/ });
  await edit.first().click();

  // 掃描代理欄位只在啟用掃描後出現
  const scanToggle = page.locator(".n-form-item", { hasText: "啟用掃描" })
    .locator(".n-checkbox, .n-switch").first();
  await scanToggle.scrollIntoViewIfNeeded();
  if (!(await scanToggle.getAttribute("class"))?.includes("checked")) await scanToggle.click();

  const field = page.locator(".n-form-item", { hasText: "掃描代理" });
  await field.scrollIntoViewIfNeeded();
  // 未指派 → 必須說「不會被掃描」，而不是任由使用者以為設定完成了
  await expect(field).toContainText("不會被掃描");
});
