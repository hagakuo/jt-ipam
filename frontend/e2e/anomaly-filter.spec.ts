/**
 * 異常偵測：篩選 IP／主機名稱（使用者要求，2026-09-25）。
 * 同一個關鍵字套用到所有分類，頁籤數字變成「符合／全部」—— 一眼看出某個 IP 出現在哪幾類。
 * scan 端點攔截：驗 UI 行為，不驗偵測本身。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const REPORT = {
  ip_conflicts: [], mac_drifts: [], rogue_dhcp: [], external_exposure: [], dangling_dns: [],
  duplicate_ip_records: [], suspicious_changes: [], fw_rule_rot: [],
  ghost_ips: [
    { ip: "198.51.100.21", hostname: "pc-fin-015" },
    { ip: "198.51.100.22", hostname: "ipam01" },
    { ip: "203.0.113.9", hostname: "dmz-web01" },
  ],
  unauthorized_ips: [{ ip: "198.51.100.22" }],
};

test("篩選套用到所有分類，頁籤顯示符合／全部", async ({ page }) => {
  await page.route("**/api/v1/anomalies/scan", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify(REPORT) }));
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/anomaly");
  await page.getByRole("button", { name: /執行偵測/ }).click();
  await page.locator(".n-tabs-tab", { hasText: /^失聯 IP \(3\)$/ }).click();

  const pane = page.locator(".n-tab-pane:visible");
  await expect(pane.getByPlaceholder(/篩選：IP／主機名稱/)).toBeVisible();
  // 有值之後 Naive UI 會拿掉佔位字元素，之後改用 class 找
  const filter = pane.locator(".cat-filter input");
  await filter.fill("198.51.100.22");
  await expect(page.locator(".n-tabs-tab", { hasText: /^失聯 IP \(1\/3\)$/ })).toBeVisible();
  await expect(page.locator(".n-tabs-tab", { hasText: /^未授權 IP \(1\/1\)$/ })).toBeVisible();
  const rows = pane.locator(".n-data-table-tbody .n-data-table-tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("ipam01");

  // 主機名稱也比得到；切到別的頁籤關鍵字還在
  await filter.fill("dmz");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("203.0.113.9");
  await page.locator(".n-tabs-tab", { hasText: /^未授權 IP/ }).click();
  await expect(page.locator(".n-tabs-tab", { hasText: /^未授權 IP \(0\/1\)$/ })).toBeVisible();
  await expect(page.locator(".n-tab-pane:visible")).toHaveCount(1);   // 頁籤切換有動畫，等它停
  await expect(page.locator(".n-tab-pane:visible .cat-filter input")).toHaveValue("dmz");

  await page.locator(".n-tab-pane:visible .cat-filter input").fill("");
  await expect(page.locator(".n-tabs-tab", { hasText: /^失聯 IP \(3\)$/ })).toBeVisible();
});
