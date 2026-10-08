/**
 * 指示計的「未納管」格子（使用者 2026-10-06：就算關閉自動收錄，也要看得出這個 IP 被用、但不是我們納管）。
 * 樣本：seed_e2e 在 10.20.0.0/24 放了兩個沒有 IP 記錄的目擊 —— 10.20.0.240（3 分鐘前、有 MAC）與 10.20.0.241（兩天前）。
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

test("沒有記錄、但看得到在用的位址畫成「未納管」，不是閒置；圖例有數量、滑過看得到誰看到的", async ({ page }) => {
  await login(page);
  const subs = await page.evaluate(async () => {
    const r = await fetch("/api/v1/subnets?page_size=500", {
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } });
    return r.json();
  });
  const sn = subs.items.find((s: any) => s.cidr === "10.20.0.0/24");
  expect(sn, "找不到樣本子網路（先跑 seed_e2e）").toBeTruthy();
  await page.goto(`/subnets/${sn.id}`);
  const grid = page.locator(".subnet-grid");
  await expect(grid).toBeVisible({ timeout: 20_000 });
  const cells = grid.locator('.cell[data-state="unmanaged"]');
  await expect(cells).toHaveCount(2, { timeout: 15_000 });
  // 兩天前的那個畫淡一點
  await expect(grid.locator(".cell-unmanaged-old")).toHaveCount(1);
  await expect(page.getByTestId("grid-legend-unmanaged")).toContainText("(2)");
  await cells.first().hover();
  const tip = page.locator(".jt-cell-tip");
  await expect(tip).toContainText("10.20.0.240");
  await expect(tip).toContainText("未納管");
  await expect(tip).toContainText("掃描代理");
  await expect(tip).toContainText("00:00:5e:00:53:f0");
});

test("IP 清單也列出未納管的位址；點指示計的格子進到這個位址的頁面，右上有探測、新增、返回", async ({ page }) => {
  await login(page);
  const subs = await page.evaluate(async () => {
    const r = await fetch("/api/v1/subnets?page_size=500", {
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } });
    return r.json();
  });
  const sn = subs.items.find((s: any) => s.cidr === "10.20.0.0/24");
  await page.goto(`/subnets/${sn.id}`);
  // 清單：未納管自成一列（不是併進閒置區間），看得到標籤、MAC 與誰看到的
  const row = page.getByTestId("ip-row-unmanaged").filter({ hasText: "10.20.0.240" });
  await expect(row).toBeVisible({ timeout: 20_000 });
  await expect(row).toContainText("未納管");
  await expect(row).toContainText("00:00:5e:00:53:f0");
  await expect(row).toContainText("掃描代理");
  // 指示計的格子 → 位址頁
  await page.locator('.subnet-grid .cell[data-state="unmanaged"]').first().click();
  await expect(page).toHaveURL(new RegExp(`/subnets/${sn.id}/unmanaged/10\\.20\\.0\\.240`));
  await expect(page.getByTestId("um-title")).toContainText("10.20.0.240");
  await expect(page.getByTestId("um-title")).toContainText("未納管");
  await expect(page.getByTestId("um-info")).toContainText("00:00:5e:00:53:f0");
  await expect(page.getByTestId("um-identify")).toBeVisible();
  await page.getByTestId("um-create").click();
  await expect(page.locator(".n-modal")).toBeVisible();
  await expect(page.locator(".n-modal")).toContainText("10.20.0.240");
  await page.keyboard.press("Escape");
  await page.getByTestId("um-back").click();
  await expect(page).toHaveURL(new RegExp(`/subnets/${sn.id}$`));
  // 清單的列也點得進去
  await page.getByTestId("ip-row-unmanaged").filter({ hasText: "10.20.0.241" }).click();
  await expect(page).toHaveURL(/\/unmanaged\/10\.20\.0\.241/);
});
