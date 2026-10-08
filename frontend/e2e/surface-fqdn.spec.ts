/**
 * 對外開放服務：IP／FQDN 兩個視角。
 *
 * FQDN 視角的重點是「人記得的是名字不是位址」——同一個 IP 的 A 記錄與 CNAME 別名
 * 都要各自成列，且 IP 仍是可點進詳細資料的連結。另驗異常偵測頁的 ?tab= 深連結
 * （通知點進來要落在對應分類）與統計卡可點切換。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";

async function login(page: any) {
  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });
}

test("對外開放服務：FQDN 視角列出名稱並連回 IP", async ({ page }) => {
  await login(page);
  await page.goto(BASE + "/attack-surface");

  // 預設是 IP 視角
  await expect(page.getByText(/^以 IP 檢視 \(/)).toBeVisible();
  await expect(page.locator("thead").first()).toContainText("IP");

  await page.getByText(/^以 FQDN 檢視 \(/).click();
  const head = page.locator("thead").first();
  await expect(head).toContainText("FQDN");
  await expect(head).toContainText("對外開放的埠");

  // A 記錄與 CNAME 別名各一列，都指到同一個位址
  await expect(page.getByText("web.example.net")).toBeVisible();
  await expect(page.getByText("meet.example.net")).toBeVisible();
  expect(await page.getByText("198.51.100.7").count()).toBeGreaterThan(1);

  // IP 是連結：點下去進到該 IP 的詳細資料頁
  await page.getByText("198.51.100.7").first().click();
  await expect(page).toHaveURL(/\/addresses\//, { timeout: 10000 });
});

test("異常偵測：?tab= 深連結落在對應分類，統計卡可點", async ({ page }) => {
  await login(page);
  await page.goto(BASE + "/anomaly?tab=dangling_dns");
  await page.getByRole("button", { name: /執行偵測/ }).click();
  await expect(page.locator(".n-tabs-tab--active")).toContainText("失效 DNS 記錄", {
    timeout: 20000,
  });

  // 統計卡有外框，點了會切到該分類
  const card = page.locator(".anom-stat").first();
  await expect(card).toBeVisible();
  await card.click();
  await expect(page.locator(".n-tabs-tab--active")).toContainText("IP 衝突");
});
