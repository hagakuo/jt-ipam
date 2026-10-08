/**
 * IP 詳細資料頁「主機名稱來源」與 FDB 標籤：**直接開網址**（fresh load）也要出現。
 *
 * 回報：從清單開彈窗看得到、直接開網址／重新整理就消失 —— 觸發載入的 watch
 * 沒有 immediate，inline 模式下 show/id 從掛載起就定值，watch 永遠不觸發。
 * hostname-sources 與 switch-port 端點以路由攔截固定回應；IP 本體是真資料。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";
const IP_ID = process.env.E2E_IP_ID ?? "";

test("IP 詳細資料直接載入也顯示主機名稱來源與 FDB", async ({ page }) => {
  test.skip(!IP_ID, "需要 E2E_IP_ID（先在 test DB seed 一筆 IP）");

  await page.route("**/api/v1/addresses/*/hostname-sources", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({
      effective: "e2e-host", pin: null, order: ["manual", "scanner"],
      observations: [
        { source: "manual", hostname: "e2e-host", observed_at: "2026-08-17T00:00:00Z" },
        { source: "scanner", hostname: "e2e-host.example", observed_at: "2026-08-17T00:00:00Z" },
      ] }) }));
  await page.route("**/api/v1/addresses/*/switch-port", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({
      ip: "198.51.100.77", mac: null, locations: [],
      likely_access_port: { switch: "sw-e2e", port: "eth1/0/9" } }) }));

  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });

  // 關鍵：直接 goto 詳細資料頁（不經清單），模擬重新整理／貼網址
  await page.goto(BASE + `/addresses/${IP_ID}`);
  await expect(page.getByText("198.51.100.77").first()).toBeVisible({ timeout: 15000 });

  await expect(page.getByText("主機名稱來源")).toBeVisible();
  await expect(page.getByText(/scanner|掃描代理/).first()).toBeVisible();
  await expect(page.getByText(/FDB/).first()).toBeVisible();
});
