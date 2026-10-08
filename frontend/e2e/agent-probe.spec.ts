/**
 * 連線診斷的「執行來源」：從 jt-ipam 主機，或指定某個掃描代理在當地執行。
 *
 * 由來：伺服器只看得到自己那一段網路。要驗證客戶站台內部通不通，必須從那個網段裡面打。
 * 代理只由內往外連，所以請求走工作佇列（建立 → 代理長輪詢領取 → 回報 → 前端取回）。
 *
 * 這支只驗 UI 行為（選單、提示、送出後的等待狀態），代理端執行本身由後端測試涵蓋。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";

test.beforeEach(async ({ page }) => {
  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });
  await page.goto(BASE + "/tools");
  // 代理清單是非同步載回來的 —— 不等它就點開下拉，選項裡只會有「伺服器」，
  // 而失敗訊息看起來像「代理選項不見了」。整套跑的時候比單獨跑更容易踩到。
  const agents = page.waitForResponse(
    (r) => r.url().includes("/api/v1/scan-agents") && r.ok(), { timeout: 15000 },
  ).catch(() => null);
  await page.locator(".n-tabs-tab").filter({ hasText: "連線診斷" }).first().click();
  await agents;
});

test("可選擇從伺服器或從掃描代理執行", async ({ page }) => {
  const sel = page.locator(".n-base-selection").first();
  await expect(sel).toBeVisible();

  await sel.click();
  // 用會自動重試的 expect，不要用 allInnerTexts() 一次讀完 —— 下拉面板是非同步掛上去的，
  // 讀太早就只拿到空陣列或只有第一個選項，而失敗訊息會說「沒有掃描代理這個選項」，
  // 看起來像功能壞了。代理一多（e2e 跑久了會累積）就更容易踩到。
  const opt = (text: string) =>
    page.locator(".n-base-select-option").filter({ hasText: text }).first();
  // 預設一定要有「伺服器」這個選項，且是預設值（維持既有行為）
  await expect(opt("伺服器")).toBeVisible();
  await expect(opt("掃描代理")).toBeVisible();

  // 選了代理要明講封包從哪裡送出 —— 使用者若不知道，會誤判測試結果
  await page.locator(".n-base-select-option").filter({ hasText: "掃描代理" }).first().click();
  await expect(page.getByText(/封包會由該掃描代理所在的網段送出/)).toBeVisible();
});

test("指派給代理後顯示等待狀態，不會靜靜卡住", async ({ page }) => {
  // 攔截：建立工作成功，但結果一直是 pending → 驗「等待中」的呈現
  await page.route("**/api/v1/tools/net/agent-probe", (route) =>
    route.fulfill({ contentType: "application/json",
                    body: JSON.stringify({ job_id: "11111111-1111-1111-1111-111111111111",
                                           status: "pending" }) }));
  await page.route("**/api/v1/tools/net/agent-probe/*", (route) =>
    route.fulfill({ contentType: "application/json",
                    body: JSON.stringify({ job_id: "11111111-1111-1111-1111-111111111111",
                                           kind: "ping", status: "running",
                                           result: null, error: null }) }));

  await page.locator(".n-base-selection").first().click();
  await page.locator(".n-base-select-option").filter({ hasText: "掃描代理" }).first().click();

  await page.getByPlaceholder(/一行一個/).first().fill("198.51.100.7");
  await page.getByRole("button", { name: /執行/ }).first().click();

  await expect(page.getByText(/已指派給代理，等待結果/)).toBeVisible({ timeout: 10000 });
});
