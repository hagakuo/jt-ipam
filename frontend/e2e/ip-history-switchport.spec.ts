/**
 * IP 詳細資料：異動記錄（總數／篩選／分頁）與交換器位置（拆兩欄輸入）。
 *
 * 由來：實機單一 IP 最多 1,838 筆異動記錄且幾乎全是同一種事件，原本只有「載入更多」
 * 且看不出總數；交換器位置則是唯讀顯示 `sw@port`、編輯卻是含 " / " 的單一輸入框，
 * 使用者照著畫面手打會存成錯的格式。
 *
 * 需要先 seed 一筆有大量異動記錄的 IP，id 由 E2E_HIST_IP 傳入。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";
const IP_ID = process.env.E2E_HIST_IP ?? "";

test.beforeEach(async ({ page }) => {
  test.skip(!IP_ID, "需要 E2E_HIST_IP（先 seed 一筆含大量異動記錄的 IP）");
  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });
  await page.goto(BASE + `/addresses/${IP_ID}`);
});

test("異動記錄：標題帶總數、可篩選、可分頁", async ({ page }) => {
  const header = page.locator(".n-collapse-item__header").filter({ hasText: "異動記錄" }).first();
  await header.click();
  // 標題必須帶總數 —— 否則看不出這一頁是全部還是冰山一角
  await expect(header).toContainText(/（\d+）/, { timeout: 10000 });

  const pane = page.locator(".n-collapse-item").filter({ hasText: "異動記錄" }).first();
  const firstPage = await pane.locator(".n-timeline-item").count();
  expect(firstPage).toBeGreaterThan(0);
  expect(firstPage).toBeLessThanOrEqual(50);          // 一頁 50 筆，不會整批塞進 DOM

  // 分頁存在且可翻
  await expect(pane.locator(".n-pagination")).toBeVisible();
  await pane.locator(".n-pagination-item", { hasText: /^2$/ }).first().click();
  await expect(pane.locator(".n-timeline-item").first()).toBeVisible();

  // 兩個篩選下拉（事件類型／來源），選項帶筆數
  await expect(pane.locator(".n-select")).toHaveCount(2);
});

test("交換器位置：編輯拆成交換器與埠兩格，存檔後顯示為 sw@port", async ({ page }) => {
  await page.getByRole("button", { name: /編輯/ }).first().click();
  const sw = page.getByPlaceholder("交換器名稱");
  const port = page.getByPlaceholder(/^埠/);
  await expect(sw).toBeVisible();
  // 既有值要正確拆開（儲存格式是 "sw / port"）
  expect(await sw.inputValue()).not.toContain("/");
  await expect(page.getByText(/LibreNMS 同步維護/)).toBeVisible();

  await port.fill("eth1/0/9");
  await page.getByRole("button", { name: /儲存/ }).click();
  // 唯讀顯示用 @ 串接，代表存回去的是正規格式而不是使用者手打的樣子
  await expect(page.getByText(/@eth1\/0\/9/).first()).toBeVisible({ timeout: 10000 });
});
