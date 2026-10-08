/**
 * 異常偵測 → 未授權 IP 的 AI 判讀：欄位標題「操作」（不與按鈕同名）、
 * 背景執行＋檢視結果、markdown 渲染（無裸 **）、模型標示、下載報告。
 * scan 與 triage 端點都攔截 —— 驗 UI 行為，不驗後端與 LLM。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";

const EMPTY: Record<string, any[]> = {
  ip_conflicts: [], mac_drifts: [], ghost_ips: [], rogue_dhcp: [],
  external_exposure: [], dangling_dns: [], duplicate_ip_records: [],
  suspicious_changes: [], fw_rule_rot: [],
};

test("異常偵測 AI 判讀流程", async ({ page }) => {
  await page.route("**/api/v1/anomalies/scan", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({
      ...EMPTY, unauthorized_ips: [{ ip: "203.0.113.50" }] }) }));
  await page.route("**/api/v1/anomalies/triage", async (route) => {
    await new Promise((r) => setTimeout(r, 1200));
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({
      ip: "203.0.113.50",
      card: "1. **設備類型**：無法判斷（缺 `hostname`）。\n\n2. **風險評估**：中高。",
      disclaimer: "此為語言模型依觀測證據所做的推測",
      model: "gemma4:26b" }) });
  });

  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });
  await page.goto(BASE + "/anomaly");

  await page.getByRole("button", { name: /執行偵測/ }).click();
  await page.getByText(/未授權 IP \(1\)/).click();
  await expect(page.getByText("203.0.113.50").first()).toBeVisible();

  // 欄位標題是「操作」，不得再叫 AI 判讀（與按鈕同名像貼錯）
  const thead = page.locator(".n-tab-pane thead").first();
  await expect(thead).toContainText("操作");
  expect(await thead.innerText()).not.toContain("AI 判讀");

  // 按鈕帶 icon；按下背景跑（不彈窗），完成後長出「檢視結果」
  const aiBtn = page.getByRole("button", { name: "AI 判讀" }).first();
  expect(await aiBtn.locator("svg").count()).toBeGreaterThan(0);
  await aiBtn.click();
  await expect(page.locator(".n-modal-container .n-card")).toHaveCount(0);
  const viewBtn = page.getByRole("button", { name: "檢視結果" }).first();
  await expect(viewBtn).toBeVisible({ timeout: 10000 });

  // 檢視：markdown 渲染（有 strong/code、無裸 **）＋模型標示
  await viewBtn.click();
  const modal = page.locator(".n-modal-container");
  await expect(modal.locator(".triage-body strong").first()).toBeVisible();
  expect(await modal.locator(".triage-body code").count()).toBeGreaterThan(0);
  expect(await modal.locator(".triage-body").innerText()).not.toContain("**");
  await expect(modal.getByText(/模型：gemma4:26b/)).toBeVisible();

  // 下載 .md：檔名與內容（含模型與原始 markdown）
  const [dl] = await Promise.all([
    page.waitForEvent("download"),
    modal.getByRole("button", { name: "下載 .md" }).click(),
  ]);
  expect(dl.suggestedFilename()).toBe("ip-triage-203.0.113.50.md");
  const fs = await import("node:fs/promises");
  const text = await fs.readFile((await dl.path())!, "utf-8");
  expect(text).toContain("**設備類型**");
  expect(text).toContain("gemma4:26b");
});
