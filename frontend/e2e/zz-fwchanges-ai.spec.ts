/**
 * 防火牆規則異動：認可／AI 解讀按鈕要有 icon；AI 解讀背景執行，
 * 完成後長出「檢視結果」鈕；結果視窗要渲染 markdown（不能露出裸 **）。
 * AI 端點以路由攔截回假 markdown —— 這裡驗的是 UI 流程，不是 LLM。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";

test("fw-rule-changes AI 解讀流程", async ({ page }) => {
  // 攔 AI 端點：延遲 1.5s 模擬長作業，回 markdown
  await page.route("**/api/v1/anomalies/fw-rule-changes/*/analyze", async (route) => {
    await new Promise((r) => setTimeout(r, 1500));
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        card: "**1. 這次異動做了什麼**\n\n新增規則允許 `8443` 連往 **內部主機**。\n\n- 風險等級：低",
        disclaimer: "此為語言模型推測",
        model: "gemma4:26b",
      }),
    });
  });

  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });

  await page.goto(BASE + "/fw-rule-changes");
  await expect(page.getByText("router-e2e").first()).toBeVisible({ timeout: 15000 });

  // 欄位標題是「操作」，不得與按鈕同名（認可／AI 解讀 各出現兩次會像貼錯）
  const thead = page.locator("thead").first();
  await expect(thead).toContainText("操作");
  expect(await thead.innerText()).not.toContain("認可");
  expect(await thead.innerText()).not.toContain("AI 解讀");

  // 欄寬：操作欄夠放按鈕就好，多餘寬度優先給異動內容（量幾何、不要用看的）
  const thCells = page.locator("thead th");
  const widths: Record<string, number> = {};
  for (let i = 0; i < await thCells.count(); i++) {
    const txt = (await thCells.nth(i).innerText()).trim();
    widths[txt] = (await thCells.nth(i).boundingBox())?.width ?? 0;
  }
  expect(widths["操作"]).toBeLessThanOrEqual(200);
  const widest = Math.max(...Object.values(widths));
  expect(widths["異動內容"]).toBe(widest);

  // 非 baseline 那列要有帶 icon 的認可與 AI 解讀按鈕
  const ackBtn = page.getByRole("button", { name: "認可" }).first();
  const aiBtn = page.getByRole("button", { name: "AI 解讀" }).first();
  await expect(ackBtn).toBeVisible();
  await expect(aiBtn).toBeVisible();
  expect(await ackBtn.locator("svg").count()).toBeGreaterThan(0);
  expect(await aiBtn.locator("svg").count()).toBeGreaterThan(0);

  // 按下 AI 解讀：檢視結果鈕尚不存在 → 完成後長出來（背景執行、不彈視窗）
  await expect(page.getByRole("button", { name: "檢視結果" })).toHaveCount(0);
  await aiBtn.click();
  // 執行中不應直接開結果視窗
  await expect(page.locator(".n-modal-container .n-card")).toHaveCount(0);
  const viewBtn = page.getByRole("button", { name: "檢視結果" }).first();
  await expect(viewBtn).toBeVisible({ timeout: 10000 });
  expect(await viewBtn.locator("svg").count()).toBeGreaterThan(0);

  // 檢視結果：markdown 要渲染成 <strong>／<code>，畫面上不得出現裸 **
  await viewBtn.click();
  const modal = page.locator(".n-modal-container");
  await expect(modal.getByText("此為語言模型推測")).toBeVisible();
  await expect(modal.locator(".fwai-body strong").first()).toBeVisible();
  expect(await modal.locator(".fwai-body code").count()).toBeGreaterThan(0);
  const bodyText = await modal.locator(".fwai-body").innerText();
  expect(bodyText).not.toContain("**");

  // 模型標示與下載報告（.md 保留 markdown；.txt 純文字無 ** 標記）
  await expect(modal.getByText(/模型：gemma4:26b/)).toBeVisible();
  const [dlMd] = await Promise.all([
    page.waitForEvent("download"),
    modal.getByRole("button", { name: "下載 .md" }).click(),
  ]);
  expect(dlMd.suggestedFilename()).toMatch(/^fw-change-ai-.*\.md$/);
  const fs = await import("node:fs/promises");
  const mdText = await fs.readFile((await dlMd.path())!, "utf-8");
  expect(mdText).toContain("**內部主機**");
  expect(mdText).toContain("gemma4:26b");
  const [dlTxt] = await Promise.all([
    page.waitForEvent("download"),
    modal.getByRole("button", { name: "下載 .txt" }).click(),
  ]);
  expect(dlTxt.suggestedFilename()).toMatch(/\.txt$/);
  const txtText = await fs.readFile((await dlTxt.path())!, "utf-8");
  expect(txtText).toContain("內部主機");
  expect(txtText).not.toContain("**");
});
