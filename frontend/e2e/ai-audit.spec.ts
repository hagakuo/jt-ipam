import { test, expect, type Page } from "@playwright/test";

// AI 巡檢：儀表板區塊 → 巡檢頁（含免責說明與依據資料）→ 立即執行 → 忽略。
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test.describe("AI 巡檢", () => {
  test("巡檢頁：發現、免責說明、依據資料、忽略", async ({ page }) => {
    await login(page);
    await page.goto("/ai-audit");

    // 免責說明必須看得到 —— 這些是模型推測，不是查核過的事實
    await expect(page.getByText(/不是查核過的事實/)).toBeVisible();

    const first = page.locator(".fx").first();
    await expect(first).toBeVisible({ timeout: 15_000 });
    // 每筆發現都要帶依據資料，否則使用者無從判斷
    await expect(first.locator(".fx-ev")).toBeVisible();

    const before = await page.locator(".fx").count();
    await first.getByRole("button", { name: "忽略" }).click();
    await expect(page.locator(".fx")).toHaveCount(before - 1, { timeout: 15_000 });

    // 忽略不是刪除：切到「已忽略」要看得到它
    await page.getByText("已忽略", { exact: true }).click();
    await expect(page.locator(".fx").first()).toBeVisible({ timeout: 15_000 });
  });

  test("依據資料的 IP 可以點過去查證", async ({ page }) => {
    await login(page);
    await page.goto("/ai-audit");
    // 查證要能一鍵翻到那筆紀錄 —— 附了依據卻不能點，等於還是叫人自己去搜尋
    const ip = page.locator(".fx .fx-ip").first();
    await expect(ip).toBeVisible({ timeout: 15_000 });
    const text = (await ip.textContent())!.trim();
    await ip.click();
    await expect(page).toHaveURL(new RegExp(`/addresses\\?q=${text.replace(/\./g, "\\.")}`));
  });

  test("儀表板區塊：數字可點、進到巡檢頁", async ({ page }) => {
    await login(page);
    await page.goto("/");
    const card = page.locator(".dash-ai");
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.getByText(/AI 推測/)).toBeVisible();
    await card.locator(".ai-cell").first().click();
    await expect(page).toHaveURL(/\/ai-audit/);
  });

  test("LLM 設定頁有巡檢排程", async ({ page }) => {
    await login(page);
    await page.goto("/llm");
    await expect(page.getByText("AI 巡檢排程")).toBeVisible({ timeout: 15_000 });
    // 排程是「每天幾點幾分」，不是間隔；範圍與模型也要在同一張卡片上
    await expect(page.getByText("排程時間")).toBeVisible();
    await expect(page.getByText("巡檢範圍（子網路）")).toBeVisible();
    await expect(page.getByText("巡檢使用的模型")).toBeVisible();
  });
});
