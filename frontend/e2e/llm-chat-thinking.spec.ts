/**
 * AI 對話可以關閉思考（2026-10-01 使用者決定「可設定」）：預設開（以前的行為），
 * 關掉之後存起來、重新載入還是關的。實際送給模型的參數由後端測試驗（test_chat_thinking_setting.py）。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("設定頁：AI 對話的思考開關預設開、關掉會存起來", async ({ page }) => {
  await login(page);
  await page.goto("/llm");
  const box = page.getByTestId("chat-thinking");
  await expect(box).toContainText("AI 對話允許模型先思考");
  await expect(box).toContainText("AI 巡檢與 AI 判讀一律關閉思考");
  const sw = box.locator(".n-switch");
  await expect(sw).toHaveClass(/n-switch--active/);

  const patched = page.waitForResponse(
    (r) => r.url().includes("/api/v1/system/llm") && r.request().method() === "PATCH");
  await sw.click();
  const resp = await patched;
  expect(resp.request().postDataJSON()).toEqual({ chat_thinking: false });
  expect((await resp.json()).chat_thinking).toBe(false);

  await page.reload();
  await expect(page.getByTestId("chat-thinking").locator(".n-switch")).not.toHaveClass(/n-switch--active/);

  // 還原成預設（其他測試不受影響）
  const back = page.waitForResponse(
    (r) => r.url().includes("/api/v1/system/llm") && r.request().method() === "PATCH");
  await page.getByTestId("chat-thinking").locator(".n-switch").click();
  expect((await (await back).json()).chat_thinking).toBe(true);
});

test("思考檢查：逐個模型列出有沒有照「關閉思考」做，沒照做時附排除方法", async ({ page }) => {
  await login(page);
  await page.route("**/api/v1/ai/thinking-check", (r) => r.fulfill({ json: { results: [
    { role: "chat", model: "gemma4:26b", ok: true, thinking: false, reasoning_chars: 0, think_tag: false,
      empty_answer: false, answer: "OK", seconds: 0.5, rejected_params: ["thinking_budget_tokens"], error: null },
    { role: "audit", model: "audit:14b", ok: true, thinking: true, reasoning_chars: 0, think_tag: false,
      empty_answer: true, answer: "", seconds: 3.1, rejected_params: [], error: null },
    { role: "interpret", model: "judge:32b", ok: false, thinking: null, reasoning_chars: 0, think_tag: false,
      empty_answer: false, answer: "", seconds: 0, rejected_params: [], error: "transport: ConnectError: refused" },
  ] } }));
  await page.goto("/llm");
  await page.getByTestId("think-check").click();
  const box = page.getByTestId("think-results");
  await expect(box).toContainText("對話模型 gemma4:26b：有照「關閉思考」做，0.5 秒回答");
  await expect(box).toContainText("伺服器不收：thinking_budget_tokens（已自動拿掉）");
  await expect(box).toContainText("巡檢模型 audit:14b：仍在先思考（回答是空的，思考內容可能被閘道藏起來，3.1 秒）");
  await expect(box).toContainText("判讀模型 judge:32b：檢查失敗 —— transport: ConnectError: refused");
  await expect(box).toContainText("ollama_chat/");               // 有模型沒照做 → 排除方法
});
