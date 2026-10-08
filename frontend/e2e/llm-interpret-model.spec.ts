/**
 * AI 判讀可以獨立指定模型（2026-09-30）：未授權 IP 判讀、IP 調查、防火牆規則異動解讀三者共用。
 * 留空＝沿用對話模型；判讀結果上標出實際使用的模型。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const MODELS = {
  models: ["gemma4:26b", "judge-model:32b", "nomic-embed-text:latest"].map((name) => ({
    name, size: null, modified_at: null, family: null, parameter_size: null,
  })),
};

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("設定頁：選判讀模型會存起來、重新載入還在；嵌入模型不可選", async ({ page }) => {
  await login(page);
  await page.route("**/api/v1/system/llm/models", (r) => r.fulfill({ json: MODELS }));
  await page.goto("/llm");
  const card = page.getByTestId("interpret-card");
  await expect(card).toBeVisible();

  const patched = page.waitForResponse(
    (r) => r.url().includes("/api/v1/system/llm") && r.request().method() === "PATCH");
  await page.getByTestId("interpret-model").click();
  await page.locator(".n-base-select-option", { hasText: "judge-model:32b" }).click();
  const resp = await patched;
  expect(resp.request().postDataJSON()).toEqual({ ai_interpret_model: "judge-model:32b" });
  expect((await resp.json()).ai_interpret_model).toBe("judge-model:32b");

  await page.getByTestId("interpret-model").click();
  await expect(page.locator(".n-base-select-option--disabled", { hasText: "nomic-embed-text" })).toHaveCount(1);
  await page.keyboard.press("Escape");

  await page.reload();
  await expect(page.getByTestId("interpret-card")).toContainText("judge-model:32b");

  // 還原：清掉＝回去沿用對話模型（其他測試不受影響）
  const api = new URL(resp.url()).origin;
  const cleared = await page.evaluate(async (origin) => {
    const r = await fetch(`${origin}/api/v1/system/llm`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json",
                 Authorization: `Bearer ${localStorage.getItem("access_token")}` },
      body: JSON.stringify({ ai_interpret_model: "", ai_interpret_num_ctx: 0 }),
    });
    return (await r.json()).ai_interpret_model;
  }, api);
  expect(cleared).toBeNull();
});

test("IP 調查：判讀下方標出實際使用的模型", async ({ page }) => {
  await login(page);
  const sse = [
    { type: "content", text: "## 判讀\n這台是印表機。", elapsed: 1.2 },
    { type: "done", text: "## 判讀\n這台是印表機。", model: "judge-model:32b", elapsed: 1.5 },
  ].map((x) => `data: ${JSON.stringify(x)}\n\n`).join("");
  await page.route("**/api/v1/investigate/narrative/stream**", (r) => r.fulfill({
    status: 200, headers: { "content-type": "text/event-stream" }, body: sse }));
  await page.goto("/addresses");
  await page.getByText("10.20.0.10", { exact: true }).first().click();
  await page.getByRole("button", { name: /調查/ }).click();
  await page.getByRole("button", { name: /請 AI 判讀/ }).click();
  await expect(page.getByTestId("inv-ai-model")).toHaveText(/judge-model:32b/);
});
