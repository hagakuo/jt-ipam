/**
 * 對話泡泡的服務標籤要照實際的設定（GitHub issue #37）。
 * 以前寫死「本地 Ollama」，接 OpenAI 相容服務也一樣。測完把設定切回 Ollama。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function setProvider(page: any, provider: "ollama" | "openai") {
  const r = await page.evaluate(async (p: string) => {
    const res = await fetch("/api/v1/system/llm", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("access_token")}` },
      body: JSON.stringify({ provider: p }),
    });
    return res.status;
  }, provider);
  expect(r).toBe(200);
}

test("OpenAI 相容服務顯示「OpenAI 相容」，Ollama 顯示「本地 Ollama」", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  try {
    for (const [p, label] of [["openai", "OpenAI 相容"], ["ollama", "本地 Ollama"]] as const) {
      await setProvider(page, p);
      await page.reload();
      await page.locator(".chat-fab").click();
      await expect(page.locator(".chat-badge")).toHaveText(label, { timeout: 10_000 });
    }
  } finally {
    await setProvider(page, "ollama");
  }
});
