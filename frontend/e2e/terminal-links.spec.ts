import { test, expect, type Page } from "@playwright/test";

/**
 * 終端機裡的網址要能點。
 *
 * 這支測試的重點是**續行**：TUI（Claude Code、k9s 這類）會自己算寬度把網址切成好幾列，
 * 那些列在緩衝區裡是各自獨立的邏輯行。只驗第一列會漏掉真正的問題，
 * 所以這裡刻意把滑鼠停在網址的**第二列**，要求它照樣認得整條網址。
 *
 * 需要一台可以用密碼登入的 SSH 目標（用 loopback 上的拋棄式帳號即可）：
 *   E2E_SSH_ADDRESS_ID=<IPAM 裡那筆 IP 記錄的 id，且 ssh_enabled=true>
 *   E2E_SSH_USER / E2E_SSH_PASS
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const ADDRESS_ID = process.env.E2E_SSH_ADDRESS_ID || "";
const SSH_USER = process.env.E2E_SSH_USER || "";
const SSH_PASS = process.env.E2E_SSH_PASS || "";

test.skip(!ADMIN_PASS || !ADDRESS_ID || !SSH_USER || !SSH_PASS,
  "需要 E2E_ADMIN_PASS + E2E_SSH_ADDRESS_ID/USER/PASS 才能跑");

const URL_LONG =
  "https://claude.com/oauth/authorize?code=true&client_id=9d1c0f4a-0000-4a10-92c1-5244f1966f13" +
  "&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback" +
  "&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference" +
  "&code_challenge=Xk7pQ2vR8sT1uV3wY5zA6bC9dE0fG2hJ4kL6mN8pQ0r" +
  "&state=aB3dE5gH7jK9mN1pQ3sU5wY7zA9cE1gJ3lN5qS7uX9";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test.describe("終端機網址連結", () => {
  test("被 TUI 切成多列的網址：續行也能點，且點到的是完整網址", async ({ page }) => {
    await login(page);
    await page.goto(`/ssh/${ADDRESS_ID}`);

    await page.locator('input[placeholder="root"]').fill(SSH_USER);
    await page.locator('input[type="password"]').first().fill(SSH_PASS);
    await page.getByRole("button", { name: /SSH 連線|Connect/ }).first().click();

    // 第一次連線要確認主機金鑰指紋（TOFU）
    const trust = page.getByRole("button", { name: /信任|Trust/ }).first();
    if (await trust.count()) await trust.click();
    await expect(page.locator(".xterm")).toBeVisible({ timeout: 20_000 });

    // fold 切齊終端機寬度 → 每一列都寫滿，正是 TUI 自己斷行的樣子
    await page.locator(".xterm-screen").click();
    await page.keyboard.type(`clear; printf '%s\\n' "${URL_LONG}" | fold -w $(tput cols)`);
    await page.keyboard.press("Enter");
    await expect(page.locator(".xterm-rows")).toContainText("https://claude.com", { timeout: 10_000 });

    // 停在網址的「第二列」——只認第一列的話這裡就會失敗
    const spot = await page.evaluate(() => {
      const rows = [...document.querySelectorAll(".xterm-rows > div")];
      const idx = rows.map((r, i) => [r, i] as const)
        .filter(([r]) => /(^|\s)https:\/\/claude\.com\//.test(r.textContent ?? "")).pop()?.[1];
      if (idx === undefined) throw new Error("畫面上找不到網址");
      const box = rows[idx + 1].getBoundingClientRect();
      return { x: box.x + 60, y: box.y + box.height / 2 };
    });
    await page.mouse.move(spot.x, spot.y);

    const bar = page.locator(".term-linkbar");
    await expect(bar).toBeVisible({ timeout: 5_000 });
    // 懸停時要顯示**完整**目標：終端機文字由遠端主機控制，不能只讓人看到被切碎的樣子
    expect((await bar.innerText()).trim()).toBe(URL_LONG);

    const [popup] = await Promise.all([
      page.waitForEvent("popup", { timeout: 8_000 }),
      page.mouse.click(spot.x, spot.y),
    ]);
    expect(popup.url()).toBe(URL_LONG);
    await popup.close();
  });
});
