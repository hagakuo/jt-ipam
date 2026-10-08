import { test, expect } from "@playwright/test";

/**
 * 裝置表單的「主要 IP」要搜得到清單第一批以外的位址（GitHub issue #27）。
 *
 * 原本一次載 500 筆、再靠 n-select 的 filterable 在**已載入的那些**裡過濾：
 * 站台超過 500 個位址時，剛建好的那筆就選不到，而且打關鍵字也沒用 ——
 * 因為關鍵字只搜記憶體。搜尋必須送到後端。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("主要 IP 的關鍵字搜尋走後端，找得到第一批以外的位址", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  // 目標必須是**不在第一批裡**的位址 —— 那正是這個缺陷的成立條件。
  // 直接照舊版的載入方式抓第一頁 500 筆，再從後面的頁挑一筆有主機名稱的。
  const target = await page.evaluate(async () => {
    const auth = { Authorization: `Bearer ${localStorage.getItem("access_token")}` };
    const first = await (await fetch("/api/v1/addresses?page=1&page_size=500", { headers: auth })).json();
    const seen = new Set((first.items ?? []).map((a: any) => a.id));
    if (first.total <= 500) return { total: first.total as number, hostname: "" };
    const rest = await (await fetch("/api/v1/addresses?page=2&page_size=500", { headers: auth })).json();
    const pick = (rest.items ?? []).find((a: any) => a.hostname && !seen.has(a.id));
    return { total: first.total as number, hostname: (pick?.hostname ?? "") as string };
  });
  test.skip(!target.hostname,
            "這個環境的位址不到 501 筆（或第 501 筆之後都沒有主機名稱），測不出「第一批之外」");

  await page.goto("/devices");
  await page.getByRole("button", { name: /新增/ }).first().click();
  const dialog = page.locator(".n-modal");
  await expect(dialog).toBeVisible();

  // 打關鍵字時要真的向後端要（帶 q=），而不是只在前端過濾
  const asked = page.waitForRequest((r) =>
    r.url().includes("/api/v1/addresses") && r.url().includes(`q=${target.hostname}`));

  const ipSelect = dialog.locator(".n-form-item", { hasText: "主要 IP" }).locator(".n-base-selection");
  await ipSelect.click();
  await page.keyboard.type(target.hostname);
  await asked;

  // 而且那筆真的出現在選項裡、選得下去
  const option = page.locator(".n-base-select-option", { hasText: target.hostname }).first();
  await expect(option).toBeVisible({ timeout: 10_000 });
  await option.click();
  await expect(ipSelect).toContainText(target.hostname);
});
