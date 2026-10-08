import { test, expect } from "@playwright/test";

/**
 * 區段清單必須是完整的（GitHub issue #27）。
 *
 * 原本 `Sections.vue` 只抓第一頁 50 筆，而分頁與搜尋都是前端在做 —— 於是
 * 第 51 個之後的區段整批消失，連下方的「共 N 筆」都跟著錯（它數的是載進來的
 * 列數，不是伺服器的總數）。回報者有 95 個區段，把每頁筆數改成 500 依然只看得到 50 個。
 *
 * 這裡驗的是「畫面上的總數與伺服器一致，而且每一列真的翻得到」。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("區段清單不會停在第一頁", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  // 伺服器上真正有幾個區段。要用瀏覽器裡那把 token 去問 —— `page.request` 不帶
  // localStorage 的 Bearer token，直接打會拿到 401，然後 total 是 undefined
  // 而測試看起來像「畫面錯了」。
  const serverTotal = await page.evaluate(async () => {
    const r = await fetch("/api/v1/sections?page=1&page_size=1", {
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
    });
    return (await r.json()).total as number;
  });
  test.skip(serverTotal <= 50, "這個環境的區段不到 51 個，測不出截斷");

  await page.goto("/sections");
  await expect(page.locator(".n-data-table-tbody .n-data-table-tr").first())
    .toBeVisible({ timeout: 15_000 });

  // 畫面宣稱的總數要與伺服器一致 —— 只抓第一頁時這裡會是 50
  const claimed = await page.locator("body").innerText()
    .then((t) => Number(t.match(/共\s*(\d+)\s*筆/)?.[1] ?? -1));
  expect(claimed, "畫面宣稱的總筆數與伺服器不符").toBe(serverTotal);

  // 而且每一列都翻得到：把所有分頁的列數加起來要等於總數
  let seen = 0;
  for (let i = 1; ; i += 1) {
    seen += await page.locator(".n-data-table-tbody .n-data-table-tr").count();
    const next = page.locator(".n-pagination-item--button").last();
    if (seen >= serverTotal || !(await next.isEnabled().catch(() => false))) break;
    await next.click();
    await page.waitForTimeout(400);
    if (i > 50) break;                     // 保險，別在版面壞掉時無限翻頁
  }
  expect(seen, "翻完所有分頁仍少於伺服器總數").toBe(serverTotal);
});
