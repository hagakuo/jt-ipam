/**
 * IP 詳細頁的「所屬別名」要跟上下兩段同一種排法。
 *
 * 以前是一行「所屬別名：[名稱（廠牌）]」夾在規則清單與「any 規則不列出」的註記中間：
 * 標題是深色內文字、跟標籤擠同一行，廠牌塞在括號裡，看不出是哪一台防火牆。
 * 樣本：seed_e2e 的 fw-e2e／web_hosts 涵蓋 198.51.100.7。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

test("所屬別名：獨立標題、每筆寫出防火牆，註記緊跟規則", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/addresses?q=198.51.100.7");
  await page.getByText("198.51.100.7", { exact: true }).first().click();
  await page.waitForURL(/addresses\/[0-9a-f-]{36}/);

  const title = page.getByText(/^\s*所屬別名（1）\s*$/);
  await expect(title).toBeVisible({ timeout: 20_000 });
  const row = page.locator(".fw-table tr", { hasText: "web_hosts" }).filter({ hasText: "fw-e2e" }).last();
  await expect(row).toContainText("opnsense");
  await expect(row).toContainText("e2e：對外網站主機");      // 別名說明以前沒顯示

  const t = (await title.boundingBox())!;
  const r = (await row.boundingBox())!;
  expect(r.y, "別名那一行要在標題下面，不是跟標題擠同一行").toBeGreaterThanOrEqual(t.y + t.height - 1);
  const note = (await page.getByText(/來源或目的為 any 的規則/).boundingBox())!;
  expect(note.y, "any 註記在說明規則，要在別名區塊上面").toBeLessThan(t.y);
});

test("防火牆規則：表格排法，每一欄上下對齊", async ({ page }) => {
  // 使用者要求（2026-09-25）：以前一條規則擠成一行字，來源／目的／說明長短不一，上下對不齊
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/addresses?q=198.51.100.7");
  await page.getByText("198.51.100.7", { exact: true }).first().click();
  await page.waitForURL(/addresses\/[0-9a-f-]{36}/);

  const rules = page.locator(".fw-table").first();
  await expect(rules.locator("tbody tr")).toHaveCount(2, { timeout: 20_000 });
  const heads = await rules.locator("thead th").allInnerTexts();
  for (const h of ["防火牆", "動作", "來源", "目的", "連接埠", "比對依據", "說明"]) {
    expect(heads.map((x) => x.trim()), `少了「${h}」欄`).toContain(h);
  }
  // 每一欄：表頭與每一列的儲存格左緣相同
  const lefts = await rules.evaluate((tbl) => Array.from(tbl.querySelectorAll("tr")).map(
    (tr) => Array.from(tr.children).map((c) => Math.round(c.getBoundingClientRect().left))));
  for (const row of lefts.slice(1)) expect(row, "欄位沒有對齊").toEqual(lefts[0]);
  await expect(rules.locator("tbody tr", { hasText: "block" }).locator(".fw-block")).toBeVisible();
});

async function openIp(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/addresses?q=198.51.100.7");
  await page.getByText("198.51.100.7", { exact: true }).first().click();
  await page.waitForURL(/addresses\/[0-9a-f-]{36}/);
  await expect(page.locator(".fw-table").first()).toBeVisible({ timeout: 20_000 });
}

test("滑過有整行光棒、各區塊標題看得出分區、NAT 欄位順序跟規則一樣", async ({ page }) => {
  // 使用者要求（2026-09-25）
  await openIp(page);
  const row = page.locator(".fw-table").first().locator("tbody tr").first();
  const before = await row.evaluate((el) => getComputedStyle(el).backgroundColor);
  await row.hover();
  await expect.poll(() => row.evaluate((el) => getComputedStyle(el).backgroundColor)).not.toBe(before);

  for (const title of [/防火牆規則（/, /所屬別名（/, /關聯的 NAT 規則（/]) {
    const el = page.locator(".detail-sec-title", { hasText: title });
    await expect(el).toBeVisible();
    expect(await el.evaluate((e) => parseFloat(getComputedStyle(e).borderLeftWidth)),
      "區塊標題要有左側色條").toBeGreaterThan(0);
  }

  const nat = page.locator(".fw-table").nth(2);
  const heads = (await nat.locator("thead th").allInnerTexts()).map((x) => x.trim());
  expect(heads.slice(0, 4), "前兩欄是廠牌與設備名稱，跟防火牆規則一樣").toEqual(["", "防火牆", "類型", "名稱"]);
});

test("點規則那一列 → 規則頁選好那一台、只顯示那一筆；顯示全部可還原", async ({ page }) => {
  await openIp(page);
  await page.locator(".fw-table").first().locator("tbody tr", { hasText: "block" }).click();
  await page.waitForURL(/\/firewall\?.*tab=rules.*focus=/);
  const banner = page.locator(".focus-row-banner");
  await expect(banner).toContainText("只顯示從 IP 詳細頁點選的項目", { timeout: 20_000 });
  const rows = page.locator(".n-tab-pane:visible .n-data-table-tbody .n-data-table-tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("203.0.113.0/24");
  await banner.getByRole("button", { name: "顯示全部" }).click();
  await expect(banner).toBeHidden();
  await expect(rows).toHaveCount(2);
});

test("點別名那一列 → 別名頁只顯示那一個別名", async ({ page }) => {
  await openIp(page);
  await page.locator(".fw-table").nth(1).locator("tbody tr", { hasText: "web_hosts" }).click();
  await page.waitForURL(/\/firewall\?.*tab=aliases.*focus=web_hosts/);
  await expect(page.locator(".focus-row-banner")).toBeVisible({ timeout: 20_000 });
  const rows = page.locator(".n-tab-pane:visible .n-data-table-tbody .n-data-table-tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("web_hosts");
});

test("點 NAT 那一列 → NAT 頁只顯示那一筆", async ({ page }) => {
  await openIp(page);
  await page.locator(".fw-table").nth(2).locator("tbody tr").first().click();
  await page.waitForURL(/\/nat\?.*focus=/);
  await expect(page.locator(".focus-row-banner")).toBeVisible({ timeout: 20_000 });
  const rows = page.locator(".n-data-table-tbody .n-data-table-tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("e2e-https-forward");
});
