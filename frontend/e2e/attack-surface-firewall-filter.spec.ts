import { test, expect } from "@playwright/test";

/**
 * 對外開放服務：除了防火牆「類型」，也要選得到是**哪一台**。
 *
 * 同一種類型底下常常有好幾台，而使用者要問的是
 * 「這一台開了哪些對外服務」。原本只能選類型，選完還是混在一起。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("可以只看某一台防火牆的對外開放服務", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  await page.goto("/attack-surface");
  const rows = page.locator(".n-data-table-tbody .n-data-table-tr");
  await expect(rows.first()).toBeVisible({ timeout: 20_000 });

  const body = await page.locator("body").innerText();
  test.skip(!body.includes("router-e2e-a") || !body.includes("router-e2e-b"),
            "這個環境沒有兩台以上的防火牆樣本");

  const before = await rows.count();
  // 廠牌（opnsense/pfSense…）與「哪一台」是兩件事，篩選器的文字也必須分得開 ——
  // 原本兩個都叫「全部防火牆」，使用者與測試都分不出誰是誰
  await expect(page.locator(".n-select", { hasText: "全部廠牌" })).toHaveCount(1);
  const fwSelect = page.locator(".n-select", { hasText: "全部防火牆" });
  await expect(fwSelect).toHaveCount(1);
  await fwSelect.click();
  // n-select 的 placeholder 是渲染出來的節點，不是 input 的 placeholder 屬性 ——
  // getByPlaceholder 抓不到（第一版就是這樣逾時的）
  await page.locator(".n-base-select-option", { hasText: "router-e2e-a" }).first().click();
  await page.waitForTimeout(400);

  const after = await rows.count();
  expect(after, "選了某一台之後應該只剩它的").toBeLessThan(before);
  await expect(page.locator(".n-data-table-tbody")).not.toContainText("router-e2e-b");
  await expect(page.locator(".n-data-table-tbody")).toContainText("router-e2e-a");
});
