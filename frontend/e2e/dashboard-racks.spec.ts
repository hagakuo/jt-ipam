/**
 * 儀表板的「機櫃」卡片（最下面）：設定看哪個機房的全部機櫃，或挑幾個機櫃；設定跟著帳號。
 * 種子資料的「測試機房 A」裡有角鋼層架、KALLAX、LackRack、一般機櫃等。
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

async function openSettings(page: Page) {
  await page.getByTestId("dash-racks-settings").click();
  await expect(page.locator(".n-modal")).toBeVisible();
}

test("選機房 → 那一間的機櫃都畫出來；改成挑一個機櫃 → 只剩那一個；重新整理後設定還在", async ({ page }) => {
  await login(page);
  await page.goto("/");
  const card = page.getByTestId("dash-racks");
  await expect(card).toBeVisible({ timeout: 20_000 });

  await openSettings(page);
  await page.getByText("一個機房的全部機櫃").click();
  await page.getByTestId("dash-racks-room").click();
  await page.locator(".n-base-select-option", { hasText: "測試機房 A" }).click();
  await page.getByTestId("dash-racks-save").click();
  await expect(card).toContainText("測試機房 A");
  await expect(card.locator(".dr-rack").filter({ hasText: "KALLAX-24" })).toBeVisible({ timeout: 15_000 });
  expect(await card.locator(".dr-rack").count()).toBeGreaterThan(2);
  // 整排同一個縮放比例：以前每台各自縮到放得下，42U 被縮小、3 層層架維持原尺寸，看起來一樣高
  await expect.poll(async () => new Set(await card.locator(".rack-wrap").evaluateAll(
    (els) => els.map((e) => getComputedStyle(e).transform))).size, { timeout: 10_000 }).toBe(1);

  // 大小可以調（使用者 2026-10-06）：放大後整排一起變大，比例不變
  const scaleOf = async () => card.locator(".rack-wrap").first().evaluate(
    (e) => new DOMMatrix(getComputedStyle(e).transform).a);
  const before = await scaleOf();
  await openSettings(page);
  const handle = page.getByTestId("dash-racks-scale").getByRole("slider");
  await handle.focus();
  for (let i = 0; i < 5; i++) await page.keyboard.press("ArrowRight");
  await page.getByTestId("dash-racks-save").click();
  await expect.poll(scaleOf, { timeout: 10_000 }).toBeGreaterThan(before * 1.3);
  expect(new Set(await card.locator(".rack-wrap").evaluateAll(
    (els) => els.map((e) => getComputedStyle(e).transform))).size).toBe(1);
  // 還原大小
  await openSettings(page);
  await handle.focus();
  for (let i = 0; i < 5; i++) await page.keyboard.press("ArrowLeft");
  await page.getByTestId("dash-racks-save").click();

  await openSettings(page);
  await page.getByText("指定幾個機櫃").click();
  await page.getByTestId("dash-racks-pick").click();
  await page.keyboard.type("KALLAX");
  await page.locator(".n-base-select-option", { hasText: "KALLAX-24" }).first().click();
  await page.keyboard.press("Escape");
  await page.getByTestId("dash-racks-save").click();
  await expect(card.locator(".dr-rack")).toHaveCount(1, { timeout: 15_000 });

  await page.reload();
  await expect(page.getByTestId("dash-racks").locator(".dr-rack")).toHaveCount(1, { timeout: 20_000 });

  // 還原：不要影響其他 spec 的儀表板
  await openSettings(page);
  await page.getByText("一個機房的全部機櫃").click();
  await page.getByTestId("dash-racks-room").locator(".n-base-clear").click({ force: true }).catch(() => {});
  await page.getByTestId("dash-racks-save").click();
  await expect(page.getByTestId("dash-racks")).toContainText("還沒選要顯示哪個機房或哪些機櫃");
});
