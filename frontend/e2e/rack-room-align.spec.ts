/**
 * 整排機櫃要站在同一條地板線上，卡片上方的按鈕也要對齊。
 *
 * 落地對齊的基準本來是用**資料推算**的高度，但那個值不含外框的 border/padding，
 * 而那是逐型態不同的（標準機櫃 12px、鍍鉻層架 8px…）—— 最高的那一台補白被夾到 0，
 * 就比別人低個幾 px。差距很小，用看的只會覺得「地板高度好像不一樣」，要量。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function openRoom(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/racks");
  await page.waitForTimeout(600);
  await page.locator(".n-base-selection").first().click();       // 選機房
  await page.locator(".n-base-select-option").first().click();
  await page.locator(".rack-row .rack-frame").first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);                                // 等 ResizeObserver 回報
}

/** 每一座的「地板線」：框的下緣再往下加上腳（離地）的高度。以前每種型態的腳都一樣短，量框的
 *  下緣就夠；LackRack 桌下有 44mm、KALLAX 直接落地，站在同一個地板上的是**腳**，不是框。 */
async function bottoms(page: any): Promise<number[]> {
  return page.locator(".rack-row .rack-frame").evaluateAll(
    (els: Element[]) => els.map((e) => +(e.getBoundingClientRect().bottom
      + (parseFloat(getComputedStyle(e).getPropertyValue("--rd-floor")) || 0)).toFixed(1)));
}

test("整排機櫃的底部落在同一條線上（不同型態的外框厚度不能影響）", async ({ page }) => {
  await openRoom(page);
  const sep = await bottoms(page);
  test.skip(sep.length < 2, "這個機房只有一台機櫃，比不出對齊");
  expect(Math.max(...sep) - Math.min(...sep), `獨立卡片：${sep.join(" / ")}`).toBeLessThan(1.5);

  await page.getByText("合併卡片", { exact: true }).last().click();
  await page.locator(".merged-rack .rack-frame").first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);
  const merged = await bottoms(page);
  expect(Math.max(...merged) - Math.min(...merged), `合併卡片：${merged.join(" / ")}`)
    .toBeLessThan(1.5);
});

test("合併卡片的工具列按鈕要對齊（n-space 靠 baseline 會差一兩 px）", async ({ page }) => {
  await openRoom(page);
  await page.getByText("合併卡片", { exact: true }).last().click();
  await page.locator(".merged-toolbar").first().waitFor({ timeout: 20_000 });
  const tops = await page.locator(".merged-toolbar .n-button").evaluateAll(
    (els: Element[]) => els.map((e) => +e.getBoundingClientRect().top.toFixed(1)));
  expect(tops.length).toBeGreaterThan(1);
  expect(Math.max(...tops) - Math.min(...tops), `按鈕上緣：${tops.join(" / ")}`).toBeLessThan(1.5);
});

/** 每一座的縮放倍率（.rack-wrap 的 transform；沒縮放時是 none → 1） */
async function scales(page: any): Promise<number[]> {
  return page.locator(".rack-row .rack-wrap").evaluateAll((els: Element[]) => els.map((e) => {
    const m = getComputedStyle(e).transform;
    return m === "none" ? 1 : +new DOMMatrix(m).a.toFixed(2);
  }));
}

test("整排共用一條顯示大小拉桿：獨立卡片與合併卡片都有，一拉整排一起縮、縮了仍落在同一條地板線", async ({ page }) => {
  // 使用者回報：合併卡片沒有縮放拉桿；獨立（分開）卡片要「一次一拉全部一起改變大小」
  await openRoom(page);
  for (const mode of ["獨立卡片", "合併卡片"]) {
    await page.getByText(mode, { exact: true }).last().click();
    await page.locator(".rack-row .rack-frame").first().waitFor({ timeout: 20_000 });
    // 取得焦點的是把手外層（role=slider）；naive-ui 的拉桿只認方向鍵、不認 Home/End
    const handle = page.locator(".merged-toolbar [role=slider]").first();
    await expect(handle, `${mode}：沒有縮放拉桿`).toBeVisible();
    await handle.focus();
    for (let i = 0; i < 13; i++) await page.keyboard.press("ArrowRight");  // 先回到 100%
    await expect.poll(async () => (await scales(page)).every((s) => s === 1)).toBe(true);
    for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowLeft");   // 每格 5% → 80%
    await expect.poll(() => scales(page), { message: `${mode}：整排要一起縮` })
      .toEqual((await scales(page)).map(() => 0.8));
    await page.waitForTimeout(500);
    // 地板線：腳的長度也跟著縮，所以 --rd-floor 要乘上縮放倍率
    const floors = await page.locator(".rack-row .rack-frame").evaluateAll((els: Element[]) =>
      els.map((e) => e.getBoundingClientRect().bottom
        + 0.8 * (parseFloat(getComputedStyle(e).getPropertyValue("--rd-floor")) || 0)));
    expect(Math.max(...floors) - Math.min(...floors), `${mode} 縮放後：${floors.join(" / ")}`)
      .toBeLessThan(1.5);
    for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowRight");   // 還原成 100%
  }
});
