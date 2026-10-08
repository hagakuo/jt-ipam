/**
 * 「欄位」選單拖拉改變欄位順序（使用者 2026-10-05：所有頁面可以挑欄位的，也要可以拖拉改變欄位順序）。
 *
 * 在 IP 位址清單把「主機名稱」拖到「IP」上面：表頭順序要跟著變、重新整理後還在、
 * 「還原預設值」要連順序一起還原。欄位偏好存在帳號上，用臨時帳號跑，不影響平行跑的其他 spec。
 */
import { test, expect, type Page } from "@playwright/test";
import { createTempAdmin, deleteTempUser, type TempUser } from "./helpers/tempAdmin";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

let tmp: TempUser | null = null;
test.beforeAll(async ({ request }) => { tmp = await createTempAdmin(request, "colorder"); });
test.afterAll(async ({ request }) => { await deleteTempUser(request, tmp); });

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(tmp!.username);
  await page.getByPlaceholder(/密碼|Password/).fill(tmp!.password);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

/** 表頭目前的欄位 key 順序（只看這次關心的兩欄） */
async function headerOrder(page: Page): Promise<string[]> {
  const keys = await page.locator("thead th[data-col-key]").evaluateAll(
    (ths) => ths.map((th) => th.getAttribute("data-col-key") || ""));
  return keys.filter((k) => k === "ip" || k === "hostname");
}

async function openPicker(page: Page) {
  await page.getByRole("button", { name: "欄位", exact: true }).click();
  await expect(page.locator(".col-picker-row[data-picker-key='hostname']")).toBeVisible();
}

test("IP 位址清單：拖拉欄位選單改變欄位順序，重新整理後還在，還原預設值會還原", async ({ page }) => {
  await login(page);
  await page.goto("/addresses");
  await expect(page.locator("thead th[data-col-key='hostname']")).toBeVisible({ timeout: 15_000 });
  await expect.poll(() => headerOrder(page)).toEqual(["ip", "hostname"]);

  await openPicker(page);
  const handle = page.locator(".col-picker-row[data-picker-key='hostname'] .col-drag");
  const target = page.locator(".col-picker-row[data-picker-key='ip']");
  const saved = page.waitForResponse((r) =>
    r.url().includes("/api/v1/me/preferences") && r.request().method() === "PATCH");
  // 選單打開有縮放動畫：先 hover（Playwright 會等元素位置穩定）再量位置，否則會按到動畫中途的別的地方
  await handle.hover();
  const hb = (await handle.boundingBox())!;
  const tb = (await target.boundingBox())!;
  await page.mouse.down();
  await page.mouse.move(hb.x + hb.width / 2, tb.y + 2, { steps: 8 });
  await page.mouse.up();

  // 選單裡與表頭都變成「主機名稱」在「IP」前面
  await expect.poll(() => page.locator(".col-picker-row").evaluateAll(
    (rows) => rows.map((r) => r.getAttribute("data-picker-key")).filter((k) => k === "ip" || k === "hostname")))
    .toEqual(["hostname", "ip"]);
  await expect.poll(() => headerOrder(page)).toEqual(["hostname", "ip"]);
  expect((await saved).ok()).toBeTruthy();

  // 存在帳號上：後端讀回來的偏好裡有這張表的順序
  const stored = await page.evaluate(async () => {
    const r = await fetch("/api/v1/me/preferences", {
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
    });
    return (await r.json()).table_columns?.["addresses:order"] as string[] | undefined;
  });
  expect(stored?.indexOf("hostname")).toBeLessThan(stored?.indexOf("ip") ?? -1);

  // 清掉本機快取再重新整理，確定是從後端讀回來的
  await page.evaluate(() => localStorage.removeItem("jt-ipam:table_columns"));
  await page.reload();
  await expect(page.locator("thead th[data-col-key='hostname']")).toBeVisible({ timeout: 15_000 });
  await expect.poll(() => headerOrder(page)).toEqual(["hostname", "ip"]);

  // 還原預設值：順序也回來
  await openPicker(page);
  await page.getByRole("button", { name: "還原預設值" }).click();
  await expect.poll(() => headerOrder(page)).toEqual(["ip", "hostname"]);
});

test("鍵盤也能調整順序：把手聚焦後按方向鍵", async ({ page }) => {
  await login(page);
  await page.goto("/addresses");
  await expect(page.locator("thead th[data-col-key='hostname']")).toBeVisible({ timeout: 15_000 });
  await openPicker(page);
  await page.locator(".col-picker-row[data-picker-key='hostname'] .col-drag").focus();
  await page.keyboard.press("ArrowUp");
  await expect.poll(() => headerOrder(page)).toEqual(["hostname", "ip"]);
  // 焦點留在同一個把手上，可以連續按
  await page.keyboard.press("ArrowDown");
  await expect.poll(() => headerOrder(page)).toEqual(["ip", "hostname"]);
});
