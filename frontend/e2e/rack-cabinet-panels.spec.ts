/**
 * 機櫃的頂板與底座要有厚度（使用者回報「近乎只有一條線，不合理」）。
 *
 * 機櫃圖出現在好幾個地方，改畫法時每一處都要跟上（使用者特別交代）：
 * 機櫃頁（單櫃、整排）、裝置詳細頁的機櫃縮圖、匯出的檔案。這裡三處都量。
 * 頂板 50mm ≈ 31.5px、底座 75mm ≈ 47.2px（1U 44.45mm＝28px）。
 */
import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function api(page: Page, path: string) {
  return page.evaluate(async (p) => (await fetch(p, {
    headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
  })).json(), path);
}

/** 頂板（內距上緣）與底座（最下面那一 U 的下框）各多厚 */
async function panels(page: Page, frameSel: string) {
  return page.locator(frameSel).first().evaluate((el) => {
    const rows = [...el.querySelectorAll(".u-row")] as HTMLElement[];
    return {
      roof: parseFloat(getComputedStyle(el).paddingTop),
      base: parseFloat(getComputedStyle(rows[rows.length - 1]).borderBottomWidth),
    };
  });
}

test("機櫃頁：頂板與底座有實際厚度", async ({ page }) => {
  await login(page);
  const racks = await api(page, "/api/v1/racks?page_size=500");
  const id = racks.items.find((r: any) => r.name === "RACK-01").id;
  await page.goto(`/racks?rack=${id}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });
  const p = await panels(page, ".rack-frame");
  expect(p.roof).toBeGreaterThan(30);
  expect(p.base).toBeGreaterThan(45);
});

test("裝置詳細頁的機櫃縮圖也一樣", async ({ page }) => {
  await login(page);
  const devs = await api(page, "/api/v1/devices?page_size=500");
  const nas = (devs.items ?? devs).find((d: any) => d.name === "nas-01");
  await page.goto(`/devices/${nas.id}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });
  const p = await panels(page, ".rack-frame");
  expect(p.roof).toBeGreaterThan(30);
  expect(p.base).toBeGreaterThan(45);
});

test("匯出的 SVG 也畫出頂板與底座", async ({ page }) => {
  await login(page);
  const racks = await api(page, "/api/v1/racks?page_size=500");
  const id = racks.items.find((r: any) => r.name === "RACK-01").id;
  await page.goto(`/racks?rack=${id}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });
  await page.locator(".rd-toolbar").getByRole("button", { name: /匯出/ }).first().click();
  const dl = page.waitForEvent("download");
  await page.locator(".n-dropdown-option", { hasText: /^SVG$/ }).first().click();
  const file = await (await dl).path();
  const svg = readFileSync(file!, "utf8");
  expect(svg).toContain('class="rack-roof"');
  expect(svg).toContain('class="rack-base"');
});

test("最下面那一 U 的編號在那一 U 的正中間，不是掉進底座", async ({ page }) => {
  await login(page);
  const racks = await api(page, "/api/v1/racks?page_size=500");
  const id = racks.items.find((r: any) => r.name === "RACK-01").id;
  await page.goto(`/racks?rack=${id}`);
  const frame = page.locator(".rack-frame").first();
  await frame.waitFor({ timeout: 20_000 });
  const rows = frame.locator(".u-row");
  const last = rows.last();
  const rb = (await last.boundingBox())!;
  const base = await last.evaluate((el) => parseFloat(getComputedStyle(el).borderBottomWidth));
  const nums = page.locator(".u-gutter .u-num-out");
  const lab = nums.last().locator("xpath=.");
  // 編號文字的中心 vs 那一 U（不含底下的底座）的中心
  const center = await lab.evaluate((el) => {
    const r = document.createRange(); r.selectNodeContents(el);
    const b = r.getBoundingClientRect(); return b.top + b.height / 2;
  });
  const want = rb.y + (rb.height - base) / 2;
  expect(Math.abs(center - want), `編號偏了 ${center - want}px`).toBeLessThan(2);
});
