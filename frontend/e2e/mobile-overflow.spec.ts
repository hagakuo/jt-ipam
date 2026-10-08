/**
 * 手機上的四個版面問題（使用者 2026-09-28 用 iPhone 回報）。量幾何，不看截圖（TEST_CHECKLIST §5c）。
 *
 * 1. 側欄滑不動、捲到後面的頁面、放開又彈回去 —— 根因是 iOS 的 100vh 比實際看得到的高
 *    （工具列收起時的高度）。Playwright 模擬不出 iOS 會伸縮的工具列，所以這裡驗的是修法的
 *    每一個零件：高度用 dvh 後等於可見高度、選單捲到底不外傳、後面的頁面鎖住、遮罩不吃捲動。
 * 2. 主控台狀態列把「連線錯誤」擠成直排、右邊超出畫面
 * 3. 機櫃圖在手機上預設太大
 * 4. 通知彈出框超出畫面左邊
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const RACK = process.env.E2E_SHELF_RACK_ID || "";
const SAMPLE_IP = "10.20.0.12";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const W = 390;
test.use({ viewport: { width: W, height: 700 }, hasTouch: true, isMobile: true });

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("側欄：高度等於可見高度、選單自己捲、後面的頁面鎖住", async ({ page }) => {
  await login(page);
  await page.locator(".mobile-menu-btn").click();
  await expect(page.locator(".sider-mask")).toBeVisible();

  const probe = await page.evaluate(() => {
    const sider = document.querySelector(".app-sider") as HTMLElement;
    const sc = document.querySelector(".app-sider .n-layout-sider-scroll-container") as HTMLElement;
    const mask = document.querySelector(".sider-mask") as HTMLElement;
    const root = document.querySelector(".app-root") as HTMLElement;
    return {
      inner: window.innerHeight,
      sider: sider.getBoundingClientRect().height,
      root: root.getBoundingClientRect().height,
      overscroll: getComputedStyle(sc).overscrollBehaviorY,
      maskTouch: getComputedStyle(mask).touchAction,
      htmlOpen: document.documentElement.classList.contains("sider-open"),
      bodyOverflow: getComputedStyle(document.body).overflowY,
    };
  });
  expect(Math.abs(probe.sider - probe.inner)).toBeLessThanOrEqual(1);
  expect(Math.abs(probe.root - probe.inner)).toBeLessThanOrEqual(1);
  expect(probe.overscroll).toBe("contain");
  expect(probe.maskTouch).toBe("none");
  expect(probe.htmlOpen).toBe(true);
  expect(probe.bodyOverflow).toBe("hidden");

  // 用手指往上滑，要捲的是選單本身；捲到底再滑也不能傳給後面的頁面。
  // （CDP 的 synthesizeScrollGesture 在無頭模式不會動，逐點送觸控事件才是真的「滑」）
  const sc = page.locator(".app-sider .n-layout-sider-scroll-container");
  const overflow = await sc.evaluate((el) => el.scrollHeight - el.clientHeight);
  expect(overflow, "選單要比畫面長，否則這段驗不到（視窗高度調矮一點）").toBeGreaterThan(50);
  const cdp = await page.context().newCDPSession(page);
  async function swipe(x: number, y0: number, y1: number) {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x, y: y0 }] });
    for (let i = 1; i <= 12; i++) {
      await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x, y: y0 + ((y1 - y0) * i) / 12 }] });
    }
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await page.waitForTimeout(700);   // 等慣性捲動停下來再量
  }
  const behind = () => page.evaluate(() => ({
    win: window.scrollY,
    content: [...document.querySelectorAll(".n-layout-scroll-container")].map((e) => (e as HTMLElement).scrollTop),
  }));
  const before = await behind();
  await swipe(120, 600, 250);
  await expect.poll(() => sc.evaluate((el) => el.scrollTop)).toBeGreaterThan(20);
  await swipe(120, 600, 150);            // 已經在底部，再滑一次
  await swipe(W - 40, 600, 200);         // 在暗掉的遮罩上滑
  expect(await behind(), "後面的頁面不可以跟著捲").toEqual(before);

  // 收起後解鎖
  await page.locator(".sider-mask").click({ position: { x: W - 20, y: 300 } });
  await expect.poll(() => page.evaluate(() => document.documentElement.classList.contains("sider-open"))).toBe(false);
});

test("通知彈出框不超出畫面", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "notifications" }).click();
  const pop = page.locator(".notif-pop");
  await expect(pop).toBeVisible();
  const b = (await pop.boundingBox())!;
  expect(b.x).toBeGreaterThanOrEqual(0);
  expect(b.x + b.width).toBeLessThanOrEqual(W);
});

test("主控台狀態列：放不下時換行，不擠成直排、不超出畫面", async ({ page }) => {
  await login(page);
  const auth = await page.evaluate(() => `Bearer ${localStorage.getItem("access_token")}`);
  const found = await (await page.request.get(`/api/v1/addresses?q=${SAMPLE_IP}&page_size=5`,
    { headers: { Authorization: auth } })).json();
  const id = found.items?.find((x: { ip: string }) => String(x.ip).split("/")[0] === SAMPLE_IP)?.id;
  expect(id, "找不到樣本 IP（先跑 seed_e2e）").toBeTruthy();
  // 長一點的主機名稱與裝置名稱，逼它一定要換行；取票失敗 → 連線錯誤狀態
  await page.route(`**/api/v1/addresses/${id}`, async (route) => {
    const r = await route.fetch();
    const body = await r.json();
    await route.fulfill({ response: r, json: { ...body, hostname: "workstation-3f-01", device_name: "desk-pc-3f-east" } });
  });
  await page.route(`**/api/v1/addresses/${id}/rdp/ticket`, (route) =>
    route.fulfill({ status: 400, json: { detail: "e2e: ticket refused" } }));
  await page.goto(`/rdp/${id}`);
  await page.getByPlaceholder("Administrator").fill("u");
  await page.locator("input[type=password]").first().fill("p");
  await page.locator(".rdp-form").getByRole("button", { name: "RDP 連線" }).click();
  const status = page.locator(".rdp-status");
  await expect(status).toHaveAttribute("data-state", "error");

  const geo = await status.evaluate((el) => {
    const label = el.querySelector(":scope > span:not(.rdp-dot):not(.rdp-ip)") as HTMLElement;
    const r = el.getBoundingClientRect();
    return { left: r.left, right: r.right, labelH: label.getBoundingClientRect().height,
             lineH: parseFloat(getComputedStyle(label).lineHeight) || 20, doc: document.documentElement.scrollWidth };
  });
  expect(geo.left).toBeGreaterThanOrEqual(0);
  expect(geo.right).toBeLessThanOrEqual(W);
  expect(geo.labelH, "「連線錯誤」要維持一行").toBeLessThan(geo.lineH * 1.5);
  expect(geo.doc).toBeLessThanOrEqual(W);
});

test("機櫃圖：手機預設比例依畫面縮小，拉過就記住（跟桌機分開）", async ({ page }) => {
  test.skip(!RACK, "需要 E2E_SHELF_RACK_ID");
  await login(page);
  await page.evaluate(() => { localStorage.removeItem("jt.rackZoom.mobile"); localStorage.setItem("jt.rackZoom", "1"); });
  await page.goto(`/racks?rack=${RACK}`);
  const val = page.locator(".zoom-ctl__val").first();
  await expect(val).toBeVisible({ timeout: 20_000 });
  await expect.poll(async () => parseInt(await val.innerText(), 10)).toBeLessThanOrEqual(45);
  expect(parseInt(await val.innerText(), 10)).toBeGreaterThanOrEqual(35);
  // 寬度放得下：不必左右捲
  const fits = await page.locator(".rack-scroll").first().evaluate((el) => el.scrollWidth <= el.clientWidth + 1);
  expect(fits).toBe(true);

  // 使用者拉過 → 記在手機專用的鍵，重新整理後沿用；桌機的值不動
  const handle = page.locator(".zoom-ctl .n-slider-handle").first();
  await handle.focus();
  await page.keyboard.press("ArrowRight");
  const chosen = await val.innerText();
  await page.reload();
  await expect(page.locator(".zoom-ctl__val").first()).toHaveText(chosen, { timeout: 20_000 });
  expect(await page.evaluate(() => localStorage.getItem("jt.rackZoom"))).toBe("1");
});
