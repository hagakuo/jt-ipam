/**
 * 匯出的圖要跟畫面上的是同一台機櫃。
 *
 * 客戶回報 PNG／draw.io「高度超高、機櫃樣式完全不對」。兩個原因：
 * - 並排對齊的基準早就從「U 數」改成**像素**，匯出那一份還當成 U 數去乘固定列高
 *   → 圖高變成幾萬 px、整張幾乎全白；
 * - 匯出自己另寫了一份幾何，層架改版只改到畫面那一份 —— 沒有層板、每層一樣高、
 *   橫向還在讀早就被 rack_slot 取代的舊欄位，放在頂板上面的那台整個不見。
 *
 * 所以這裡量的是「匯出的 SVG」本身，不是畫面。
 */
import { test, expect } from "@playwright/test";
import * as fs from "fs";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const RACK = process.env.E2E_SHELF_RACK_ID || "";
test.skip(!ADMIN_PASS || !RACK, "需要 E2E_ADMIN_PASS 與 E2E_SHELF_RACK_ID");

async function login(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function exportSvg(page: any): Promise<string> {
  const [dl] = await Promise.all([
    page.waitForEvent("download"),
    (async () => {
      await page.getByRole("button", { name: /匯出/ }).first().click();
      await page.getByText("SVG", { exact: true }).first().click();
    })(),
  ]);
  return fs.readFileSync((await dl.path())!, "utf-8");
}

test("層架匯出：尺寸合理、標題講層、層板與層內位置都在", async ({ page }) => {
  await login(page);
  await page.goto(`/racks?rack=${RACK}`);
  const frame = page.locator(".rack-frame").first();
  await frame.waitFor({ timeout: 20_000 });
  await page.waitForTimeout(300);
  const onScreen = (await frame.boundingBox())!;

  const svg = await exportSvg(page);
  const m = /width="([\d.]+)" height="([\d.]+)"/.exec(svg)!;
  const [w, h] = [Number(m[1]), Number(m[2])];

  // 高度要跟畫面同一個量級（含標題列的一點餘裕），不是幾萬 px
  expect(h, `匯出高度 ${h} vs 畫面 ${onScreen.height}`)
    .toBeLessThan(onScreen.height * 1.5 + 200);
  expect(h).toBeGreaterThan(onScreen.height * 0.5);
  expect(w).toBeLessThan(600);

  // 標題用「層」不是 U
  expect(svg).toMatch(/\(9 層\)/);
  // 頂板上方那一列畫得出來（以前整台不見）
  expect(svg).toContain("srv-top-01");
  expect(svg).toContain("頂");
  // 同一層並排的兩台不可以疊在同一個 x
  const xs = [...svg.matchAll(/<rect x="([\d.]+)"[^>]*stroke="rgba\(0,0,0,0\.3\)"/g)]
    .map((g) => Number(g[1]));
  expect(new Set(xs).size, `裝置方塊的 x：${xs.join(",")}`).toBeGreaterThan(1);
});

test("匯出的側架只到最上面那片層板，左右一樣高", async ({ page }) => {
  await login(page);
  await page.goto(`/racks?rack=${RACK}`);
  await page.locator(".rack-frame").first().waitFor({ timeout: 20_000 });
  const svg = await exportSvg(page);

  // 側架是 12px 寬的長條；左右各一根
  const posts = [...svg.matchAll(/<rect x="([\d.]+)" y="([\d.]+)" width="12" height="([\d.]+)"/g)]
    .map((m) => ({ x: +m[1], y: +m[2], h: +m[3] }));
  expect(posts.length, "左右各一根側架").toBe(2);
  // 對稱：同一個 y、同一個高度。不對稱時畫面上就是「右邊那根頂到上面去了」
  expect(posts[0].y).toBeCloseTo(posts[1].y, 3);
  expect(posts[0].h).toBeCloseTo(posts[1].h, 3);

  // 放在頂板上面那台，整台要**在側架的上緣之上**（板子上面是開放的，沒有柱子）
  const spark = /<rect x="[\d.]+" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"[^>]*stroke="rgba\(0,0,0,0\.3\)"\/>\n<text[^>]*>srv-top-01</.exec(svg)
    ?? /<rect x="[\d.]+" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"[^>]*stroke="rgba\(0,0,0,0\.3\)"/.exec(
      svg.slice(0, svg.indexOf("srv-top-01")));
  expect(spark, "找不到 srv-top-01 的方塊").not.toBeNull();
  const devBottom = Number(spark![1]) + Number(spark![3]);
  expect(devBottom, `裝置下緣 ${devBottom} 應該落在側架上緣 ${posts[0].y} 附近`)
    .toBeLessThanOrEqual(posts[0].y + 1);
});
