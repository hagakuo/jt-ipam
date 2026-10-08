/**
 * 三種新型態：角鋼層架、IKEA KALLAX、LackRack —— 畫面畫得對、表單套得對。
 * 樣本：seed_e2e 的 ANGLE-90（角鋼 90×45×180 四層）、KALLAX-24（2×4）、LACK-16（兩張疊）。
 *
 * 量幾何而不是只看截圖：第一版的橫桿畫進了格子裡（漸層以內距框為準），截圖縮小之後
 * 只像「橫桿粗了一點」，量 background-origin 與板的位置才抓得到。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function openRoom(page: Page) {
  await page.goto("/racks");
  await page.waitForTimeout(800);
  await page.locator(".n-base-selection").first().click();
  await page.locator(".n-base-select-option").first().click();
  await page.locator(".rack-row .rack-frame").first().waitFor({ timeout: 20_000 });
  await page.waitForTimeout(800);
}

/** 名稱要在裝置方塊的正中間（曾經因為扣錯板厚，桌面上那台的名稱被推進桌面裡） */
async function labelCentered(page: Page, cardName: string, dev: string) {
  const part = card(page, cardName).locator(".u-part", { hasText: dev }).first();
  const pb = (await part.boundingBox())!;
  const lb = (await part.locator(".d-name").first().boundingBox())!;
  expect(Math.abs(lb.y + lb.height / 2 - (pb.y + pb.height / 2)),
    `${dev} 的名稱沒有在方塊中間`).toBeLessThan(2.5);
}

const card = (page: Page, name: string) =>
  page.locator(".rack-row > *").filter({ hasText: new RegExp(`${name}（|${name} \\(`) }).first();

test("角鋼層架：兩支立柱在前、橫桿畫在每層底下那段（不是格子裡）", async ({ page }) => {
  await login(page);
  await openRoom(page);
  const frame = card(page, "ANGLE-90").locator(".rack-frame.is-angle");
  await expect(frame).toHaveCount(1);
  const g = await frame.evaluate((el) => {
    const post = getComputedStyle(el, "::before");
    const rows = [...el.querySelectorAll(".u-row")] as HTMLElement[];
    const r = getComputedStyle(rows[1]);
    return {
      postW: parseFloat(post.width), postBg: post.backgroundImage,
      origin: r.backgroundOrigin, board: parseFloat(r.borderBottomWidth), rows: rows.length,
    };
  });
  expect(g.postW).toBeGreaterThan(19);            // 40mm ≈ 20.7px
  expect(g.postBg).toContain("svg");              // 葫蘆孔圖磚
  expect(g.origin).toBe("border-box");            // 橫桿要畫在邊框（板）那一段
  expect(g.board).toBeGreaterThan(5);
  expect(g.rows).toBe(4);                         // 3 層＋頂板上面
});

test("KALLAX：2 欄有一條直隔板、外框落地、裝置在左邊那一格", async ({ page }) => {
  await login(page);
  await openRoom(page);
  const c = card(page, "KALLAX-24");
  const frame = c.locator(".rack-frame.is-kallax");
  await expect(frame.locator(".kallax-div")).toHaveCount(1);
  await expect(frame.locator(".kallax-box")).toHaveCount(1);
  const fb = (await frame.boundingBox())!;
  const div = (await frame.locator(".kallax-div").boundingBox())!;
  const nas = (await c.locator(".u-part", { hasText: "nas-kallax" }).first().boundingBox())!;
  expect(Math.abs(div.x + div.width / 2 - (fb.x + fb.width / 2))).toBeLessThan(2);   // 正中間
  expect(nas.x + nas.width).toBeLessThan(div.x + div.width + 1);                      // 在左邊那格
  // 外框底板的下緣就是框的下緣（KALLAX 沒有腳）
  const box = (await frame.locator(".kallax-box").boundingBox())!;
  expect(Math.abs(box.y + box.height - (fb.y + fb.height - 4))).toBeLessThan(2);
  await labelCentered(page, "KALLAX-24", "ups-kallax");   // 最下面那格：底下是 40mm 外框
});

test("LackRack：桌面上方放得了東西、兩張疊起來中間再一片桌面", async ({ page }) => {
  await login(page);
  await openRoom(page);
  const c = card(page, "LACK-16");
  const frame = c.locator(".rack-frame.is-lack");
  const g = await frame.evaluate((el) => {
    const rows = [...el.querySelectorAll(".u-row")] as HTMLElement[];
    return {
      rows: rows.length,
      firstIsTop: rows[0].classList.contains("is-top"),
      boards: rows.filter((r) => r.classList.contains("has-board")).length,
      slab: parseFloat(getComputedStyle(rows[0]).borderBottomWidth),
    };
  });
  expect(g.rows).toBe(17);                         // 16U＋桌面上方
  expect(g.firstIsTop).toBe(true);
  expect(g.boards).toBe(2);                        // 最上面那張的桌面＋兩張之間
  expect(g.slab).toBeGreaterThan(28);              // 桌面 50mm ≈ 31.5px
  await expect(frame).not.toHaveClass(/is-shelf/); // 以 U 計
  // 桌面上的那台要站在桌面上：它的下緣就是第一列（桌面上方）的內容下緣
  const ap = (await c.locator(".u-part", { hasText: "ap-lack" }).first().boundingBox())!;
  const top = (await frame.locator(".u-row").first().boundingBox())!;
  expect(Math.abs(ap.y + ap.height - (top.y + top.height - g.slab))).toBeLessThan(3);
  await labelCentered(page, "LACK-16", "ap-lack");
});

test("LackRack：桌腳跟桌面一樣是 50mm、每塊都有輪廓線、腳底剛好落在地面", async ({ page }) => {
  // 使用者回報：桌腳比桌面細一大截（只畫了耳朵外面那 34mm）、沒有框線、最下面那截像突出去。
  // IKEA 官方線稿：桌腳正面與桌面一樣厚（都是 5cm），每一個邊都有線。
  await login(page);
  await openRoom(page);
  const frame = card(page, "LACK-16").locator(".rack-frame.is-lack");
  const g = await frame.evaluate((el) => {
    const box = (e: Element) => e.getBoundingClientRect();
    const legs = [...el.querySelectorAll(".lack-leg")];
    const tops = [...el.querySelectorAll(".lack-top")];
    const rows = [...el.querySelectorAll(".u-row")];
    const cs = (e: Element) => getComputedStyle(e);
    return {
      legs: legs.length, tops: tops.length,
      legW: legs.map((e) => box(e).width), topH: tops.map((e) => box(e).height),
      legBorder: legs.map((e) => [cs(e).borderLeftWidth, cs(e).borderBottomWidth, cs(e).borderLeftColor]),
      topBorder: tops.map((e) => [cs(e).borderTopWidth, cs(e).borderBottomWidth]),
      wood: cs(legs[0] ?? el).backgroundColor,
      legBottom: legs.map((e) => box(e).bottom),
      ground: box(el).bottom + parseFloat(cs(el).getPropertyValue("--rd-floor")),
      lastRowBottom: box(rows[rows.length - 1]).bottom,
      floor: parseFloat(cs(el).getPropertyValue("--rd-floor")),
      topSpan: tops.map((e) => [box(e).left, box(e).right]),
      legSpan: [box(legs[0] ?? el).left, box(legs[legs.length - 1] ?? el).right],
    };
  });
  expect(g.legs).toBe(2);
  expect(g.tops).toBe(2);                                        // 兩張疊：兩片桌面
  for (const w of g.legW) expect(Math.abs(w - 50 * 250 / 482.6), `桌腳寬 ${w}`).toBeLessThan(1);   // 50mm
  for (const h of g.topH) expect(Math.abs(h - 50 * 28 / 44.45), `桌面厚 ${h}`).toBeLessThan(1);    // 50mm
  for (const [l, b, color] of g.legBorder) {
    expect(l).toBe("1px");
    expect(b, "腳底要收邊，否則看起來像突出去").toBe("1px");
    expect(color).not.toBe(g.wood);
  }
  for (const [t, b] of g.topBorder) { expect(t).toBe("1px"); expect(b).toBe("1px"); }
  for (const b of g.legBottom) expect(Math.abs(b - g.ground), "腳底＝地面").toBeLessThan(1);
  // 最下面那一 U 到地面就是桌下的 44mm，不多不少（以前多了 4px 內距）
  expect(Math.abs(g.ground - g.lastRowBottom - g.floor)).toBeLessThan(1);
  for (const [l, r] of g.topSpan) {                              // 桌面跟桌腳外緣齊平
    expect(Math.abs(l - g.legSpan[0])).toBeLessThan(1);
    expect(Math.abs(r - g.legSpan[1])).toBeLessThan(1);
  }
});

async function openCreate(page: Page) {
  await page.goto("/racks");
  await page.getByRole("button", { name: /新增/ }).first().click();
  await page.locator(".n-modal").waitFor();
}
async function pickKind(page: Page, label: RegExp) {
  const item = page.locator(".n-modal .n-form-item").filter({ hasText: /^種類/ }).first();
  await item.locator(".n-base-selection").click();
  await page.locator(".n-base-select-option", { hasText: label }).first().click();
}
const numberIn = (page: Page, label: RegExp) =>
  page.locator(".n-modal .n-form-item").filter({ has: page.locator(".n-form-item-label", { hasText: label }) })
    .first().locator("input").first();

test("表單：三種型態各有自己的一鍵套用與顏色", async ({ page }) => {
  await login(page);
  await openCreate(page);

  await pickKind(page, /角鋼層架/);
  await expect(page.locator(".n-modal .n-form-item-label", { hasText: /^顏色/ })).toHaveCount(1);
  const presets = page.locator(".n-modal .preset-buttons button");
  await expect(presets).toHaveCount(5);
  await presets.filter({ hasText: "120×45×180 公分・5 層" }).click();
  await expect(numberIn(page, /^層數/)).toHaveValue("4");              // 5 片板＝4 層之間＋頂板上面
  await expect(numberIn(page, /^寬度/)).toHaveValue("1200");
  // (1800 − 59 × 5 − 10) ÷ 4 = 373.75
  await expect(numberIn(page, /^每層高度/)).toHaveValue("374");

  await pickKind(page, /KALLAX/);
  await expect(presets).toHaveCount(7);
  await presets.filter({ hasText: "3×4 格" }).click();
  await expect(numberIn(page, /^寬度/)).toHaveValue("1115");          // 65 + 350 × 3
  await expect(numberIn(page, /^層數/)).toHaveValue("4");

  await pickKind(page, /LackRack/);
  await expect(presets).toHaveCount(3);
  await presets.filter({ hasText: "2 張（16U）" }).click();
  await expect(numberIn(page, /^U 高度|^高度/)).toHaveValue("16");
});

test("表單：換型態時還沒動過的列數跟著換成該型態的常見值", async ({ page }) => {
  await login(page);
  await openCreate(page);
  await expect(numberIn(page, /^U 高度|^高度/)).toHaveValue("42");
  await pickKind(page, /KALLAX/);
  await expect(numberIn(page, /^層數/)).toHaveValue("4");
  await pickKind(page, /木質層架/);                                     // 以前換到 IVAR 不會跟著換
  await expect(numberIn(page, /^層數/)).toHaveValue("6");
  await pickKind(page, /LackRack/);
  await expect(numberIn(page, /^U 高度|^高度/)).toHaveValue("8");
});

async function lackId(page: Page): Promise<string> {
  const r = await page.evaluate(async () => {
    const res = await fetch("/api/v1/racks?page_size=500",
      { headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } });
    return res.json();
  });
  return r.items.find((x: any) => x.name === "LACK-16").id;
}

test("單櫃檢視：桌腳不會跑出卡片、壓到下面的圖例", async ({ page }) => {
  await login(page);
  await page.goto(`/racks?rack=${await lackId(page)}`);
  const frame = page.locator(".rack-frame.is-lack").first();
  await frame.waitFor({ timeout: 20_000 });
  await page.waitForTimeout(600);
  const g = await frame.evaluate((el) => ({
    bottom: el.getBoundingClientRect().bottom,
    floor: parseFloat(getComputedStyle(el).getPropertyValue("--rd-floor")),
  }));
  expect(g.floor).toBeGreaterThan(20);             // LACK 桌下約 44mm ≈ 28px
  const legend = (await page.locator(".legend").first().boundingBox())!;
  expect(legend.y, "圖例被桌腳壓到").toBeGreaterThanOrEqual(g.bottom + g.floor - 0.5);
});

test("單櫃檢視：改顏色存檔後畫面立刻換，不用重新整理", async ({ page }) => {
  await login(page);
  const id = await lackId(page);
  await page.goto(`/racks?rack=${id}`);
  const frame = page.locator(".rack-frame.is-lack").first();
  await frame.waitFor({ timeout: 20_000 });
  const wood = () => frame.evaluate((el) => getComputedStyle(el).getPropertyValue("--fin-wood").trim());
  const before = await wood();
  const row = page.locator("tr", { hasText: "LACK-16" }).first();
  await row.locator("td").last().locator("button").nth(1).click();      // 釘選、編輯、刪除
  await page.locator(".n-modal").waitFor();
  const item = page.locator(".n-modal .n-form-item").filter({ has: page.locator(".n-form-item-label", { hasText: /^顏色/ }) }).first();
  await item.locator(".n-base-selection").click();
  const target = before === "#2c2c2e" ? "白色" : "黑色";
  await page.locator(".n-base-select-option", { hasText: target }).first().click();
  await page.locator(".n-modal").getByRole("button", { name: /儲存/ }).click();
  await expect.poll(wood, { timeout: 10_000 }).not.toBe(before);
  // 還原成原本的顏色，別讓下一輪測試吃到改過的資料
  await row.locator("td").last().locator("button").nth(1).click();
  await page.locator(".n-modal").waitFor();
  await item.locator(".n-base-selection").click();
  await page.locator(".n-base-select-option", { hasText: target === "白色" ? "黑色" : "白色" }).first().click();
  await page.locator(".n-modal").getByRole("button", { name: /儲存/ }).click();
  await expect.poll(wood, { timeout: 10_000 }).toBe(before);
});
