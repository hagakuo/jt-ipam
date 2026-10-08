import { test, expect } from "@playwright/test";

/**
 * 上線判定的證據勾選：分組＋對齊。
 *
 * 使用者回報「這裡這樣排 很不整齊」—— 原本是自由換行，每個項目字數不同，
 * 每一列的起點就跟著跑。改成「種類在列首 + 固定欄寬的網格」。
 * 版面問題要**量幾何**，截圖看起來還好不算數。
 */
const PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!PASS, "需要 E2E_ADMIN_PASS");

test("採信哪些證據：分組且欄位對齊", async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1000 });
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(process.env.E2E_ADMIN_USER || "admin");
  await page.getByPlaceholder(/密碼|Password/).fill(PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));

  await page.goto("/system-settings", { waitUntil: "domcontentloaded" });
  // 等元素出現，不要等固定秒數 —— 設定是 onMounted 才去拿的，機器慢一點就會誤判成 0 組
  const rows = page.locator(".ss-src-row");
  await expect(rows.first()).toBeVisible({ timeout: 20_000 });
  expect(await rows.count(), "應該至少有「探測／監控」與「ARP 表」兩組").toBeGreaterThan(1);

  // 每一列第一格的 x 相同 → 各列真的對齊（不是靠看的）
  const firstXs: number[] = [];
  for (let i = 0; i < await rows.count(); i++) {
    const box = await rows.nth(i).locator(".ss-src-item").first().boundingBox();
    firstXs.push(Math.round(box!.x));
  }
  expect(new Set(firstXs).size, `各列起點不一致：${firstXs.join(", ")}`).toBe(1);

  // 內部鍵不可以露出來（使用者回報看到全小寫的 paloalto）
  const text = await page.locator(".ss-src-grid").first().innerText();
  expect(text).not.toMatch(/paloalto|pfsense|fortigate|opnsense/);

  // ── 窄視窗：選項不可以衝出卡片 ──
  // 使用者回報「寬度不夠時，證據來源的選項跑出卡片外了」。原本的版面測試只在
  // 1500px 跑過，這種缺陷天生只在窄的時候才出現 —— 所以逐個寬度量。
  for (const width of [1500, 1180, 900, 820, 700]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.waitForTimeout(350);
    const worst = await page.locator(".ss-group").filter({ hasText: "上線判定" }).first()
      .evaluate((card) => {
        const right = card.getBoundingClientRect().right;
        return Array.from(card.querySelectorAll(".ss-src-item"))
          .reduce((acc, e) => Math.max(acc, e.getBoundingClientRect().right - right), -9999);
      });
    expect(worst, `視窗 ${width}px 時選項超出卡片 ${worst.toFixed(0)}px`).toBeLessThanOrEqual(0);

    // 每一列的**每一格**都要落在同一組欄位上 —— 只比第一格會漏掉「項目少的列欄寬被撐大」
    // （使用者回報：VPN 只有 3 項、DHCP 2 項，欄位和上面 4 項的列對不齊；原因是 auto-fit）
    const perRow = await page.locator(".ss-src-row").evaluateAll((rs) =>
      rs.map((r) => Array.from(r.querySelectorAll(".ss-src-item"))
        .map((e) => Math.round(e.getBoundingClientRect().left))));
    const cols = [...new Set(perRow.flat())].sort((a, b) => a - b);
    const widest = Math.max(...perRow.map((xs) => new Set(xs).size));
    expect(cols.length, `視窗 ${width}px 時欄位對不齊：${JSON.stringify(perRow)}`).toBe(widest);
    // 上面那條要看資料：只有「項目比欄數少、又不只一項」的列才看得出來，測試庫剛好沒有這種列。
    // 直接比每一列算出來的欄寬：auto-fit 會把用不到的欄收成 0px，欄寬就跟別列不同
    const tracks = await page.locator(".ss-src-grid").evaluateAll((gs) =>
      gs.map((g) => getComputedStyle(g).gridTemplateColumns));
    expect(new Set(tracks).size, `視窗 ${width}px 時各列欄寬不同：${JSON.stringify(tracks)}`).toBe(1);
  }
});
