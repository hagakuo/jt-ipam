/**
 * 「未裝 Agent 的 IP」可以依區段／子網路／單位篩選 —— Wazuh 與 OCS 兩頁都要（共用元件）。
 * 另外：OCS 代理版本顯示精簡版（Unix 2.10.0），原始長字串會把版本號截掉。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

for (const path of ["/wazuh", "/ocs"]) {
  test(`${path}：未裝 Agent 的 IP 依區段篩選`, async ({ page }) => {
    await login(page);
    await page.goto(path);
    await page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ }).click();
    const pane = page.locator(".n-tab-pane:visible");
    const alert = pane.locator(".n-alert").first();
    await expect(alert).toBeVisible({ timeout: 20_000 });
    const before = (await alert.innerText()).trim();

    // 選第一個區段
    await pane.locator(".n-base-selection", { hasText: "區段" }).click();
    const opt = page.locator(".n-base-select-option").first();
    const section = (await opt.innerText()).trim();
    await opt.click();
    await page.waitForTimeout(400);

    await expect(alert).toHaveText(/\d+ \/ \d+/);             // 篩選中：「篩選數 / 總數」
    expect((await alert.innerText()).trim()).not.toBe(before);
    const cells = await pane.locator(".n-data-table-tbody .n-data-table-tr").evaluateAll(
      (trs: Element[], idx: number) => trs.map((tr) => (tr.children[idx] as HTMLElement)?.innerText.trim()),
      await pane.locator(".n-data-table-th").evaluateAll((ths: Element[]) =>
        ths.findIndex((th) => (th as HTMLElement).innerText.trim().startsWith("區段"))));
    expect(cells.length).toBeGreaterThan(0);
    for (const c of cells) expect(c).toBe(section);
  });
}

test("OCS 代理版本顯示精簡版", async ({ page }) => {
  await login(page);
  await page.goto("/ocs");
  await page.locator(".n-tabs-tab", { hasText: /代理數/ }).click();
  const cell = page.locator(".n-data-table-tr", { hasText: "101" }).locator("span[title^='OCS-NG_']");
  await expect(cell).toHaveText("Unix 2.10.0", { timeout: 20_000 });
});

test("四個篩選下拉排在同一列（不是上下疊）", async ({ page }) => {
  await login(page);
  await page.goto("/wazuh");
  await page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ }).click();
  const sels = page.locator(".n-tab-pane:visible .scope-filter .n-base-selection");
  await expect(sels).toHaveCount(4, { timeout: 20_000 });
  const ys = await sels.evaluateAll((els: Element[]) => els.map((e) => Math.round(e.getBoundingClientRect().top)));
  expect(new Set(ys).size, `四個下拉的 top：${ys.join(", ")}`).toBe(1);
});

// 「有沒有上線」（2026-09-27 使用者要求）：狀態欄是 IP 清單同一顆燈號，篩選用同一套規則
for (const path of ["/wazuh", "/ocs"]) {
  test(`${path}：未裝 Agent 的 IP 依上線狀態篩選`, async ({ page }) => {
    await login(page);
    await page.goto(path);
    await page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ }).click();
    const pane = page.locator(".n-tab-pane:visible");
    await expect(pane.locator(".n-alert").first()).toBeVisible({ timeout: 20_000 });
    await expect(pane.locator(".n-data-table-th", { hasText: "狀態" })).toBeVisible();
    await expect(pane.locator(".n-data-table-tbody .live-dot").first()).toBeVisible();

    await pane.getByTestId("scope-status").click();
    const opts = page.locator(".n-base-select-option");
    await expect(opts.first()).toBeVisible();
    const labels = (await opts.allInnerTexts()).map((x) => x.trim());
    for (const l of labels) expect(["上線", "近期出現", "離線", "未知"]).toContain(l);
    await opts.first().click();
    await page.waitForTimeout(300);

    await expect(pane.locator(".n-alert").first()).toHaveText(/\d+ \/ \d+/);
    // 篩完每一列的燈號顏色都一樣（同一種狀態）
    const colors = await pane.locator(".n-data-table-tbody .live-dot").evaluateAll(
      (els: Element[]) => els.map((e) => (e as HTMLElement).style.background));
    expect(colors.length).toBeGreaterThan(0);
    expect(new Set(colors).size, colors.join(", ")).toBe(1);
  });
}

// 伺服器端分頁（2026-10-01）：大站台 5 萬筆缺口不再整份抓回來；翻頁、排序、關鍵字都由後端做
for (const path of ["/wazuh", "/ocs"]) {
  test(`${path}：未裝 Agent 的 IP 由後端分頁、排序、搜尋`, async ({ page }) => {
    await login(page);
    await page.goto(path);
    const reqs: URL[] = [];
    page.on("request", (r) => { if (r.url().includes("missing-agents")) reqs.push(new URL(r.url())); });
    const first = page.waitForResponse((r) => r.url().includes("missing-agents"));
    await page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ }).click();
    const body = await (await first).json();
    expect(Array.isArray(body), "應該拿到分頁物件而不是整份清單").toBe(false);
    expect(reqs[0].searchParams.get("page")).toBe("1");
    expect(body.items.length).toBeLessThanOrEqual(Number(reqs[0].searchParams.get("page_size")));

    const pane = page.locator(".n-tab-pane:visible");
    const rows = pane.locator(".n-data-table-tbody .n-data-table-tr");
    await expect(rows.first()).toBeVisible({ timeout: 20_000 });
    await expect(pane.locator(".n-data-table")).toContainText(`${body.total}`);   // 分頁列的總筆數是後端的 total

    // 依主機名稱排序：送 sort＋order，第一列就是整份裡排第一的（naive-ui 點一下先倒序、再點正序）
    const hostCol = await pane.locator(".n-data-table-th").evaluateAll((ths: Element[]) =>
      ths.findIndex((th) => (th as HTMLElement).innerText.trim().startsWith("主機名稱")));
    const hostTh = pane.locator(".n-data-table-th").nth(hostCol);
    const desc = page.waitForResponse((r) => r.url().includes("sort=hostname") && r.url().includes("order=desc"));
    await hostTh.click();
    const descBody = await (await desc).json();
    const names = descBody.items.map((i: { hostname: string }) => i.hostname);
    expect(names.length).toBeGreaterThan(0);
    await expect(rows.first().locator("td").nth(hostCol)).toHaveText(names[0]);
    const asc = page.waitForResponse((r) => r.url().includes("sort=hostname") && r.url().includes("order=asc"));
    await hostTh.click();
    const ascBody = await (await asc).json();
    await expect(rows.first().locator("td").nth(hostCol)).toHaveText(ascBody.items[0].hostname);
    expect(ascBody.items[0].hostname).not.toBe(names[0]);

    // 關鍵字交給後端：輸入主機名稱的一段，結果每一列都含那一段
    const needle = String(names[0]).slice(0, Math.max(3, String(names[0]).length - 1));
    const searched = page.waitForResponse((r) => r.url().includes("missing-agents") && r.url().includes("q="));
    await pane.getByTestId("missing-filter").locator("input").fill(needle);
    const sb = await (await searched).json();
    expect(sb.total).toBeGreaterThan(0);
    for (const i of sb.items) {
      expect(`${i.hostname}\n${i.ip}`.toLowerCase()).toContain(needle.toLowerCase());
    }
    await expect(pane.locator(".n-alert").first()).toHaveText(new RegExp(`${sb.total} / \\d+`));
  });
}
