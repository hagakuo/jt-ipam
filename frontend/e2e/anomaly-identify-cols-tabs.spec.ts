/**
 * 2026-09-29 使用者回饋的四件事，一次在瀏覽器裡量：
 * 1. 異常偵測清單的操作欄有「探測」—— IPAM 有記錄的開那筆記錄的探測頁；未授權 IP（IPAM 沒有記錄）
 *    以位址探測，頁面標出「IPAM 沒有記錄」
 * 2. 欄寬依內容：值很短的欄（狀況、來源、介面、埠）不跟長欄平分，空間留給最後一欄「說明」
 * 3. 表格欄寬可以拖拉（全站 NDataTable；手寫表格走 v-col-resize）
 * 4. 頁籤列放不下時兩端有左右捲動按鈕（沒有滾輪也到得了最左、最右）
 *
 * 異常偵測結果與探測的「發起／歷史」用路由攔截固定回應（e2e 環境沒有代理、也沒有真的異常），
 * 以位址探測的「這個位址歸哪個子網路」打真的後端（seed_e2e 的 10.20.0.0/24）。
 */
import { escapeRegExp } from "./fixtures/regexp";
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const UNREG_IP = "10.20.0.200";      // 在 seed 的 10.20.0.0/24 裡，但 IPAM 沒有記錄
const RECORD_IP = "10.20.0.12";      // seed 的 db-01

const REPORT = {
  ip_conflicts: [], mac_drifts: [], rogue_dhcp: [], external_exposure: [], dangling_dns: [],
  duplicate_ip_records: [], suspicious_changes: [], arp_only_liveness: [], stale_device_links: [],
  mac_flapping: [],
  unauthorized_ips: [{ ip: UNREG_IP }],
  ghost_ips: [] as Record<string, unknown>[],
  fw_rule_rot: [
    { kind: "dangling_nat", firewall: "fw-edge-01", name: "web forward", source: "opnsense",
      interface: "WAN", port: 8443, descr: "",
      detail: "埠轉發的目標位址不在 IPAM —— 目標可能已回收，或從未登記", detail_key: "anomaly.rot.dangling_nat" },
    { kind: "any_any", firewall: "fw-branch-02", name: "", source: "pfsense", interface: "openvpn", descr: "",
      detail: "any → any 放行 —— 等於這個介面沒有防火牆", detail_key: "anomaly.rot.any_any" },
  ],
};

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function recordId(page: Page): Promise<string> {
  const r = await page.request.get(`/api/v1/addresses?q=${RECORD_IP}&page_size=5`, {
    headers: { Authorization: `Bearer ${await page.evaluate(() => localStorage.getItem("access_token") || "")}` },
  });
  const items = (await r.json()).items ?? [];
  return items.find((x: { ip: string }) => String(x.ip).split("/")[0] === RECORD_IP)?.id ?? "";
}

async function openAnomaly(page: Page, report: typeof REPORT) {
  await page.route("**/api/v1/anomalies/scan", (route) => route.fulfill({ json: report }));
  await page.goto("/anomaly");
  await page.getByRole("button", { name: /執行偵測/ }).click();
}

test("未授權 IP 的操作欄有「探測」→ 以位址探測（IPAM 沒有記錄）", async ({ page }) => {
  let posted = false;
  await page.route(/\/api\/v1\/identify\/ip\/[^/]+\/history$/, (route) => route.fulfill({ json: { items: [] } }));
  await page.route(/\/api\/v1\/identify\/ip\/[^/]+$/, async (route) => {
    if (route.request().method() === "POST") {
      posted = true;
      return route.fulfill({ status: 202, json: { job_id: "00000000-0000-4000-8000-00000000e2f1", agent_id: "a",
                                                   agent_name: "agent-e2e", status: "pending" } });
    }
    return route.fallback();          // 「歸哪個子網路」打真的後端
  });
  await login(page);
  await openAnomaly(page, REPORT);
  await page.getByText(/未授權 IP \(1\)/).click();

  const btn = page.getByTestId("anomaly-identify").first();
  await expect(btn).toBeVisible();
  // 同一欄還有 AI 判讀；探測在最前面
  const ai = page.getByRole("button", { name: "AI 判讀" }).first();
  expect((await btn.boundingBox())!.x).toBeLessThan((await ai.boundingBox())!.x);

  await btn.click();
  await expect(page).toHaveURL(new RegExp(`/identify/ip/${escapeRegExp(UNREG_IP)}`));
  await expect(page.getByTestId("identify-unregistered")).toContainText("IPAM 沒有記錄");
  await expect(page.getByTestId("identify-unregistered")).toContainText("10.20.0.0/24");
  const start = page.getByTestId("identify-start");
  await expect(start).toBeEnabled();
  await start.click();
  await expect.poll(() => posted).toBe(true);

  // 返回：回到異常偵測
  await page.getByRole("button", { name: "返回" }).click();
  await expect(page).toHaveURL(/\/anomaly/);
});

test("有 IP 記錄的列：探測開那筆記錄的探測頁；不在管理網段的位址講清楚", async ({ page }) => {
  await login(page);
  const id = await recordId(page);
  expect(id, "找不到 seed 的樣本 IP（先跑 seed_e2e）").not.toBe("");
  await openAnomaly(page, { ...REPORT, ghost_ips: [{ ip: RECORD_IP, hostname: "db-01", ip_address_id: id,
                                                     last_seen_scanner: null, last_seen_librenms: null }] });
  await page.getByText(/失聯 IP \(1\)/).click();
  await page.getByTestId("anomaly-identify").first().click();
  await expect(page).toHaveURL(new RegExp(`/addresses/${id}/identify`));

  // 直接開一個不在任何子網路的位址：頁面說明原因，不給按
  await page.goto("/identify/ip/198.18.255.77");
  await expect(page.getByText("不在 IPAM 管理的子網路內")).toBeVisible();
  await expect(page.getByTestId("identify-start")).toBeDisabled();
});

test("防火牆規則劣化：短欄依內容、說明欄拿到剩下的寬度；欄寬可以拖拉；狀況翻成字", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  await openAnomaly(page, REPORT);
  await page.getByText(/防火牆規則劣化 \(2\)/).click();
  const pane = page.locator(".n-tab-pane:visible");
  await expect(pane.locator("td").filter({ hasText: "埠轉發目標不在 IPAM" }).first()).toBeVisible();
  await expect(pane.locator("td").filter({ hasText: /^dangling_nat$/ })).toHaveCount(0);
  await expect(pane.locator("thead")).toContainText("防火牆");
  await expect(pane.locator("td").filter({ hasText: "fw-edge-01" })).toHaveCount(1);

  const th = (label: string) => pane.locator("th").filter({ hasText: new RegExp(`^${label}$`) }).first();
  const w = async (label: string) => (await th(label).boundingBox())!.width;
  const detail = await w("說明");
  for (const short of ["來源", "介面", "埠"]) {
    expect(await w(short), `${short} 不該跟說明平分寬度`).toBeLessThan(detail / 2.5);
  }
  // 說明整句看得到（不再被截成「…不在 IPA…」）：1440 寬時一行放得下，窄的時候換行也不截斷
  const cell = pane.locator("td").filter({ hasText: "埠轉發的目標位址不在 IPAM" }).first();
  await expect(cell).toContainText("目標可能已回收，或從未登記");
  expect(await cell.evaluate((el) => el.scrollWidth > el.clientWidth + 1), "說明欄被截斷").toBe(false);
  expect(await cell.locator(".n-data-table-td__ellipsis, .n-ellipsis").count(), "說明欄不該用省略號").toBe(0);
  const lineH = parseFloat(await cell.evaluate((el) => getComputedStyle(el).lineHeight)) || 20;
  expect((await cell.boundingBox())!.height, "1440 寬時說明應該一行放得下").toBeLessThan(lineH * 2 + 16);

  // 拖拉「來源」的右緣 +80px → 變寬約 80px
  const before = await w("來源");
  const handle = th("來源").locator(".n-data-table-resize-button");
  const hb = (await handle.boundingBox())!;
  await page.mouse.move(hb.x + hb.width / 2, hb.y + hb.height / 2);
  await page.mouse.down();
  await page.mouse.move(hb.x + hb.width / 2 + 40, hb.y + hb.height / 2, { steps: 4 });
  await page.mouse.move(hb.x + hb.width / 2 + 80, hb.y + hb.height / 2, { steps: 4 });
  await page.mouse.up();
  const after = await w("來源");
  expect(after - before).toBeGreaterThan(60);
  expect(after - before).toBeLessThan(100);
});

test("頁籤列放不下時兩端有左右捲動按鈕，按得到最左、最右", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await login(page);
  await openAnomaly(page, REPORT);
  const nav = page.locator(".n-tabs-nav-scroll-wrapper").first();
  const left = nav.getByTestId("tabs-scroll-left");
  const right = nav.getByTestId("tabs-scroll-right");
  await expect(right).toBeVisible();
  await expect(left).toBeHidden();
  const scroller = nav.locator("> div").first();
  const sl = () => scroller.evaluate((el) => el.scrollLeft);

  await right.click();
  await expect.poll(sl).toBeGreaterThan(100);
  await expect(left).toBeVisible();

  // 一直按右：最後一個頁籤完整進到畫面、右箭頭消失
  for (let i = 0; i < 8 && await right.isVisible(); i++) { await right.click(); await page.waitForTimeout(400); }
  await expect(right).toBeHidden();
  const last = page.locator(".n-tabs-tab").filter({ hasText: /IP 頻繁更換 MAC/ }).first();
  const lb = (await last.boundingBox())!;
  const nb = (await nav.boundingBox())!;
  expect(lb.x + lb.width).toBeLessThanOrEqual(nb.x + nb.width + 1);

  // 往左按到底：回到第一個頁籤，左箭頭消失
  await left.dblclick();
  await expect.poll(sl).toBeLessThan(2);
  await expect(left).toBeHidden();

  // 箭頭不能蓋掉可點的頁籤：點最左邊的頁籤仍切得過去
  await page.locator(".n-tabs-tab").filter({ hasText: /IP 衝突/ }).first().click();
  await expect(page.locator(".n-tabs-tab--active")).toContainText("IP 衝突");
});

test("手寫的表格（通知矩陣）欄寬也能拖拉", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  await page.goto("/notification-channels");
  const th = page.locator("table.nmx thead th").first();
  await expect(th).toBeVisible({ timeout: 20_000 });
  const before = (await th.boundingBox())!.width;
  const hb = (await th.locator(".jt-col-resize").boundingBox())!;
  await page.mouse.move(hb.x + hb.width / 2, hb.y + hb.height / 2);
  await page.mouse.down();
  await page.mouse.move(hb.x + hb.width / 2 + 60, hb.y + hb.height / 2, { steps: 5 });
  await page.mouse.up();
  const after = (await th.boundingBox())!.width;
  expect(after - before).toBeGreaterThan(45);
  expect(after - before).toBeLessThan(75);
});
