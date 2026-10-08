/**
 * 掃描代理負載面板（2026-09-28 使用者要求「自動記錄每輪 scan 花多久，太長要通知管理員」）。
 * 建一台測試代理、用它的金鑰回報一輪過重的統計，然後從畫面操作：清單的負載欄 → 面板 → 建議與逐子網路。
 * 通知裡的連結（/scan-agents?load=<id>）要直接打開那一台的面板。
 */
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

let agentId = "";
let agentName = "";
let token = "";

async function adminToken(request: APIRequestContext): Promise<string> {
  const r = await request.post("/api/v1/auth/login", { data: { username: ADMIN_USER, password: ADMIN_PASS, realm: "local" } });
  expect(r.ok()).toBeTruthy();
  return (await r.json()).access_token;
}

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test.beforeAll(async ({ request }) => {
  token = await adminToken(request);
  agentName = `e2e-load-${Date.now().toString(36)}`;
  const r = await request.post("/api/v1/scan-agents", { headers: { Authorization: `Bearer ${token}` }, data: { name: agentName } });
  expect(r.status(), await r.text()).toBe(201);
  const ag = await r.json();
  agentId = ag.id;
  const cycle = {
    duration_s: 290, interval_s: 300, heavy_backlog: 12,
    subnets: [
      { cidr: "198.51.100.0/24", hosts: 254, total_hosts: 254, alive: 40, duration_s: 200, truncated: false },
      { cidr: "203.0.113.0/24", hosts: 254, total_hosts: 254, alive: 20, duration_s: 60, truncated: false },
      { cidr: "192.0.2.0/24", hosts: 254, total_hosts: 254, alive: 10, duration_s: 30, truncated: false },
    ],
  };
  for (let i = 0; i < 2; i++) {
    const rep = await request.post("/api/v1/scan-agents/report", {
      headers: { "X-Agent-Key": ag.enroll_key }, data: { results: [], cycle } });
    expect(rep.ok(), await rep.text()).toBeTruthy();
  }
});

test.afterAll(async ({ request }) => {
  if (agentId) await request.delete(`/api/v1/scan-agents/${agentId}`, { headers: { Authorization: `Bearer ${token}` } });
});

test("清單的負載欄 → 面板：耗時、趨勢、建議、逐子網路", async ({ page }) => {
  await login(page);
  await page.goto("/scan-agents");
  const row = page.locator(".n-data-table-tr", { hasText: agentName });
  const cell = row.getByTestId("scan-load-cell");
  await expect(cell).toContainText("97%", { timeout: 20_000 });
  await expect(cell).toContainText("待辦 12");
  await cell.click();

  const panel = page.locator(".n-drawer");
  await expect(panel.getByTestId("scan-load-summary")).toContainText("過重");
  await expect(panel.getByTestId("scan-load-summary")).toContainText("97%");
  await expect(panel.getByTestId("scan-load-trend")).toBeVisible();
  // 建議要能直接照做：移掉最慢的 198.51.100.0/24 就能降到 70% 以下
  await expect(panel.getByTestId("scan-load-suggestions")).toContainText("198.51.100.0/24");
  await expect(panel.getByTestId("scan-load-suggestions")).toContainText("70%");
  const subs = panel.getByTestId("scan-load-subnets");
  await expect(subs).toContainText("203.0.113.0/24");
  await expect(subs).toContainText("787.4 ms");      // 200 秒 ÷ 254 個位址
});

test("通知的連結直接打開那一台的面板，手機上也不超出畫面", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  await page.goto(`/scan-agents?load=${agentId}`);
  const panel = page.locator(".n-drawer");
  await expect(panel.getByTestId("scan-load-summary")).toBeVisible({ timeout: 20_000 });
  await expect(panel).toContainText(agentName);
  // 抽屜是滑進來的：等動畫停下來再量
  await expect.poll(async () => {
    const b = (await panel.boundingBox())!;
    return b.x >= 0 && b.x + b.width <= 391;
  }, { timeout: 5_000 }).toBe(true);
});
