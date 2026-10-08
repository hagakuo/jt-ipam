/**
 * SFTP 單檔上限可以在系統設定改，改了會自動實測傳輸路徑（使用者要求，2026-09-26）。
 *
 * 路徑上任何一層（前端反向代理、IPAM 的 nginx）吃不下，都要在設定頁當場講出來 ——
 * 這些設定讀不到，只能由瀏覽器實際送一次。這裡驗兩件事：
 *   ① 正常的路：顯示上下傳速度與「傳一個上限大小的檔案要多久」
 *   ② 有問題的路：傳到一半被以「訊息太大」（1009）切斷 → 講出是單一訊息大小被限制
 *      （用 routeWebSocket 模擬一個會這樣做的代理）
 */
import { test, expect, type Page } from "@playwright/test";

const PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!PASS, "需要 E2E_ADMIN_PASS");
test.setTimeout(120_000);

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(process.env.E2E_ADMIN_USER || "admin");
  await page.getByPlaceholder(/密碼|Password/).fill(PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));
}

async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const r = await fetch(path, { method, body: body === undefined ? undefined : JSON.stringify(body),
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}`, "Content-Type": "application/json" } });
    return { status: r.status, json: await r.json().catch(() => null) };
  }, { method, path, body });
}

let saved: Record<string, unknown> = {};

test.beforeEach(async ({ page }) => {
  await login(page);
  const cs = await api(page, "GET", "/api/v1/system/console-security");
  saved = { rdp_clipboard_paste: cs.json.rdp_clipboard_paste, rdp_engine: cs.json.rdp_engine,
            vnc_engine: cs.json.vnc_engine, ssh_engine: cs.json.ssh_engine,
            sftp_max_file_mb: cs.json.sftp_max_file_mb };
  await api(page, "PUT", "/api/v1/system/console-security", { ...saved, sftp_max_file_mb: 100 });
});

test.afterEach(async ({ page }) => {
  await api(page, "PUT", "/api/v1/system/console-security", saved);
});

const field = (page: Page) => page.locator(".fld.sftp-max");

test("調高上限：存起來並自動實測路徑，講出速度與估算時間", async ({ page }) => {
  await page.goto("/system-settings");
  const input = field(page).locator("input");
  await expect(input).toHaveValue("100", { timeout: 20_000 });
  await input.fill("2048");
  await input.press("Enter");
  // 改了就自動檢查（不用另外按）
  const result = field(page).locator(".sftp-probe-result");
  await expect(result).toContainText("傳輸路徑正常", { timeout: 60_000 });
  await expect(result).toContainText("2.0 GB");
  await expect(result).toContainText(/上傳約每秒 [\d.]+ (MB|KB)/);
  // 真的存進去了
  const cs = await api(page, "GET", "/api/v1/system/console-security");
  expect(cs.json.sftp_max_file_mb).toBe(2048);
  // 上限放大過：重新打開頁面也會自動檢查一次（路徑可能在設定之後才變）
  await page.reload();
  await expect(field(page).locator(".sftp-probe-result")).toContainText("傳輸路徑正常", { timeout: 60_000 });
});

test("路上有一層限制訊息大小：講出是 1009「訊息太大」", async ({ page }) => {
  await api(page, "PUT", "/api/v1/system/console-security", { ...saved, sftp_max_file_mb: 4096 });
  // 模擬一個會把大訊息切斷的代理：握手照常、ready 照常，第一個資料框一到就以 1009 關閉
  await page.routeWebSocket(/\/00000000-0000-0000-0000-000000000000\/sftp\/ws/, (ws) => {
    ws.send(JSON.stringify({ type: "ready", probe: true }));
    ws.onMessage((m) => {
      if (typeof m === "string") {
        const req = JSON.parse(m);
        if (req.type === "put") ws.send(JSON.stringify({ type: "put_ready", id: req.id }));
      } else {
        ws.close({ code: 1009, reason: "message too big" });
      }
    });
  });
  await page.goto("/system-settings");
  const result = field(page).locator(".sftp-probe-result");
  await expect(result).toContainText("訊息太大", { timeout: 60_000 });
  await expect(result).toContainText("1009");
  await expect(result).not.toContainText("傳輸路徑正常");
});

test("上限超出範圍：不存、提示範圍、輸入框回到原值（不可以被夾到邊界後存下去）", async ({ page }) => {
  await page.goto("/system-settings");
  const input = field(page).locator("input");
  await expect(input).toHaveValue("100", { timeout: 20_000 });
  for (const bad of ["0", "999999"]) {
    await input.fill(bad);
    await input.press("Enter");
    await expect(page.getByText("1～102400 MB").first()).toBeVisible();
    await expect(input).toHaveValue("100");
  }
  const cs = await api(page, "GET", "/api/v1/system/console-security");
  expect(cs.json.sftp_max_file_mb).toBe(100);
});
