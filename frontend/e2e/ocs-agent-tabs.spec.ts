/**
 * OCS 整合頁要比照 Wazuh：「代理數」與「未裝 Agent 的 IP」兩個頁籤。
 * 代理數要一台電腦一筆 —— seed_e2e 的 web-01 與 198.51.100.7 是同一台 OCS 電腦（id 101）。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

test("OCS：代理數一台電腦一筆、未裝 Agent 的 IP 不含已盤點的", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/ocs");

  const agentsTab = page.locator(".n-tabs-tab", { hasText: /代理數/ });
  await expect(agentsTab).toHaveText(/代理數 \(1\)/, { timeout: 20_000 });
  const missingTab = page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ });
  await expect(missingTab).toBeVisible();

  await agentsTab.click();
  const row = page.locator(".n-data-table-tr", { hasText: "101" }).first();
  await expect(row).toContainText("10.20.0.10");
  await expect(row).toContainText("198.51.100.7");
  await expect(row).toContainText("E2E");

  await missingTab.click();
  const missTable = page.locator(".n-tab-pane:visible .n-data-table").first();
  await expect(missTable).toContainText("10.20.0.11");            // app-01：有名字、沒盤點
  await expect(missTable).not.toContainText("10.20.0.10");        // web-01 已盤點
});

async function api(page: import("@playwright/test").Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const r = await fetch(path, { method, body: body === undefined ? undefined : JSON.stringify(body),
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}`,
                 "Content-Type": "application/json" } });
    return { status: r.status, json: r.status === 204 ? null : await r.json().catch(() => null) };
  }, { method, path, body });
}

test("OCS：限定子網路範圍後，未裝 Agent 的 IP 只列範圍內的", async ({ page }) => {
  // 使用者要求（2026-09-25）：OCS 也要能像 Wazuh 一樣限定子網路；限定後清單要跟著清理
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto("/ocs");
  const servers = (await api(page, "GET", "/api/v1/ocs")).json.items;
  try {
    const row = page.locator(".n-data-table-tr", { hasText: servers[0].name }).first();
    await row.locator(".col-actions button").first().click();         // 編輯
    const dlg = page.locator(".n-modal");
    const item = dlg.locator(".n-form-item").filter({ hasText: "限定子網路範圍" });
    await expect(item).toContainText("未裝 Agent 的 IP");
    await item.locator(".n-base-selection").click();
    await page.locator(".n-base-select-option", { hasText: "198.51.100.0/24" }).click();
    await dlg.locator(".n-card-header").click();                      // 收起下拉（Escape 會把整個對話框關掉）
    await dlg.getByRole("button", { name: /儲存/ }).click();
    await expect(dlg).toBeHidden();

    const saved = (await api(page, "GET", "/api/v1/ocs")).json.items[0];
    expect(saved.scope_subnet_ids).toHaveLength(1);

    await page.locator(".n-tabs-tab", { hasText: /未裝 Agent 的 IP/ }).click();
    const pane = page.locator(".n-tab-pane:visible");
    await expect(pane.locator(".n-alert")).toContainText("只列整合設定的限定子網路範圍");
    await expect(pane.locator(".n-data-table").first()).not.toContainText("10.20.0.11");
  } finally {
    for (const s of servers) await api(page, "PATCH", `/api/v1/ocs/${s.id}`, { scope_subnet_ids: [] });
  }
});
