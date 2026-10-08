/**
 * 主控台連線表單上的「連線路徑」：按連線之前就看得到走直連、哪台跳板或哪台掃描代理，走不通的話原因。
 * 跳板改放在掃描代理頁的頁籤：左側選單不再有獨立一項，舊的 /jump-hosts 網址照樣到得了。
 *
 * 種子資料（tests/seed_e2e.py）：127.0.0.1（console-target）開了 SSH／RDP／VNC，子網路沒有設出口＝直連。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function consoleTargetId(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const tok = localStorage.getItem("access_token") || "";
    const r = await fetch("/api/v1/addresses?q=127.0.0.1&page_size=5", { headers: { Authorization: `Bearer ${tok}` } });
    const items = (await r.json()).items as { id: string; ip: string }[];
    return items.find((i) => i.ip.split("/")[0] === "127.0.0.1")!.id;
  });
}

for (const kind of ["ssh", "sftp", "rdp", "vnc"]) {
  test(`${kind.toUpperCase()} 連線表單顯示連線路徑（直連）`, async ({ page }) => {
    await login(page);
    const id = await consoleTargetId(page);
    await page.goto(`/${kind}/${id}`);
    const note = page.getByTestId("console-route-note");
    await expect(note).toBeVisible({ timeout: 15_000 });
    await expect(note).toContainText("連線路徑：直連");
    await expect(page.getByTestId("console-route-error")).toHaveCount(0);
  });
}

test("「變更」就地開視窗改這個 IP 的出口，不會跳到子網路頁；也能開子網路的編輯視窗", async ({ page }) => {
  await login(page);
  // 專用的 10.20.0.41（seed_e2e），不動共用的 console-target —— 其他平行跑的主控台 spec 會用到它
  const ids = await page.evaluate(async () => {
    const tok = localStorage.getItem("access_token") || "";
    const H = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" };
    const r = await fetch("/api/v1/addresses?q=10.20.0.41&page_size=5", { headers: H });
    const ip = ((await r.json()).items as { id: string; ip: string }[]).find((i) => i.ip.split("/")[0] === "10.20.0.41")!;
    await fetch(`/api/v1/addresses/${ip.id}`, { method: "PATCH", headers: H,
      body: JSON.stringify({ jump_host_id: null, console_agent_id: null }) });   // 上次殘留
    const j = await fetch("/api/v1/jump-hosts", { method: "POST", headers: H, body: JSON.stringify({
      name: `e2e-route-${Date.now()}`, host: "198.51.100.9", port: 22, username: "e2e",
      auth_kind: "password", password: "x", enabled: true }) });
    return { ipId: ip.id, jumpId: (await j.json()).id as string };
  });
  try {
    await page.goto(`/ssh/${ids.ipId}`);
    const note = page.getByTestId("console-route-note");
    await expect(note).toContainText("連線路徑：直連", { timeout: 15_000 });

    await page.getByTestId("console-route-change").click();
    const dlg = page.getByTestId("console-route-edit");
    await expect(dlg).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/ssh/${ids.ipId}$`));     // 以前會跳到子網路頁
    await dlg.getByTestId("console-egress").locator(".n-base-selection").click();
    await page.locator(".n-base-select-option", { hasText: "e2e-route-" }).first().click();
    await dlg.getByTestId("console-route-save").click();
    await expect(dlg).toBeHidden();
    await expect(note).toContainText("經由跳板「e2e-route-", { timeout: 10_000 });
    await expect(note).toContainText("此 IP 的設定");

    // 整個子網路一起改 → 子網路的編輯視窗（與子網路頁同一個元件）
    await page.getByTestId("console-route-change").click();
    await page.getByTestId("console-route-edit-subnet").click();
    await expect(page.locator(".n-card-header", { hasText: "編輯 子網路" })).toBeVisible();
  } finally {
    await page.evaluate(async ({ ipId, jumpId }) => {
      const tok = localStorage.getItem("access_token") || "";
      const H = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" };
      await fetch(`/api/v1/addresses/${ipId}`, { method: "PATCH", headers: H,
        body: JSON.stringify({ jump_host_id: null, console_agent_id: null }) });
      await fetch(`/api/v1/jump-hosts/${jumpId}`, { method: "DELETE", headers: H });
    }, ids);
  }
});

test("跳板在掃描代理頁的頁籤；左側選單沒有獨立一項，舊網址轉過來", async ({ page }) => {
  await login(page);
  await page.goto("/jump-hosts");
  await expect(page).toHaveURL(/\/scan-agents\?tab=jump/);
  await expect(page.getByRole("button", { name: "需求與設定" })).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("agent-tabs").locator(".n-tabs-tab", { hasText: "掃描代理" }).click();
  await expect(page).not.toHaveURL(/tab=jump/);
  await expect(page.locator(".n-menu").getByText("跳板主機", { exact: true })).toHaveCount(0);
});
