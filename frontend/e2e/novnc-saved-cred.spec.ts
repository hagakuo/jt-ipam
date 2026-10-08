/**
 * noVNC：勾「記住此帳密」連線失敗後，已存帳密的下拉要顯示名稱，不是一串 UUID。
 *
 * 使用者回報（2026-09-24）：下拉顯示一串 UUID。原因是存完只把選取值設成新的 id、
 * 沒有重新載入清單，下拉找不到對應選項就把值原樣印出來；連線一失敗回到表單就會看到。
 * 同一個畫面的錯誤也要講清楚是哪一組帳密被拒、要的是 PVE 的帳密。
 *
 * 樣本：seed_e2e 的 vm-novnc-01（10.20.0.232），PVE 連線實例指到 RFC 5737 的保留位址，
 * 一定連不上 —— 帳密是在向 PVE 要 ticket 之前存的，所以不需要真的 PVE。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const IP = "10.20.0.232";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function api(page: Page, method: string, path: string) {
  return page.evaluate(async ({ method, path }) => {
    const r = await fetch(path, { method,
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` } });
    return { status: r.status, json: r.status === 204 ? null : await r.json().catch(() => null) };
  }, { method, path });
}

test("記住帳密後連線失敗，下拉顯示已存帳密的名稱而不是 UUID", async ({ page }) => {
  await login(page);
  const found = await api(page, "GET", `/api/v1/addresses?q=${IP}&page_size=20`);
  const ipId = found.json.items.find((x: any) => String(x.ip).split("/")[0] === IP).id;
  // 前一輪留下的已存帳密先清掉（這個測試要從「沒有任何已存帳密」開始）
  const old = await api(page, "GET", `/api/v1/ssh-credentials?protocol=pve&target_ip_id=${ipId}`);
  for (const c of old.json) await api(page, "DELETE", `/api/v1/ssh-credentials/${c.id}`);

  await page.goto(`/novnc/${ipId}`);
  const form = page.locator(".vnc-form");
  await form.getByPlaceholder("root").fill("root");
  await form.locator("input[type=password]").fill("e2e-not-the-password");
  await form.locator(".n-form-item").filter({ hasText: "記住此帳密" }).locator(".n-switch").click();
  await form.getByRole("button", { name: /連線/ }).click();

  // 連不上 → 回到表單並顯示錯誤；錯誤要是後端講的原因（以前前端先逾時，只剩一句「取得連線票證失敗」）
  const err = form.locator(".n-alert").filter({ hasText: "PVE" }).first();
  await expect(err).toBeVisible({ timeout: 30_000 });
  await expect(err).toContainText("198.51.100.250");
  const picked = form.locator(".n-base-selection").first();
  await expect(picked).toContainText(`pve@${IP}（root@pam）`);
  await expect(picked).not.toContainText(/[0-9a-f]{8}-[0-9a-f]{4}-/);

  const after = await api(page, "GET", `/api/v1/ssh-credentials?protocol=pve&target_ip_id=${ipId}`);
  for (const c of after.json) await api(page, "DELETE", `/api/v1/ssh-credentials/${c.id}`);
});
