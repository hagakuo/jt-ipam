/**
 * 子網路 IP 清單的篩選要能疊加（使用者回報：開了「只看失聯 IP」再開「只看 DHCP」，清單沒有再縮小）。
 * 原因是篩選寫成一連串提前 return，開了失聯就直接回傳，DHCP 永遠套不到。
 * IP 清單與 DHCP 範圍用路由攔截固定四筆：失聯＋DHCP、失聯、DHCP、都不是。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("只看失聯＋只看 DHCP＋篩選字 三者疊加", async ({ page }) => {
  await login(page);
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  const subs = await (await page.request.get("/api/v1/subnets?page_size=200", {
    headers: { Authorization: `Bearer ${token}` } })).json();
  const sub = (subs.items ?? subs).find((s: { cidr: string }) => String(s.cidr).startsWith("10.20.0.0"));
  expect(sub, "找不到 10.20.0.0/24（先跑 seed_e2e）").toBeTruthy();

  const old = new Date(Date.now() - 60 * 86400000).toISOString();
  const now = new Date().toISOString();
  const ip = (n: number, seen: string, host: string) => ({
    id: `00000000-0000-4000-8000-0000000000${n}`, ip: `10.20.0.${n}`, hostname: host, state: "active",
    subnet_id: sub.id, mac: null, last_seen_scanner: seen, last_seen_librenms: null,
    subnet_scan_enabled: true, exclude_from_ping: false, description: null });
  const items = [ip(10, old, "lost-dhcp"), ip(11, old, "lost-static"), ip(12, now, "up-dhcp"), ip(13, now, "up-static")];
  await page.route(/\/api\/v1\/addresses\?.*subnet_id=/, (route) =>
    route.fulfill({ json: { items, total: items.length, page: 1, page_size: 1000 } }));
  await page.route("**/api/v1/dhcp-ranges", (route) =>
    route.fulfill({ json: [{ start_ip: "10.20.0.10", end_ip: "10.20.0.10", source: "manual", source_name: null },
                           { start_ip: "10.20.0.12", end_ip: "10.20.0.12", source: "manual", source_name: null }] }));

  await page.goto(`/subnets/${sub.id}`);
  const hosts = () => page.locator(".n-data-table-td", { hasText: /^(lost|up)-/ }).allInnerTexts();
  await expect.poll(async () => (await hosts()).sort()).toEqual(["lost-dhcp", "lost-static", "up-dhcp", "up-static"]);

  await page.getByRole("button", { name: /只看失聯/ }).click();
  await expect.poll(async () => (await hosts()).sort()).toEqual(["lost-dhcp", "lost-static"]);
  await page.getByRole("button", { name: /只看 DHCP/ }).click();
  await expect.poll(async () => (await hosts()).sort()).toEqual(["lost-dhcp"]);
  await expect(page.getByText(/符合 1 個/)).toBeVisible();

  // 關掉失聯、留 DHCP：兩筆在 DHCP 範圍內
  await page.getByRole("button", { name: /只看失聯/ }).click();
  await expect.poll(async () => (await hosts()).sort()).toEqual(["lost-dhcp", "up-dhcp"]);
  // 再加篩選字
  await page.getByPlaceholder("篩選").fill("up-");
  await expect.poll(async () => (await hosts()).sort()).toEqual(["up-dhcp"]);
});
