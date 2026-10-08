/**
 * 清單換頁之後點進一筆、再按上一頁，要回到原本那一頁，不是第 1 頁（使用者 2026-10-05）。
 * 頁碼記在網址上（?page=2）。種子資料的子網路沒有多到要分頁，把位址清單的回應複製成 120 筆。
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

test("子網路的 IP 清單：第 2 頁點出去再按上一頁，還在第 2 頁", async ({ page }) => {
  await login(page);
  const subnetId = await page.evaluate(async () => {
    const tok = localStorage.getItem("access_token") || "";
    const r = await fetch("/api/v1/subnets?q=10.20.0.0&page_size=20", { headers: { Authorization: `Bearer ${tok}` } });
    return ((await r.json()).items as { id: string; cidr: string }[]).find((s) => s.cidr === "10.20.0.0/24")!.id;
  });
  await page.route((u) => u.pathname === "/api/v1/addresses" && u.searchParams.get("subnet_id") === subnetId,
    async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      const base = body.items[0];
      body.items = Array.from({ length: 120 }, (_, i) => ({
        ...base, id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
        ip: String(base.ip).replace(/^10\.20\.0\.\d+/, `10.20.0.${i + 2}`),
        hostname: `pg-${i}`,
      }));
      body.total = 120;
      await route.fulfill({ response: res, json: body });
    });
  await page.goto(`/subnets/${subnetId}`);
  await expect(page.getByText("pg-0", { exact: true })).toBeVisible({ timeout: 15_000 });
  await page.locator(".n-pagination-item", { hasText: /^2$/ }).first().click();
  await expect(page).toHaveURL(/[?&]page=2/);
  await expect(page.getByText("pg-100", { exact: true })).toBeVisible();
  await page.goto("/");
  await page.goBack();
  await expect(page).toHaveURL(/[?&]page=2/);
  await expect(page.getByText("pg-100", { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("pg-0", { exact: true })).toHaveCount(0);
});
