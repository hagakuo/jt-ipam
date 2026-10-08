/**
 * Recog 指紋庫頁（管理 → Recog 指紋庫，比照 MAC 製造商資料庫頁）。
 *
 * - 版本資訊頁只列 Recog 的版本，點了到這一頁（使用者要求：細節跟更新不放在版本頁）
 * - 看得到裝了哪一版、幾條指紋、每個指紋檔、授權；沒裝時講「未安裝」
 * - 「立即檢查更新」：回應用路由攔截（e2e 環境不一定連得到 GitHub），驗畫面會跟著更新
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

const STATUS = {
  installed: true, release: "3.2.0", databases: 2, fingerprints: 4671, skipped: 5,
  updated_at: "2026-09-29T07:00:00+00:00", checked_at: "2026-09-29T07:30:00+00:00",
  last_ok_at: "2026-09-29T07:30:00+00:00", latest: "3.2.0", error: null,
  project_url: "https://github.com/rapid7/recog", license: "BSD-2-Clause",
  database_list: [
    { key: "http_servers", protocol: "http", database_type: "service", fingerprints: 4000 },
    { key: "ssh_banners", protocol: "ssh", database_type: "service", fingerprints: 671 },
  ],
};

test("版本頁只列版本並連到 Recog 頁；Recog 頁有版本、筆數、指紋檔、授權", async ({ page }) => {
  await login(page);
  await page.goto("/version");
  const link = page.getByTestId("version-recog-link");
  await expect(link).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("version-recog-update")).toHaveCount(0);   // 更新不在版本頁
  await link.click();
  await expect(page).toHaveURL(/\/recog$/);
  const box = page.getByTestId("recog-status");
  // 真的後端：裝了就有版本號，沒裝就寫未安裝 —— 兩種都要講清楚，不可以空白
  await expect(box).toContainText(/\d+\.\d+|未安裝/);
  await expect(box).toContainText("BSD-2-Clause");
});

test("立即檢查更新後畫面跟著變；失敗原因顯示出來", async ({ page }) => {
  let status: Record<string, unknown> = { ...STATUS, release: "3.1.30", fingerprints: 4600 };
  await page.route("**/api/v1/system/recog/status", (route) => route.fulfill({ json: status }));
  await login(page);
  await page.goto("/recog");
  await expect(page.getByTestId("recog-status")).toContainText("3.1.30");
  await page.route("**/api/v1/system/recog/update", (route) => {
    status = STATUS;
    return route.fulfill({ json: {
      result: { status: "updated", previous: "3.1.30", release: "3.2.0", latest: "3.2.0", fingerprints: 4671 },
      status: STATUS } });
  });
  await page.getByTestId("recog-update").click();
  await expect(page.locator(".n-message").filter({ hasText: "已更新到 Recog 3.2.0" })).toBeVisible();
  await expect(page.getByTestId("recog-status")).toContainText("4,671");
  await expect(page.getByText("http_servers")).toBeVisible();

  await page.unroute("**/api/v1/system/recog/update");
  await page.route("**/api/v1/system/recog/update", (route) => {
    status = { ...STATUS, error: "cannot reach GitHub (e2e)" };
    return route.fulfill({ json: {
      result: { status: "error", release: "3.2.0", error: "cannot reach GitHub (e2e)" }, status } });
  });
  await page.getByTestId("recog-update").click();
  await expect(page.getByTestId("recog-error")).toContainText("cannot reach GitHub (e2e)");
});
