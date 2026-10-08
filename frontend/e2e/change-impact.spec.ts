/**
 * 變更影響預演：開關、從 IP 頁建立、看結果、匯出、送審與覆核的權限關卡。
 *
 * 打真的後端（seed_e2e 的 198.51.100.7 有防火牆別名、規則與 NAT 引用）。功能預設關閉，
 * 這支測試開了之後在 afterAll 關回去，不影響其他測試的選單。
 */
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const SAMPLE_IP = "198.51.100.7";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function token(request: APIRequestContext): Promise<string> {
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

let ipId = "";
let wasEnabled = false;

test.beforeAll(async ({ request }) => {
  const auth = { Authorization: `Bearer ${await token(request)}` };
  wasEnabled = (await (await request.get("/api/v1/change-impact/settings", { headers: auth })).json()).enabled;
  const found = await (await request.get(`/api/v1/addresses?q=${SAMPLE_IP}&page_size=5`, { headers: auth })).json();
  ipId = found.items?.find((x: { ip: string }) => String(x.ip).split("/")[0] === SAMPLE_IP)?.id ?? "";
  expect(ipId, "找不到樣本 IP（先跑 seed_e2e）").not.toBe("");
});

test.afterAll(async ({ request }) => {
  const auth = { Authorization: `Bearer ${await token(request)}` };
  await request.put("/api/v1/change-impact/settings", { headers: auth, data: { enabled: wasEnabled } });
});

test("關閉時沒有入口；在系統設定打開後，選單與 IP 頁都出現", async ({ page, request }) => {
  const auth = { Authorization: `Bearer ${await token(request)}` };
  await request.put("/api/v1/change-impact/settings", { headers: auth, data: { enabled: false } });
  await login(page);
  await page.goto(`/addresses/${ipId}`);
  await expect(page.getByRole("button", { name: "調查" })).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("ip-change-impact-btn")).toHaveCount(0);
  await page.goto("/system-settings");
  const sw = page.getByTestId("cip-enabled-switch");
  await expect(sw).toBeVisible({ timeout: 20_000 });
  await sw.click();
  await expect(page.locator(".n-menu").getByText("變更影響預演")).toBeVisible();
  await page.goto(`/addresses/${ipId}`);
  await expect(page.getByTestId("ip-change-impact-btn")).toBeVisible({ timeout: 20_000 });
});

test("從 IP 頁預演改址：看到引用、證據、缺口與模板待辦，可以匯出；送審後的覆核要逐項處置並填理由", async ({ page, request }) => {
  const auth = { Authorization: `Bearer ${await token(request)}` };
  await request.put("/api/v1/change-impact/settings", { headers: auth, data: { enabled: true, allow_self_review: false } });
  await login(page);
  await page.goto(`/addresses/${ipId}`);
  await page.getByTestId("ip-change-impact-btn").click();
  await expect(page.getByTestId("cip-wiz-target")).toHaveText(SAMPLE_IP);
  await page.getByTestId("cip-wiz-new-ip").locator("input").fill("198.51.100.77");
  await page.getByTestId("cip-wiz-submit").click();
  await expect(page).toHaveURL(/\/change-impact\//, { timeout: 20_000 });
  await expect(page.getByTestId("cip-dryrun")).toContainText("尚未執行任何變更");
  await expect(page.getByTestId("cip-summary")).toBeVisible({ timeout: 30_000 });
  const findings = page.getByTestId("cip-findings");
  await expect(findings).toContainText("web_hosts");
  await expect(findings).toContainText("e2e-https-forward");
  // 展開一列：看得到證據的來源與收錄時間、規則版本
  await page.locator(".n-data-table-expand-trigger").first().click();
  await expect(findings).toContainText("v1");
  await page.locator(".n-tabs-tab", { hasText: "證據與資料缺口" }).click();
  await expect(page.getByTestId("cip-gaps")).toContainText("來源或目的為 any 的規則不逐條列出");
  await page.locator(".n-tabs-tab", { hasText: "待辦與復原" }).click();
  await expect(page.getByTestId("cip-phase-rollback")).toContainText("198.51.100.7");
  await expect(page.getByTestId("cip-phase-change")).toContainText("防火牆");
  // 匯出 Markdown
  await page.getByRole("button", { name: "匯出" }).hover();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByText("Markdown", { exact: true }).click()]);
  expect(dl.suggestedFilename()).toMatch(/\.md$/);
  // 送審 → 覆核：沒填處置與理由就送不出去
  await page.getByTestId("cip-act-submit").click();
  await expect(page.getByTestId("cip-lifecycle")).toHaveText("送審中");
  await page.getByTestId("cip-act-review").click();
  await page.getByTestId("cip-review-submit").click();
  await expect(page.locator(".n-message")).toContainText(/不能覆核自己的計畫|需要處置|reason|理由/);
});
