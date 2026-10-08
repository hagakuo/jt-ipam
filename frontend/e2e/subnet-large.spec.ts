/**
 * 超大規模的子網路頁（2026-09-29）：一個 /16 有六萬多個已登記的位址。
 *
 * - 這一頁一次最多載入 1,000 筆：超過時要講清楚只列了前面這些，並連到可以分頁搜尋的 IP 位址清單
 * - 表格分頁（1,000 列一次畫出來會讓瀏覽器卡住將近十秒）
 * - IP 指示計用後端彙總的每個 /24 已用數（拿前 1,000 筆來畫只剩幾格）
 */
import { test, expect, type Page, type APIRequestContext } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function token(request: APIRequestContext): Promise<string> {
  const r = await request.post("/api/v1/auth/login", { data: { username: ADMIN_USER, password: ADMIN_PASS, realm: "local" } });
  return (await r.json()).access_token;
}
async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("/16：截斷提示、表格分頁、指示計用後端彙總", async ({ page, request }) => {
  const auth = { Authorization: `Bearer ${await token(request)}` };
  const sections = await (await request.get("/api/v1/sections", { headers: auth })).json();
  const sectionId = (sections.items ?? sections)[0].id;
  const cidr = `10.${240 + (Date.now() % 10)}.0.0/16`;
  const created = await request.post("/api/v1/subnets", { headers: auth, data: { cidr, section_id: sectionId, description: "e2e-large" } });
  expect(created.ok(), await created.text()).toBeTruthy();
  const subnetId = (await created.json()).id;
  const base = cidr.split(".").slice(0, 2).join(".");
  try {
    const items = Array.from({ length: 1000 }, (_, i) => ({
      id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, subnet_id: subnetId,
      ip: `${base}.${Math.floor(i / 250)}.${(i % 250) + 1}`, state: "active", hostname: null, mac: null,
      effective_status: "online", created_at: "2026-09-29T00:00:00Z", updated_at: "2026-09-29T00:00:00Z",
    }));
    await page.route(/\/api\/v1\/addresses\?subnet_id=/, (r) => r.fulfill({ json: { items, total: 65534, page: 1, page_size: 1000 } }));
    await page.route(/\/blocks$/, (r) => r.fulfill({ json: { prefix: 24, blocks:
      Array.from({ length: 256 }, (_, b) => ({ start: `${base}.${b}.0`, used: 256 })) } }));
    await login(page);
    await page.goto(`/subnets/${subnetId}`);
    const note = page.getByTestId("subnet-addresses-truncated");
    await expect(note).toContainText("65,534");
    await expect(note).toContainText("1,000");
    await expect(note.getByRole("link")).toHaveAttribute("href", new RegExp(`/addresses\\?subnet_id=${subnetId}`));
    await expect(page.locator(".agg-cell")).toHaveCount(256);
    await expect(page.getByTestId("grid-legend-partial")).toContainText("1,000");
    await expect(page.locator(".n-data-table-tbody .n-data-table-tr")).toHaveCount(100);
  } finally {
    await request.delete(`/api/v1/subnets/${subnetId}`, { headers: auth });
  }
});
