/**
 * IP 編輯視窗的裝置欄：同一台裝置只給一個「關聯」按鈕。
 *
 * 起因（使用者 2026-10-06：「這兩個差在那」）：前端自己比對主機名稱的「關聯相符的裝置」與後端建議的
 * 「關聯到既有裝置」各自判斷，常常指向同一台，畫面上就出現兩個意思一樣的按鈕。
 * 後端建議看得到 MAC、連接埠，對到多台也不猜，所以有它的答案時只顯示它的。
 */
import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const API = process.env.E2E_API_URL || "http://127.0.0.1:8010";
const ADDR = "10.20.0.78";          // seed_e2e 的「伺服器網段」裡沒有用到的位址
const NAME = "e2e-link-once";
const OTHER = "e2e-link-other";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function ok(res: any, what: string) {
  if (!res.ok()) throw new Error(`${what} 失敗 HTTP ${res.status()}：${await res.text()}`);
  return res;
}

/** 一台叫 NAME 的裝置＋一筆主機名稱也是 NAME、還沒關聯裝置的 IP。可重跑。 */
async function seed(request: any): Promise<string> {
  const { access_token } = await (await ok(await request.post(`${API}/api/v1/auth/login`, {
    data: { username: ADMIN_USER, password: ADMIN_PASS } }), "登入")).json();
  const h = { Authorization: `Bearer ${access_token}` };
  for (const name of [NAME, OTHER]) {
    const have = await (await ok(await request.get(`${API}/api/v1/devices?q=${name}&page_size=50`,
                                                  { headers: h }), "列出裝置")).json();
    if (!(have.items ?? []).some((d: any) => d.name === name)) {
      await ok(await request.post(`${API}/api/v1/devices`, { headers: h, data: { name } }), "建立裝置");
    }
  }
  const subnets = await (await ok(await request.get(`${API}/api/v1/subnets?page_size=500`, { headers: h }),
                                  "列出網段")).json();
  const subnet = (subnets.items ?? []).find((s: any) => String(s.cidr) === "10.20.0.0/24");
  if (!subnet) throw new Error("找不到 seed_e2e 的 10.20.0.0/24（先跑 seed_e2e）");
  const found = await (await ok(await request.get(
    `${API}/api/v1/addresses?subnet_id=${subnet.id}&q=${ADDR}`, { headers: h }), "查位址")).json();
  const row = (found.items ?? []).find((a: any) => a.ip === ADDR);
  if (row) {
    await ok(await request.patch(`${API}/api/v1/addresses/${row.id}`, {
      headers: h, data: { hostname: NAME, device_id: null } }), "重設位址");
    return row.id;
  }
  const created = await ok(await request.post(`${API}/api/v1/addresses`, {
    headers: h, data: { subnet_id: subnet.id, ip: ADDR, hostname: NAME } }), "建立位址");
  return (await created.json()).id;
}

test("主機名稱對到既有裝置時，只出現一個關聯按鈕", async ({ page, request }) => {
  const id = await seed(request);
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto(`/addresses/${id}`);
  await page.getByRole("button", { name: /^編輯$/ }).click();

  const links = page.getByRole("button", { name: new RegExp(`關聯.*「${NAME}」`) });
  await expect(links.first()).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);       // 前端比對與後端建議兩邊都載入完
  await expect(links).toHaveCount(1);

  // 主機名稱改了還沒存：後端建議是照舊名稱算的，改由前端比對到的那台出現（不可以兩個都不見）
  await page.locator(".n-form-item", { hasText: "主機名稱" }).first().locator("input").fill(OTHER);
  const other = page.getByRole("button", { name: new RegExp(`關聯.*「${OTHER}」`) });
  await expect(other).toHaveCount(1);
  await expect(links).toHaveCount(0);
});
