/**
 * IP 詳細資料的「主機名稱來源」：手動設定的名稱要刪得掉，每個來源要看得到最後回報時間。
 *
 * 起因：IP 換了一台設備，舊的「手動: 舊名稱」一直掛著（手動不會自己過期），使用者找不到地方刪；
 * 其他來源（NetBIOS、mDNS…）也分不出是今天還是兩個月前回報的。
 * 只有「手動」有 ×：其他來源刪了下次同步又會回來，換設備時由 MAC 異動自動清掉。
 */
import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const API = process.env.E2E_API_URL || "http://127.0.0.1:8010";
const ADDR = "10.20.0.77";        // seed_e2e 的「伺服器網段」裡沒有用到的位址
const OLD_NAME = "e2e-old-laptop";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

/** setup 的每一步都要驗狀態：靜靜失敗的 setup 會變成「功能壞了」的假象。 */
async function ok(res: any, what: string) {
  if (!res.ok()) throw new Error(`${what} 失敗 HTTP ${res.status()}：${await res.text()}`);
  return res;
}

/** 位址存在就改主機名稱、不存在就建立：都會留下一筆「手動」觀測。可重跑（不刪位址，刪掉會進冷卻期）。 */
async function seed(request: any): Promise<{ id: string; h: Record<string, string> }> {
  const auth = await ok(await request.post(`${API}/api/v1/auth/login`, {
    data: { username: ADMIN_USER, password: ADMIN_PASS },
  }), "登入");
  const { access_token } = await auth.json();
  const h = { Authorization: `Bearer ${access_token}` };
  const subnets = await (await ok(await request.get(`${API}/api/v1/subnets?page_size=500`, { headers: h }),
                                  "列出網段")).json();
  const subnet = (subnets.items ?? []).find((s: any) => String(s.cidr) === "10.20.0.0/24");
  if (!subnet) throw new Error("找不到 seed_e2e 的 10.20.0.0/24（先跑 seed_e2e）");
  const found = await (await ok(await request.get(
    `${API}/api/v1/addresses?subnet_id=${subnet.id}&q=${ADDR}`, { headers: h }), "查位址")).json();
  const row = (found.items ?? []).find((a: any) => a.ip === ADDR);
  if (row) {
    await ok(await request.patch(`${API}/api/v1/addresses/${row.id}`, {
      headers: h, data: { hostname: OLD_NAME },
    }), "設定手動主機名稱");
    return { id: row.id, h };
  }
  const created = await ok(await request.post(`${API}/api/v1/addresses`, {
    headers: h, data: { subnet_id: subnet.id, ip: ADDR, hostname: OLD_NAME },
  }), "建立位址");
  return { id: (await created.json()).id, h };
}

test("手動主機名稱可以刪除，來源標籤顯示最後回報時間", async ({ page, request }) => {
  const { id, h } = await seed(request);

  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
  await page.goto(`/addresses/${id}`);

  const tag = page.getByTestId("hostname-src-manual");
  await expect(tag).toContainText(OLD_NAME, { timeout: 20_000 });

  // 滑過去看得到最後回報時間
  await tag.hover();
  await expect(page.getByText(/最後回報：\d{4}/)).toBeVisible();

  // × 先問過才刪
  await tag.locator(".n-tag__close").click();
  const confirm = page.locator(".n-popconfirm");
  await expect(confirm).toContainText(OLD_NAME);
  await confirm.getByRole("button", { name: /確定|確認|OK/ }).click();

  await expect(page.getByText("已移除手動主機名稱")).toBeVisible();
  await expect(page.getByTestId("hostname-src-manual")).toHaveCount(0);

  // 後端真的刪了，而且有效主機名稱跟著重算（沒有其他來源 → 空）
  const src = await (await ok(await request.get(`${API}/api/v1/addresses/${id}/hostname-sources`,
                                               { headers: h }), "讀主機名稱來源")).json();
  expect(src.observations.map((o: any) => o.source)).not.toContain("manual");
  const addr = await (await ok(await request.get(`${API}/api/v1/addresses/${id}`, { headers: h }),
                               "讀位址")).json();
  expect(addr.hostname ?? null).not.toBe(OLD_NAME);
});
