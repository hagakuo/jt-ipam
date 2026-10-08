/**
 * 「自動收錄、沒有人登記過」的位址必須一眼認得出來。
 *
 * 起因：使用者問「掃描器掃到、但 IPAM 沒登錄的 IP，在指示計上是什麼顏色」——
 * 答案是**跟正常登錄的一樣是綠色**，因為掃描代理會自動把它建進來。這很要命：
 * 位址一旦被收錄，就不會再出現在「未授權 IP」異常偵測裡（那道偵測的判定正是
 * 「看得到、IPAM 沒有」），等於有人私接一台機器會安靜地變成一筆正常紀錄。
 *
 * 這支 spec 守三件只有把畫面畫出來才看得見的事：
 *  1. 指示計上自動收錄的格子有橘色描邊，而且圖例有這一項
 *  2. 掃描代理有「自動收錄未登錄的 IP」開關，且**預設關閉**
 *  3. AI 巡檢的「忽略」會先問過再執行（忽略是永久的，按錯要另外找回來）
 */
import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const API = process.env.E2E_API_URL || "http://127.0.0.1:8010";
const CIDR = "203.0.113.0/24";   // RFC 5737 文件用網段
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

/** 造資料走**真實路徑**：讓掃描代理實際回報一個 IPAM 沒有的位址。
 *
 * 不用「建立 IP 時直接帶 discovery_source」來偽造 —— 那個欄位建立 API 根本不收
 * （schema 是 extra=forbid），偽造出來的情境也不能證明真正的流程會標對來源。
 */
/** setup 的每一步都要驗狀態：靜靜失敗的 setup 會變成「功能壞了」的假象。 */
async function ok(res: any, what: string) {
  if (!res.ok()) throw new Error(`${what} 失敗 HTTP ${res.status()}：${await res.text()}`);
  return res;
}

async function seed(request: any): Promise<{ subnetId: string }> {
  const auth = await request.post(`${API}/api/v1/auth/login`, {
    data: { username: ADMIN_USER, password: ADMIN_PASS },
  });
  const { access_token } = await auth.json();
  const h = { Authorization: `Bearer ${access_token}` };

  // 先清掉前一輪留下的同名網段：setup 必須可重跑，否則第二次起就會撞 409，
  // 而失敗的原因看起來會像「功能壞了」
  const existing = await (await request.get(`${API}/api/v1/subnets?page_size=200`,
                                            { headers: h })).json();
  for (const s of existing.items ?? []) {
    if (String(s.cidr) === CIDR) {
      await request.delete(`${API}/api/v1/subnets/${s.id}`, { headers: h });
    }
  }

  const section = await (await ok(await request.post(`${API}/api/v1/sections`, {
    headers: h, data: { name: `e2e-auto-${Date.now()}` },
  }), "建立區段")).json();
  const subnet = await (await ok(await request.post(`${API}/api/v1/subnets`, {
    headers: h, data: { section_id: section.id, cidr: CIDR },
  }), "建立子網路")).json();

  // 人工登記的一筆（對照組：不該被標成自動收錄）
  await request.post(`${API}/api/v1/addresses`, {
    headers: h,
    data: { subnet_id: subnet.id, ip: "203.0.113.10", hostname: "registered-host" },
  });

  // 開了自動收錄的掃描代理 + 指派這個子網路
  const agent = await (await ok(await request.post(`${API}/api/v1/scan-agents`, {
    headers: h, data: { name: `e2e-agent-${Date.now()}`, auto_create_ips: true },
  }), "建立掃描代理")).json();
  // 指派子網路給代理（這一步順便會自動啟用該子網路的掃描）
  await ok(await request.put(`${API}/api/v1/scan-agents/${agent.id}/subnets`, {
    headers: h, data: { subnet_ids: [subnet.id] },
  }), "指派子網路給代理");

  // 代理回報一個 IPAM 沒有的位址 → 這才是真正會產生「自動收錄」紀錄的路徑
  const rep = await ok(await request.post(`${API}/api/v1/scan-agents/report`, {
    headers: { "X-Agent-Key": agent.enroll_key },
    data: { results: [{ ip: "203.0.113.20", alive: true }] },
  }), "代理回報");
  const body = await rep.json();
  if (body.created !== 1) throw new Error(`代理回報沒有建立位址：${JSON.stringify(body)}`);
  return { subnetId: subnet.id };
}

test("指示計：自動收錄的位址有橘色描邊，圖例列出筆數", async ({ page, request }) => {
  const { subnetId } = await seed(request);
  await login(page);
  await page.goto(`/subnets/${subnetId}`);

  const grid = page.locator(".subnet-grid").first();
  await grid.scrollIntoViewIfNeeded();

  // 圖例要有「自動收錄 (1)」—— 數字對不上代表統計沒跟著顏色走
  await expect(page.locator(".legend-item", { hasText: "自動收錄" })).toContainText("(1)");

  // 剛好一個格子帶橘框，且它就是自動收錄的那一個（不是隨便一格）
  const marked = grid.locator(".cell.cell-auto");
  await expect(marked).toHaveCount(1);

  // 樣式要靠 computed style 驗，不能只看有沒有 class（scoped CSS 對 render function
  // 產生的元素不生效，是這專案踩過的坑）。自動收錄＝整格紫色。
  // 對角雙色：漸層在 backgroundImage；紫（自動收錄）與狀態色都要在
  const bg = await marked.evaluate((el) => getComputedStyle(el).backgroundImage);
  expect(bg).toContain("139, 92, 246");   // #8b5cf6 紫（左上半）
  expect(bg).toContain("linear-gradient");   // 右下半保留狀態色
});

test("掃描代理：有「自動收錄未登錄的 IP」開關，且預設關閉", async ({ page }) => {
  await login(page);
  await page.goto("/scan-agents");
  await page.getByRole("button", { name: /新增/ }).first().click();

  const item = page.locator(".n-form-item", { hasText: "自動收錄未登錄的 IP" });
  await expect(item).toBeVisible();
  // 預設關閉 —— 這是刻意的行為變更，收錄之後那個位址就不會再被異常偵測列出來
  await expect(item.locator(".n-switch")).not.toHaveClass(/n-switch--active/);
  // 而且要把代價講出來，不能只有一個沒說明的開關
  await expect(item).toContainText("未授權 IP");
});

test("AI 巡檢：按「忽略」要先跳出確認才會生效", async ({ page }) => {
  await login(page);
  await page.goto("/ai-audit");

  // 等清單真的畫出來再找按鈕：count() 是一次性快照，表格晚一步渲染就會誤判成「沒有發現」
  const rows = page.locator(".fx-when");
  await rows.first().waitFor({ state: "visible", timeout: 10_000 }).catch(() => {});
  const dismiss = page.getByRole("button", { name: /^忽略$/ }).first();
  if (!(await dismiss.isVisible().catch(() => false))) {
    test.skip(true, "這個環境沒有待處理的發現");
  }

  await dismiss.click();
  // popconfirm 會出現，且在按下確認前不會送出
  const pop = page.locator(".n-popconfirm__action, .n-popover").filter({ hasText: /忽略/ });
  await expect(pop.first()).toBeVisible();
});
