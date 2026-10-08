/**
 * issue #45：獨立的 Kea 與 ISC DHCP 伺服器的設定頁。
 *
 * - Kea：新增 → 列表看得到（不顯示密碼）→ 測試連線失敗時講清楚原因 → 刪除
 * - ISC DHCP：新增並選代理 → 代理回報（打真的回報端點）後，列表顯示讀檔狀態與最後回報 → 讀不到檔時看得出是哪個檔
 * - 已被其他來源用掉的代理在下拉選單裡反灰
 *
 * 真的 Kea／isc-dhcp-server 往返另外用容器實測過（見 TEST_CHECKLIST 7b3）；這裡驗畫面。
 */
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const SUFFIX = Date.now().toString(36);

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function auth(request: APIRequestContext) {
  const r = await request.post("/api/v1/auth/login", { data: { username: ADMIN_USER, password: ADMIN_PASS, realm: "local" } });
  return { Authorization: `Bearer ${(await r.json()).access_token}` };
}

test("Kea：新增、測試連線失敗有原因、刪除", async ({ page }) => {
  test.setTimeout(120_000);           // 連不上的主機光是連線逾時就要 30 秒
  await login(page);
  await page.goto("/kea-dhcp");
  await expect(page.getByText("Kea DHCP 伺服器").first()).toBeVisible();
  await page.getByTestId("kea-create").click();
  const name = `kea-e2e-${SUFFIX}`;
  await page.getByTestId("kea-name").locator("input").fill(name);
  // 文件用位址：連不到（或被外連防護擋下），測試連線要把原因講出來
  await page.getByTestId("kea-url").locator("input").fill("http://192.0.2.199:8000/");
  await page.getByTestId("kea-save").click();
  const row = page.locator("tr").filter({ hasText: name });
  await expect(row).toBeVisible();
  await expect(row).not.toContainText("password");

  await expect(page.locator(".n-modal")).toHaveCount(0);     // 對話框淡出時的遮罩會吃掉點擊
  const [resp] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/kea-dhcp/servers/") && r.url().endsWith("/test"), { timeout: 45_000 }),
    row.getByRole("button", { name: "測試" }).click(),
  ]);
  expect(resp.status()).toBe(502);
  // 連不上要等後端 30 秒的連線逾時；前端不可以先用自己的 15 秒逾時蓋掉真正的原因
  await expect(page.locator(".n-message").filter({ hasText: /Kea DHCP 回報錯誤：.+/ })).toBeVisible();

  await row.getByRole("button", { name: "刪除" }).click();
  await page.mouse.move(5, 5);        // 滑鼠留在刪除鈕上時，它的提示會蓋住確認鈕
  await page.locator(".n-popconfirm").getByRole("button", { name: /確定|確認|OK/ }).click();
  await expect(page.locator("tr").filter({ hasText: name })).toHaveCount(0);
});

test("ISC DHCP：選代理 → 代理回報後顯示讀檔狀態；讀不到檔時看得出是哪個檔", async ({ page, request }) => {
  const h = await auth(request);
  const ag = await request.post("/api/v1/scan-agents", { headers: h, data: { name: `dhcp-host-${SUFFIX}` } });
  expect(ag.status(), await ag.text()).toBe(201);
  const agent = await ag.json();
  const other = await (await request.post("/api/v1/scan-agents", { headers: h, data: { name: `dhcp-host2-${SUFFIX}` } })).json();

  try {
    await login(page);
    await page.goto("/isc-dhcp");
    await expect(page.getByText("ISC DHCP 伺服器").first()).toBeVisible();
    // 設定說明：路徑只能在 DHCP 主機上改、不會送出檔案原文
    await expect(page.getByText("/etc/jt-ipam-agent.env", { exact: false })).toBeVisible();
    await expect(page.getByText("不會送出檔案原文", { exact: false })).toBeVisible();

    await page.getByTestId("isc-create").click();
    const name = `isc-e2e-${SUFFIX}`;
    await page.getByTestId("isc-name").locator("input").fill(name);
    await page.getByTestId("isc-agent").click();
    await page.locator(".n-base-select-option").filter({ hasText: agent.name }).first().click();
    await page.getByTestId("isc-save").click();
    const row = page.locator("tr").filter({ hasText: name });
    await expect(row).toContainText(agent.name);

    // 代理回報（跟真的代理打同一個端點、帶它自己的金鑰）
    const list = await (await request.get("/api/v1/isc-dhcp/servers", { headers: h })).json();
    const src = list.items.find((x: { name: string }) => x.name === name);
    const report = (confOk: boolean) => ({
      source_id: src.id,
      pools: [{ subnet: "198.51.100.0/24", start: "198.51.100.100", end: "198.51.100.150" }],
      reservations: [], leases: [],
      files: {
        conf: { path: "/etc/dhcp/dhcpd.conf", ok: confOk, error: confOk ? null : "PermissionError: Permission denied" },
        leases: { path: "/var/lib/dhcp/dhcpd.leases", ok: true, error: null },
      },
    });
    const rep = await request.post("/api/v1/scan-agents/dhcpd-report", { headers: { "X-Agent-Key": agent.enroll_key }, data: report(true) });
    expect(rep.status(), await rep.text()).toBe(200);
    await page.reload();
    await expect(row.getByTestId("isc-file-dhcpd.conf")).toContainText("✓");
    await expect(row.getByTestId("isc-file-dhcpd.leases")).toContainText("✓");

    // 讀不到設定檔：標紅、最後錯誤寫出檔名與原因
    await request.post("/api/v1/scan-agents/dhcpd-report", { headers: { "X-Agent-Key": agent.enroll_key }, data: report(false) });
    await page.reload();
    await expect(row.getByTestId("isc-file-dhcpd.conf")).toContainText("✗");
    await expect(row).toContainText("/etc/dhcp/dhcpd.conf: PermissionError");

    // 同一台代理不能再給第二個來源：選單裡反灰
    await page.getByTestId("isc-create").click();
    await page.getByTestId("isc-agent").click();
    const used = page.locator(".n-base-select-option").filter({ hasText: agent.name }).first();
    await expect(used).toHaveClass(/n-base-select-option--disabled/);
    await expect(page.locator(".n-base-select-option").filter({ hasText: other.name }).first())
      .not.toHaveClass(/n-base-select-option--disabled/);
    await page.keyboard.press("Escape");

    await request.delete(`/api/v1/isc-dhcp/servers/${src.id}`, { headers: h });
  } finally {
    await request.delete(`/api/v1/scan-agents/${agent.id}`, { headers: h });
    await request.delete(`/api/v1/scan-agents/${other.id}`, { headers: h });
  }
});
