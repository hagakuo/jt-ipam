/**
 * 主控台經由掃描代理中繼（issue #24 階段二）：真實瀏覽器 → 後端 → 代理撥回來的 WebSocket → 目標。
 *
 * 環境（見 TEST_CHECKLIST「主控台經由掃描代理中繼」）：兩個容器各是一個「客戶站台」，容器內的位址都是
 * 10.99.0.5（重疊網段），後端完全連不到；每個站台跑 sshd 與一台掃描代理（代理主機不設任何中繼變數），
 * 家目錄各放一個 site-a.txt／site-b.txt。jt-ipam 裡兩個 10.99.0.0/24 子網路各指派自己的代理為出口。
 * 只有中繼走對了，才會在 A 看到 site-a.txt、在 B 看到 site-b.txt。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const IP_A = process.env.E2E_RELAY_IP_A || "";
const IP_B = process.env.E2E_RELAY_IP_B || "";
const SUBNET_A = process.env.E2E_RELAY_SUBNET_A || "";
test.skip(!ADMIN_PASS || !IP_A || !IP_B, "需要 E2E_ADMIN_PASS、E2E_RELAY_IP_A、E2E_RELAY_IP_B（中繼測試環境）");
test.setTimeout(120_000);

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function sftpThrough(page: Page, ipId: string) {
  await page.goto(`/sftp/${ipId}`);
  await expect(page.getByText(/SFTP 連線到/)).toBeVisible({ timeout: 15_000 });
  const manual = page.getByPlaceholder("root");
  if (await manual.isVisible().catch(() => false)) {
    await manual.fill("tester");
    await page.locator('input[type="password"]').first().fill("TestPass!2026");
  }
  await page.getByRole("button", { name: "連線" }).click();
}

test("兩個重疊網段的同一個位址，各自經由自己的掃描代理連到對的主機", async ({ page }) => {
  await login(page);
  for (const [ip, mine, other, agent] of [[IP_A, "site-a.txt", "site-b.txt", "relay-site-a"],
                                         [IP_B, "site-b.txt", "site-a.txt", "relay-site-b"]]) {
    await sftpThrough(page, ip);
    await expect(page.getByText(mine)).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(other)).toHaveCount(0);
    // 狀態列要講出實際路徑：經由哪一台掃描代理（不是「經由跳板」）
    await expect(page.getByText(`經由掃描代理：${agent}`)).toBeVisible();
    if (process.env.SHOT_DIR) await page.screenshot({ path: `${process.env.SHOT_DIR}/relay-${agent}.png` });
  }
});

test("RDP 經由掃描代理（guacd）：連上、畫出畫面、狀態列標出代理", async ({ page }) => {
  // 站台 B 的容器網路裡有一台 xrdp（jtipam-rdp-target，--network container:<站台 B>）
  test.skip(!process.env.E2E_RELAY_RDP, "沒有在站台 B 起 xrdp（E2E_RELAY_RDP=1）");
  await login(page);
  await page.goto(`/rdp/${IP_B}`);
  await page.getByPlaceholder("Administrator").fill("rdpuser");
  await page.locator("input[type=password]").first().fill("TestPw-123");
  await page.locator(".rdp-form").getByRole("button", { name: "RDP 連線" }).click();
  await expect(page.locator(".rdp-status")).toContainText("已連線", { timeout: 45_000 });
  await expect(page.getByText("經由掃描代理：relay-site-b")).toBeVisible();
  await expect.poll(() => page.locator(".guac-host").evaluate((host) => {
    let n = 0;
    for (const c of Array.from(host.querySelectorAll("canvas"))) {
      const w = Math.min(c.width, 800), h = Math.min(c.height, 600);
      if (!w || !h) continue;
      const d = (c as HTMLCanvasElement).getContext("2d")!.getImageData(0, 0, w, h).data;
      for (let i = 0; i < d.length; i += 16) if (d[i + 3] && (d[i] || d[i + 1] || d[i + 2])) n++;
    }
    return n;
  }), { timeout: 20_000 }).toBeGreaterThan(1000);
  if (process.env.SHOT_DIR) await page.screenshot({ path: `${process.env.SHOT_DIR}/relay-rdp.png` });
});

test("掃描代理頁：允許中繼、允許的埠都在這裡設定；代理主機什麼都沒設也顯示「代理可以中繼」", async ({ page }) => {
  await login(page);
  await page.goto("/scan-agents");
  const row = page.locator("tr", { hasText: "relay-site-a" }).first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.locator("td.col-actions button").nth(1).click();          // 第二顆是「編輯」
  await expect(page.getByTestId("agent-relay-switch")).toBeVisible();
  await expect(page.getByTestId("agent-relay-ports").locator("input")).toHaveValue("22,3389,5900-5910");
  await expect(page.getByTestId("agent-relay-state")).toHaveText("代理可以中繼");
  await expect(page.getByTestId("agent-relay")).not.toContainText("JT_IPAM_RELAY=1");
  if (process.env.SHOT_DIR) await page.locator(".n-modal").screenshot({ path: `${process.env.SHOT_DIR}/relay-agent-page.png` });
});

test("系統設定有中繼總開關；子網路的主控台出口列出它的掃描代理", async ({ page }) => {
  await login(page);
  await page.goto("/system-settings");
  await expect(page.getByTestId("console-relay-switch")).toBeVisible({ timeout: 15_000 });
  test.skip(!SUBNET_A, "沒有給 E2E_RELAY_SUBNET_A");
  await page.goto(`/subnets/${SUBNET_A}`);
  await page.getByRole("button", { name: /編輯/ }).first().click();
  const egress = page.getByTestId("console-egress");
  await expect(egress).toBeVisible({ timeout: 15_000 });
  await expect(egress).toContainText("relay-site-a");
  if (process.env.SHOT_DIR) await page.locator(".n-modal").screenshot({ path: `${process.env.SHOT_DIR}/relay-egress.png` });
});
