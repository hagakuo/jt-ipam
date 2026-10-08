/**
 * RustDesk「刪除舊註冊」（0182、代理 1.2.0）：兩邊都同意才做得到 —— 伺服器設定「允許刪除舊註冊」＋主機端以 --allow-delete
 * 安裝的代理（輪詢回報 capabilities.delete）。裝置頁籤勾選離線的裝置 → 確認視窗 → 代理下次輪詢取走、刪之前再查一次線上狀態。
 *
 * 自己建一台伺服器（不動種子資料 rd-e2e，rustdesk.spec.ts 的斷言才不受影響），由測試扮演代理：輪詢、回報裝置、送回刪除結果。
 */
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const NO_CAP = { delete: false, delete_reason: "not enabled on this host (re-run the installer with --allow-delete)" };
const CAN = { delete: true, delete_reason: null };
// 900100001 上線中；900100002／900100003 從未上線；900100004 上線過、現在離線
const IDS = ["900100001", "900100002", "900100003", "900100004"];

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function adminToken(request: APIRequestContext): Promise<string> {
  const r = await request.post("/api/v1/auth/login", { data: { username: ADMIN_USER, password: ADMIN_PASS, realm: "local" } });
  expect(r.ok(), "admin API 登入要成功").toBeTruthy();
  return (await r.json()).access_token;
}

function report(sourceId: string, online: Record<string, boolean>) {
  return {
    source_id: sourceId, version: "1.1.16", public_key: "E2EfakeRustDeskKeyForTestsOnly0000000000000=",
    files: { db: { path: "/var/lib/rustdesk-server/db_v2.sqlite3", ok: true, error: null, truncated: false } },
    online_ok: true, online_error: null,
    peers: IDS.map((id) => ({ id, created_at: "2023-01-02 03:04:05", ip: null, online: !!online[id] })),
  };
}

test("刪除舊註冊：兩邊都允許才能勾選刪除，結果與紀錄看得到", async ({ page, request }, testInfo) => {
  test.setTimeout(120_000);
  const tok = await adminToken(request);
  const auth = { Authorization: `Bearer ${tok}` };
  const name = `rd-del-e2e-${Date.now().toString(36)}`;
  const created = await request.post("/api/v1/rustdesk/servers", { headers: auth, data: { name } });
  expect(created.status(), await created.text()).toBe(201);
  const { id: sid, agent_key: key } = await created.json();
  const agent = { "X-Agent-Key": key };
  const poll = async (capabilities: object) => (await request.post("/api/v1/rustdesk/agent/poll", {
    headers: agent, data: { version: "1.2.0", hostname: "rd-del-host", data_dir: "/var/lib/rustdesk-server", capabilities },
  })).json();
  try {
    await poll(NO_CAP);
    // 第一次回報 900100001、900100004 上線；第二次 900100004 離線 → 它「上線過」，不算從未上線
    for (const online of [{ "900100001": true, "900100004": true }, { "900100001": true }]) {
      const r = await request.post("/api/v1/rustdesk/agent/report", { headers: agent, data: report(sid, online) });
      expect(r.ok(), await r.text()).toBeTruthy();
    }

    await login(page);
    await page.goto("/rustdesk?tab=devices");
    const peers = page.getByTestId("rustdesk-peers");
    const pick = page.getByTestId("rustdesk-peers-server");
    await expect(pick).toBeVisible({ timeout: 15_000 });           // 種子資料另有 rd-e2e，所以一定有伺服器選單
    if (!(await pick.innerText()).includes(name)) {
      await pick.click();
      await page.locator(".n-base-select-option", { hasText: name }).click();
    }
    await expect(pick).toContainText(name);
    await expect(peers.locator("tbody tr")).toHaveCount(4, { timeout: 15_000 });
    // 預設關：沒有勾選欄、按鈕反灰，提示說要先開設定
    await expect(peers.locator(".n-data-table-th--selection")).toHaveCount(0);
    const delBtn = page.getByTestId("rustdesk-del-btn");
    await expect(delBtn).toBeDisabled();
    await delBtn.hover();
    await expect(page.locator(".n-tooltip").last()).toContainText("允許刪除舊註冊");

    // 伺服器設定打開「允許刪除舊註冊」
    await page.getByTestId("rustdesk-tabs").locator(".n-tabs-tab", { hasText: "RustDesk 伺服器" }).click();
    const row = page.getByTestId("rustdesk-servers").locator("tr", { hasText: name });
    await row.getByTestId("rustdesk-edit").click();
    await expect(page.locator(".n-modal")).toContainText("--allow-delete");
    await page.getByTestId("rustdesk-allow-delete").click();
    const saved = page.waitForResponse((r) => r.request().method() === "PATCH" && r.url().includes(sid));
    await page.getByTestId("rustdesk-save").click();
    expect((await saved).status()).toBe(200);
    // 安裝指令多了 JT_RD_ALLOW_DELETE=1，並說明原因與「已裝好的主機只要執行這行」
    await row.getByTestId("rustdesk-install").click();
    const install = page.getByTestId("rustdesk-install-modal");
    await expect(install.getByTestId("rustdesk-install-cmd")).toContainText("JT_RD_ALLOW_DELETE=1 bash");
    await expect(install.getByTestId("rustdesk-install-allow-delete")).toContainText("env JT_RD_ALLOW_DELETE=1 bash");
    await expect(install.getByTestId("rustdesk-install-cap")).toContainText("唯讀");
    await page.screenshot({ path: testInfo.outputPath("install-allow-delete.png") });
    await page.keyboard.press("Escape");

    // 網頁允許了，但代理回報沒有寫入權限：有勾選欄，按鈕仍反灰，提示帶出代理的原因
    await page.getByTestId("rustdesk-tabs").locator(".n-tabs-tab", { hasText: "裝置" }).click();
    await expect(peers.locator(".n-data-table-th--selection")).toHaveCount(1);
    await delBtn.hover();
    await expect(page.locator(".n-tooltip").last()).toContainText("--allow-delete");

    // 代理以 --allow-delete 重裝後回報寫得了
    await poll(CAN);
    await page.reload();
    await expect(peers.locator("tbody tr")).toHaveCount(4, { timeout: 15_000 });
    // 上線中的不能勾
    const onlineRow = peers.locator("tbody tr", { hasText: "900100001" });
    await expect(onlineRow.locator(".n-checkbox")).toHaveClass(/n-checkbox--disabled/);
    // 「從未上線」篩選 → 全選符合條件 → 只勾到那兩個
    // 有兩台伺服器（伺服器選單在清單載入後才出現）：上線篩選要改到上線篩選本身，不是旁邊的對應狀態
    // （工具列的子元件沒有 key 時，選單會沿用對應狀態的事件處理）
    await page.getByTestId("rustdesk-online-filter").click();
    await page.locator(".n-base-select-option", { hasText: /^從未上線$/ }).click();
    await expect(peers.locator("tbody tr")).toHaveCount(2);
    await expect(page.getByTestId("rustdesk-match-filter")).not.toContainText("never");
    await page.getByTestId("rustdesk-del-select-all").click();
    await expect(delBtn).toBeEnabled();
    await expect(delBtn).toContainText("(2)");
    await page.screenshot({ path: testInfo.outputPath("devices-ticked.png") });

    await delBtn.click();
    const confirm = page.getByTestId("rustdesk-del-confirm");
    await expect(confirm).toContainText("刪除 2 個註冊");
    await expect(confirm).toContainText("上線中的裝置會略過");
    await expect(confirm).toContainText("自己重新註冊");
    await page.screenshot({ path: testInfo.outputPath("confirm.png") });
    const queued = page.waitForResponse((r) => r.request().method() === "POST" && r.url().includes("/peers/delete"));
    await page.getByTestId("rustdesk-del-confirm-btn").click();
    expect((await queued).status()).toBe(202);
    await expect(page.getByTestId("rustdesk-del-summary")).toContainText("等待中 2");

    // 扮演代理：取走工作，一個刪掉、一個剛好上線了（略過）
    const cfg = await poll(CAN);
    expect(cfg.peer_deletes.map((j: { rustdesk_id: string }) => j.rustdesk_id).sort()).toEqual(["900100002", "900100003"]);
    const byId = Object.fromEntries(cfg.peer_deletes.map((j: { req_id: string; rustdesk_id: string }) => [j.rustdesk_id, j.req_id]));
    const res = await request.post("/api/v1/rustdesk/agent/delete-result", { headers: agent, data: {
      source_id: sid, results: [{ req_id: byId["900100002"], status: "deleted" },
                                { req_id: byId["900100003"], status: "skipped_online" }] } });
    expect(res.ok(), await res.text()).toBeTruthy();

    const summary = page.getByTestId("rustdesk-del-summary");
    await expect(summary).toContainText("已刪除 1", { timeout: 15_000 });
    await expect(summary).toContainText("略過（上線中）1");
    await expect(peers.locator("tbody tr", { hasText: "900100002" })).toHaveCount(0);
    await expect(peers.locator("tbody tr", { hasText: "900100003" })).toHaveCount(1);
    await page.screenshot({ path: testInfo.outputPath("summary.png") });

    await page.getByTestId("rustdesk-del-log-btn").click();
    const log = page.getByTestId("rustdesk-del-log");
    await expect(log.locator("tbody tr")).toHaveCount(2);
    await expect(log.locator("tr", { hasText: "900100002" })).toContainText("已刪除");
    await expect(log.locator("tr", { hasText: "900100003" })).toContainText("略過（上線中）");
    await expect(log.locator("tr", { hasText: "900100002" })).toContainText(ADMIN_USER);
    await page.screenshot({ path: testInfo.outputPath("log.png") });
  } finally {
    await request.delete(`/api/v1/rustdesk/servers/${sid}`, { headers: auth });
  }
});
