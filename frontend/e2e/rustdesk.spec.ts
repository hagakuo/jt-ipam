/**
 * RustDesk Server（開源版）整合：版面照 Wazuh 整合頁，頁籤切換「RustDesk 伺服器／裝置／連線稽核」；
 * 伺服器列有編輯／測試／立即同步／安裝指令；專用 RustDesk 代理（不是掃描代理）用每台伺服器自己的金鑰。
 * IP 詳細資料顯示 RustDesk ID 與「以 RustDesk 連線」（rustdesk:// 網址，帶伺服器與公鑰、不帶密碼）。
 *
 * 種子資料（tests/seed_e2e.py）：rd-e2e（client_address=rd.example.net、代理 rd-host-e2e、金鑰 AGENT_KEY），三個裝置：
 * 100200300 → 10.20.0.40（seen-host-01，上線、已對應）、100200301（NAT 共用）、100200302（不在管理網段、離線）。
 */
import { test, expect, type Page } from "@playwright/test";

const AGENT_KEY = "rustdesk-e2e-agent-key-" + "0".repeat(20);
// 測試扮演代理輪詢時帶的狀態（與種子資料一致，別的測試看到的畫面才不會變）
const AGENT_POLL = { hostname: "rd-host-e2e", data_dir: "/var/lib/rustdesk-server",
                     receiver: { listening: true, port: 21114, error: null } };

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

async function openTab(page: Page, name: string) {
  await page.getByTestId("rustdesk-tabs").locator(".n-tabs-tab", { hasText: name }).click();
}

test("整合頁：伺服器狀態與裝置清單（搜尋、上線篩選、對應狀態）", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk");
  await expect(page.locator(".n-card-header")).toContainText("RustDesk 整合");
  const servers = page.getByTestId("rustdesk-servers");
  const row = servers.locator("tr", { hasText: "rd-e2e" });
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(row).toContainText("1.1.16");
  await expect(row).toContainText("共 3");
  await expect(row).toContainText("上線 2");
  await expect(row).toContainText("已對應 1");
  await expect(row).toContainText("rd-host-e2e");
  await expect(row.getByTestId("rustdesk-reports")).toContainText("接收中 · TCP 21114");
  // 公鑰在表格裡只預覽前 5 個字
  await expect(row.getByTestId("rustdesk-key-preview")).toHaveText(/^.{5}…$/);
  // 裝置清單在自己的頁籤，不在伺服器表格下面
  await expect(page.getByTestId("rustdesk-peers")).toBeHidden();

  await openTab(page, "裝置");
  await expect(page).toHaveURL(/tab=devices/);
  await expect(page.getByTestId("rustdesk-tabs").locator(".n-tabs-tab", { hasText: "裝置" })).toContainText("(3)");
  const peers = page.getByTestId("rustdesk-peers");
  await expect(peers.locator("tbody tr")).toHaveCount(3);
  const mapped = peers.locator("tr", { hasText: "100200300" });
  // IP 與主機名稱各自一欄（使用者：「ip 跟 hostname 欄位不要放一起」）
  await expect(mapped.getByRole("button", { name: "10.20.0.40", exact: true })).toBeVisible();
  await expect(mapped.locator("td", { hasText: /^seen-host-01$/ }).first()).toBeVisible();
  await expect(mapped).not.toContainText("10.20.0.40（seen-host-01）");
  await expect(mapped).toContainText("已對應");
  await expect(peers.locator("tr", { hasText: "100200301" })).toContainText("多台共用");
  await expect(peers.locator("tr", { hasText: "100200302" })).toContainText("不在管理網段");

  await page.getByTestId("rustdesk-search").locator("input").fill("100200302");
  await expect(peers.locator("tbody tr")).toHaveCount(1);
  await expect(peers.locator("tbody tr").first()).toContainText("離線");
  await page.getByTestId("rustdesk-search").locator("input").fill("");
  await expect(peers.locator("tbody tr")).toHaveCount(3);

  await page.getByTestId("rustdesk-online-filter").click();
  await page.locator(".n-base-select-option", { hasText: /^上線$/ }).click();
  await expect(peers.locator("tbody tr")).toHaveCount(2);

  // 點對應的 IP → IP 詳細資料
  await page.getByTestId("rustdesk-online-filter").click();
  await page.locator(".n-base-select-option", { hasText: /^全部$/ }).click();
  await peers.locator("tr", { hasText: "100200300" }).getByRole("button", { name: /10\.20\.0\.40/ }).click();
  await expect(page).toHaveURL(/\/addresses\/[0-9a-f-]+$/);
  await expect(page.getByTestId("ip-rustdesk-id")).toContainText("100200300");
});

test("IP 詳細資料：RustDesk ID 與連線按鈕（帶伺服器與公鑰、不帶密碼）", async ({ page }) => {
  await login(page);
  const id = await page.evaluate(async () => {
    const tok = localStorage.getItem("access_token") || "";
    const r = await fetch("/api/v1/addresses?q=10.20.0.40&page_size=5", { headers: { Authorization: `Bearer ${tok}` } });
    return ((await r.json()).items as { id: string; ip: string }[]).find((i) => i.ip.split("/")[0] === "10.20.0.40")!.id;
  });
  await page.goto(`/addresses/${id}`);
  await expect(page.getByTestId("ip-rustdesk-id")).toContainText("100200300", { timeout: 15_000 });
  const row = page.locator(".n-descriptions-table-row", { hasText: "RustDesk" }).first();
  await expect(row).toContainText("rd-e2e");
  // 上線狀態與最後回報改放「各來源最後出現」，主機名稱在「主機名稱來源」：這一列不重複
  await expect(page.getByTestId("ip-rustdesk-id")).not.toContainText("上線");
  await expect(page.getByTestId("ip-seen-section")).toContainText("RustDesk 客戶端");
  const btn = page.getByTestId("rustdesk-connect");
  await expect(btn).toBeVisible();
  // 現在是叫出操作者電腦上的客戶端：按鈕右上角標「本機」
  await expect(page.getByTestId("rustdesk-local-badge")).toHaveText("本機");
  const href = await btn.getAttribute("href");
  expect(href).toBe("rustdesk://connect/100200300@rd.example.net?key=E2EfakeRustDeskKeyForTestsOnly0000000000000=");
  expect(href).not.toContain("password");
});

test("操作欄：編輯／測試／立即同步／安裝指令都在，而且不用捲動就看得到", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await login(page);
  await page.goto("/rustdesk");
  const row = page.getByTestId("rustdesk-servers").locator("tr", { hasText: "rd-e2e" });
  await expect(row).toBeVisible({ timeout: 15_000 });
  const table = await page.getByTestId("rustdesk-servers").boundingBox();
  for (const id of ["rustdesk-edit", "rustdesk-test", "rustdesk-sync", "rustdesk-install"]) {
    const b = await row.getByTestId(id).boundingBox();
    expect(b, id).not.toBeNull();
    expect(b!.x + b!.width, `${id} 要在表格可見範圍內（操作欄固定在右側）`).toBeLessThanOrEqual(table!.x + table!.width + 1);
  }
  // 編輯：表單帶出目前的值
  await row.getByTestId("rustdesk-edit").click();
  await expect(page.getByTestId("rustdesk-client-address").locator("input")).toHaveValue("rd.example.net");
  await page.keyboard.press("Escape");
});

test("安裝指令：專用 RustDesk 代理的一行指令、金鑰、安裝位置與代理狀態", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk");
  const row = page.getByTestId("rustdesk-servers").locator("tr", { hasText: "rd-e2e" });
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.getByTestId("rustdesk-install").click();
  const box = page.getByTestId("rustdesk-install-modal");
  const cmd = box.getByTestId("rustdesk-install-cmd");
  await expect(cmd).toContainText("/api/v1/rustdesk/agent/installer.sh", { timeout: 10_000 });
  await expect(cmd).toContainText(`JT_IPAM_AGENT_KEY=${AGENT_KEY}`);
  await expect(cmd).not.toContainText("scan-agents");
  await expect(box).toContainText("/opt/jt-ipam-rustdesk-agent/jt_ipam_rustdesk_agent.py");
  await expect(box).toContainText("/etc/jt-ipam-rustdesk-agent.env");
  await expect(box.getByTestId("rustdesk-install-state")).toContainText("rd-host-e2e");
});

test("立即同步：通知代理（代理每 10 秒輪詢）", async ({ page, request }) => {
  await login(page);
  await page.goto("/rustdesk");
  const row = page.getByTestId("rustdesk-servers").locator("tr", { hasText: "rd-e2e" });
  await expect(row).toBeVisible({ timeout: 15_000 });
  const sent = page.waitForResponse((r) => r.request().method() === "POST" && r.url().includes("/sync-now"));
  await row.getByTestId("rustdesk-sync").click();
  expect((await sent).status()).toBe(202);
  await expect(page.locator(".n-message")).toContainText(/已通知代理|代理目前沒有連線/);
  // 代理下一次輪詢會拿到 report_now（單次）
  const poll = await request.post("/api/v1/rustdesk/agent/poll", { headers: { "X-Agent-Key": AGENT_KEY }, data: AGENT_POLL });
  expect((await poll.json()).report_now).toBe(true);
});

test("測試：代理在 RustDesk 主機上逐項檢查，結果顯示在視窗裡", async ({ page, request }) => {
  await login(page);
  await page.goto("/rustdesk");
  const row = page.getByTestId("rustdesk-servers").locator("tr", { hasText: "rd-e2e" });
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.getByTestId("rustdesk-test").click();
  const box = page.getByTestId("rustdesk-test-result");
  await expect(box).toContainText("等待代理");
  // 這裡由測試扮演代理：輪詢拿到 test_id → 送回結果
  let testId: string | null = null;
  await expect.poll(async () => {
    const r = await request.post("/api/v1/rustdesk/agent/poll", { headers: { "X-Agent-Key": AGENT_KEY }, data: AGENT_POLL });
    testId = (await r.json()).test_id;
    return testId;
  }, { timeout: 10_000 }).toBeTruthy();
  const res = await request.post("/api/v1/rustdesk/agent/test-result", {
    headers: { "X-Agent-Key": AGENT_KEY },
    data: { test_id: testId, checks: [
      { key: "database", ok: true, detail: "/var/lib/rustdesk-server/db_v2.sqlite3: 3 IDs" },
      { key: "online_query", ok: true, detail: "192.0.2.73:21115" },
      { key: "receiver", ok: false, detail: "TCP 21114: OSError: [Errno 98] Address already in use" },
    ] },
  });
  expect((await res.json()).status).toBe("ok");
  await expect(box).toContainText("1 項沒有通過", { timeout: 10_000 });
  await expect(box.getByTestId("rustdesk-check-database")).toContainText("hbbs 資料庫");
  await expect(box.getByTestId("rustdesk-check-receiver")).toContainText("Address already in use");
});

test("新增伺服器：客戶端位址格式不對會被擋下，正確的可以存", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk");
  await expect(page.getByTestId("rustdesk-servers").locator("tr", { hasText: "rd-e2e" })).toBeVisible({ timeout: 15_000 });
  const name = `rd-new-${Date.now()}`;
  await page.getByTestId("rustdesk-create").click();
  await page.getByTestId("rustdesk-name").locator("input").fill(name);
  await page.getByTestId("rustdesk-client-address").locator("input").fill("rd.example.net/evil");
  await page.getByTestId("rustdesk-save").click();
  await expect(page.locator(".n-message")).toBeVisible();
  await expect(page.getByTestId("rustdesk-servers").locator("tr", { hasText: name })).toHaveCount(0);
  await page.getByTestId("rustdesk-client-address").locator("input").fill("rd2.example.net:21116");
  await page.getByTestId("rustdesk-save").click();
  // 存好直接給這台伺服器專用代理的安裝指令（金鑰只出現這一次）
  const install = page.getByTestId("rustdesk-install-modal");
  await expect(install).toContainText("已建立");
  await expect(install.getByTestId("rustdesk-install-cmd")).toContainText("JT_IPAM_AGENT_KEY=");
  await expect(install.getByTestId("rustdesk-install-state")).toContainText("尚未安裝");
  await page.keyboard.press("Escape");
  const row = page.getByTestId("rustdesk-servers").locator("tr", { hasText: name });
  await expect(row).toBeVisible();
  // 收拾：刪掉剛建的（tooltip 會蓋住 popconfirm，直接送 click 事件，同 mikrotik.spec）
  await row.locator("button.n-button--error-type").click();
  const confirmBtn = page.locator(".n-popconfirm__action button").last();
  await expect(confirmBtn).toBeVisible();
  const deleted = page.waitForResponse((r) => r.request().method() === "DELETE" && r.url().includes("/rustdesk/"));
  await confirmBtn.dispatchEvent("click");
  expect((await deleted).status()).toBe(204);
  await expect(row).toHaveCount(0);
});

test("客戶端回報：裝置清單有主機名稱與比對依據，連線稽核頁籤列出整段連線與告警", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk?tab=devices");
  const peers = page.getByTestId("rustdesk-peers");
  const row = peers.locator("tr", { hasText: "100200300" });
  await expect(row).toContainText("seen-host-01", { timeout: 15_000 });
  await expect(row).toContainText("alice");
  await expect(row).toContainText("Windows 11 Pro");
  // 回報的主機名稱、登入帳號、作業系統各自一欄
  await expect(row.locator("td", { hasText: /^alice$/ })).toHaveCount(1);
  await expect(row.locator("td", { hasText: /^Windows 11 Pro$/ })).toHaveCount(1);
  await expect(row.getByTestId("rustdesk-evidence")).toContainText("主機名稱");
  await expect(row.getByTestId("rustdesk-evidence")).toContainText("回報 IP");

  await openTab(page, "連線稽核");
  await expect(page).toHaveURL(/tab=audit/);
  const audit = page.getByTestId("rustdesk-audit");
  await expect(audit.locator("tbody tr")).toHaveCount(5, { timeout: 15_000 });
  await expect(audit.locator("tr", { hasText: "驗證通過" })).toContainText("helpdesk");
  await expect(audit.locator("tr", { hasText: "驗證通過" })).toContainText("遠端桌面");
  await expect(audit.locator("tr", { hasText: "檔案傳輸" })).toContainText("C:/Users/alice/Desktop");
  await expect(audit.locator("tr", { hasText: "告警" })).toContainText("一分鐘內密碼錯誤 6 次");
  // 受控端與對方都拆成 ID／名稱／IP 各一欄
  const authRow = audit.locator("tr", { hasText: "驗證通過" });
  await expect(authRow.locator("td", { hasText: /^999888777$/ })).toHaveCount(1);
  await expect(authRow.locator("td", { hasText: /^helpdesk$/ })).toHaveCount(1);
  await page.getByTestId("rustdesk-audit-search").locator("input").fill("helpdesk");
  await expect(audit.locator("tbody tr")).toHaveCount(2);
});

test("告警通知的連結直接開到連線稽核頁籤", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk?tab=audit");
  await expect(page.getByTestId("rustdesk-audit")).toBeVisible({ timeout: 15_000 });
});

test("IP 詳細資料：顯示客戶端回報的使用者與 OS（主機名稱在「主機名稱來源」）", async ({ page }) => {
  await login(page);
  const id = await page.evaluate(async () => {
    const tok = localStorage.getItem("access_token") || "";
    const r = await fetch("/api/v1/addresses?q=10.20.0.40&page_size=5", { headers: { Authorization: `Bearer ${tok}` } });
    return ((await r.json()).items as { id: string; ip: string }[]).find((i) => i.ip.split("/")[0] === "10.20.0.40")!.id;
  });
  await page.goto(`/addresses/${id}`);
  const rep = page.getByTestId("ip-rustdesk-reported");
  await expect(rep).toContainText("alice", { timeout: 15_000 });
  await expect(rep).toContainText("Windows 11 Pro");
  await expect(rep).not.toContainText("seen-host-01");
});

async function ipIdOf(page: Page, ip: string): Promise<string> {
  return page.evaluate(async (want) => {
    const tok = localStorage.getItem("access_token") || "";
    const r = await fetch(`/api/v1/addresses?q=${want}&page_size=5`, { headers: { Authorization: `Bearer ${tok}` } });
    return ((await r.json()).items as { id: string; ip: string }[]).find((i) => i.ip.split("/")[0] === want)!.id;
  }, ip);
}

async function toggleRustDeskSwitch(page: Page) {
  await page.getByRole("button", { name: "編輯" }).first().click();
  const sw = page.getByTestId("ip-rustdesk-enable");
  await sw.scrollIntoViewIfNeeded();
  await sw.click();
  await page.getByRole("button", { name: /儲存|保存/ }).first().click();
}

test("RustDesk 連線按鈕比照 VNC：IP 編輯裡關掉就消失，開回來才出現", async ({ page }) => {
  // 開關存不存得住只有走完「改→存→重載」才知道
  await login(page);
  const url = `/addresses/${await ipIdOf(page, "10.20.0.40")}`;
  await page.goto(url);
  await expect(page.getByTestId("rustdesk-connect")).toBeVisible({ timeout: 15_000 });
  await toggleRustDeskSwitch(page);
  await page.goto(url);
  await expect(page.getByTestId("ip-rustdesk-id")).toContainText("100200300", { timeout: 15_000 });
  await expect(page.getByTestId("rustdesk-connect")).toHaveCount(0);
  // 收尾：開回來
  await toggleRustDeskSwitch(page);
  await page.goto(url);
  await expect(page.getByTestId("rustdesk-connect")).toBeVisible({ timeout: 15_000 });
});

test("同一台裝置的另一個 IP 有 RustDesk：編輯畫面講清楚對應在哪，連結過去就是那個 IP", async ({ page }) => {
  // 一台電腦兩張網卡時 RustDesk 只對應得到連出去的那個 IP（使用者 2026-10-05：「怎麼沒有啟用 RustDesk 連線的選項了」）。
  // 後端判斷「同一台」與權限收斂由 pytest 驗；這裡只驗畫面，把 API 回應換成那種情況，不動共用的種子資料。
  await login(page);
  const target = await ipIdOf(page, "10.20.0.40");
  const other = await ipIdOf(page, "10.20.0.41");
  await page.route((u) => u.pathname === `/api/v1/addresses/${other}`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const res = await route.fetch();
    const body = await res.json();
    body.rustdesk = null;
    body.rustdesk_elsewhere = [{ address_id: target, ip: "10.20.0.40", rustdesk_id: "100200300", enabled: true }];
    await route.fulfill({ response: res, json: body });
  });
  await page.goto(`/addresses/${other}`);
  await page.getByRole("button", { name: "編輯" }).first().click();
  const hint = page.getByTestId("ip-rustdesk-elsewhere");
  await hint.scrollIntoViewIfNeeded();
  await expect(hint).toContainText("這個 IP 沒有對應到 RustDesk 裝置");
  await expect(hint).toContainText("RustDesk ID 100200300");
  await expect(hint).toContainText("已啟用");
  await expect(page.getByTestId("ip-rustdesk-enable")).toHaveCount(0);
  await hint.getByTestId("ip-rustdesk-elsewhere-link").click();
  await expect(page).toHaveURL(new RegExp(`/addresses/${target}$`));
  await expect(page.getByTestId("ip-rustdesk-id")).toContainText("100200300", { timeout: 15_000 });
});

test("Key 設錯的裝置：伺服器列有「Key 錯誤 N」、點下去只列那些裝置；IP 頁講清楚怎麼改", async ({ page }) => {
  // Key 錯的客戶端照樣「就緒」、照樣回報、區網直連也正常，只有走中繼被拒（2026-10-05 實機）。
  // 代理讀日誌、後端歸到裝置的部分由 pytest 驗；這裡把 API 回應換成那種情況，不動共用的種子資料。
  await login(page);
  const at = new Date(Date.now() - 60_000).toISOString();
  const kp = { at, scope: "relay", count: 4 };
  let keyFilterSent = false;
  await page.route((u) => /\/api\/v1\/rustdesk\/servers$/.test(u.pathname), async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    for (const s of body.items) if (s.name === "rd-e2e") s.key_problems = 1;
    await route.fulfill({ response: res, json: body });
  });
  await page.route((u) => /\/api\/v1\/rustdesk\/servers\/[^/]+\/peers$/.test(u.pathname), async (route) => {
    const url = new URL(route.request().url());
    const filtered = url.searchParams.get("key_problem") === "true";
    // 後端真的會依 key_problem 篩（種子資料裡沒有 Key 錯的裝置）：拿掉條件抓回來，這裡自己篩
    url.searchParams.delete("key_problem");
    const res = await route.fetch({ url: url.toString() });
    const body = await res.json();
    if (filtered) {
      keyFilterSent = true;
      body.items = body.items.filter((p: { rustdesk_id: string }) => p.rustdesk_id === "100200300");
      body.total = body.items.length;
    }
    for (const p of body.items) if (p.rustdesk_id === "100200300") p.key_problem = kp;
    await route.fulfill({ response: res, json: body });
  });
  await page.goto("/rustdesk");
  const badge = page.getByTestId("rustdesk-servers").locator("tr", { hasText: "rd-e2e" }).getByTestId("rustdesk-key-problems");
  await expect(badge).toHaveText("Key 錯誤 1", { timeout: 15_000 });
  await badge.click();
  await expect(page).toHaveURL(/tab=devices/);
  await expect(page.getByTestId("rustdesk-key-filter")).toHaveClass(/n-checkbox--checked/);
  const row = page.getByTestId("rustdesk-peers-table").locator("tr", { hasText: "100200300" });
  await expect(row.getByTestId("rustdesk-key-problem")).toHaveText("Key 錯誤", { timeout: 15_000 });
  await expect(page.getByTestId("rustdesk-peers-table").locator("tbody tr")).toHaveCount(1);
  expect(keyFilterSent, "篩選交給伺服器（key_problem=true）").toBe(true);
  await row.getByTestId("rustdesk-key-problem").hover();
  await expect(page.locator(".n-tooltip").last()).toContainText("RustDesk Key 跟伺服器不同");

  const id = await ipIdOf(page, "10.20.0.40");
  await page.route((u) => u.pathname === `/api/v1/addresses/${id}`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const res = await route.fetch();
    const body = await res.json();
    body.rustdesk.key_problem = kp;
    await route.fulfill({ response: res, json: body });
  });
  await page.goto(`/addresses/${id}`);
  const alert = page.getByTestId("ip-rustdesk-key-problem");
  await expect(alert).toContainText("中繼伺服器", { timeout: 15_000 });
  await expect(alert).toContainText("被拒 4 次");
  await expect(alert).toContainText("ID / 中繼伺服器");
});

test("網頁連線可用時只有一顆分割按鈕：主鍵網頁連線，▾ 裡才是本機客戶端", async ({ page }) => {
  // 使用者 2026-10-05：「不要獨立兩個按鈕…合為左按鈕本身右邊向下拉才彈出的選項」（照 Proxmox 主控台）
  await login(page);
  const id = await ipIdOf(page, "10.20.0.40");
  await page.route((u) => u.pathname === `/api/v1/addresses/${id}`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const res = await route.fetch();
    const body = await res.json();
    body.rustdesk.web_available = true;
    await route.fulfill({ response: res, json: body });
  });
  await page.goto(`/addresses/${id}`);
  await expect(page.getByTestId("rustdesk-web-connect")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("rustdesk-connect"), "本機客戶端不再是獨立的按鈕").toHaveCount(0);
  await expect(page.getByTestId("rustdesk-local-badge")).toHaveCount(0);
  // 滑過去都要有說明（使用者 2026-10-05）：▾ 是「其他連線方式」，選項說明會開本機安裝的客戶端軟體
  await page.getByTestId("rustdesk-more").hover();
  await expect(page.locator(".n-tooltip", { hasText: "其他連線方式" })).toBeVisible();
  await page.getByTestId("rustdesk-more").click();
  const item = page.locator(".n-dropdown-option", { hasText: "用本機的 RustDesk 客戶端軟體開啟" });
  await expect(item).toBeVisible();
  await item.hover();
  await expect(page.locator(".n-tooltip", { hasText: "不經過 jt-ipam 網頁" })).toBeVisible();
  // 按下去要記一筆稽核（連線本身不經 jt-ipam；「調查」的遠端連線記錄靠它）
  const audited = page.waitForRequest((r) => r.method() === "POST" && r.url().includes(`/addresses/${id}/rustdesk/local-open`));
  await item.click();
  await audited;
});

test("裝置清單：可以挑選欄位，標題排序交給伺服器，複製按鈕滑過有提示", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk?tab=devices");
  const table = page.getByTestId("rustdesk-peers-table");
  await expect(table.locator("tbody tr")).toHaveCount(3, { timeout: 15_000 });

  // 伺服器端排序：點「回報的主機名稱」→ 請求帶 sort=hostname（第一下降冪、第二下升冪，同全站），沒有值的排最後
  const desc = page.waitForResponse((r) => r.url().includes("/peers?") && r.url().includes("sort=hostname")
    && r.url().includes("order=desc"));
  await table.locator("th", { hasText: "回報的主機名稱" }).click();
  await desc;
  await expect(table.locator("tbody tr").first()).toContainText("100200300");  // 只有一台有名稱：其餘排最後
  const asc = page.waitForResponse((r) => r.url().includes("sort=hostname") && r.url().includes("order=asc"));
  await table.locator("th", { hasText: "回報的主機名稱" }).click();
  await asc;
  await expect(table.locator("tbody tr").first()).toContainText("100200300");

  // 欄位挑選：關掉「作業系統」→ 表頭不見；再開回來
  const peersBox = page.getByTestId("rustdesk-peers");
  await peersBox.getByRole("button", { name: /欄位/ }).click();
  const osItem = page.locator(".n-popover .n-checkbox", { hasText: "作業系統" });
  await osItem.click();
  await expect(table.locator("th", { hasText: "作業系統" })).toHaveCount(0);
  await osItem.click();
  await expect(table.locator("th", { hasText: "作業系統" })).toHaveCount(1);
  await page.keyboard.press("Escape");

  // 複製按鈕：滑過去有提示文字
  const copy = table.locator("tr", { hasText: "100200300" }).getByTestId("copy-btn").first();
  await copy.hover();
  await expect(page.locator(".n-tooltip", { hasText: "複製 ID" })).toBeVisible();
});

test("連線稽核：可以挑選欄位、標題排序交給伺服器", async ({ page }) => {
  await login(page);
  await page.goto("/rustdesk?tab=audit");
  const table = page.getByTestId("rustdesk-audit-table");
  await expect(table.locator("tbody tr")).toHaveCount(5, { timeout: 15_000 });
  const sorted = page.waitForResponse((r) => r.url().includes("/audit?") && r.url().includes("sort=peer_name"));
  await table.locator("th", { hasText: "對方名稱" }).click();
  await sorted;
  await page.getByTestId("rustdesk-audit").getByRole("button", { name: /欄位/ }).click();
  const item = page.locator(".n-popover .n-checkbox", { hasText: "對方 IP" });
  await item.click();
  await expect(table.locator("th", { hasText: "對方 IP" })).toHaveCount(0);
  await item.click();
  await expect(table.locator("th", { hasText: "對方 IP" })).toHaveCount(1);
});

test("網頁連線表單照 VNC 的已存帳密：已存密碼下拉預設選第一筆、清掉改手動輸入、記住密碼開關、刪除（附錄 D.5）", async ({ page }) => {
  // 真的連上去要有受控端（見 rustdesk-web.spec.ts）；這裡只驗表單，把金庫的回應換成「有一筆已存的密碼」，不動共用的種子資料
  await login(page);
  const id = await ipIdOf(page, "10.20.0.40");
  let saved = true;
  const deleted: string[] = [];
  await page.route((u) => u.pathname === "/api/v1/ssh-credentials", async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    expect(new URL(route.request().url()).searchParams.get("protocol")).toBe("rustdesk");
    await route.fulfill({ json: saved ? [{
      id: "00000000-0000-4000-8000-0000000000aa", label: "RustDesk 100200300", protocol: "rustdesk", username: "",
      auth_type: "password", domain: null, target_ip_id: id, has_password: true, has_private_key: false,
      last_used_at: null, created_at: new Date().toISOString(),
    }] : [] });
  });
  await page.route((u) => u.pathname.startsWith("/api/v1/ssh-credentials/"), async (route) => {
    if (route.request().method() !== "DELETE") return route.continue();
    deleted.push(route.request().url());
    saved = false;
    await route.fulfill({ status: 204, body: "" });
  });
  await page.goto(`/rustdesk/${id}`);
  // 第一列「已存密碼」預設選第一筆：不顯示密碼框與「記住密碼」
  const select = page.getByTestId("rdweb-saved-password");
  await expect(page.getByTestId("rdweb-saved-row")).toContainText("已存密碼", { timeout: 15_000 });
  await expect(select).toContainText("RustDesk 100200300");
  await expect(page.getByTestId("rdweb-password")).toHaveCount(0);
  await expect(page.getByTestId("rdweb-remember")).toHaveCount(0);
  await expect(page.getByTestId("rdweb-store-hint")).toContainText("使用已儲存的密碼");
  // 選「使用其他密碼（手動輸入）」：密碼框＋「記住密碼」開關；開了之後說明會存到伺服器、可以取名
  await select.click();
  await page.locator(".n-base-select-option", { hasText: "使用其他密碼（手動輸入）" }).click();
  await expect(page.getByTestId("rdweb-password")).toBeVisible();
  await expect(page.getByTestId("rdweb-store-hint")).toContainText("密碼僅用於本次連線，不會儲存於伺服器");
  await page.getByTestId("rdweb-remember").click();
  await expect(page.getByTestId("rdweb-store-hint")).toContainText("登入成功時");
  await expect(page.getByTestId("rdweb-remember-label")).toBeVisible();
  // 選回已存的，旁邊的刪除鈕刪掉
  await select.click();
  await page.locator(".n-base-select-option", { hasText: "RustDesk 100200300" }).click();
  await expect(page.getByTestId("rdweb-password")).toHaveCount(0);
  await page.getByTestId("rdweb-delete-saved").click();
  await page.locator(".n-popconfirm__action button").last().click();
  await expect(page.getByTestId("rdweb-password")).toBeVisible();
  expect(deleted).toHaveLength(1);
  await expect(page.getByTestId("rdweb-delete-saved")).toHaveCount(0);
  await expect(page.getByTestId("rdweb-remember")).toBeVisible();
  // 一筆都沒有了：整列「已存密碼」不出現（下拉裡只剩手動輸入，沒有東西可選；使用者 2026-10-05）
  await expect(page.getByTestId("rdweb-saved-row")).toHaveCount(0);
  await page.reload();
  await expect(page.getByTestId("rdweb-password")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("rdweb-saved-row")).toHaveCount(0);
});
