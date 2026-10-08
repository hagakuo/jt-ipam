/**
 * IP 的「探測」頁：只有管理員看得到；開始 → 進度 → 摘要／應用程式／前後比對／連接埠 → 下載原始結果。
 *
 * 真正的探測要掃描代理跑 nmap，e2e 環境沒有代理，所以三個 identify 端點用路由攔截固定回應，
 * 驗的是畫面流程。「一般使用者看不到按鈕、直接打 API 也被拒」則打真的後端。
 * 樣本：seed_e2e 的 db-01（10.20.0.12）。
 */
import { test, expect, type APIRequestContext, type Page } from "@playwright/test";
import crypto from "node:crypto";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const PLAIN_USER = `e2e-idf-${Date.now().toString(36)}`;
const PLAIN_PASS = `Idf-${crypto.randomBytes(9).toString("base64url")}`;
const SAMPLE_IP = "10.20.0.12";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function token(request: APIRequestContext, username: string, password: string): Promise<string> {
  const r = await request.post("/api/v1/auth/login", { data: { username, password, realm: "local" } });
  expect(r.ok(), `${username} API 登入要成功`).toBeTruthy();
  return (await r.json()).access_token;
}

async function login(page: Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(username);
  await page.getByPlaceholder(/密碼|Password/).fill(password);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

let ipId = "";
let plainId: string | null = null;
let grantId: string | null = null;

test.beforeAll(async ({ request }) => {
  const auth = { Authorization: `Bearer ${await token(request, ADMIN_USER, ADMIN_PASS)}` };
  const found = await (await request.get(`/api/v1/addresses?q=${SAMPLE_IP}&page_size=5`, { headers: auth })).json();
  ipId = found.items?.find((x: { ip: string }) => String(x.ip).split("/")[0] === SAMPLE_IP)?.id ?? "";
  expect(ipId, "找不到樣本 IP（先跑 seed_e2e）").not.toBe("");
  const r = await request.post("/api/v1/users", { headers: auth, data: {
    username: PLAIN_USER, email: `${PLAIN_USER}@example.com`, password: PLAIN_PASS } });
  expect(r.status(), await r.text()).toBe(201);
  plainId = (await r.json()).id;
  // 給它看得到所有子網路的唯讀權限：新帳號什麼都看不到，連 IP 詳細頁都進不去
  const g = await request.post("/api/v1/system/permissions", { headers: auth, data: {
    object_type: "section", object_id: null, principal_type: "user", principal_id: plainId, level: "read" } });
  expect(g.ok(), await g.text()).toBeTruthy();
  grantId = (await g.json()).id;
});

test.afterAll(async ({ request }) => {
  if (!plainId) return;
  const auth = { Authorization: `Bearer ${await token(request, ADMIN_USER, ADMIN_PASS)}` };
  if (grantId) await request.delete(`/api/v1/system/permissions/${grantId}`, { headers: auth });
  await request.delete(`/api/v1/users/${plainId}`, { headers: auth });
});

test("唯讀使用者看不到探測按鈕，直接打 API 也被拒", async ({ page, request }) => {
  await login(page, PLAIN_USER, PLAIN_PASS);
  await page.goto(`/addresses/${ipId}`);
  await expect(page.getByText(SAMPLE_IP).first()).toBeVisible({ timeout: 20_000 });
  // 同一排的「調查」按鈕在，探測按鈕不在 —— 確定不是整排還沒畫出來
  await expect(page.getByRole("button", { name: "調查" })).toBeVisible();
  await expect(page.getByTestId("ip-identify-btn")).toHaveCount(0);
  // 直接開探測頁也看不到內容
  await page.goto(`/addresses/${ipId}/identify`);
  await expect(page.getByTestId("identify-start")).toHaveCount(0);
  await expect(page.getByTestId("identify-history")).toHaveCount(0);

  const plainAuth = { Authorization: `Bearer ${await token(request, PLAIN_USER, PLAIN_PASS)}` };
  expect((await request.post(`/api/v1/addresses/${ipId}/identify`, { headers: plainAuth })).status()).toBe(403);
  expect((await request.get(`/api/v1/addresses/${ipId}/identify`, { headers: plainAuth })).status()).toBe(403);
});

test("管理員：按下探測 → 開探測頁 → 看得到進度 → 完成後顯示摘要、應用程式、前後比對，可下載原始結果", async ({ page }) => {
  const JOB = "00000000-0000-4000-8000-00000000e2e1";
  const OLD = "00000000-0000-4000-8000-00000000e2e0";
  let started = false;
  let polls = 0;
  const summary = { device_type: "server", os: "Linux 5.15 - 6.8", vendor: "IANA", names: ["db-01.example.test"],
                    applications: ["OpenSSH 9.6p1", "PostgreSQL DB 16", "AnyDesk"],
                    services: ["22/tcp ssh OpenSSH 9.6p1", "5432/tcp postgresql PostgreSQL DB 16"],
                    evidence: ["os:Linux 5.15 - 6.8 (96%)", "osclass:general purpose", "oui:IANA",
                               "recog:OpenSSH running on Ubuntu (22/tcp ssh.banner)"],
                    model: "PowerEdge R650", recog: "3.2.0",
                    nmap_available: true };
  const oldBrief = { job_id: OLD, status: "done", agent_name: "agent-e2e", created_at: "2026-09-27T01:00:00Z",
                     finished_at: "2026-09-27T01:01:00Z", summary };
  const done = {
    job_id: JOB, status: "done", error: null, error_code: null, agent_name: "agent-e2e",
    created_at: "2026-09-28T01:00:00Z", claimed_at: "2026-09-28T01:00:02Z", finished_at: "2026-09-28T01:01:30Z",
    progress: { stage: "scan" },
    result: { target: SAMPLE_IP, names: { rdns: "db-01.example.test", netbios: null, mdns: null },
              nmap: { available: true, ports: [
                { port: 22, proto: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.6p1",
                  extrainfo: "Ubuntu Linux; protocol 2.0", scripts: { "ssh-hostkey": "256 SHA256:e2e (ED25519)" } },
                { port: 5432, proto: "tcp", state: "open", service: "postgresql", product: "PostgreSQL DB",
                  version: "16", scripts: {} },
              ], os: [{ name: "Linux 5.15 - 6.8", accuracy: 96 }] } },
    summary,
    changes: { previous_job_id: OLD, previous_at: "2026-09-27T01:00:00Z", opened: ["5432/tcp"], closed: ["80/tcp"],
               changed: [{ port: "22/tcp", before: "OpenSSH 8.9p1", after: "OpenSSH 9.6p1" }] },
  };
  await page.route(/\/api\/v1\/addresses\/[^/]+\/identify(\/[^/?]+)?(\?.*)?$/, async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (req.method() === "POST") {
      started = true;
      return route.fulfill({ status: 202, json: { job_id: JOB, agent_id: "a", agent_name: "agent-e2e", status: "pending" } });
    }
    if (path.endsWith("/history")) {
      const items = started ? [{ ...oldBrief, job_id: JOB, status: polls < 2 ? "running" : "done",
                                  created_at: "2026-09-28T01:00:00Z", summary: null }, oldBrief] : [oldBrief];
      return route.fulfill({ json: { items } });
    }
    if (path.endsWith(OLD)) return route.fulfill({ json: { ...done, job_id: OLD, created_at: oldBrief.created_at, changes: null } });
    polls += 1;   // 前兩次還在跑（第一次在查名稱、第二次在掃描），之後完成
    if (polls === 1) return route.fulfill({ json: { ...done, status: "running", progress: { stage: "names" }, result: null, summary: null, changes: null } });
    if (polls === 2) return route.fulfill({ json: { ...done, status: "running", progress: { stage: "scan" }, result: null, summary: null, changes: null } });
    return route.fulfill({ json: done });
  });

  await login(page, ADMIN_USER, ADMIN_PASS);
  await page.goto(`/addresses/${ipId}`);
  const btn = page.getByTestId("ip-identify-btn");
  await expect(btn).toBeVisible({ timeout: 20_000 });
  const b1 = (await btn.boundingBox())!;
  const b2 = (await page.getByRole("button", { name: "調查" }).boundingBox())!;
  expect(b1.x).toBeLessThan(b2.x);                       // 探測在調查的左邊

  await btn.click();
  await expect(page).toHaveURL(new RegExp(`/addresses/${ipId}/identify`));   // 獨立頁面，不是對話框
  await expect(page.locator(".n-modal")).toHaveCount(0);
  await expect(page.getByText("關掉這一頁不會中斷探測", { exact: false })).toBeVisible();
  // 一進來就顯示最近一次（歷次清單的第一筆）
  await expect(page.getByTestId("identify-history-item")).toHaveCount(1);
  await expect(page.getByTestId("identify-summary")).toBeVisible();

  await page.getByTestId("identify-start").click();
  const prog = page.getByTestId("identify-progress");
  await expect(prog).toBeVisible();
  await expect(prog).toContainText("查詢名稱");
  await expect(page.getByTestId("identify-summary")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("identify-status")).toContainText("完成於");
  await expect(page.getByTestId("identify-history-item")).toHaveCount(2);

  const sum = page.getByTestId("identify-summary");
  await expect(sum).toContainText("伺服器／電腦");
  // 類型是推測：畫面要講明可能不準（使用者回饋：NAS 被判成攝影機）
  await expect(page.getByTestId("identify-guess")).toContainText("推測");
  await expect(page.getByTestId("identify-guess-note")).toContainText("可能判斷錯誤");
  await expect(sum).toContainText("db-01.example.test");
  await expect(page.getByTestId("identify-apps")).toContainText("AnyDesk");
  // Recog 指紋庫：型號、比中的依據、用的是哪一版
  await expect(page.getByTestId("identify-model")).toHaveText("PowerEdge R650");
  await expect(sum).toContainText("recog:OpenSSH running on Ubuntu");
  await expect(page.getByTestId("identify-recog-note")).toContainText("Recog 3.2.0");
  const ch = page.getByTestId("identify-changes");
  await expect(ch).toContainText("5432/tcp");
  await expect(ch).toContainText("80/tcp");
  await expect(ch).toContainText("OpenSSH 8.9p1 → OpenSSH 9.6p1");
  await expect(page.getByTestId("identify-ports")).toContainText("ssh-hostkey");
  // 欄寬依內容：產品與其他資訊只拿需要的寬度，剩下的給最後一欄「讀到的資訊」（使用者回饋：拉寬後沒充分利用）
  await page.setViewportSize({ width: 1920, height: 1000 });
  const th = (label: string) => page.getByTestId("identify-ports").locator("th").filter({ hasText: label }).first();
  const wProduct = (await th("產品").boundingBox())!.width;
  const wExtra = (await th("其他資訊").boundingBox())!.width;
  const wScripts = (await th("讀到的資訊").boundingBox())!.width;
  expect(wScripts).toBeGreaterThan(wProduct + wExtra);
  expect(wProduct).toBeLessThan(400);

  // 原始結果可以直接下載，不用自己複製
  await page.getByText("原始結果").click();
  const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId("identify-download").click()]);
  expect(dl.suggestedFilename()).toMatch(/^identify-10\.20\.0\.12-.*\.json$/);
  const body = JSON.parse(await (await dl.createReadStream())!.toArray().then((b) => Buffer.concat(b).toString()));
  expect(body.nmap.ports[0].port).toBe(22);

  // 點回上一次
  await page.getByTestId("identify-history-item").nth(1).click();
  await expect(page).toHaveURL(new RegExp(`job=${OLD}`));
  await expect(page.getByTestId("identify-changes")).toHaveCount(0);
});


test("探測時主機沒有回應：講清楚是沒回應，不是「無法判斷」", async ({ page }) => {
  const JOB = "00000000-0000-4000-8000-00000000e2e9";
  const silent = { device_type: "no_response", no_response: true, os: null, vendor: "ProxmoxServe", names: [],
                   applications: [], services: [], evidence: ["oui:ProxmoxServe"], nmap_available: true };
  const brief = { job_id: JOB, status: "done", agent_name: "agent-e2e", created_at: "2026-09-29T06:37:01Z",
                  finished_at: "2026-09-29T06:37:09Z", summary: silent };
  await page.route(/\/api\/v1\/addresses\/[^/]+\/identify(\/[^/?]+)?(\?.*)?$/, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/history")) return route.fulfill({ json: { items: [brief] } });
    return route.fulfill({ json: { ...brief, error: null, error_code: null, claimed_at: brief.created_at,
      progress: null, changes: null,
      result: { target: SAMPLE_IP, names: { rdns: null, netbios: null, mdns: null },
                nmap: { available: true, ports: [], os: [], mac: null, closed: 0 } } } });
  });
  await login(page, ADMIN_USER, ADMIN_PASS);
  await page.goto(`/addresses/${ipId}/identify`);
  const alert = page.getByTestId("identify-no-response");
  await expect(alert).toContainText("完全沒有回應");
  await expect(alert).toContainText("ProxmoxServe");
  await expect(page.getByTestId("identify-summary")).toContainText("沒有回應");
  await expect(page.getByTestId("identify-guess")).toHaveCount(0);
  // 摘要沒有帶 Recog 版本＝伺服器沒裝指紋庫：要講出來，不然看不出判斷為什麼比較少
  await expect(page.getByTestId("identify-recog-note")).toContainText("沒有安裝 Recog");
});


test("已經抓到的資料都顯示出來：Windows 名稱、埠數、耗時、名稱來源、判斷說明、憑證與金鑰、照埠號猜、截斷", async ({ page }) => {
  const JOB = "00000000-0000-4000-8000-00000000e2f1";
  const OLD = "00000000-0000-4000-8000-00000000e2f0";
  const soon = new Date(Date.now() + 10 * 86400000).toISOString().slice(0, 19);
  const summary = {
    device_type: "windows", os: "Windows 10 Pro 19045", vendor: null, nic_vendor: "Example Corp",
    names: ["laptop-07.corp.example.test", "LAPTOP-07"], applications: [], services: [], evidence: ["smb-os:Windows 10 Pro 19045"],
    nmap_available: true, scan_failed: false, scan_error: null,
    name_sources: [{ name: "laptop-07.corp.example.test", sources: ["rdns", "rdp"] }, { name: "LAPTOP-07", sources: ["netbios", "rdp"] }],
    windows: { computer: "LAPTOP-07", domain: "CORP", dns_domain: "corp.example.test", fqdn: "laptop-07.corp.example.test",
               workgroup: null, product_version: "10.0.19045" },
    certs: [{ port: "3389/tcp", subject: "CN=laptop-07.corp.example.test", issuer: "CN=laptop-07.corp.example.test",
              self_signed: true, not_before: "2026-01-01T00:00:00", not_after: soon, sha256: "ab".repeat(32), sha1: null,
              key: "rsa 2048", san: [] }],
    ssh_keys: [{ port: "22/tcp", type: "ssh-ed25519", bits: 256, fingerprint: "SHA256:e2eNewKeyExampleExample" }],
    port_counts: { open: 3, closed: 990, filtered: 7 }, distance: 1, uptime_seconds: 864000, elapsed: 83.4, os_scan: false,
    mac: "00:00:5e:00:53:07", mac_seen: "00:00:5E:00:53:99",
    notes: [{ code: "no_os_scan", params: {} }, { code: "port_table_guess", params: { ports: "9100/tcp" } },
            { code: "mac_differs", params: { seen: "00:00:5E:00:53:99" } }],
  };
  const done = {
    job_id: JOB, status: "done", error: null, error_code: null, agent_name: "agent-e2e",
    created_at: "2026-10-07T01:00:00Z", claimed_at: "2026-10-07T01:00:02Z", finished_at: "2026-10-07T01:01:30Z",
    progress: null, summary,
    result: { target: SAMPLE_IP, names: {}, nmap: { available: true, ports: [
      { port: 9100, proto: "tcp", state: "open", service: "jetdirect", method: "table", scripts: {} },
      { port: 3389, proto: "tcp", state: "open", service: "ms-wbt-server", method: "probed",
        scripts: { "ssl-cert": "Subject: commonName=laptop-07" }, truncated: ["ssl-cert"] },
    ] } },
    changes: { previous_job_id: OLD, previous_at: "2026-10-06T01:00:00Z", opened: [], closed: [], changed: [],
               baseline: null, current: null, fields: [{ field: "os", before: "Windows 10 Pro 19044", after: "Windows 10 Pro 19045" }],
               names_added: [], names_removed: [],
               ssh_keys: [{ port: "22/tcp", type: "ssh-ed25519", before: "SHA256:e2eOldKey", after: "SHA256:e2eNewKeyExampleExample" }],
               certs: [] },
  };
  const brief = { job_id: JOB, status: "done", agent_name: "agent-e2e", created_at: done.created_at,
                  finished_at: done.finished_at, summary };
  await page.route(/\/api\/v1\/addresses\/[^/]+\/identify(\/[^/?]+)?(\?.*)?$/, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/history")) return route.fulfill({ json: { items: [brief] } });
    return route.fulfill({ json: done });
  });
  await login(page, ADMIN_USER, ADMIN_PASS);
  await page.goto(`/addresses/${ipId}/identify`);
  const sum = page.getByTestId("identify-summary");
  await expect(sum).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("identify-windows")).toHaveText("電腦 LAPTOP-07 · 網域 CORP（corp.example.test）");
  await expect(page.getByTestId("identify-port-counts")).toHaveText("開放 3 · 關閉 990 · 過濾 7");
  await expect(page.getByTestId("identify-scan")).toHaveText("耗時 1:23 · 1 跳 · 推估開機 10 天");
  await expect(page.getByTestId("identify-name").first()).toContainText("反解 · RDP");
  await expect(page.getByTestId("identify-mac")).toHaveText("00:00:5e:00:53:07");
  await expect(page.getByTestId("identify-mac-seen")).toContainText("00:00:5E:00:53:99");
  const notes = page.getByTestId("identify-notes");
  await expect(notes).toContainText("代理不是以 root 執行");
  await expect(notes).toContainText("9100/tcp 沒有認出服務");
  // 憑證與金鑰
  const certs = page.getByTestId("identify-certs");
  await expect(certs).toContainText("CN=laptop-07.corp.example.test");
  await expect(certs).toContainText("自簽");
  await expect(certs).toContainText(/\d+ 天後到期/);
  await expect(certs).toContainText("SHA-256 AB:AB:AB");
  await expect(page.getByTestId("identify-ssh-keys")).toContainText("SHA256:e2eNewKeyExampleExample");
  // 照埠號猜的服務、被截斷的輸出都有標記
  await expect(page.getByTestId("identify-port-guess")).toHaveCount(1);
  await expect(page.getByTestId("identify-ports")).toContainText("（已截斷）");
  // 前後比對：作業系統與主機金鑰
  const ch = page.getByTestId("identify-changes");
  await expect(ch).toContainText("Windows 10 Pro 19044 → Windows 10 Pro 19045");
  await expect(page.getByTestId("identify-change-key")).toContainText("SHA256:e2eOldKey → SHA256:e2eNewKeyExampleExample");
  await expect(ch).toContainText("可能是被冒充");
});

test("nmap 失敗不是「沒有回應」；上一次沒回應時連接埠不比", async ({ page }) => {
  const JOB = "00000000-0000-4000-8000-00000000e2f9";
  const failed = { device_type: "unknown", no_response: false, os: null, vendor: null, names: [], applications: [],
                   services: [], evidence: [], nmap_available: true, scan_failed: true,
                   scan_error: "exit 1: Failed to resolve given hostname/IP", notes: [] };
  const brief = { job_id: JOB, status: "done", agent_name: "agent-e2e", created_at: "2026-10-07T02:00:00Z",
                  finished_at: "2026-10-07T02:00:09Z", summary: failed };
  await page.route(/\/api\/v1\/addresses\/[^/]+\/identify(\/[^/?]+)?(\?.*)?$/, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/history")) return route.fulfill({ json: { items: [brief] } });
    return route.fulfill({ json: { ...brief, error: null, error_code: null, claimed_at: brief.created_at, progress: null,
      result: { target: SAMPLE_IP, names: {}, nmap: { available: true, exit: 1, ports: [] } },
      changes: { previous_job_id: "x", previous_at: "2026-10-06T02:00:00Z", opened: [], closed: [], changed: [],
                 baseline: "no_response", current: null } } });
  });
  await login(page, ADMIN_USER, ADMIN_PASS);
  await page.goto(`/addresses/${ipId}/identify`);
  await expect(page.getByTestId("identify-scan-failed")).toContainText("nmap 執行失敗", { timeout: 20_000 });
  await expect(page.getByTestId("identify-scan-failed")).toContainText("Failed to resolve");
  await expect(page.getByTestId("identify-no-response")).toHaveCount(0);
  await expect(page.getByTestId("identify-cmp-blocked")).toContainText("上一次探測沒有回應");
});
