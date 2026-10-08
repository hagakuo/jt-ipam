/**
 * guacd 引擎：RDP、VNC、SSH 三種主控台改用 guacd 之後都要真的能用（使用者要求，2026-09-25）。
 *
 * 需要（缺一就跳過）：
 *   E2E_ADMIN_PASS                    管理員密碼
 *   本機 guacd（127.0.0.1:4822）      scripts/guacd/ 編好的預編檔；設定頁的狀態要是「可用」
 *   RDP 靶  127.0.0.1:3389           docker run -d -p 127.0.0.1:3389:3389 jtipam-rdp-target
 *   VNC 靶  127.0.0.1:5999           python3 e2e/fixtures/vnc-target.py --port 5999
 *   SSH 靶  127.0.0.1:2222           tester / TestPass!2026（sshd 容器）
 *   VNC 帳密靶 127.0.0.1:5998         vncuser / VncE2e-pass1（VeNCrypt 帳密；沒起就只跳過帳號那兩個測試）：
 *     docker run -d --name jtipam-vnc-plain -p 127.0.0.1:5998:5900 --entrypoint bash jtipam-rdp-target -c \
 *       'useradd -m vncuser; echo vncuser:VncE2e-pass1 | chpasswd; Xvnc :0 -rfbport 5900 \
 *        -SecurityTypes TLSPlain,Plain -PlainUsers vncuser -geometry 1280x800 & sleep 2; DISPLAY=:0 exec xterm'
 *   seed_e2e 的 console-target（127.0.0.1，SSH／RDP／VNC 都開）
 *
 * 畫面上的字沒有辦法直接讀，所以驗三件事：
 *   ① 狀態變成「已連線」、畫面的 canvas 不是一片黑（連線失敗也會有 canvas，一定要量像素）
 *   ② 按鍵真的以 Guacamole 的 key 指令送出去了（錄 WebSocket 送出的訊息）
 *   ③ 中文（輸入法、直接插入）以 Unicode keysym 送出 —— 接在 div 上時完全送不出去
 * 遠端畫出來的內容（打的字、中文字寬）由 scripts/guacd/verify.sh 的截圖與人工檢查涵蓋。
 */
import { test, expect, type Page } from "@playwright/test";
import net from "node:net";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const r = await fetch(path, { method, body: body === undefined ? undefined : JSON.stringify(body),
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}`, "Content-Type": "application/json" } });
    return { status: r.status, json: r.status === 204 ? null : await r.json().catch(() => null) };
  }, { method, path, body });
}

/** 畫面上非黑像素的數量（所有 guacamole 圖層的 canvas 加總） */
async function paintedPixels(page: Page): Promise<number> {
  return page.locator(".guac-host").evaluate((host) => {
    let n = 0;
    for (const c of Array.from(host.querySelectorAll("canvas"))) {
      const w = Math.min(c.width, 800), h = Math.min(c.height, 600);
      if (!w || !h) continue;
      const d = c.getContext("2d")!.getImageData(0, 0, w, h).data;
      for (let i = 0; i < d.length; i += 16) if (d[i + 3] && (d[i] || d[i + 1] || d[i + 2])) n++;
    }
    return n;
  });
}

/** 畫面最上面那一行字的右端位置（像素）。量字級用：同一行內容字變大就變寬。
 *  （數「畫了多少像素」不準：字變大、行數變少，固定範圍內的總量差不多。） */
async function firstLineRight(page: Page): Promise<number> {
  return page.locator(".guac-host").evaluate((host) => {
    let best = 0;
    for (const c of Array.from(host.querySelectorAll("canvas"))) {
      if (!c.width || !c.height) continue;
      const h = Math.min(c.height, 400);
      const d = c.getContext("2d")!.getImageData(0, 0, c.width, h).data;
      const lit = (x: number, y: number) => {
        const i = (y * c.width + x) * 4;
        return d[i + 3] > 0 && d[i] + d[i + 1] + d[i + 2] > 90;
      };
      let y0 = -1;
      for (let y = 0; y < h && y0 < 0; y++) for (let x = 0; x < c.width; x += 2) if (lit(x, y)) { y0 = y; break; }
      if (y0 < 0) continue;
      let right = 0;
      for (let y = y0; y < Math.min(h, y0 + 40); y++) {
        let rowLit = false;
        for (let x = 0; x < c.width; x++) if (lit(x, y)) { rowLit = true; right = Math.max(right, x); }
        if (!rowLit && y > y0 + 4) break;       // 第一行結束
      }
      best = Math.max(best, right);
    }
    return best;
  });
}

function recordSent(page: Page): string[] {
  const sent: string[] = [];
  page.on("websocket", (ws) => ws.on("framesent", (f) => { sent.push(String(f.payload)); }));
  return sent;
}

let consoleIp = "";
let saved: Record<string, unknown> = {};

test.beforeEach(async ({ page }) => {
  await login(page);
  const cs = await api(page, "GET", "/api/v1/system/console-security");
  test.skip(!cs.json?.guacd_available, "本機沒有 guacd（見檔頭）");
  saved = { rdp_clipboard_paste: cs.json.rdp_clipboard_paste, rdp_engine: cs.json.rdp_engine,
            vnc_engine: cs.json.vnc_engine, ssh_engine: cs.json.ssh_engine };
  await api(page, "PUT", "/api/v1/system/console-security",
    { ...saved, rdp_engine: "guacd", vnc_engine: "guacd", ssh_engine: "guacd" });
  const found = await api(page, "GET", "/api/v1/addresses?q=127.0.0.1&page_size=50");
  consoleIp = found.json.items.find((x: any) => String(x.ip).split("/")[0] === "127.0.0.1")?.id || "";
  test.skip(!consoleIp, "沒有 console-target（先跑 seed_e2e）");
});

test.afterEach(async ({ page }) => {
  if (Object.keys(saved).length) await api(page, "PUT", "/api/v1/system/console-security", saved);
});

test("RDP 走 guacd：連上、畫出畫面、鍵盤送得出去", async ({ page }) => {
  const sent = recordSent(page);
  await page.goto(`/rdp/${consoleIp}`);
  await page.getByPlaceholder("Administrator").fill("rdpuser");
  await page.locator("input[type=password]").first().fill("TestPw-123");
  await page.locator(".rdp-form").getByRole("button", { name: "RDP 連線" }).click();
  await expect(page.locator(".rdp-status")).toContainText("已連線", { timeout: 45_000 });
  // 狀態列要標出這次用的引擎（使用者要求）；Beta 標示已拿掉
  await expect(page.locator(".rdp-status .conn-engine")).toHaveText("引擎：guacd");
  await expect(page.locator(".rdp-status")).not.toContainText("Beta");
  await expect.poll(() => paintedPixels(page), { timeout: 15_000 }).toBeGreaterThan(1000);
  await page.locator(".guac-box").click({ position: { x: 300, y: 300 } });
  await page.keyboard.type("echo e2e");
  await page.keyboard.press("Enter");
  await expect.poll(() => sent.filter((m) => m.startsWith("3.key,")).length).toBeGreaterThanOrEqual(18);
  // 切到 Guacamole 協定之後不可以再送 JSON（config 是唯一的一則）
  expect(sent.filter((m) => m.startsWith("{")).length).toBe(1);
  // 工具列：送出按鍵選單要走 guacd（Ctrl+Alt+Del 是三個 key 按下）
  const before = sent.length;
  await page.getByRole("button", { name: /送出按鍵/ }).click();
  await page.locator(".n-dropdown-option", { hasText: "Del" }).first().click();
  await expect.poll(() => sent.slice(before).filter((m) => m.startsWith("3.key,")).length).toBe(6);
});

test("VNC 走 guacd：畫出測試靶的畫面", async ({ page }) => {
  await page.goto(`/vnc/${consoleIp}`);
  await page.locator("input[type=password]").first().fill("any");
  await page.locator(".n-input-number input").first().fill("5999");
  await page.locator(".vnc-form").getByRole("button", { name: "VNC 連線" }).click();
  await expect(page.locator(".vnc-status")).toContainText("已連線", { timeout: 30_000 });
  await expect(page.locator(".vnc-status .conn-engine")).toHaveText("引擎：guacd");
  await expect(page.locator(".vnc-status")).not.toContainText("Beta");
  // 測試靶是綠底加左上角白方塊：量得到大量非黑像素
  await expect.poll(() => paintedPixels(page), { timeout: 15_000 }).toBeGreaterThan(10_000);
});

function portOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port, timeout: 1500 });
    sock.once("connect", () => { sock.destroy(); resolve(true); });
    sock.once("error", () => resolve(false));
    sock.once("timeout", () => { sock.destroy(); resolve(false); });
  });
}

async function fillVnc(page: Page, user: string, pass: string, port: number) {
  await page.getByPlaceholder(/傳統 VNC 只有密碼/).fill(user);
  await page.locator("input[type=password]").first().fill(pass);
  await page.locator(".n-input-number input").first().fill(String(port));
  await page.locator(".vnc-form").getByRole("button", { name: "VNC 連線" }).click();
}

// 有些 VNC 要帳號＋密碼（使用者問，2026-09-25）：guacd 要把帳號帶過去；沒填要講「請填帳號」
test("VNC 走 guacd：要求帳號的伺服器（VeNCrypt 帳密）", async ({ page }) => {
  test.skip(!(await portOpen(5998)), "沒有 VNC 帳密靶（見檔頭）");
  await page.goto(`/vnc/${consoleIp}`);
  await fillVnc(page, "", "VncE2e-pass1", 5998);
  await expect(page.locator(".vnc-status")).toContainText("連線錯誤", { timeout: 30_000 });
  await expect(page.getByText("請在「帳號」欄填入帳號")).toBeVisible();

  await page.getByRole("button", { name: /返回|重新設定|重新連線/ }).first().click();
  await fillVnc(page, "vncuser", "VncE2e-pass1", 5998);
  await expect(page.locator(".vnc-status")).toContainText("已連線", { timeout: 30_000 });
  await expect.poll(() => paintedPixels(page), { timeout: 15_000 }).toBeGreaterThan(10_000);
});

test("VNC 內建引擎填了帳號：明講要改用 guacd", async ({ page }) => {
  await api(page, "PUT", "/api/v1/system/console-security", { ...saved, rdp_engine: "guacd", vnc_engine: "builtin", ssh_engine: "guacd" });
  const t = await api(page, "POST", `/api/v1/addresses/${consoleIp}/vnc/ticket`);
  test.skip(t.json?.detail?.code === "console_vnc_not_installed", "這台沒有內建 VNC 引擎（aardwolf）");
  await page.goto(`/vnc/${consoleIp}`);
  await fillVnc(page, "someone", "any", 5999);
  await expect(page.getByText(/內建的 VNC 引擎不支援帳號/)).toBeVisible({ timeout: 30_000 });
});

test("SSH 走 guacd：主機金鑰確認、終端機畫面、中文與貼上", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const sent = recordSent(page);
  await page.goto(`/ssh/${consoleIp}`);
  await page.getByPlaceholder("root").fill("tester");
  await page.locator(".n-input-number input").first().fill("2222");
  await page.locator("input[type=password]").first().fill("TestPass!2026");
  await page.getByRole("button", { name: "SSH 連線" }).click();
  const trust = page.getByRole("button", { name: "信任並連線" });
  if (await trust.waitFor({ state: "visible", timeout: 8_000 }).then(() => true).catch(() => false)) {
    await trust.click();
  }
  await expect(page.locator(".ssh-status")).toContainText("已連線", { timeout: 30_000 });
  await expect(page.locator(".ssh-status .conn-engine")).toHaveText("引擎：guacd");
  await expect.poll(() => paintedPixels(page), { timeout: 15_000 }).toBeGreaterThan(500);

  await page.locator(".guac-box").click({ position: { x: 100, y: 100 } });
  await expect.poll(() => page.evaluate(() => document.activeElement?.className)).toContain("guac-ime");
  await page.keyboard.type("echo ");
  await page.keyboard.insertText("中文");
  await page.keyboard.press("Enter");
  // 中文要以 Unicode keysym（0x01000000＋碼位）送出：中＝0x4E2D → 16797229
  await expect.poll(() => sent.some((m) => m.includes(",8.16797229,"))).toBe(true);
  expect(sent.some((m) => m.startsWith("3.key,3.101,"))).toBe(true);        // e

  // 瀏覽器剪貼簿 → Ctrl+Shift+V：先送剪貼簿內容，再送 V
  await page.evaluate(() => navigator.clipboard.writeText("e2e-pasted"));
  const before = sent.length;
  await page.keyboard.down("Control"); await page.keyboard.down("Shift");
  await page.keyboard.press("KeyV");
  await page.keyboard.up("Shift"); await page.keyboard.up("Control");
  await expect.poll(() => sent.slice(before).some((m) => m.startsWith("9.clipboard,"))).toBe(true);
  const after = sent.slice(before);
  const clipAt = after.findIndex((m) => m.startsWith("9.clipboard,"));
  const vAt = after.findIndex((m) => m.startsWith("3.key,2.86,1.1"));
  expect(clipAt).toBeGreaterThanOrEqual(0);
  expect(vAt, "V 要在剪貼簿之後才送出（否則貼上的是舊內容）").toBeGreaterThan(clipAt);
});

test("SSH 走 guacd：密碼錯誤要講得出原因", async ({ page }) => {
  await page.goto(`/ssh/${consoleIp}`);
  await page.getByPlaceholder("root").fill("tester");
  await page.locator(".n-input-number input").first().fill("2222");
  await page.locator("input[type=password]").first().fill("wrong-password");
  await page.getByRole("button", { name: "SSH 連線" }).click();
  const trust = page.getByRole("button", { name: "信任並連線" });
  if (await trust.waitFor({ state: "visible", timeout: 8_000 }).then(() => true).catch(() => false)) {
    await trust.click();
  }
  await expect(page.locator(".ssh-status")).toContainText("連線錯誤", { timeout: 30_000 });
  // guacd 的 SSH 密碼錯時有兩種回法：直接回認證失敗，或再要一次密碼（我們不在這裡問，當成錯誤）
  await expect(page.locator(".n-alert").filter({ hasText: /認證|帳號密碼|authentication/i }).first()).toBeVisible();
});

test("系統設定：三個協定都能選 guacd，並顯示 guacd 的狀態", async ({ page }) => {
  await page.goto("/system-settings");
  const status = page.locator(".guacd-status");
  await expect(status).toContainText("RDP ✓");
  await expect(status).toContainText("VNC ✓");
  await expect(status).toContainText("SSH ✓");
  for (const label of [/RDP 連線引擎/, /VNC 連線引擎/, /SSH 連線引擎/]) {
    await expect(page.locator(".fld", { hasText: label }).locator(".n-base-selection")).toContainText("guacd");
  }
});

test.describe("高解析度螢幕（像素倍率 2）", () => {
  test.use({ deviceScaleFactor: 2 });

  test("SSH 走 guacd：字不會大一倍，而且連線中可以調字級", async ({ page }) => {
    // 使用者回報：Retina 上字很大、右上的 A−／A+ 不見了。以前 DPI 乘了倍率、畫面尺寸卻沒乘，
    // guacd 依 DPI 把字畫成兩倍大，再 1:1 顯示出來
    const sent = recordSent(page);
    const received: string[] = [];
    page.on("websocket", (ws) => ws.on("framereceived", (f) => { received.push(String(f.payload)); }));
    await page.goto(`/ssh/${consoleIp}`);
    await page.getByPlaceholder("root").fill("tester");
    await page.locator(".n-input-number input").first().fill("2222");
    await page.locator("input[type=password]").first().fill("TestPass!2026");
    await page.getByRole("button", { name: "SSH 連線" }).click();
    const trust = page.getByRole("button", { name: "信任並連線" });
    if (await trust.waitFor({ state: "visible", timeout: 8_000 }).then(() => true).catch(() => false)) {
      await trust.click();
    }
    await expect(page.locator(".ssh-status")).toContainText("已連線", { timeout: 30_000 });

    const cfg = JSON.parse(sent.find((m) => m.startsWith("{") && m.includes('"type":"config"'))!);
    const boxW = await page.locator(".guac-box").evaluate((el) => el.clientWidth);
    expect(Math.abs(cfg.width - boxW * 2)).toBeLessThanOrEqual(2);   // 畫面用裝置像素算
    expect(cfg.dpi).toBe(192);
    expect(cfg.font_size).toBeGreaterThan(0);
    // 顯示時縮回 CSS 像素：遠端畫面在頁面上的寬度等於容器寬度，不是兩倍
    await expect.poll(() => page.locator(".guac-host").evaluate((host) => {
      const el = host.firstElementChild as HTMLElement | null;
      return el ? Math.round(el.getBoundingClientRect().width) : 0;
    })).toBeLessThanOrEqual(boxW + 2);

    // A−／A+ 在 guacd 引擎也要有，按了用 argv 串流改字級（工作階段不中斷）。
    // **要確認 guacd 真的套用了**：以前只驗「瀏覽器有送出」就算過，實際上後端代理把 argv 丟掉了
    // （使用者回報按了沒反應）。所以看 guacd 回的 ack，以及畫面上的字是不是真的變大。
    const bigger = page.getByRole("button", { name: "A+" });
    await expect(bigger).toBeVisible();
    await page.waitForTimeout(800);
    const widthBefore = await firstLineRight(page);
    expect(widthBefore).toBeGreaterThan(50);
    const before = sent.length;
    for (let i = 0; i < 4; i++) await bigger.click();
    await expect.poll(() => sent.slice(before).some((m) => m.startsWith("4.argv,") && m.includes("9.font-size"))).toBe(true);
    await expect.poll(() => received.some((m) => /(^|;)3\.ack,\d+\.\d+,[^;]*,1\.0;/.test(m)),
                      { message: "guacd 沒有回 ack（argv 沒送到或被拒）" }).toBe(true);
    await expect.poll(() => firstLineRight(page), { timeout: 10_000,
                      message: "按了 A+ 字沒有變大" }).toBeGreaterThan(widthBefore * 1.2);
    await expect(page.locator(".ssh-status")).toContainText("已連線");
  });
});
