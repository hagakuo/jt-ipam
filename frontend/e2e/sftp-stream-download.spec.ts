/**
 * SFTP 大檔下載（2026-09-26）：上限可以在系統設定放大到 GB 級，整個檔案收進記憶體會把分頁
 * 撐爆 —— 超過 64 MB 改成邊收邊寫進磁碟（File System Access API）。這裡驗：
 *   ① 有 API：寫進磁碟的內容與遠端**逐位元組一致**（雜湊比對），而且真的是走串流（分很多次寫）
 *   ② 沒有 API（Firefox／Safari）：退回收進記憶體，照樣下載得到完整的檔案
 *   ③ 超過系統設定的上限：當場就講，不必先等伺服器拒絕
 *
 * 需要 e2e/fixtures/sftp-target.py 起在 E2E_SFTP_PORT（預設 2223，2222 通常是 SSH 靶），
 * 根目錄 E2E_SFTP_ROOT；console-target（127.0.0.1）由 seed_e2e 建立。
 * 存檔對話框在無頭瀏覽器裡沒辦法操作，所以把 showSaveFilePicker 換成一個記錄寫入內容的假物件。
 */
import { test, expect, type Page } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";
import { writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";

const PASS = process.env.E2E_ADMIN_PASS || "";
const ROOT = process.env.E2E_SFTP_ROOT || "";
const PORT = process.env.E2E_SFTP_PORT || "2223";
test.skip(!PASS || !ROOT || !existsSync(ROOT), "需要 E2E_ADMIN_PASS 與 E2E_SFTP_ROOT（見檔頭）");
test.setTimeout(180_000);

const BIG = "big-stream.bin";
const SIZE = 80 * 1024 * 1024 + 12345;       // 超過 64 MB，而且不是區塊大小的整數倍
let sha = "";

test.beforeAll(() => {
  const buf = randomBytes(SIZE);
  writeFileSync(join(ROOT, BIG), buf);
  sha = createHash("sha256").update(buf).digest("hex");
});
test.afterAll(() => { rmSync(join(ROOT, BIG), { force: true }); });

async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const r = await fetch(path, { method, body: body === undefined ? undefined : JSON.stringify(body),
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}`, "Content-Type": "application/json" } });
    return { status: r.status, json: await r.json().catch(() => null) };
  }, { method, path, body });
}

let saved: Record<string, unknown> = {};
let ipId = "";

async function setup(page: Page, limitMb: number) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));
  const cs = await api(page, "GET", "/api/v1/system/console-security");
  saved = { rdp_clipboard_paste: cs.json.rdp_clipboard_paste, rdp_engine: cs.json.rdp_engine,
            sftp_max_file_mb: cs.json.sftp_max_file_mb };
  await api(page, "PUT", "/api/v1/system/console-security", { ...saved, sftp_max_file_mb: limitMb });
  const found = await api(page, "GET", "/api/v1/addresses?q=127.0.0.1&page_size=50");
  ipId = found.json.items.find((x: any) => String(x.ip).split("/")[0] === "127.0.0.1")?.id || "";
  test.skip(!ipId, "沒有 console-target（先跑 seed_e2e）");
  await api(page, "PATCH", `/api/v1/addresses/${ipId}`, { sftp_enabled: true });
}

async function connect(page: Page) {
  await page.goto(`/sftp/${ipId}`);
  await expect(page.getByText(/SFTP 連線到/)).toBeVisible();
  const manual = page.getByPlaceholder("root");
  if (await manual.isVisible().catch(() => false)) {
    await manual.fill("tester");
    await page.locator('input[type="password"]').first().fill("TestPass!2026");
  }
  await page.locator(".n-input-number input").first().fill(PORT);
  await page.keyboard.press("Tab");
  await page.getByRole("button", { name: "連線" }).click();
  await expect(page.locator("tr", { hasText: BIG })).toBeVisible({ timeout: 20_000 });
}

test.afterEach(async ({ page }) => {
  if (Object.keys(saved).length) await api(page, "PUT", "/api/v1/system/console-security", saved);
});

test("大檔直接寫進磁碟：內容逐位元組一致，而且是分很多次寫的", async ({ page }) => {
  // 假的存檔對話框：記下每一次寫入，關檔時算雜湊
  await page.addInitScript(() => {
    (window as any).__saved = { name: "", writes: 0, bytes: 0, done: false, aborted: false, sha: "" };
    (window as any).showSaveFilePicker = async (opts: any) => {
      const st = (window as any).__saved;
      st.name = opts?.suggestedName ?? "";
      const parts: Uint8Array[] = [];
      return {
        createWritable: async () => ({
          write: async (u8: Uint8Array) => { parts.push(new Uint8Array(u8)); st.writes++; st.bytes += u8.byteLength; },
          close: async () => {
            const all = new Uint8Array(st.bytes);
            let off = 0;
            for (const p of parts) { all.set(p, off); off += p.byteLength; }
            const d = await crypto.subtle.digest("SHA-256", all);
            st.sha = Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
            st.done = true;
          },
          abort: async () => { st.aborted = true; },
        }),
      };
    };
  });
  await setup(page, 200);
  await connect(page);
  await page.locator("tr", { hasText: BIG }).getByRole("button", { name: "下載" }).click();
  await expect.poll(() => page.evaluate(() => (window as any).__saved.done), { timeout: 120_000 }).toBe(true);
  const st = await page.evaluate(() => (window as any).__saved);
  expect(st.name).toBe(BIG);
  expect(st.bytes).toBe(SIZE);
  expect(st.sha, "寫進磁碟的內容與遠端不一致").toBe(sha);
  expect(st.writes, "沒有分段寫入 —— 那就是整個收進記憶體了").toBeGreaterThan(100);
  expect(st.aborted).toBe(false);
});

test("瀏覽器不支援直接寫入磁碟：退回收進記憶體，照樣拿到完整的檔案", async ({ page }) => {
  await page.addInitScript(() => { delete (window as any).showSaveFilePicker; });
  await setup(page, 200);
  await connect(page);
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout: 120_000 }),
    page.locator("tr", { hasText: BIG }).getByRole("button", { name: "下載" }).click(),
  ]);
  const p = await download.path();
  const { readFileSync } = await import("node:fs");
  expect(createHash("sha256").update(readFileSync(p!)).digest("hex")).toBe(sha);
});

test("超過系統設定的上限：當場就講", async ({ page }) => {
  await setup(page, 50);
  await connect(page);
  await page.locator("tr", { hasText: BIG }).getByRole("button", { name: "下載" }).click();
  await expect(page.getByText(/超過 50 MB 上限/).first()).toBeVisible({ timeout: 5_000 });
});
