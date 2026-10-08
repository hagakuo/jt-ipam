/**
 * RDP 連線引擎的切換（管理 → 系統設定）。
 *
 * 守兩件事：
 *   ① 預設是 guacd（2026-09-27 起，RDP 與 VNC 都是；SSH 仍是內建），而且標著「預設」。
 *   ② 這台機器不能用 FreeRDP 時，畫面要講得出缺什麼、怎麼裝。選項擺在那裡、
 *      按下去才發現不能用，比沒有這個選項更糟。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username|ユーザー名/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password|パスワード/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /^(登入|Sign in|サインイン)$/ }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

/** 讀目前設定（繞過畫面，用來確認「存得住」而不是只看下拉的樣子）。 */
async function readSetting(page: Page) {
  return page.evaluate(async () => {
    const r = await fetch("/api/v1/system/console-security", {
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
    });
    return r.json();
  });
}

test.describe("RDP 連線引擎", () => {
  test("預設是 guacd，而且切換存得住", async ({ page }) => {
    await login(page);

    // 先把設定歸位，讓這支測試不依賴前一次跑完留下的狀態
    await page.evaluate(async () => {
      await fetch("/api/v1/system/console-security", {
        method: "PUT",
        headers: { "Content-Type": "application/json",
                   Authorization: `Bearer ${localStorage.getItem("access_token")}` },
        body: JSON.stringify({ rdp_clipboard_paste: false, rdp_engine: "guacd", vnc_engine: "guacd",
                               ssh_engine: "builtin" }),
      });
    });

    await page.goto("/system-settings");
    const field = page.locator(".fld", { hasText: /RDP 連線引擎|RDP connection engine|RDP 接続エンジン/ });
    await expect(field).toContainText(/guacd（預設）|guacd \(default\)|guacd（既定）/, { timeout: 15_000 });
    // 「預設」標在各自的預設值上：VNC 是 guacd、SSH 是內建
    const vnc = page.locator(".fld", { hasText: /VNC 連線引擎|VNC connection engine|VNC 接続エンジン/ });
    await expect(vnc).toContainText(/guacd（預設）|guacd \(default\)|guacd（既定）/);
    const ssh = page.locator(".fld", { hasText: /SSH 連線引擎|SSH connection engine|SSH 接続エンジン/ });
    await expect(ssh).toContainText(/內建（預設）|Built-in \(default\)|組み込み（既定）/);

    // 切到 FreeRDP
    await field.locator(".n-select").click();
    await page.locator(".n-base-select-option", { hasText: /FreeRDP/ }).click();
    await expect(field).toContainText(/FreeRDP/);

    await expect.poll(async () => (await readSetting(page)).rdp_engine).toBe("freerdp");

    // 重新整理之後仍然是 FreeRDP（確認讀回來的值有套到畫面上）
    await page.reload();
    await expect(field).toContainText(/FreeRDP/, { timeout: 15_000 });

    // 收尾：切回預設
    await field.locator(".n-select").click();
    await page.locator(".n-base-select-option", { hasText: /guacd/ }).click();
    await expect.poll(async () => (await readSetting(page)).rdp_engine).toBe("guacd");
  });

  test("切換引擎不會把剪貼簿設定一起清掉", async ({ page }) => {
    // 兩個欄位共用同一個端點，寫一個很容易蓋掉另一個
    await login(page);
    await page.evaluate(async () => {
      await fetch("/api/v1/system/console-security", {
        method: "PUT",
        headers: { "Content-Type": "application/json",
                   Authorization: `Bearer ${localStorage.getItem("access_token")}` },
        body: JSON.stringify({ rdp_clipboard_paste: true, rdp_engine: "guacd" }),
      });
    });
    await page.goto("/system-settings");
    const field = page.locator(".fld", { hasText: /RDP 連線引擎|RDP connection engine|RDP 接続エンジン/ });
    await expect(field).toContainText(/guacd/, { timeout: 15_000 });
    await field.locator(".n-select").click();
    await page.locator(".n-base-select-option", { hasText: /FreeRDP/ }).click();

    await expect.poll(async () => (await readSetting(page)).rdp_clipboard_paste).toBe(true);

    await page.evaluate(async () => {
      await fetch("/api/v1/system/console-security", {
        method: "PUT",
        headers: { "Content-Type": "application/json",
                   Authorization: `Bearer ${localStorage.getItem("access_token")}` },
        body: JSON.stringify({ rdp_clipboard_paste: false, rdp_engine: "guacd" }),
      });
    });
  });
});
