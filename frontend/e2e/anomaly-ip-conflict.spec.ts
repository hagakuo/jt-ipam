/**
 * IP 衝突要看得到掃描代理看到的 MAC —— GitHub issue #41。
 *
 * 回報者只有掃描代理、沒接 LibreNMS：兩台 VM 輪流回應同一個固定 IP，異常偵測卻永遠是空的
 * （偵測器只讀 LibreNMS 寫的 ARP 表）。這裡走真實路徑：建一個掃描代理、用它的金鑰回報兩次
 * （同一個 IP、兩個 MAC）、按「執行偵測」，IP 衝突表要列出這個 IP，並寫出依據與「掃描代理」。
 * 樣本：seed_e2e 的 10.20.0.0/24；代理做完會刪掉（IP 留著：刪掉會進冷卻期，下一輪建不起來）。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const IP = "10.20.0.231";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

/** 在頁面裡打 API（沿用登入後的 token 與同源代理） */
async function api(page: Page, method: string, path: string, body?: unknown,
                   headers: Record<string, string> = {}) {
  return page.evaluate(async ({ method, path, body, headers }) => {
    const h: Record<string, string> = { "Content-Type": "application/json", ...headers };
    if (!h["X-Agent-Key"]) h.Authorization = `Bearer ${localStorage.getItem("access_token")}`;
    const r = await fetch(path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, json: r.status === 204 ? null : await r.json().catch(() => null) };
  }, { method, path, body, headers });
}

test("掃描代理看到同一個 IP 有兩個 MAC → 異常偵測列出 IP 衝突，寫出依據與誰看到的", async ({ page }) => {
  await login(page);
  const subs = await api(page, "GET", "/api/v1/subnets?page_size=500");
  const sn = subs.json.items.find((s: any) => s.cidr === "10.20.0.0/24");
  // 有就沿用、沒有才建，做完也不刪：刪掉的位址會進冷卻期，下一輪就建不起來了
  const found = await api(page, "GET", `/api/v1/addresses?q=${IP}&page_size=50`);
  if (!found.json.items.some((x: any) => String(x.ip).split("/")[0] === IP)) {
    await api(page, "POST", `/api/v1/addresses/cooldowns/${sn.id}/${IP}/clear`, { reason: "e2e" });
    const ip = await api(page, "POST", "/api/v1/addresses", { subnet_id: sn.id, ip: IP });
    expect(ip.status, JSON.stringify(ip.json)).toBe(201);
  }
  const agent = await api(page, "POST", "/api/v1/scan-agents", { name: `e2e-conflict-${Date.now()}` });
  expect(agent.status).toBe(201);
  try {
    // RFC 7042 的文件用 MAC 範圍，不是任何一張真的網卡
    for (const mac of ["00:00:5e:00:53:01", "00:00:5e:00:53:02"]) {
      const r = await api(page, "POST", "/api/v1/scan-agents/report",
        { results: [{ ip: IP, alive: true, mac }] }, { "X-Agent-Key": agent.json.enroll_key });
      expect(r.status, JSON.stringify(r.json)).toBe(200);
    }

    await page.goto("/anomaly?tab=ip_conflicts");
    await page.getByRole("button", { name: "執行偵測" }).click();
    const row = page.locator("tr", { hasText: IP }).first();
    await expect(row).toBeVisible({ timeout: 20_000 });
    await expect(row).toContainText("ARP：1 小時內看到多個 MAC");
    await expect(row).toContainText("00:00:5e:00:53:01");
    await expect(row).toContainText("00:00:5e:00:53:02");
    await expect(row).toContainText("掃描代理");
  } finally {
    await api(page, "DELETE", `/api/v1/scan-agents/${agent.json.id}`);
  }
});
