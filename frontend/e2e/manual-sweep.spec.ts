/**
 * 真實瀏覽器巡檢：把今天改過的頁面逐一走過，攔 console 錯誤與失敗請求。
 *
 * 這不是斷言功能正確的測試，而是**找出「畫面壞掉但沒人發現」的那一類問題** ——
 * 今天已經有兩次是這種形狀（匯出報告取錯欄位印出 undefined、登入頁把 502 說成密碼錯）。
 * 型別檢查與單元測試都看不到它們，只有真的把頁面渲染出來才會現形。
 *
 * 跑法（本機，不碰 prod）：
 *   E2E_BASE_URL=http://127.0.0.1:5199 E2E_ADMIN_USER=... E2E_ADMIN_PASS=... \
 *     npx playwright test e2e/manual-sweep.spec.ts --project=chromium
 */
import { test, expect, type ConsoleMessage, type Request } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

/** 逐頁走訪的清單：今天動過的頁面優先。 */
const PAGES: { path: string; name: string }[] = [
  { path: "/", name: "儀表板" },
  { path: "/addresses", name: "IP 位址" },
  { path: "/devices", name: "裝置" },
  { path: "/subnets", name: "子網路" },
  { path: "/sections", name: "區段" },
  { path: "/racks", name: "機櫃" },
  { path: "/locations", name: "機房 / 地點" },
  { path: "/ip-changes", name: "IP 異動記錄" },
  { path: "/virt", name: "虛擬化 (Proxmox VE)" },
  { path: "/virt-vmware", name: "虛擬化 (VMware)" },
  { path: "/anomaly", name: "異常偵測" },
  { path: "/ai-audit", name: "AI 巡檢" },
  { path: "/tools", name: "工具" },
  { path: "/system-settings", name: "系統設定" },
  { path: "/llm", name: "LLM / AI" },
  { path: "/esxi", name: "整合 VMware" },
  { path: "/topology", name: "IP 拓樸圖" },
  { path: "/customers", name: "單位" },
  { path: "/requests", name: "IP 申請" },
  { path: "/audit", name: "稽核記錄" },
  { path: "/tasks", name: "作業" },
];

/** 這些訊息不是缺陷：瀏覽器對自簽憑證、favicon、擴充功能的雜訊。 */
function isNoise(text: string): boolean {
  return /favicon|ResizeObserver loop|Download the Vue Devtools|autocomplete/i.test(text);
}

test.setTimeout(300_000);   // 20 幾頁逐一走訪，預設 30 秒不夠

test("逐頁巡檢：沒有 console 錯誤，也沒有失敗的 API 請求", async ({ page }) => {
  const problems: string[] = [];
  let current = "";

  page.on("console", (m: ConsoleMessage) => {
    if (m.type() === "error" && !isNoise(m.text())) {
      problems.push(`[console] ${current}｜${m.text().slice(0, 220)}`);
    }
  });
  page.on("pageerror", (e) => {
    problems.push(`[pageerror] ${current}｜${String(e).slice(0, 220)}`);
  });
  page.on("requestfailed", (r: Request) => {
    // ERR_ABORTED＝巡檢在請求進行中就切換頁面，是這支腳本自己造成的，不是缺陷
    const aborted = (r.failure()?.errorText ?? "").includes("ERR_ABORTED");
    if (!aborted && !isNoise(r.url())) {
      problems.push(`[requestfailed] ${current}｜${r.url()} ${r.failure()?.errorText ?? ""}`);
    }
  });
  page.on("response", (r) => {
    // 401 在登入前是正常的；其餘 4xx/5xx 都要看
    if (r.status() >= 400 && r.status() !== 401 && r.url().includes("/api/")) {
      problems.push(`[http ${r.status()}] ${current}｜${r.url().replace(/https?:\/\/[^/]+/, "")}`);
    }
  });

  // ── 登入
  current = "登入";
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入|Sign in/i }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"), { timeout: 20_000 });

  // ── 逐頁
  for (const p of PAGES) {
    current = p.name;
    // networkidle 對有輪詢的畫面（通知鈴鐺）永遠等不到 —— 等 DOM 就緒再讓它沉澱一下
    await page.goto(p.path, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    // 頁面至少要畫出東西（不是白畫面）
    const body = (await page.locator("body").innerText()).trim();
    expect(body.length, `${p.name} 是空白畫面`).toBeGreaterThan(20);
    await page.screenshot({ path: `test-results/sweep-${p.path.replace(/\W+/g, "_")}.png`,
                            fullPage: false });
  }

  if (problems.length) {
    // 全部列出來再失敗 —— 只報第一個會讓人一輪只修得掉一個
    throw new Error(`發現 ${problems.length} 個問題：\n` + problems.join("\n"));
  }
});
