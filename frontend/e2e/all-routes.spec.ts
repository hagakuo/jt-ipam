/**
 * 全路由巡檢：**每一個頁面都要被真的打開過一次**。
 *
 * 為什麼要有這支：我們有 78 個 view，但先前的巡檢只走 22 條路由 —— 也就是說
 * 四十幾個頁面從來沒有任何測試打開過。那類缺陷（渲染成功但內容錯、i18n 鍵沒補、
 * 某個 API 路徑漏了 /api/v1 首碼）型別檢查與單元測試都看不到，只有真的渲染才會現形。
 *
 * 路由清單**從 `src/router/index.ts` 現場解析**，不是手抄的常數：新增頁面就自動納入，
 * 不會出現「清單忘了更新，所以看起來全綠」。
 *
 * 跑法（本機，不碰 prod）：
 *   E2E_BASE_URL=http://127.0.0.1:5199 E2E_ADMIN_USER=... E2E_ADMIN_PASS=... \
 *     npx playwright test e2e/all-routes.spec.ts --project=chromium
 */
import { test, expect, type ConsoleMessage } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");
test.setTimeout(900_000);   // 七十幾頁逐一走訪

/**
 * 這幾條刻意不走 —— 它們**不是**「還沒測」，而是本來就不能用這種方式打開：
 * 主控台類需要一個真的能連上的目標（另有 sftp.spec / terminal-links.spec 專門測），
 * 帶參數的詳細資料頁沒有可靠的假 id（deep-sweep.spec 從清單點進去測）。
 */
const SKIP = new Set([
  "/login", "/ssh/:id", "/sftp/:id", "/rdp/:id", "/vnc/:id", "/novnc/:id", "/bmc/:id", "/rustdesk/:id",
]);

function routePaths(): string[] {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(resolve(here, "../src/router/index.ts"), "utf-8");
  const out: string[] = [];
  for (const m of src.matchAll(/path:\s*"([^"]*)"/g)) {
    const p = m[1];
    if (p === "" || p === "/") { out.push("/"); continue; }
    if (p.startsWith("/:") || p.includes("(")) continue;      // catch-all / 萬用
    const url = p.startsWith("/") ? p : `/${p}`;
    if (SKIP.has(p) || SKIP.has(url)) continue;
    if (url.includes(":")) continue;                          // 需要 id 的詳細資料頁
    out.push(url);
  }
  return [...new Set(out)];
}

/**
 * 未翻譯的鍵長得像 `區塊.鍵`，但畫面上合法的文字也長那樣（`pf.example`、`mysqld.sock`、
 * `message.src_ip`）。所以只認**真的存在於語系檔的頂層區塊名**開頭的字串 ——
 * 純靠形狀比對會被一堆假警報淹掉，然後就沒人看了。
 */
function i18nNamespaces(): Set<string> {
  const here = dirname(fileURLToPath(import.meta.url));
  const zh = JSON.parse(readFileSync(resolve(here, "../src/i18n/zh-TW.json"), "utf-8"));
  return new Set(Object.keys(zh));
}

/**
 * 這些不是未翻譯的鍵，是**畫面本來就要顯示的識別字**：事件規則的事件名稱
 * （`anomaly.detected` 這種是要讓人抄去填規則的）、系統日誌裡的資料表欄位名。
 * 它們剛好與語系檔的頂層區塊同名，才會被上面那條規則掃到。
 */
const NOT_I18N = [
  /^(anomaly|firewall|ip|subnet)\.[a-z_.]+$/,   // 事件規則的事件名稱
  /\.(created_at|updated_at|deleted_at)$/,      // 日誌／SQL 裡的欄位名
  /^app\.cli\./,                                // CLI 指令裡的 Python 模組路徑（python -m app.cli.recog）
];

function isNoise(text: string): boolean {
  return /favicon|ResizeObserver loop|Download the Vue Devtools|autocomplete/i.test(text);
}

test("每一條路由都打得開，且沒有 JS 例外或失敗的 API 請求", async ({ page }) => {
  // 刻意用**偏窄**的視窗跑：版面缺陷幾乎都是窄的時候才現形，寬螢幕上一切看起來都好
  //（使用者回報「寬度不夠時，證據來源的選項跑出卡片外」時，既有測試全綠）。
  await page.setViewportSize({ width: 900, height: 1000 });
  const paths = routePaths();
  // 解析失敗會讓這支測試「走 0 頁然後全綠」—— 那比沒測還糟，所以先擋住
  expect(paths.length, "從 router 解析不到路由（格式改了？）").toBeGreaterThan(50);

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
  page.on("response", (r) => {
    if (r.status() >= 400 && r.status() !== 401 && r.url().includes("/api/")) {
      problems.push(`[http ${r.status()}] ${current}｜${r.url().replace(/https?:\/\/[^/]+/, "")}`);
    }
  });

  current = "登入";
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入|Sign in/i }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"), { timeout: 20_000 });

  const ns = i18nNamespaces();
  const blank: string[] = [];
  for (const path of paths) {
    current = path;
    await page.goto(path, { waitUntil: "domcontentloaded" });
    // 白畫面＝這個頁面在渲染時就掛了。**用輪詢而不是固定等待**：機器忙的時候
    // 固定 900ms 會抓到還沒畫完的畫面，變成假的「空白」（實際發生過，/sections）。
    let body = "";
    const deadline = Date.now() + 6000;
    do {
      body = (await page.locator("body").innerText()).trim();
      if (body.length > 20) break;
      await page.waitForTimeout(300);
    } while (Date.now() < deadline);
    if (body.length <= 20) blank.push(path);

    // 橫向溢出：整頁不該可以左右捲。窄視窗才會現形的版面缺陷（例如選項衝出卡片外）
    // 只有在窄的時候量才抓得到 —— 巡檢在這裡把每一頁都量一次。
    const overflow = await page.evaluate(() =>
      Math.round(document.documentElement.scrollWidth - document.documentElement.clientWidth));
    if (overflow > 4) problems.push(`[版面] ${path}｜橫向溢出 ${overflow}px`);
    // 未翻譯的 i18n 鍵會直接以 `區塊.鍵` 的形式露在畫面上
    for (const m of body.matchAll(/\b([a-zA-Z_]+)\.([a-zA-Z_][a-zA-Z0-9_.]{2,})\b(?![a-zA-Z0-9./:@-])/g)) {
      if (!ns.has(m[1])) continue;
      if (NOT_I18N.some((re) => re.test(m[0]))) continue;
      problems.push(`[i18n] ${path}｜未翻譯鍵「${m[0]}」`);
    }
  }

  if (blank.length) problems.unshift(`空白畫面：${blank.join(", ")}`);
  if (problems.length) {
    throw new Error(
      `走過 ${paths.length} 條路由，發現 ${problems.length} 個問題：\n` + problems.join("\n"));
  }
});
