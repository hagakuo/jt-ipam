/**
 * 手機版面全路由巡檢：**每一個畫面都用手機寬度（390px）打開一次**並量版面（使用者 2026-09-28
 * 要求「所有畫面都要用手機版面看過一次」）。
 *
 * all-routes.spec 用 900px 跑，抓得到 JS 例外與失敗請求，但手機才會現形的問題它看不到：
 * 主控台狀態列把「連線錯誤」擠成直排、通知框超出畫面左邊，都是在 390px 才出事。
 *
 * 每頁量三件事：
 * 1. 整頁可以左右捲（scrollWidth > 視窗寬）
 * 2. 有元素跑出畫面外，而且外層沒有能左右捲的容器接住（表格包在可橫捲的容器裡是正常的）
 * 3. 中文被擠成直排：一段中文的寬度不到兩個字、高度卻有好幾行
 *
 * 路由清單與 all-routes 一樣從 router 現場解析；帶 id 的詳細頁與主控台表單頁從 API 拿第一筆。
 * 設 E2E_SHOT_DIR 會逐頁截圖（人工看過一遍用）。
 */
import { test, expect, type Page } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const SHOT_DIR = process.env.E2E_SHOT_DIR || "";
const W = 390;

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");
test.setTimeout(1_500_000);
test.use({ viewport: { width: W, height: 844 }, isMobile: true, hasTouch: true });

function routePaths(): string[] {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(resolve(here, "../src/router/index.ts"), "utf-8");
  const out: string[] = [];
  for (const m of src.matchAll(/path:\s*"([^"]*)"/g)) {
    const p = m[1];
    if (p === "" || p === "/") { out.push("/"); continue; }
    if (p.startsWith("/:") || p.includes("(")) continue;
    const url = p.startsWith("/") ? p : `/${p}`;
    out.push(url);
  }
  return [...new Set(out)];
}

/** 帶 id 的路由 → 從 API 拿一筆真的 id。拿不到就略過並記下來（不假裝測過）。 */
const ID_SOURCES: Record<string, string> = {
  "/sections/:id": "/api/v1/sections?page_size=1",
  "/subnets/:id": "/api/v1/subnets?page_size=1",
  "/addresses/:id": "/api/v1/addresses?q=10.20.0.12&page_size=1",
  "/requests/:id": "/api/v1/ip-requests?page_size=1",
  "/devices/:id": "/api/v1/devices?page_size=1",
  "/customers/:id": "/api/v1/customers?page_size=1",
  // 主控台：打開的是連線表單（沒有真的目標），手機上表單本身也要排得好
  "/ssh/:id": "/api/v1/addresses?q=10.20.0.12&page_size=1",
  "/sftp/:id": "/api/v1/addresses?q=10.20.0.12&page_size=1",
  "/rdp/:id": "/api/v1/addresses?q=10.20.0.12&page_size=1",
  "/vnc/:id": "/api/v1/addresses?q=10.20.0.12&page_size=1",
  "/rustdesk/:id": "/api/v1/addresses?q=10.20.0.12&page_size=1",
};
const SKIP = new Set(["/login", "/novnc/:id", "/bmc/:id"]);   // 需要 PVE／BMC 目標，另有專屬 spec

async function resolveIds(page: Page, paths: string[]): Promise<{ urls: string[]; skipped: string[] }> {
  const token = await page.evaluate(() => localStorage.getItem("access_token"));
  const urls: string[] = [];
  const skipped: string[] = [];
  for (const p of paths) {
    if (SKIP.has(p)) continue;
    if (!p.includes(":")) { urls.push(p); continue; }
    const src = ID_SOURCES[p];
    if (!src) { skipped.push(`${p}（沒有取 id 的來源）`); continue; }
    const r = await page.request.get(src, { headers: { Authorization: `Bearer ${token}` } });
    const j = r.ok() ? await r.json() : null;
    const id = (Array.isArray(j) ? j[0] : j?.items?.[0])?.id;
    if (id) urls.push(p.replace(":id", String(id)));
    else skipped.push(`${p}（API 沒有資料）`);
  }
  return { urls, skipped };
}

/** 在頁面裡量版面。回傳問題描述（空陣列＝沒事）。 */
async function measure(page: Page): Promise<string[]> {
  return page.evaluate((vw) => {
    const out: string[] = [];
    const de = document.documentElement;
    const over = Math.round(de.scrollWidth - de.clientWidth);
    if (over > 2) out.push(`整頁可左右捲 ${over}px`);

    const desc = (el: Element) => {
      const cls = (el.getAttribute("class") || "").split(/\s+/).filter((c) => c && !c.startsWith("data-v")).slice(0, 3).join(".");
      const txt = ((el as HTMLElement).innerText || "").replace(/\s+/g, " ").trim().slice(0, 30);
      return `${el.tagName.toLowerCase()}${cls ? "." + cls : ""}${txt ? `「${txt}」` : ""}`;
    };
    const visible = (el: Element, r: DOMRect) => {
      if (r.width < 1 || r.height < 1) return false;
      const cs = getComputedStyle(el);
      return cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05;
    };
    /**
     * 跑出畫面外的元素，外層是誰接住它：
     * - 可以左右捲的容器（overflow-x auto／scroll，而且真的比較寬）→ 正常，使用者滑得到
     * - 會裁切的容器（hidden／clip）→ 內容被裁掉、使用者看不到 —— 這才是問題。
     *   但文字省略（…）與小元件自己裁切是刻意的，所以只看寬度 200px 以上的容器。
     */
    const catcher = (el: Element): "scroll" | "cut" | null => {
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        if (getComputedStyle(p).textOverflow === "ellipsis") return "scroll";   // 刻意的省略號
        const ox = getComputedStyle(p).overflowX;
        if ((ox === "auto" || ox === "scroll") && p.scrollWidth > p.clientWidth + 1) return "scroll";
        if ((ox === "hidden" || ox === "clip") && p.getBoundingClientRect().width >= 200) return "cut";
      }
      return null;
    };
    const offenders: { el: Element; how: string }[] = [];
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      if (el.closest("svg") && el.tagName.toLowerCase() !== "svg") continue;
      const r = el.getBoundingClientRect();
      if (!visible(el, r)) continue;
      if (r.right <= vw + 2 && r.left >= -2) continue;
      if (getComputedStyle(el).position === "fixed" && r.left >= vw) continue;  // 收起來的抽屜
      const how = catcher(el);
      if (how === "scroll") continue;
      // 只報最外層的那個：父層也超出的話，子層是被帶出去的
      if (offenders.some((o) => o.el.contains(el))) continue;
      offenders.push({ el, how: how === "cut" ? "被裁掉" : "超出畫面" });
    }
    for (const { el, how } of offenders.slice(0, 5)) {
      const r = el.getBoundingClientRect();
      out.push(`${how} ${desc(el)} [${Math.round(r.left)}, ${Math.round(r.right)}]`);
    }

    // 文字被擠成直排：直接量文字節點實際排成幾行（Range 的每個行框），每行只剩一兩個中文字、
    // 或英數每行只剩幾個字元（網址被擠成「http / s://1 / 92.0」）就是被擠壞了
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const reported = new Set<Element>();
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = (node.textContent || "").trim();
      const cjk = (text.match(/[\u4e00-\u9fff\u3040-\u30ff]/g) || []).length;
      const len = text.replace(/\s+/g, "").length;
      if (cjk < 2 && len < 8) continue;
      const el = node.parentElement;
      if (!el || reported.has(el)) continue;
      const r = el.getBoundingClientRect();
      if (!visible(el, r)) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      const tops = new Set(Array.from(range.getClientRects()).filter((x) => x.width > 0).map((x) => Math.round(x.top)));
      const lines = tops.size;
      if (lines < 3) continue;
      // 以中文為主的文字看每行幾個中文字；英文夾幾個中文字（工具說明）照英數的標準看
      const squeezed = cjk >= len * 0.5 ? cjk / lines <= 1.5 : len / lines <= 4;
      if (squeezed) {
        reported.add(el);
        out.push(`文字被擠成直排 ${desc(el)}（${lines} 行）`);
      }
    }
    return out;
  }, W);
}

test("每一個畫面在手機寬度都排得好", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入|Sign in/i }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"), { timeout: 20_000 });

  const paths = routePaths();
  expect(paths.length, "從 router 解析不到路由（格式改了？）").toBeGreaterThan(50);
  const { urls, skipped } = await resolveIds(page, paths);
  if (SHOT_DIR) mkdirSync(SHOT_DIR, { recursive: true });

  const problems: string[] = [];
  let n = 0;
  for (const url of urls) {
    n += 1;
    await page.goto(url, { waitUntil: "domcontentloaded" });
    const deadline = Date.now() + 6000;
    do {
      if ((await page.locator("body").innerText()).trim().length > 20) break;
      await page.waitForTimeout(300);
    } while (Date.now() < deadline);
    await page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
    await page.waitForTimeout(400);
    for (const p of await measure(page)) problems.push(`${url}｜${p}`);
    if (SHOT_DIR) {
      // 內容是在版面的內層容器捲動、不是整頁捲：一個畫面一個畫面捲下去拍，拍到的就是手機上
      // 真實的樣子（改 CSS 讓整頁長高會把寬的內容撐開、變成桌機版面，拍到的是假的）
      const base = `${String(n).padStart(3, "0")}${url.replace(/[/:?=&]+/g, "_").slice(0, 60)}`;
      // 捲動的是哪一層不固定（有的頁在內容區、有的在外層版面）：挑捲動空間最大的那個
      const total = await page.evaluate(() => {
        let best: HTMLElement | null = null;
        for (const el of Array.from(document.querySelectorAll<HTMLElement>(".n-layout-scroll-container"))) {
          const room = el.scrollHeight - el.clientHeight;
          if (room > 4 && (!best || room > best.scrollHeight - best.clientHeight)) best = el;
        }
        document.querySelectorAll("[data-shot-scroller]").forEach((e) => e.removeAttribute("data-shot-scroller"));
        if (!best) return 1;
        best.setAttribute("data-shot-scroller", "1");
        return Math.ceil(best.scrollHeight / best.clientHeight);
      });
      for (let k = 0; k < Math.min(total, 6); k++) {
        await page.evaluate((i) => {
          const el = document.querySelector<HTMLElement>("[data-shot-scroller]");
          if (el) el.scrollTop = i * el.clientHeight;
        }, k);
        await page.waitForTimeout(150);
        await page.screenshot({ path: `${SHOT_DIR}/${base}_p${k}.png`, timeout: 15_000 }).catch(() => {});
      }
    }
  }
  if (skipped.length) console.log(`略過（沒有可用的 id）：${skipped.join("、")}`);
  if (problems.length) {
    throw new Error(`手機寬度走過 ${urls.length} 個畫面，發現 ${problems.length} 個問題：\n` + problems.join("\n"));
  }
});
