/**
 * 有資料時的深入巡檢：點進去、開視窗、按按鈕。
 *
 * 空清單的頁面幾乎不會出錯 —— 今天所有「畫面壞掉」的缺陷都發生在**有資料**的渲染路徑
 * （匯出取錯欄位、關係圖少節點、欄位沒進預設清單）。所以這支專門走那些路徑，
 * 並針對「取不到值」的痕跡（undefined / [object Object] / NaN / 未翻譯鍵名）做斷言。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");
test.setTimeout(180_000);

/** 畫面上絕不該出現的字樣：都代表某個值沒取到，而不是「這裡本來就沒東西」。 */
const BAD = [
  "undefined", "[object Object]", "NaN", "null null",
  // 未翻譯的鍵名會直接以 `區塊.鍵` 的形式露在畫面上
  /\b[a-z_]+\.[a-z_]{4,}\b(?![a-zA-Z0-9./:-])/,
];

async function assertNoBrokenValues(page: Page, where: string) {
  const body = await page.locator("body").innerText();
  for (const bad of BAD) {
    if (typeof bad === "string") {
      expect(body, `${where} 出現「${bad}」`).not.toContain(bad);
    }
  }
}

test.beforeEach(async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入|Sign in/i }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"), { timeout: 20_000 });
});

test("IP 清單 → 詳細資料 → 關係圖", async ({ page }) => {
  await page.goto("/addresses");
  await page.waitForTimeout(1500);
  await expect(page.locator("body")).toContainText("10.20.0.10");
  await assertNoBrokenValues(page, "IP 清單");

  await page.getByText("10.20.0.10", { exact: true }).first().click();
  await page.waitForTimeout(1800);
  const body = await page.locator("body").innerText();
  expect(body, "詳細資料沒顯示主機名稱").toContain("web-01");
  expect(body, "關係圖沒畫出來").toContain("關係圖");
  await assertNoBrokenValues(page, "IP 詳細資料");
  await page.screenshot({ path: "test-results/deep-ip-detail.png" });
});

test("裝置詳細資料：虛實、連接埠、關係圖", async ({ page }) => {
  await page.goto("/devices");
  await page.waitForTimeout(1500);
  await expect(page.locator("body")).toContainText("nas-01");
  await page.getByText("nas-01", { exact: true }).first().click();
  await page.waitForTimeout(1800);
  const body = await page.locator("body").innerText();
  expect(body, "沒有連接埠清單").toMatch(/eth0|連接埠/);
  await assertNoBrokenValues(page, "裝置詳細資料");
  await page.screenshot({ path: "test-results/deep-device-detail.png" });
});

test("虛擬化 (VMware)：VM 清單、IP 連結、port group", async ({ page }) => {
  await page.goto("/virt-vmware");
  await page.waitForTimeout(1800);
  // 用會自動重試的斷言，不要用一次性 innerText 快照 —— 表格晚一點才畫出來就會誤判
  await expect(page.locator("body")).toContainText("vcenter-lab");
  let body = await page.locator("body").innerText();
  // 跨平台提示：另一個平台有資料時要說出來並給連結（客戶回報的困惑就是這個）
  expect(body, "缺少跨平台提示").toContain("Proxmox VE");
  // VM 在另一個分頁
  await page.locator(".n-tabs-tab", { hasText: /^VM/ }).first().click();
  await page.waitForTimeout(1200);
  await expect(page.locator("body")).toContainText("app-01");
  body = await page.locator("body").innerText();
  expect(body, "port group 沒帶出來").toContain("VM Network");
  await assertNoBrokenValues(page, "虛擬化 (VMware)");
  await page.screenshot({ path: "test-results/deep-virt-vmware.png" });
});

test("AI 巡檢：發現卡片、模型標示、markdown 有渲染", async ({ page }) => {
  await page.goto("/ai-audit");
  await page.waitForTimeout(1800);
  const body = await page.locator("body").innerText();
  expect(body, "看不到發現").toContain("管理介面位於一般用途子網路");
  expect(body, "沒有標示模型").toContain("模型");
  // markdown 應該被渲染，不該把原始標記印出來
  expect(body, "markdown 沒渲染，原始標記露出").not.toContain("**粗體**");
  expect(body, "行內 code 沒渲染").not.toContain("`code`");
  await assertNoBrokenValues(page, "AI 巡檢");
  await page.screenshot({ path: "test-results/deep-ai-audit.png" });
});

test("調查視窗：開得起來、匯出按鈕在、內容不是空的", async ({ page }) => {
  await page.goto("/addresses");
  await page.waitForTimeout(1500);
  await page.getByText("10.20.0.10", { exact: true }).first().click();
  await page.waitForTimeout(1500);
  await page.getByRole("button", { name: /調查/ }).click();
  await page.waitForTimeout(2500);
  const body = await page.locator("body").innerText();
  expect(body, "調查視窗沒開").toContain("調查");
  expect(body, "沒有匯出報告").toContain("匯出報告");
  for (const fmt of [".md", ".txt", ".html", ".csv"]) {
    expect(body, `缺少 ${fmt} 匯出`).toContain(fmt);
  }
  await assertNoBrokenValues(page, "調查視窗");
  await page.screenshot({ path: "test-results/deep-investigate.png" });
});

test("匯出的報告內容正確（實際下載一份 .md）", async ({ page }) => {
  await page.goto("/addresses");
  await page.waitForTimeout(1500);
  await page.getByText("10.20.0.10", { exact: true }).first().click();
  await page.waitForTimeout(1500);
  await page.getByRole("button", { name: /調查/ }).click();
  await page.waitForTimeout(2500);

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: ".md", exact: true }).click(),
  ]);
  const path = await download.path();
  const fs = await import("node:fs/promises");
  const text = await fs.readFile(path!, "utf-8");
  // 這正是今天修過的那個缺陷：欄位取錯 → 摘要整排「—」、DNS 每行 undefined
  expect(text, "報告出現未取到的值").not.toContain("undefined");
  expect(text, "報告倒出原始 JSON").not.toContain('{"event"');
  expect(text, "報告沒有主機名稱").toContain("web-01");
  expect(text, "報告沒有子網路").toContain("10.20.0.0/24");
});

test("切成英文介面：不該有未翻譯的鍵名露出", async ({ page }) => {
  // check-i18n 掃不到動態組出來的鍵（如 `anomaly.explain_${key}`）——
  // 今天就有一個是這樣漏掉的，只有真的把畫面切成英文才看得見。
  await page.goto("/");
  await page.waitForTimeout(1200);
  await page.evaluate(() => localStorage.setItem("locale", "en-US"));
  const pages = ["/", "/addresses", "/devices", "/anomaly", "/ai-audit",
                 "/virt", "/virt-vmware", "/system-settings", "/llm"];
  const leaks: string[] = [];
  for (const p of pages) {
    await page.goto(p);
    await page.waitForTimeout(1200);
    const body = await page.locator("body").innerText();
    // 未翻譯時 vue-i18n 會直接輸出鍵名，形如 `anomaly.explain_ghost_ips`
    // 後面還接著點號的是網域（idp.example.com），不是 i18n 鍵
    const m = body.match(/\b[a-z][a-z_]{2,}\.[a-z][a-z_]{3,}\b(?!\.)/g) ?? [];
    const suspicious = m.filter((x) =>
      !/\.(com|net|org|tools|local|test|json|js|css|py|sh|example)$/.test(x));
    if (suspicious.length) leaks.push(`${p}｜${[...new Set(suspicious)].slice(0, 6).join(", ")}`);
  }
  expect(leaks, `英文介面有未翻譯的鍵名：\n${leaks.join("\n")}`).toEqual([]);
});
