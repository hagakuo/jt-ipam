/**
 * SFTP：用真實瀏覽器連上一台真的 SFTP 伺服器，實際列目錄、下載、上傳。
 *
 * 「檔案有沒有真的傳過去」只有端到端才問得出來 —— 介面顯示「已上傳」而檔案是空的、
 * 或下載下來少了幾個 chunk，兩者在畫面上看起來都一樣正常。
 */
import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const TARGET_IP_ID = process.env.E2E_SFTP_IP_ID || "";
// 這台 SFTP 目標由 e2e/fixtures/sftp-target.py 起（見該檔開頭的用法）
const SFTP_ROOT = process.env.E2E_SFTP_ROOT || "";
const SFTP_USER = process.env.E2E_SFTP_USER || "tester";
const SFTP_PASS = process.env.E2E_SFTP_PASS || "TestPass!2026";
const SFTP_PORT = process.env.E2E_SFTP_PORT || "2222";

test.skip(!ADMIN_PASS || !TARGET_IP_ID || !SFTP_ROOT,
  "需要 E2E_ADMIN_PASS、E2E_SFTP_IP_ID 與 E2E_SFTP_ROOT");
test.setTimeout(180_000);

async function login(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function connect(page: any) {
  await login(page);
  await page.goto(`/sftp/${TARGET_IP_ID}`);
  // 連線表單的版面與 SSH 終端機一致：卡片標題「SFTP 連線到 <ip>」
  await expect(page.getByText(/SFTP 連線到/)).toBeVisible();
  await page.getByPlaceholder("root").fill(SFTP_USER);
  // 密碼欄（第一個 password 型別的輸入框）
  await page.locator('input[type="password"]').first().fill(SFTP_PASS);
  await page.locator(".n-input-number input").first().fill(SFTP_PORT);
  await page.keyboard.press("Tab");
  await page.getByRole("button", { name: "連線" }).click();
  // 連上後會自動列出根目錄
  await expect(page.getByText("nginx.conf").or(page.getByText("etc"))).toBeVisible({ timeout: 20_000 });
}

test("連線後可以列出遠端目錄", async ({ page }) => {
  await connect(page);
  const body = await page.locator("body").innerText();
  expect(body, "看不到遠端的檔案").toContain("app.log");
  expect(body, "看不到目錄").toContain("etc");
  // 含中文的檔名不可以變成亂碼
  expect(body, "中文檔名壞掉").toContain("readme-中文.txt");
  await page.screenshot({ path: "test-results/sftp-list.png" });
});

test("目錄與檔案的名稱要對齊（檔案左邊留同寬的空位）", async ({ page }) => {
  await connect(page);
  // 用量的，不用看的：曾經因為 emoji 寬度、以及 scoped CSS 套不到 render function
  // 產生的元素，兩次都差了 16～17px，而截圖乍看之下很像對齊了
  const rows = await page.locator(".sftp-name").all();
  const xs: number[] = [];
  for (const r of rows.slice(0, 6)) {
    const box = await r.locator("span").last().boundingBox();
    if (box) xs.push(Math.round(box.x));
  }
  expect(xs.length, "抓不到名稱欄").toBeGreaterThan(1);
  expect(new Set(xs).size, `名稱起始位置不一致：${xs}`).toBe(1);
});

test("檔案操作區的版面：外框、狀態列在框外、控制項同高、按鈕都有 icon", async ({ page }) => {
  await connect(page);
  // 外框把「遠端主機的內容」框起來；狀態列講的是連線，刻意留在框外
  const panel = await page.locator(".sftp-panel").boundingBox();
  const status = await page.locator(".sftp-toolbar").boundingBox();
  expect(panel && status, "抓不到面板或狀態列").toBeTruthy();
  expect(status!.y + status!.height, "狀態列被包進框裡了").toBeLessThanOrEqual(panel!.y + 1);
  const border = await page.locator(".sftp-panel")
    .evaluate((e) => getComputedStyle(e).borderTopWidth);
  expect(parseFloat(border), "面板沒有外框").toBeGreaterThan(0);

  // 路徑欄與篩選欄同高（篩選欄曾經是 small，矮一截）
  const pathH = (await page.locator(".sftp-pathbar .n-input").first().boundingBox())!.height;
  const filtH = (await page.locator(".sftp-pathbar .n-input").last().boundingBox())!.height;
  expect(Math.abs(pathH - filtH), `路徑欄 ${pathH} vs 篩選欄 ${filtH}`).toBeLessThanOrEqual(1);

  // 這排按鈕每一顆都要有 icon
  for (const name of [/上一層/, /重新整理/, /新增資料夾/, /上傳檔案/]) {
    expect(await page.getByRole("button", { name }).first().locator("svg").count(),
      `按鈕 ${name} 少了 icon`).toBeGreaterThan(0);
  }
});

test("篩選只縮小目前目錄的清單，並說出篩掉了多少", async ({ page }) => {
  await connect(page);
  const total = await page.locator("tbody tr").count();
  await page.getByPlaceholder(/篩選這個目錄/).fill("app.log");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  // 只顯示一部分卻不說，會讓人以為目錄裡就只有這些
  await expect(page.locator(".sftp-filter-note")).toContainText(String(total));
  await page.getByPlaceholder(/篩選這個目錄/).fill("");
  await expect(page.locator("tbody tr")).toHaveCount(total);
});

test("批次移動與批次刪除都真的作用在遠端", async ({ page }) => {
  // 準備三個檔案 + 一個空的目的地資料夾，全部直接寫在遠端根目錄上。
  // 目的地要先清空：留著上一輪搬過去的同名檔，這次的搬移會因為「已存在」而失敗，
  // 而後面的 existsSync 又剛好是 true —— 測試會綠得毫無意義。
  rmSync(`${SFTP_ROOT}/batch-dest`, { recursive: true, force: true });
  mkdirSync(`${SFTP_ROOT}/batch-dest`, { recursive: true });
  for (const n of ["b1.txt", "b2.txt", "b3.txt"]) {
    writeFileSync(`${SFTP_ROOT}/${n}`, `x-${n}\n`, "utf-8");
  }
  await connect(page);

  // 勾兩個 → 批次移動
  for (const n of ["b1.txt", "b2.txt"]) {
    await page.locator("tr", { hasText: n }).locator(".n-checkbox").first().click();
  }
  await expect(page.getByText(/已選 2 項/)).toBeVisible();
  await page.evaluate(() => { window.prompt = () => "/batch-dest"; });
  await page.getByRole("button", { name: "移動" }).click();
  await expect(page.locator("table").getByText("b1.txt")).toBeHidden({ timeout: 20_000 });
  expect(existsSync(`${SFTP_ROOT}/batch-dest/b1.txt`), "b1 沒有真的搬過去").toBe(true);
  expect(existsSync(`${SFTP_ROOT}/batch-dest/b2.txt`), "b2 沒有真的搬過去").toBe(true);
  expect(existsSync(`${SFTP_ROOT}/b1.txt`), "原位置還留著").toBe(false);

  // 剩下的那個 → 批次刪除
  await page.locator("tr", { hasText: "b3.txt" }).locator(".n-checkbox").first().click();
  await page.getByRole("button", { name: "刪除", exact: true }).first().click();
  await page.getByRole("button", { name: /確[定認]|是/ }).last().click();
  await expect(page.locator("table").getByText("b3.txt")).toBeHidden({ timeout: 20_000 });
  expect(existsSync(`${SFTP_ROOT}/b3.txt`), "b3 沒有真的刪掉").toBe(false);
});

test("可以進到子目錄再回上一層", async ({ page }) => {
  await connect(page);
  await page.getByText("etc", { exact: false }).first().click();
  await expect(page.getByText("nginx.conf")).toBeVisible({ timeout: 15_000 });
  await page.getByRole("button", { name: "上一層" }).click();
  await expect(page.getByText("app.log")).toBeVisible({ timeout: 15_000 });
});

test("下載的檔案內容與遠端一致", async ({ page }) => {
  await connect(page);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator("tr", { hasText: "readme-中文.txt" }).getByRole("button", { name: "下載" }).click(),
  ]);
  const p = await download.path();
  const got = readFileSync(p!, "utf-8");
  // 位元組要一模一樣 —— 少一個 chunk 或編碼轉錯，畫面上都看不出來
  expect(got).toBe("這是一份含中文檔名與內容的測試檔\n");
});

test("上傳的檔案真的出現在遠端，而且內容正確", async ({ page }) => {
  await connect(page);
  const tmp = join(tmpdir(), "jt-ipam-e2e-upload");
  if (!existsSync(tmp)) mkdirSync(tmp, { recursive: true });
  // 檔名每次不同 —— 用固定檔名的話，上一輪留下的同名檔會讓「表格出現這一列」一開始
  // 就成立，測試於是搶在寫入完成前去讀檔，讀到寫到一半的內容（這條實際上踩過）
  const name = `uploaded-中文-${Date.now()}.conf`;
  const src = `${tmp}/${name}`;
  const payload = "上傳測試\n".repeat(300);
  writeFileSync(src, payload, "utf-8");

  await page.setInputFiles('input[type="file"]', src);
  // 只認表格裡那一列 —— 右上角的提示訊息也含同一個檔名，不能拿它當作「真的傳上去了」
  await expect(page.locator("table").getByText(name)).toBeVisible({ timeout: 30_000 });

  // 直接讀遠端根目錄下的檔案 —— 介面說「已上傳」不算數，檔案在不在才算
  const landed = readFileSync(`${SFTP_ROOT}/${name}`, "utf-8");
  expect(landed).toBe(payload);
  await page.screenshot({ path: "test-results/sftp-upload.png" });
});

test("新增資料夾、改名、刪除都真的作用在遠端", async ({ page }) => {
  await connect(page);
  // 三個操作都會改變遠端主機的檔案系統 —— 每一步都回頭看磁碟，不看畫面提示
  page.on("dialog", () => { /* prompt 由下面的 evaluate 攔截，這裡不處理 */ });

  await page.evaluate(() => { window.prompt = () => "e2e-新資料夾"; });
  await page.getByRole("button", { name: "新增資料夾" }).click();
  await expect(page.locator("table").getByText("e2e-新資料夾")).toBeVisible({ timeout: 15_000 });
  expect(existsSync(`${SFTP_ROOT}/e2e-新資料夾`), "遠端沒有真的建出資料夾").toBe(true);

  await page.evaluate(() => { window.prompt = () => "e2e-改名後"; });
  await page.locator("tr", { hasText: "e2e-新資料夾" })
    .getByRole("button", { name: "重新命名" }).click();
  await expect(page.locator("table").getByText("e2e-改名後")).toBeVisible({ timeout: 15_000 });
  expect(existsSync(`${SFTP_ROOT}/e2e-改名後`), "遠端沒有真的改名").toBe(true);
  expect(existsSync(`${SFTP_ROOT}/e2e-新資料夾`), "舊名字還留著").toBe(false);

  await page.locator("tr", { hasText: "e2e-改名後" })
    .getByRole("button", { name: "刪除" }).click();
  await page.getByRole("button", { name: /確[定認]|是/ }).last().click();
  await expect(page.locator("table").getByText("e2e-改名後")).toBeHidden({ timeout: 15_000 });
  expect(existsSync(`${SFTP_ROOT}/e2e-改名後`), "遠端沒有真的刪掉").toBe(false);
});

test("SFTP 是獨立開關：關掉之後只有 SFTP 入口消失，SSH 還在", async ({ page }) => {
  // 開關存不存得住只有走完「改→存→重載」才知道；只看畫面切換到了不算數
  await login(page);
  const url = `/addresses/${TARGET_IP_ID}`;
  await page.goto(url);
  await expect(page.getByRole("button", { name: "SFTP 檔案" })).toBeVisible();

  await page.getByRole("button", { name: "編輯" }).first().click();
  await page.getByText("啟用 SFTP 檔案傳輸").scrollIntoViewIfNeeded();
  await page.locator(".n-form-item", { hasText: "啟用 SFTP 檔案傳輸" })
    .locator(".n-switch").click();
  await page.getByRole("button", { name: /儲存|保存/ }).first().click();

  await page.goto(url);                               // 重載：值真的存進資料庫了嗎
  await expect(page.getByRole("button", { name: "SFTP 檔案" })).toBeHidden({ timeout: 15_000 });
  await expect(page.getByRole("button", { name: "SSH 連線" })).toBeVisible();  // SSH 不受影響

  // 收尾：開回來，讓其他測試（與後續手動操作）看到的狀態不變
  await page.getByRole("button", { name: "編輯" }).first().click();
  await page.getByText("啟用 SFTP 檔案傳輸").scrollIntoViewIfNeeded();
  await page.locator(".n-form-item", { hasText: "啟用 SFTP 檔案傳輸" })
    .locator(".n-switch").click();
  await page.getByRole("button", { name: /儲存|保存/ }).first().click();
  await page.goto(url);
  await expect(page.getByRole("button", { name: "SFTP 檔案" })).toBeVisible({ timeout: 15_000 });
});
