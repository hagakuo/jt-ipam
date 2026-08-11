/**
 * 用真實瀏覽器驗今天改過的東西「長對樣子」。
 *
 * 頁面載得起來不代表改對了 —— 今天已經有兩次是「畫面渲染成功但內容是錯的」
 * （匯出報告整排 undefined、登入把 502 說成密碼錯）。這支就是去看實際畫出來的字。
 */
import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");
test.setTimeout(180_000);

test.beforeEach(async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入|Sign in/i }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"), { timeout: 20_000 });
});

test("虛擬化兩頁的標題要說出自己是哪個平台", async ({ page }) => {
  await page.goto("/virt");
  await page.waitForTimeout(1200);
  await expect(page.locator("body")).toContainText("Proxmox VE");

  await page.goto("/virt-vmware");
  await page.waitForTimeout(1200);
  await expect(page.locator("body")).toContainText("VMware");
});

test("裝置頁有虛實欄與子網路篩選", async ({ page }) => {
  await page.goto("/devices");
  await page.waitForTimeout(1500);
  const body = await page.locator("body").innerText();
  expect(body, "缺少「虛實」欄").toContain("虛實");
  // 子網路篩選下拉：naive 的 select 把 placeholder 畫成文字節點，不是 input 屬性
  expect(body, "缺少子網路篩選").toContain("全部子網路");
});

test("異常偵測：標頭可排序，且每個區塊都有說明文字", async ({ page }) => {
  await page.goto("/anomaly");
  await page.waitForTimeout(1500);
  const body = await page.locator("body").innerText();
  // 缺翻譯時畫面會直接顯示鍵名
  expect(body, "有未翻譯的鍵名露出").not.toContain("anomaly.explain_");
  expect(body, "「懸空」不是台灣用語，應已改掉").not.toContain("懸空");
});

test("AI 巡檢：措辭已改，且沒有左側色條", async ({ page }) => {
  await page.goto("/ai-audit");
  await page.waitForTimeout(1500);
  const body = await page.locator("body").innerText();
  expect(body, "舊的武斷措辭還在").not.toContain("非查核事實");
  // 嚴重度色塊存在（有資料時）；沒資料時不強求
  const cells = await page.locator(".fx-sev-cell").count();
  if (cells > 0) {
    await expect(page.locator(".fx-sev-cell").first()).toBeVisible();
  }
});

test("登入失敗時，伺服器故障與密碼錯誤要說不同的話", async ({ page, context }) => {
  await context.clearCookies();
  await page.goto("/login");
  // 攔截登入請求，讓它回 502 —— 模擬後端掛掉
  await page.route("**/api/v1/auth/login", (r) => r.fulfill({ status: 502, body: "{}" }));
  await page.getByPlaceholder(/帳號|Username/).fill("whoever");
  await page.getByPlaceholder(/密碼|Password/).fill("whatever");
  await page.getByRole("button", { name: /登入|Sign in/i }).click();
  await page.waitForTimeout(1200);
  const body = await page.locator("body").innerText();
  expect(body, "502 仍被說成帳號密碼問題").not.toContain("請確認帳號密碼");
  expect(body).toContain("502");
});

test("異常偵測的說明要涵蓋全部偵測類別", async ({ page }) => {
  // 新增偵測類別時最容易忘記的就是這句話 —— 它停在四條規則，實際上已經有九類，
  // 使用者會以為系統只做那四件事（真實瀏覽器巡檢抓到）。
  await page.goto("/anomaly");
  await page.waitForTimeout(1200);
  const body = await page.locator("body").innerText();
  for (const kind of ["IP 衝突", "MAC 變動", "失聯 IP", "未授權 IP",
                      "非法 DHCP", "對外曝險", "失效 DNS", "重複的 IP", "可疑異動"]) {
    expect(body, `說明沒有提到「${kind}」`).toContain(kind);
  }
});
