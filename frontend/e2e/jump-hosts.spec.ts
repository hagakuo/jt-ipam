import { test, expect, type Page } from "@playwright/test";

/**
 * 跳板主機（issue #24 階段一）。
 *
 * 分兩段：
 * - 管理頁本身（新增／指紋未釘選的警示／刪除）—— 不需要真的跳板，隨時可跑
 * - **真的經跳板連線** —— 需要一台真的 SSH 跳板，用 JUMP_* 環境變數帶進來。
 *   驗這一段的辦法寫在 TEST_CHECKLIST §7e（本機起一台拋棄式 sshd 即可）。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const JUMP_IP_ID = process.env.JUMP_TARGET_IP_ID || "";
const JUMP_KEY = process.env.JUMP_CLIENT_KEY || "";
const JUMP_PORT = process.env.JUMP_TARGET_PORT || "22";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test.describe("跳板主機", () => {
  test("需求與設定說明：系統、轉發、帳號、私鑰格式都講得到，新增視窗裡也打得開", async ({ page }) => {
    await login(page);
    await page.goto("/jump-hosts");
    await page.getByTestId("jump-help-btn").click();
    const help = page.getByTestId("jump-help");
    await expect(help).toBeVisible();
    for (const s of ["OpenSSH", "AllowTcpForwarding", "不需要 root", "不支援有密碼保護的私鑰", "信任並儲存",
                     "useradd -m -s /usr/sbin/nologin jtipam-jump", "經由掃描代理中繼"]) {
      await expect(help).toContainText(s);
    }
    if (process.env.SHOT_DIR) await help.screenshot({ path: `${process.env.SHOT_DIR}/jump-help.png` });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "新增" }).first().click();
    await page.getByRole("button", { name: "跳板要符合哪些條件？" }).click();
    await expect(help).toBeVisible();
  });

  test("新增 → 未釘選指紋要看得出來 → 刪除", async ({ page }) => {
    await login(page);
    await page.goto("/jump-hosts");

    const name = `e2e-jh-${Date.now()}`;
    await page.getByRole("button", { name: "新增" }).first().click();
    const dialog = page.locator(".n-modal");
    await expect(dialog).toBeVisible();
    const boxes = dialog.getByRole("textbox");
    await boxes.nth(0).fill(name);
    await boxes.nth(1).fill("198.51.100.9");        // TEST-NET，必連不到
    await boxes.nth(2).fill("jump");
    await dialog.locator("textarea").first().fill("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n");
    await dialog.getByRole("button", { name: "儲存" }).click();

    const row = page.locator(".n-data-table-tr", { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });
    // 沒釘選指紋的跳板一定連不了 —— 清單上要一眼看得出來，而不是等連線失敗才知道
    await expect(row).toContainText("未釘選");

    await row.locator("button.n-button--error-type").click();
    const confirmBtn = page.locator(".n-popconfirm__action button").last();
    await expect(confirmBtn).toBeVisible();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/jump-hosts/"));
    await confirmBtn.dispatchEvent("click");
    await deleted;
    await expect(page.locator(".n-data-table-tr", { hasText: name })).toHaveCount(0,
      { timeout: 10_000 });
  });

  test("窄視窗時管理頁不會橫向溢出", async ({ page }) => {
    await page.setViewportSize({ width: 900, height: 900 });
    await login(page);
    await page.goto("/jump-hosts");
    await page.waitForTimeout(800);
    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, "頁面出現橫向捲動").toBeLessThanOrEqual(1);
  });

  test("SSH 主控台真的經跳板連上目標", async ({ page }) => {
    test.skip(!JUMP_IP_ID || !JUMP_KEY, "需要真的跳板（見 TEST_CHECKLIST §7e）");
    await login(page);
    await page.goto(`/ssh/${JUMP_IP_ID}`);
    await expect(page.getByText("SSH 連線到")).toBeVisible({ timeout: 10_000 });
    await page.getByText("私鑰", { exact: true }).click();
    await page.locator('input[placeholder="root"]').fill("root");
    await page.locator(".n-input-number input").first().fill(JUMP_PORT);
    await page.locator("textarea").first().fill(JUMP_KEY);
    await page.getByRole("button", { name: "SSH 連線" }).click();

    // 目標的 host key 是**經由通道**取回來的：沒走通道的話取到的會是別台機器的
    const trust = page.getByRole("button", { name: "信任並連線" });
    if (await trust.isVisible({ timeout: 20_000 }).catch(() => false)) await trust.click();

    await expect(page.getByText(/經由跳板/)).toBeVisible({ timeout: 30_000 });
    await expect(page.locator(".ssh-status")).toContainText(/已連線|connected/,
      { timeout: 30_000 });
  });

  test("SFTP 主控台真的經跳板列出目標的目錄", async ({ page }) => {
    test.skip(!JUMP_IP_ID || !JUMP_KEY, "需要真的跳板（見 TEST_CHECKLIST §7e）");
    await login(page);
    await page.goto(`/sftp/${JUMP_IP_ID}`);
    await expect(page.getByText("SFTP 連線到")).toBeVisible({ timeout: 10_000 });
    await page.getByText("私鑰", { exact: true }).click();
    await page.locator('input[placeholder="root"]').fill("root");
    await page.locator(".n-input-number input").first().fill(JUMP_PORT);
    await page.locator("textarea").first().fill(JUMP_KEY);
    await page.getByRole("button", { name: "連線", exact: true }).click();
    // 列出目錄＝瀏覽器 → 後端 → 跳板 → 目標 → 回程，整條路都通
    await expect(page.locator(".n-data-table-tr").first()).toBeVisible({ timeout: 40_000 });
    await expect(page.getByText(/經由跳板/)).toBeVisible();
  });
});
