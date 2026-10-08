/**
 * AI 助手的浮動按鈕不可以蓋住彈出層（確認框、下拉選單、對話框）。
 *   0.6.50 發版前 e2e 抓到：位址範圍的「刪除」確認框剛好開在畫面右下角，
 *   「確定」有一半壓在浮動按鈕底下 —— 點下去開的是 AI 助手，範圍刪不掉。
 *   浮動按鈕原本 z-index 9000，比 Naive UI 彈出層（2000 起跳）還高。
 * 不靠「剛好開在哪裡」：把一個真的下拉選單搬到浮動按鈕正上方，看最上層是誰。
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

test("彈出層蓋在 AI 助手浮動按鈕上面", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await login(page);
  await page.goto("/");
  const fab = page.locator(".chat-fab");
  await expect(fab).toBeVisible();

  // 右上角的帳號選單：一個真的 Naive UI 下拉（掛在 body 底下的 follower 容器）
  await page.getByText(/admin@/).first().click();
  const menu = page.locator(".n-dropdown-menu").first();
  await expect(menu).toBeVisible();

  const top = await page.evaluate(() => {
    const fabEl = document.querySelector(".chat-fab") as HTMLElement;
    const menuEl = document.querySelector(".n-dropdown-menu") as HTMLElement;
    const follower = menuEl.closest(".v-binder-follower-content") as HTMLElement;
    const r = fabEl.getBoundingClientRect();
    // 把下拉整個搬到浮動按鈕正上方（只改位置，不動任何層級）
    follower.style.transform = "none";
    follower.style.position = "fixed";
    follower.style.left = `${r.left - 20}px`;
    follower.style.top = `${r.top - 20}px`;
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return {
      inMenu: !!hit && menuEl.contains(hit),
      inFab: !!hit && fabEl.contains(hit),
    };
  });
  expect(top.inFab, "浮動按鈕蓋在下拉選單上面").toBe(false);
  expect(top.inMenu).toBe(true);
});

/**
 * 頁面內容捲到底時，最後一列不可以壓在浮動按鈕底下。
 *   0.6.61 之後 e2e 抓到：RustDesk 伺服器清單的最後一列，右側固定欄的「刪除」鈕剛好在右下角，
 *   被浮動按鈕蓋住 —— 捲到底也一樣（內容區底部沒有留白），點下去開的是 AI 助手。
 * 不靠哪一頁剛好有幾列：把內容撐到比畫面高，捲到底，量最後一個元素的底邊在不在浮動按鈕上緣之上。
 */
for (const vp of [{ width: 1280, height: 720 }, { width: 390, height: 844 }]) {
  test(`內容捲到底不會壓在浮動按鈕底下（${vp.width}px）`, async ({ page }) => {
    await page.setViewportSize(vp);
    await login(page);
    await page.goto("/");
    const fab = page.locator(".chat-fab");
    await expect(fab).toBeVisible();
    const r = await page.evaluate(() => {
      const sc = document.querySelector(".n-layout-content .n-layout-scroll-container") as HTMLElement;
      const filler = document.createElement("div");
      filler.style.height = "3000px";
      sc.appendChild(filler);
      const last = document.createElement("div");
      last.style.height = "20px";
      sc.appendChild(last);
      // 實際捲動的可能是外層（Naive UI 的 n-scrollbar 容器），每一層都捲到底
      for (let el: HTMLElement | null = last; el; el = el.parentElement) el.scrollTop = el.scrollHeight;
      const fabTop = (document.querySelector(".chat-fab") as HTMLElement).getBoundingClientRect().top;
      return { lastBottom: last.getBoundingClientRect().bottom, fabTop };
    });
    expect(r.lastBottom, "捲到底後最後一列仍在浮動按鈕上緣之下").toBeLessThanOrEqual(r.fabTop);
  });
}
