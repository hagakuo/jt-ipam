import { test, expect, type Page } from "@playwright/test";
import { createTempAdmin, deleteTempUser, type TempUser } from "./helpers/tempAdmin";

/**
 * 日本語ロケールの端から端までの確認。
 *
 * 守っているのは「型チェックと単体テストでは見えない失敗」です。鍵が足りなければ
 * vue-i18n は黙って en-US へ退避し、画面は「一部だけ英語」になります。エラーも
 * 警告も出ません。DB の CHECK 制約に 'ja-JP' を足し忘れていれば、利用者が日本語を
 * 選んだ瞬間に保存だけが失敗し、画面には「保存に失敗しました」としか出ません。
 * どちらもブラウザで実際に切り替えてみないと分かりません。
 */
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

// 日本語では使わない繁体字だけ（新字体が別にある字）。共用の字（有・個・選・際…）を
// 入れると、正しい日本語が大量に誤検知されます。
const CHINESE_ONLY = /[這們麼嗎呢您臺灣沒裡哪樣點體實說讓會國學關與將從區發處屬單當]/;

// 語言存在帳號上：改的是自己這個臨時帳號，平行跑的其他 spec（共用 admin）不受影響
let tmp: TempUser | null = null;

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username|ユーザー名/).fill(tmp!.username);
  await page.getByPlaceholder(/密碼|Password|パスワード/).fill(tmp!.password);
  await page.getByRole("button", { name: /^(登入|Sign in|サインイン)$/ }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function setLocale(page: Page, locale: string) {
  const res = await page.evaluate(async (loc) => {
    const r = await fetch("/api/v1/me/preferences", {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("access_token")}`,
      },
      body: JSON.stringify({ locale: loc }),
    });
    return r.status;
  }, locale);
  // DB の CHECK 制約に足し忘れていると、ここが 500 や 422 になります。
  expect(res, `locale=${locale} の保存が拒否されました`).toBe(200);
}

test.describe("日本語ロケール", () => {
  test.beforeAll(async ({ request }) => { tmp = await createTempAdmin(request, "locale"); });
  test.afterAll(async ({ request }) => { await deleteTempUser(request, tmp); });
  test.afterEach(async ({ page }) => {
    // 他のテストは中文の文字列で要素を探すので、必ず戻します。
    try { await setLocale(page, "zh-TW"); } catch { /* ログイン前に落ちた場合 */ }
  });

  test("ログイン画面は未ログインでも日本語に切り替わる", async ({ page }) => {
    await page.goto("/login");
    await page.evaluate(() => localStorage.setItem("locale", "ja-JP"));
    await page.reload();
    await expect(page.getByRole("button", { name: "サインイン" })).toBeVisible();
    await expect(page.locator("body")).toContainText("ユーザー名またはメールアドレス");
    await page.evaluate(() => localStorage.removeItem("locale"));
  });

  test("主要な画面が日本語になり、未訳のキーも中国語の残りも出ない", async ({ page }) => {
    await login(page);
    await setLocale(page, "ja-JP");

    for (const path of ["/", "/subnets", "/addresses", "/devices", "/racks", "/tools", "/anomaly"]) {
      await page.goto(path);
      await page.waitForTimeout(800);

      // 中国語の混入は UI の部品だけを見る。テーブルのセルには中国語のデータが入りうる。
      const chrome = await page.evaluate(() =>
        Array.from(
          document.querySelectorAll(
            ".n-menu-item-content-header, h1, h2, h3, button, label, th, .n-card-header__main",
          ),
        )
          .map((el) => el.textContent || "")
          .join("\n"));
      expect(chrome, `${path} の UI に中国語が残っています`).not.toMatch(CHINESE_ONLY);

      // 未訳のキーは、そのまま画面に印字される（例：anomaly.explain_mac_flapping）
      const rawKeys = (await page.evaluate(() => document.body.innerText))
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => /^[a-z][a-z0-9_]{2,}\.[a-z][a-z0-9_.]{2,}$/.test(l));
      expect(rawKeys, `${path} に未訳の i18n キーが出ています`).toEqual([]);
    }

    await expect(page.locator(".n-menu")).toContainText("ダッシュボード");
  });
});
