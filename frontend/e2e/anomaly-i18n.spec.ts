/**
 * 異常偵測の表：列見出しと「説明」欄の在地化。
 *
 * 列見出しは `COLLBL` という辞書に直書きされていて、i18n を通っていませんでした。
 * 表は「偵測を実行」した後にしか描かれないので、既存のロケール確認では一度も
 * 見られていません —— 日本語に切り替えても見出しだけ中国語のまま、という状態が
 * 型チェックも単体テストも i18n の鍵チェックもすり抜けていました。
 *
 * ファイアウォールのルール劣化の「説明」も同じで、後端が組み立てた中国語の文が
 * そのまま表示されていました。いまは `detail_key`（＋`detail_params`）で送られます。
 */
import { test, expect, type Page } from "@playwright/test";
import { createTempAdmin, deleteTempUser, type TempUser } from "./helpers/tempAdmin";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

// 日本語では使わない繁体字だけ。共用の字を入れると正しい日本語が誤検知されます。
const CHINESE_ONLY = /[這們麼嗎呢您臺灣沒裡哪樣點體實說讓會國學關與將從區發處屬單當]/;

const EMPTY: Record<string, unknown[]> = {
  ip_conflicts: [], mac_drifts: [], ghost_ips: [], unauthorized_ips: [], rogue_dhcp: [],
  external_exposure: [], dangling_dns: [], duplicate_ip_records: [], suspicious_changes: [],
  arp_only_liveness: [], stale_device_links: [], mac_flapping: [],
};

// 後端が送るのと同じ形。`detail` は中国語の原文（匯出と AI 判読が使う）、
// 画面に出るのは `detail_key` のほう。
const ROT_ROWS = [
  {
    kind: "any_any", name: "fw-edge", source: "pfsense", interface: "lan",
    descr: "temporary", detail: "any → any 放行 —— 等於這個介面沒有防火牆",
    detail_key: "anomaly.rot.any_any",
  },
  {
    kind: "alias_rot", name: "srv-pool", source: "opnsense", descr: "",
    detail: "別名成員 198.51.100.7 在管理網段內但 IPAM 沒有紀錄",
    detail_key: "anomaly.rot.alias_rot",
    detail_params: { members: "198.51.100.7" },
  },
];

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
  const status = await page.evaluate(async (loc) => {
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
  expect(status, `locale=${locale} の保存が拒否されました`).toBe(200);
}

test.describe("異常偵測の表の在地化", () => {
  test.beforeAll(async ({ request }) => { tmp = await createTempAdmin(request, "locale"); });
  test.afterAll(async ({ request }) => { await deleteTempUser(request, tmp); });
  test.beforeEach(async ({ page }) => {
    await page.route("**/api/v1/anomalies/scan", (route) =>
      route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ ...EMPTY, fw_rule_rot: ROT_ROWS }),
      }));
  });

  test("日本語では列見出しも説明も日本語になる", async ({ page }) => {
    await login(page);
    await setLocale(page, "ja-JP");
    // 通知から飛んでくるのと同じ経路。タブ列は横にあふれるので、クリックでは届きません
    await page.goto("/anomaly?tab=fw_rule_rot");
    await page.getByRole("button", { name: /執行偵測|検査を実行|Run scan/ }).first().click();
    const table = page.locator(".n-data-table").first();
    await expect(table).toContainText("fw-edge");

    // 列見出し：中国語が残っていないこと
    const heads = (await table.locator("th").allInnerTexts()).join(" | ");
    expect(heads, `列見出しに中国語が残っています：${heads}`).not.toMatch(CHINESE_ONLY);
    expect(heads).toContain("説明");        // detail
    expect(heads).toContain("取得元");      // source

    // 説明欄：翻訳された文が出ること（中国語の原文がそのまま出ていないこと）
    const body = await table.innerText();
    expect(body).toContain("実質ファイアウォールがありません");
    expect(body, "中国語の原文がそのまま出ています").not.toContain("等於這個介面沒有防火牆");

    // パラメータ入りの文：{members} が空欄のまま出ていないこと
    expect(body).toContain("198.51.100.7");
    expect(body, "{members} が代入されていません").not.toContain("{members}");
  });

  test("繁體中文では従来どおり中国語で出る", async ({ page }) => {
    await login(page);
    await setLocale(page, "zh-TW");
    await page.goto("/anomaly?tab=fw_rule_rot");
    await page.getByRole("button", { name: /執行偵測|検査を実行|Run scan/ }).first().click();
    const table = page.locator(".n-data-table").first();
    await expect(table).toContainText("fw-edge");

    const heads = (await table.locator("th").allInnerTexts()).join(" | ");
    expect(heads).toContain("說明");
    expect(await table.innerText()).toContain("等於這個介面沒有防火牆");
  });
});
