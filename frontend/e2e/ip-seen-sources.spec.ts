/**
 * IP 詳細資料的「各來源最後出現」：獨立一區、三欄對齊（來源／時間／多久以前），最新的那一列標出來；
 * LibreNMS／Wazuh 的時間可點 → 帶到裝置頁並捲到那張卡片。虛實要分得出 PVE 的 KVM 與 LXC。
 *
 * 種子資料（tests/seed_e2e.py）：10.20.0.40 掛在 seen-host-01，寫入時掃描代理 5 分鐘前、LibreNMS 3 小時前、
 * Wazuh 2 天前（期望值依 API 回的時間當下算，種子放久了也照樣對）；PVE 的 LXC 容器 ct-log-01 的網卡是這個位址。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

async function openIp(page: Page) {
  await page.goto("/addresses?q=10.20.0.40");
  await page.locator("tr", { hasText: "10.20.0.40" }).first().getByText("10.20.0.40").first().click();
  const sec = page.getByTestId("ip-seen-section");
  await expect(sec).toBeVisible({ timeout: 15_000 });
  return sec;
}

/** 依 API 回的各來源時間與上線門檻，算出畫面應該顯示的「多久以前」與上線判定（與 fmtRelative／seenVerdict 同一套規則）。 */
async function expectedSeen(page: Page) {
  const id = page.url().split("/addresses/")[1]?.split(/[?#]/)[0] ?? "";
  return page.evaluate(async (ipId) => {
    const tok = localStorage.getItem("access_token") || "";
    const a = await (await fetch(`/api/v1/addresses/${ipId}`, { headers: { Authorization: `Bearer ${tok}` } })).json();
    const rtf = new Intl.RelativeTimeFormat("zh-TW", { numeric: "auto" });
    const ago = (iso: string) => {
      const sec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
      if (sec < 60) return rtf.format(-sec, "second");
      const min = Math.floor(sec / 60);
      if (min < 60) return rtf.format(-min, "minute");
      const hr = Math.floor(min / 60);
      if (hr < 24) return rtf.format(-hr, "hour");
      return rtf.format(-Math.floor(hr / 24), "day");
    };
    const minutes = a.liveness_rule.minutes as number;
    const verdict = (iso: string) => (Date.now() - new Date(iso).getTime() <= minutes * 60_000 ? "計入 · 有效" : "計入 · 已過期");
    const one = (iso: string) => ({ ago: ago(iso), verdict: verdict(iso) });
    return { scanner: one(a.last_seen_scanner), librenms: one(a.last_seen_librenms), wazuh: one(a.last_seen_wazuh) };
  }, id);
}

test("各來源最後出現獨立一區：固定順序、附多久以前、最新的那一列標出來；虛實標出 LXC", async ({ page }) => {
  await login(page);
  const sec = await openIp(page);
  await expect(sec.locator("thead")).toContainText("來源");
  await expect(sec.locator("thead")).toContainText("多久以前");
  const rows = sec.locator("tbody tr");
  await expect(rows.nth(0)).toContainText("掃描代理");
  await expect(rows.nth(1)).toContainText("LibreNMS");
  await expect(sec.locator("tr.seen-latest")).toContainText("掃描代理");
  await expect(sec.locator("tr.seen-latest")).toContainText("最新");
  // 「多久以前」與上線判定都跟著種子資料寫入的時間走：期望值用 API 回的時間當下算，種子放久了也不會假失敗
  //（以前寫死「3 小時前」「計入 · 有效」，種子資料過幾個小時就對不上）
  const exp = await expectedSeen(page);
  await expect(rows.nth(1)).toContainText(exp.librenms.ago);
  await expect(sec.locator("tr", { hasText: "Wazuh 代理" })).toContainText(exp.wazuh.ago);
  // 上線判定：在上線門檻內＝計入且有效，超過＝計入但過期；ARP 沒看過＝「—」
  await expect(sec.getByTestId("seen-verdict-scanner")).toHaveText(exp.scanner.verdict);
  await expect(sec.getByTestId("seen-verdict-librenms")).toHaveText(exp.librenms.verdict);
  await expect(sec.getByTestId("seen-verdict-arp")).toHaveCount(0);
  await expect(sec.locator("thead")).toContainText("說明");
  // 這些欄位不再散在上面的基本資料裡
  await expect(page.locator(".n-descriptions").first()).not.toContainText("最後出現");
  await expect(page.getByText("容器 · LXC")).toBeVisible();
});

test("各來源最後出現：點標題排序（時間第一下最新在上；來源依名稱）", async ({ page }) => {
  await login(page);
  const sec = await openIp(page);
  const first = () => sec.locator("tbody tr").first();
  // 與全站表格一樣：點第一下是遞減 —— 「時間」遞減＝最新的在最上面
  await sec.locator("th", { hasText: "時間" }).click();
  await expect(first()).toContainText("掃描代理");
  // 「來源」點兩下＝遞增（依名稱）
  await sec.locator("th", { hasText: "來源" }).click();
  await sec.locator("th", { hasText: "來源" }).click();
  await expect(first()).toContainText("AdGuard");
});

for (const [card, label] of [["librenms", "LibreNMS"], ["wazuh", "Wazuh"]] as const) {
  test(`最後出現（${label}）的時間點下去 → 裝置頁並捲到 ${label} 卡片`, async ({ page }) => {
    await login(page);
    await openIp(page);
    await page.getByTestId(`seen-jump-${card}`).click();
    await expect(page).toHaveURL(new RegExp(`/devices/[0-9a-f-]+\\?card=${card}$`));
    const el = page.locator(`#card-${card}`);
    await expect(el).toHaveClass(/card-focus/, { timeout: 15_000 });
    await expect(el).toBeInViewport();
    if (card === "wazuh") {
      // 狀態要翻譯（以前直接印 Wazuh 的原始值 disconnected）
      await expect(el.locator("td", { hasText: "離線" })).toBeVisible();
      await expect(el).not.toContainText("disconnected");
    }
  });
}
