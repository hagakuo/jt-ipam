import { test, expect } from "@playwright/test";

/**
 * 異常偵測：一個 IP 頻繁更換 MAC，而且可以逐 IP 忽略。
 *
 * 為什麼忽略機制是這條規則的一部分：Windows 11 / macOS / iOS / Android 開了隱私
 * 隨機化之後每次連線都換 MAC。沒有忽略，裝置一多就會把整頁洗掉，使用者只能把整條
 * 規則關掉 —— 連真正的 IP 搶用、DHCP 池異常也一起看不到。
 */
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("頻繁換 MAC 的 IP 會被列出，而且可以忽略", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });

  // 先問後端有沒有樣本，再決定要不要跑。原本是「等表格出現列」再檢查樣本在不在 ——
  // 環境裡沒有這種資料時，那一等就是 60 秒逾時，訊息寫「等不到表格列」，看起來像
  // 功能壞了。沒有樣本應該是 skip，不是 fail。
  // （樣本本身由 `tests.seed_e2e` 建立，而且每次 seed 都會重新錨定時間 ——
  //   偵測看的是「最近 7 天」，只建立不更新的 fixture 過一週就自己掉出窗外。）
  const sample = await page.evaluate(async () => {
    const r = await fetch("/api/v1/anomalies/scan", {
      method: "POST",
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` },
    });
    if (!r.ok) return null;
    const body = await r.json();
    return JSON.stringify(body?.mac_flapping ?? []);
  });
  test.skip(!sample || !sample.includes("10.20.0.10"), "這個環境沒有頻繁換 MAC 的樣本");

  // 直接用 ?tab= 進到那一類（通知點進來也是走這條路）
  await page.goto("/anomaly?tab=mac_flapping");
  await page.getByRole("button", { name: /執行偵測/ }).click();
  await expect(page.locator(".n-data-table-tbody .n-data-table-tr").first())
    .toBeVisible({ timeout: 60_000 });

  // 要看得出「這些是隨機化位址」—— 沒有這個資訊，人無從判斷該不該忽略。
  // 而且布林值要印成「是／否」，不是裸的 true（第一版就是這樣露出來的）
  await expect(page.locator(".n-data-table-thead")).toContainText("MAC 數");
  const row = page.locator(".n-data-table-tr", { hasText: "10.20.0.10" }).first();
  await expect(row).toBeVisible();
  await expect(row).not.toContainText("true");
  // 內部 UUID 不該預設顯示（可在「欄位」勾選）
  await expect(page.locator(".n-data-table-thead")).not.toContainText("IP 內部編號");

  // 版面：MAC 欄不折行，很容易蓋到「操作」欄的按鈕上（第一版就是這樣）
  const macCell = row.locator("td").nth(4);
  const btn = row.getByRole("button", { name: "忽略這個 IP" });
  const [mb, bb] = [await macCell.boundingBox(), await btn.boundingBox()];
  expect(mb!.x + mb!.width, "MAC 欄壓到操作欄的按鈕上").toBeLessThanOrEqual(bb!.x + 1);

  // 忽略之後那一列就不該再出現
  await row.getByRole("button", { name: "忽略這個 IP" }).click();
  await expect(page.locator(".n-data-table-tr", { hasText: "10.20.0.10" }))
    .toHaveCount(0, { timeout: 60_000 });

  // 把忽略清單還原 —— 這條測試會改資料，不還原的話**第二次跑就會失敗**：
  // 樣本被自己加進忽略清單，偵測再也列不出它，訊息只會說「等不到表格列」，
  // 看起來像功能壞了。實際踩過一次，追了十分鐘才發現是上一輪留下的狀態。
  const restored = await page.evaluate(async () => {
    const auth = { Authorization: `Bearer ${localStorage.getItem("access_token")}` };
    const r = await fetch("/api/v1/addresses?q=10.20.0.10&page_size=5", { headers: auth });
    const id = (await r.json()).items?.[0]?.id;
    if (!id) return "找不到樣本 IP";
    const put = await fetch(`/api/v1/anomalies/ignore/${id}`, {
      method: "PUT",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ categories: [] }),
    });
    return put.ok ? "ok" : `還原失敗 HTTP ${put.status}`;
  });
  expect(restored, "忽略清單沒有還原，下一次跑這支會失敗").toBe("ok");
});
