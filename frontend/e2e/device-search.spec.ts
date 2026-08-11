import {
  test, expect, request as playwrightRequest,
  type APIRequestContext, type Page,
} from "@playwright/test";

// 裝置清單「載不完 → 看不到也搜不到」的回歸測試（客戶回報）。
//
// 症狀：新增的裝置在「裝置」頁看不到，用名字搜也搜不到，但從機櫃點進去看得到。
// 成因：清單只抓第一頁（200 筆、依名稱排序），搜尋框又只在「已載入的那幾筆」上過濾。
//       裝置一多，排序落在後面的新裝置就整台消失；機櫃是依 rack_id 查、結果集小才看得到。
//
// 這條測試把資料撐過一頁的邊界，才驗得到 —— 裝置數少於一頁時，壞的版本也會通過。
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";

test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

const PAGE_ONE = 200;      // 清單原本一次只抓這麼多
const HEADROOM = 12;       // 撐過邊界後再多幾筆，確保目標真的落在第一頁之外

async function apiLogin(request: APIRequestContext): Promise<string> {
  const r = await request.post("/api/v1/auth/login", {
    data: { username: ADMIN_USER, password: ADMIN_PASS, realm: "local" },
  });
  expect(r.ok(), "API 登入要成功").toBeTruthy();
  return (await r.json()).access_token;
}

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test.describe("裝置清單：超過一頁時仍看得到、搜得到", () => {
  test("新增的裝置排在最後也要出現在清單與搜尋結果", async ({ page, request }) => {
    // 要造一兩百台裝置才撐得過「第一頁」的邊界，預設 30 秒不夠
    test.setTimeout(600_000);
    const token = await apiLogin(request);
    const auth = { Authorization: `Bearer ${token}` };
    const tag = `e2e${Date.now().toString().slice(-8)}`;
    const created: string[] = [];

    const mkDevice = async (name: string) => {
      const r = await request.post("/api/v1/devices", {
        headers: auth,
        data: { name, type: "server" },
      });
      expect(r.ok(), `建立 ${name} 要成功`).toBeTruthy();
      created.push((await r.json()).id);
    };

    try {
      // 現有幾筆？要墊到超過一頁，邊界才會被踩到。
      const cur = await request.get("/api/v1/devices?page_size=1", { headers: auth });
      const existing = (await cur.json()).total as number;
      const filler = Math.max(0, PAGE_ONE + HEADROOM - existing);

      // 墊檔的名字用 "aaa-" 開頭 → 依名稱排序時全部排在目標之前，把目標擠出第一頁
      // 一台一台建太慢（會撞測試逾時），分批平行建
      const names = Array.from({ length: filler },
        (_, i) => `aaa-${tag}-${String(i).padStart(4, "0")}`);
      for (let i = 0; i < names.length; i += 12) {
        await Promise.all(names.slice(i, i + 12).map(mkDevice));
      }
      // 目標裝置用 "zzz-" 開頭 → 排在最後，正是客戶那台看不到的裝置
      const target = `zzz-${tag}-target`;
      await mkDevice(target);

      // 1) 不搜尋時，清單要真的「有」全部裝置。
      // 表格是前端分頁的，最後一台不會直接出現在畫面上 —— 要看的是分頁列的總筆數：
      // 客戶的截圖正是「儀表板 272、裝置頁共 200 筆」，那個 200 就是只載到第一頁。
      const expectTotal = existing + filler + 1;
      await login(page);
      await page.goto("/devices");
      await expect(page.locator(".n-pagination")).toContainText(
        new RegExp(`共\\s*${expectTotal}\\s*筆`), { timeout: 30_000 });

      // 2) 用名字搜也要找得到（壞的版本只在已載入的那 200 筆裡過濾 → 無資料）
      // 用「型號」認這個框：頁首那顆全域搜尋的 placeholder 也含「搜尋」，
      // 拿 .first() 會抓到頁首那顆，打字進去對這張表毫無作用。
      await page.getByPlaceholder(/型號|model/i).fill(target);
      await expect(page.locator(".n-data-table-tr", { hasText: target }))
        .toBeVisible({ timeout: 15_000 });
      // 搜尋要真的有縮小範圍，否則「完全沒過濾」也會讓上一行通過
      await expect(page.locator(".n-data-table-tr", { hasText: `aaa-${tag}-` }))
        .toHaveCount(0);
    } finally {
      // 不論成敗都清乾淨，別在實例上留下幾百台測試裝置。
      // 用獨立的 request context —— 測試逾時的話，綁在測試上的那個已經被關掉，清不了東西
      // （第一次跑就是這樣在站台上留下 85 台）。
      const cleaner = await playwrightRequest.newContext({
        baseURL: process.env.E2E_BASE_URL, ignoreHTTPSErrors: true,
      });
      for (let i = 0; i < created.length; i += 12) {
        await Promise.all(created.slice(i, i + 12).map(
          (id) => cleaner.delete(`/api/v1/devices/${id}`, { headers: auth })));
      }
      await cleaner.dispose();
    }
  });
});
