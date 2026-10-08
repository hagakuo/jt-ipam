/**
 * 裝置「連接埠／佈線」的 MAC 欄顯示 OUI 廠商（2026-09-27 使用者要求），與 IP 清單同一個呈現：
 * MAC 在上、廠商在下。覆寫連接埠清單的回應，不依賴測試庫裡剛好有哪些 OUI。
 */
import { test, expect } from "@playwright/test";

const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

test("連接埠的 MAC 欄第二行是廠商", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /^(登入|Sign in)$/ }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
  const id = await page.evaluate(async () => {
    const auth = { Authorization: `Bearer ${localStorage.getItem("access_token")}` };
    const r = await (await fetch("/api/v1/devices?page=1&page_size=1", { headers: auth })).json();
    return (r.items ?? [])[0]?.id as string | undefined;
  });
  test.skip(!id, "這個環境沒有任何裝置");
  await page.route("**/api/v1/device-ports?*", async (route) => {
    await route.fulfill({ json: [
      { id: "00000000-0000-0000-0000-0000000000a1", device_id: id, name: "eno1", type: "network",
        peer_port_id: null, position: null, description: null, link: null,
        mac_address: "00:00:5e:00:53:01", mac_vendor: "IANA" },
      { id: "00000000-0000-0000-0000-0000000000a2", device_id: id, name: "eno2", type: "network",
        peer_port_id: null, position: null, description: null, link: null,
        mac_address: "00:00:5e:00:53:02", mac_vendor: null },
    ] });
  });
  await page.goto(`/devices/${id}`);
  const row1 = page.locator(".n-data-table-tr", { hasText: "eno1" });
  await expect(row1.locator(".mac-cell__mac")).toHaveText("00:00:5e:00:53:01");
  await expect(row1.locator(".mac-cell__vendor")).toHaveText("IANA");
  // 查不到廠商時就只有 MAC，不多一行空白
  const row2 = page.locator(".n-data-table-tr", { hasText: "eno2" });
  await expect(row2).toContainText("00:00:5e:00:53:02");
  await expect(row2.locator(".mac-cell__vendor")).toHaveCount(0);
});
