import { test, expect } from "@playwright/test";

/**
 * 儀表板「關係圖」的虛擬化節點。
 *
 * 使用者問：「如果客戶同時用了 vmware proxmox 整合，點上邊的虛擬化進去會到那一頁?」
 * —— 那個數字是兩邊的合計，送去任一頁都只會顯示一半，看起來像資料掉了。
 * 結論是**同時有兩套時就不要跳頁**（使用者：「點下去就不動就好」）。
 *
 * 這支要用真的瀏覽器跑：能不能點是 CSS 疊加順序決定的，程式碼看起來對不代表畫面對
 * （第一版就是把 .hier-node--static 寫在 .hier-node 前面，被蓋掉了）。
 */
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS env 才能跑");

/** 兩個虛擬化平台都在用時，儀表板的「虛擬化」節點不該可點（合計數字送去任一頁都只有一半）。 */
test("虛擬化節點：兩個平台都在時不可點", async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill("admin");
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));

  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
  const node = page.locator(".hier-node", { hasText: "虛擬化" }).first();
  await expect(node).toBeVisible();
  const singleCursor = await node.evaluate((el) => getComputedStyle(el).cursor);

  await page.route("**/api/v1/system/integration-presence", (r) =>
    r.fulfill({ json: { proxmox: true, esxi: true, opnsense: false, pfsense: false,
                        fortigate: false, paloalto: false, dns: false, cert_agents: false } }));
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
  const node2 = page.locator(".hier-node", { hasText: "虛擬化" }).first();
  const bothCursor = await node2.evaluate((el) => getComputedStyle(el).cursor);
  await node2.click();
  await page.waitForTimeout(800);
  expect(new URL(page.url()).pathname, "兩個虛擬化都在時不該跳頁").toBe("/");
  expect(bothCursor, `單一平台=${singleCursor}、兩個平台=${bothCursor}`).toBe("default");
});
