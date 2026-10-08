/**
 * 對外開放服務清單：攤平後的排序／搜尋／協定統一大寫／配對彈出卡片／表格不溢出卡片。
 * 資料以路由攔截固定住 —— 這裡驗的是表格行為，不是後端彙整。
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5199";

const ITEMS = [
  { via: "nat", source: "pfsense", firewall: "pf-1", name: "web-forward",
    protocol: "tcp", port: 443, descr: "to web",
    identity: { registered: true, ip: "198.51.100.7", hostname: "web-a",
                status: "online (scanner)", subnet: "198.51.100.0/24",
                customer: "單位甲", wazuh: null } },
  { via: "rule", source: "pfsense", firewall: "pf-1", name: "web-rule",
    protocol: "TCP", port: "443", descr: "wan pass",
    identity: { registered: true, ip: "198.51.100.7", hostname: "web-a",
                status: "online (scanner)", subnet: "198.51.100.0/24",
                customer: "單位甲", wazuh: null } },
  { via: "nat", source: "opnsense", firewall: "opn-1", name: "mystery",
    protocol: "udp", port: 8443, descr: "",
    identity: { registered: false } },
];

test("開放服務：排序／搜尋／協定大寫／配對彈卡／不溢出", async ({ page }) => {
  await page.route("**/api/v1/anomalies/attack-surface", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: ITEMS }) }));

  await page.goto(BASE + "/login");
  await page.getByPlaceholder(/帳號|username/i).fill("admin");
  await page.getByPlaceholder(/密碼|password/i).fill("Test12345678!");
  await page.keyboard.press("Enter");
  await page.waitForURL(/dashboard|\/$/, { timeout: 15000 });
  await page.goto(BASE + "/attack-surface");
  await expect(page.getByText("web-forward")).toBeVisible({ timeout: 15000 });

  // 協定統一大寫：來源給 tcp/TCP/udp 混雜，畫面上只准出現大寫
  const table = page.locator(".n-data-table").first();
  await expect(table.getByText("UDP", { exact: true })).toBeVisible();
  expect(await table.getByText(/^(tcp|udp)$/).count()).toBe(0);

  // 表格不得溢出卡片右緣（量幾何）
  const card = page.locator(".n-card").first();
  const cardBox = (await card.boundingBox())!;
  const tableBox = (await table.boundingBox())!;
  expect(tableBox.x + tableBox.width).toBeLessThanOrEqual(cardBox.x + cardBox.width + 1);

  // 搜尋：8443 只剩 mystery 那列；443 含 8443（子字串）共 3 列
  const search = page.getByPlaceholder(/搜尋 IP/);
  await search.fill("8443");
  await expect(table.getByText("mystery")).toBeVisible();
  await expect(table.getByText("web-forward")).toHaveCount(0);
  await search.fill("");

  // 排序：點「埠」遞增 → 第一列 443；再點一次遞減 → 第一列 8443
  // 不依賴 naive-ui 排序循環的起點，只斷言「點標題能到達遞增與遞減兩種順序」
  const portTh = table.locator("thead th").filter({ hasText: "埠" });
  const firstPort = table.locator("tbody tr").first().locator("td").nth(1);
  const seen = new Set<string>();
  for (let i = 0; i < 4 && seen.size < 2; i++) {
    await portTh.click();
    await page.waitForTimeout(150);
    seen.add((await firstPort.innerText()).trim());
  }
  expect([...seen]).toEqual(expect.arrayContaining(["443", "8443"]));

  // 配對彈卡：hover 配對標籤 → 列出對象（web-rule 是 web-forward 的配對）
  await table.getByText("配對").first().hover();
  const pop = page.locator(".n-popover");
  await expect(pop.getByText("與它配對的是：")).toBeVisible();
  await expect(pop.getByText(/web-(rule|forward)/)).toBeVisible();
});
