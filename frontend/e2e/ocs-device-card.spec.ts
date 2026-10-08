/**
 * 裝置明細的 OCS 卡片顯示 OCS 自己回報的硬體（2026-09-27 使用者回報）。
 *   以前製造商／型號讀裝置欄位，Windows 筆電顯示成 LibreNMS 填的「windows／Intel x64」；
 *   Supermicro 主機的序號是出廠佔位、主機板型號沒顯示；也要列出主要零件。
 * 覆寫 integrations 回應餵兩種真實形狀的摘要，桌面與手機寬度都看。
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

const SERVER_HW = {
  system: { vendor: "Supermicro", model: "Super Server", serial: null, chassis: "Desktop" },
  board: { vendor: "Supermicro", model: "X13SAZ-F", serial: "BOARD-SN-0002" },
  bios: { vendor: "American Megatrends International, LLC.", version: "2.2", date: "06/12/2023" },
  cpus: [{ model: "12th Gen Intel(R) Core(TM) i5-12400", cores: 6, threads: 12, mhz: null, count: 1 }],
  memory: { total_mb: 128564, modules: [{ size_mb: null, type: "DDR5", speed: 5600, count: 4 }] },
  disks: [{ model: "SSSTC ER3-CD1920A", size_mb: 1920383 }, { model: "SSSTC ER3-CD1920A", size_mb: 1920383 },
          { model: "SSSTC ER3-CD240", size_mb: 240057 }],
  gpus: [{ name: "Intel UHD Graphics 730", memory_mb: null },
         { name: "NVIDIA GeForce RTX 4060 Ti", memory_mb: 16380 }],
};

async function openWithOcs(page: Page, ocs: Record<string, unknown>) {
  const id = await page.evaluate(async () => {
    const auth = { Authorization: `Bearer ${localStorage.getItem("access_token")}` };
    const r = await (await fetch("/api/v1/devices?page=1&page_size=1", { headers: auth })).json();
    const items = Array.isArray(r) ? r : (r.items ?? []);
    return items[0]?.id as string | undefined;
  });
  test.skip(!id, "這個環境沒有任何裝置");
  await page.route(`**/api/v1/devices/${id}/integrations`, async (route) => {
    await route.fulfill({ json: { wazuh: null, vm: null, ocs } });
  });
  await page.goto(`/devices/${id}`);
  const card = page.locator("#card-ocs");
  await expect(card).toBeVisible();
  return card;
}

for (const width of [1440, 390]) {
  test(`OCS 卡片：主機板、出廠佔位序號、主要零件（寬 ${width}）`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await login(page);
    const card = await openWithOcs(page, {
      os: "Ubuntu 24.04 LTS", last_inventory: "2026-09-27T07:46:19+00:00",
      vendor: "Supermicro", model: "Super Server",
      serial: "BOARD-SN-0002", serial_from_board: true,
      tag: null, agent: "OCS-NG_unified_unix_agent_v2.10.5", notes: [], url: null,
      hw: SERVER_HW,
    });
    await expect(card).toContainText("Supermicro X13SAZ-F");
    await expect(card).toContainText("BOARD-SN-0002（主機板）");
    await expect(card).toContainText("12th Gen Intel(R) Core(TM) i5-12400 · 6 核 12 緒");
    // 每條容量讀不到（新版 dmidecode 印 GiB，OCS Linux 代理讀不懂）：只講可用量，不冒充實裝容量
    const mem = card.locator(".n-descriptions-table-row", { hasText: "記憶體" });
    await expect(mem).toContainText("可用 125.6 GB");
    await expect(mem).toContainText("4 × DDR5-5600（每條容量未回報）");
    // 同型號同容量的磁碟合併成一行（跟處理器、記憶體一樣）
    const disks = card.locator(".n-descriptions-table-row", { hasText: "磁碟" });
    await expect(disks).toContainText("2 × SSSTC ER3-CD1920A");
    await expect(disks).toContainText("1.92 TB");
    await expect(disks.getByText("SSSTC ER3-CD1920A")).toHaveCount(1);
    await expect(card).toContainText("NVIDIA GeForce RTX 4060 Ti");
    await expect(card).toContainText("16 GB");
    // 手機寬度：卡片不能把頁面撐出水平捲動
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
}

test("OCS 卡片顯示 OCS 的製造商／型號，不是裝置欄位的值", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await login(page);
  const card = await openWithOcs(page, {
    os: "Microsoft Windows 10 專業版 10.0.19045", last_inventory: "2026-09-26T07:27:04+00:00",
    vendor: "Dell Inc.", model: "Latitude E5270", serial: "SN-LAPTOP-07", serial_from_board: false,
    tag: null, agent: "OCS-NG_WINDOWS_AGENT_v2.11.0.1", notes: [], url: null,
    hw: {
      system: { vendor: "Dell Inc.", model: "Latitude E5270", serial: "SN-LAPTOP-07", chassis: "LapTop" },
      board: { vendor: "Dell Inc.", model: null, serial: "SN-LAPTOP-07/BOARD-0001" },
      bios: { vendor: "Dell Inc.", version: "1.19.3", date: "20/08/2018" },
      cpus: [{ model: "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz", cores: 2, threads: 4, mhz: 2501, count: 1 }],
      memory: { total_mb: 16384, modules: [{ size_mb: 16384, type: null, speed: 2133, count: 1 }] },
      disks: [{ model: "SAMSUNG SSD PM871b M.2 2280 256GB", size_mb: 244191 }],
      gpus: [{ name: "Intel(R) HD Graphics 520", memory_mb: 1024 }],
    },
  });
  await expect(card).toContainText("Dell Inc.");
  await expect(card).toContainText("Latitude E5270");
  await expect(card).toContainText("LapTop");
  await expect(card).toContainText("Dell Inc. 1.19.3 (20/08/2018)");
  await expect(card).toContainText("2 核 4 緒 · 2501 MHz");
  // 每條容量都知道：顯示實裝容量；可用量跟實裝一樣時不重複講
  const mem = card.locator(".n-descriptions-table-row", { hasText: "記憶體" });
  await expect(mem).toContainText("16 GB");
  await expect(mem).toContainText("1 × 16 GB · 2133 MT/s");
  await expect(mem).not.toContainText("可用");
  await expect(card).toContainText("244 GB");
  await expect(card).not.toContainText("Intel x64");
  await expect(card).not.toContainText("（主機板）");
});

test("還沒同步到硬體摘要時，講清楚下一次同步後才有", async ({ page }) => {
  await login(page);
  const card = await openWithOcs(page, {
    os: "Windows 11 Pro", last_inventory: null, vendor: null, model: null, serial: null,
    serial_from_board: false, tag: null, agent: null, notes: [], url: null, hw: null,
  });
  await expect(card).toContainText("硬體明細會在下一次 OCS 同步後出現");
});
