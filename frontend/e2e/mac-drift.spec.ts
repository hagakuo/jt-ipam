/**
 * MAC 漂移（2026-09-30 重新設計）：只看「同一台交換器上換了埠」，從哪個埠換到哪個埠、什麼時候。
 * 實體設備換埠是正式異常；虛擬機遷移、隨機 MAC 漫遊、共用埠之間的移動收在下方「參考」，不通知。
 */
import { test, expect, type Page } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
test.skip(!ADMIN_PASS, "需要 E2E_ADMIN_PASS");

const EMPTY = {
  ip_conflicts: [], mac_drifts: [], rogue_dhcp: [], external_exposure: [], dangling_dns: [],
  duplicate_ip_records: [], suspicious_changes: [], fw_rule_rot: [], ghost_ips: [], unauthorized_ips: [],
  arp_only_liveness: [], stale_device_links: [], mac_flapping: [], mac_drift_reference: [], total: 1,
};
const move = (mac: string, category: string, from: string, to: string) => ({
  mac, category, device_id: "00000000-0000-4000-8000-0000000000d1", device_name: "sw-floor3",
  from_port: from, to_port: to, port: to, moved_at: "2026-09-30T02:15:00+00:00",
  ips: [{ ip: "198.51.100.20", hostname: "printer-3f" }], ip_id: "00000000-0000-4000-8000-0000000000a1",
  locations: [
    { device_id: "d1", device_name: "sw-floor3", port: to, last_seen_at: "2026-09-30T02:15:00+00:00" },
    { device_id: "d1", device_name: "sw-floor3", port: from, last_seen_at: "2026-09-28T08:00:00+00:00" },
  ],
});

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
}

test("換埠：顯示交換器、原本／換到的埠、時間；參考項目收合、有分類", async ({ page }) => {
  const report = {
    ...EMPTY,
    mac_drifts: [move("00:00:5e:00:53:20", "device_move", "ge-0/0/18", "ge-0/0/21")],
    mac_drift_reference: [
      move("bc:24:11:00:53:41", "vm_migration", "ge-0/0/10", "ge-0/0/12"),
      move("06:00:5e:00:53:42", "random_mac", "ge-0/0/7", "ge-0/0/24"),
    ],
  };
  await login(page);
  await page.route("**/api/v1/anomalies/scan", (route) => route.fulfill({ json: report }));
  await page.goto("/anomaly");
  await page.getByRole("button", { name: /執行偵測/ }).click();
  await page.locator(".n-tabs-tab", { hasText: /^MAC 變動/ }).click();
  const pane = page.locator(".n-tab-pane").filter({ has: page.getByText("00:00:5e:00:53:20") });
  await expect(pane).toContainText("sw-floor3");
  await expect(pane).toContainText("ge-0/0/18");
  await expect(pane).toContainText("ge-0/0/21");
  await expect(pane).toContainText("同一台交換器");                 // 新的說明
  const ref = page.getByTestId("drift-reference");
  await expect(ref).toContainText("2");
  await expect(ref).not.toContainText("bc:24:11:00:53:41");         // 預設收合
  await ref.getByText(/參考/).click();
  await expect(ref).toContainText("虛擬機遷移");
  await expect(ref).toContainText("隨機 MAC 漫遊");
  await expect(ref).toContainText("bc:24:11:00:53:41");
});
