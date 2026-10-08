/**
 * 依 LibreNMS ARP 表自動建立 IP（#48）：整合設定裡的選項，預設關；打開才顯示代價與兩個把關選項。
 * 另外驗「未授權 IP」超過清單上限時，頁籤要講出總共有幾筆（以前靜靜切到 200 筆）。
 * 都用 page.route 模擬後端，不需要真的 LibreNMS。
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

const INSTANCE = {
  id: "00000000-0000-4000-8000-000000000048", name: "lnms-e2e", api_url: "https://librenms.example",
  enabled: true, verify_tls: true, sync_devices: true, sync_arp: true, sync_fdb: true, sync_vlans: true,
  sync_links: true, use_for_status: true, auto_add_devices: true, auto_create_ips: true,
  auto_create_from_arp: false, arp_create_require_fdb: true, arp_create_skip_dhcp: true,
  sync_interval_seconds: 300, scope_subnet_ids: null, last_sync_at: null, last_error: null,
  created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z",
};

test("依 ARP 表自動建立：預設關；打開才出現警語與把關選項；存檔送出三個欄位", async ({ page }) => {
  let patched: Record<string, unknown> | null = null;
  await page.route("**/api/v1/librenms/instances**", async (route) => {
    const req = route.request();
    if (req.method() === "PATCH") {
      patched = req.postDataJSON();
      return route.fulfill({ json: { ...INSTANCE, ...patched } });
    }
    return route.fulfill({ json: { items: [INSTANCE], total: 1, page: 1, page_size: 50 } });
  });
  await login(page);
  await page.goto("/librenms");
  const row = page.locator("tr", { hasText: "lnms-e2e" });
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.locator("button").first().click();          // 第一顆是編輯（第二顆是測試連線）

  const block = page.getByTestId("lnms-arp-create");
  await expect(block).toBeVisible();
  await expect(block).toContainText("依 ARP 表自動建立 IP");
  await expect(block).not.toContainText("未授權 IP");          // 關著時不顯示警語
  await expect(page.getByTestId("lnms-arp-require-fdb")).toHaveCount(0);

  await page.getByTestId("lnms-arp-create-switch").click();
  await expect(block).toContainText("不再出現在「未授權 IP」");
  const fdb = page.getByTestId("lnms-arp-require-fdb");
  await expect(fdb).toBeVisible();
  await expect(block).toContainText("ARP 快取幾小時到幾天才清");
  if (process.env.SHOT_DIR) await page.locator(".n-modal").screenshot({ path: `${process.env.SHOT_DIR}/lnms-arp.png` });
  await fdb.click();                                          // 取消 → 改顯示「只看 ARP」的警語
  await expect(block).toContainText("只看 ARP");
  await fdb.click();

  await page.locator(".n-modal").getByRole("button", { name: /儲存|Save/ }).click();
  await expect.poll(() => patched).not.toBeNull();
  expect(patched).toMatchObject({
    auto_create_from_arp: true, arp_create_require_fdb: true, arp_create_skip_dhcp: true,
  });
});

test("未授權 IP 超過清單上限：頁籤寫出只列了幾筆、總共幾筆", async ({ page }) => {
  const empty = ["ip_conflicts", "mac_drifts", "mac_drift_reference", "ghost_ips", "arp_only_liveness",
    "stale_device_links", "mac_flapping", "identity_changes", "rogue_dhcp", "external_exposure", "dangling_dns",
    "duplicate_ip_records", "suspicious_changes", "fw_rule_rot"];
  const report: Record<string, unknown> = Object.fromEntries(empty.map((k) => [k, []]));
  report.unauthorized_ips = [{ ip: "198.51.100.7", macs: [], last_seen_at: "2026-10-01T00:00:00Z" }];
  report.unauthorized_total = 4321;
  report.total = 1;
  await page.route("**/api/v1/anomalies/last", (route) =>
    route.fulfill({ json: { report, at: "2026-10-01T00:00:00Z", trigger: "manual" } }));
  await login(page);
  await page.goto("/anomaly?tab=unauthorized_ips");
  const note = page.getByTestId("unauth-truncated");
  await expect(note).toBeVisible({ timeout: 15_000 });
  await expect(note).toContainText("1");
  await expect(note).toContainText("4321");
});
