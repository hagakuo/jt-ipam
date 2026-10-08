import { test, expect } from "@playwright/test";

/**
 * VNC 主控台：對著測試靶（`e2e/fixtures/vnc-target.py`）連一次，確認畫面真的畫出來。
 *
 * 為什麼要有這支：2026-09-02 使用者給了一台開著 VNC 的位址要我們連連看，連不上時
 * 我們**分不出是自己的問題還是對方的問題** —— 因為沒有任何測試完成過一次 VNC 交握。
 * 有了固定的靶，客戶端這一半就有確定的答案（那次也順便抓到「不設密碼連不上」）。
 *
 * 需要三樣東西，缺一就跳過：
 *   E2E_ADMIN_PASS   管理員密碼
 *   E2E_VNC_IP_ID    一筆已開啟 VNC 的 IP 記錄 id（指向測試靶所在的位址）
 *   E2E_VNC_PORT     測試靶的連接埠（預設 5999）
 *
 * 靶：`python3 e2e/fixtures/vnc-target.py --port 5999 --host 127.0.0.1`
 * ⚠️ 本機驗證時前端要**用同源方式跑**（`vite preview` 的 proxy 指到後端），
 *    因為 WebSocket 網址是用 window.location 組的；把 API 指到別的埠只有 REST 會通。
 */
const PASS = process.env.E2E_ADMIN_PASS || "";
const IPID = process.env.E2E_VNC_IP_ID || "";
const PORT = process.env.E2E_VNC_PORT || "5999";

test.skip(!PASS || !IPID, "需要 E2E_ADMIN_PASS 與 E2E_VNC_IP_ID（見檔頭）");

test("VNC 主控台：連上測試靶並畫出畫面", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(process.env.E2E_ADMIN_USER || "admin");
  await page.getByPlaceholder(/密碼|Password/).fill(PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));

  await page.goto(`/vnc/${IPID}`);
  await page.getByPlaceholder("VNC 密碼").fill("any-password");
  await page.locator(".n-input-number input").first().fill(PORT);
  await page.getByRole("button", { name: /VNC 連線/ }).click();

  const canvas = page.locator("canvas").first();
  await expect(canvas).toBeVisible({ timeout: 30_000 });
  await page.waitForTimeout(2500);

  // 「有 canvas」不等於「畫出來了」—— 量實際像素，不然連線失敗也會通過
  const painted = await canvas.evaluate((c: HTMLCanvasElement) => {
    const ctx = c.getContext("2d")!;
    const d = ctx.getImageData(0, 0, Math.min(c.width, 200), Math.min(c.height, 200)).data;
    let painted = 0;
    for (let i = 0; i < d.length; i += 4) {
      if (d[i] !== 0 || d[i + 1] !== 0 || d[i + 2] !== 0) painted++;
    }
    return { w: c.width, h: c.height, painted };
  });
  await page.screenshot({ path: "test-results/vnc-console.png" });
  expect(painted.w, "canvas 尺寸應該來自伺服器的 ServerInit").toBeGreaterThan(100);
  expect(painted.painted, "canvas 全黑＝沒收到畫面資料").toBeGreaterThan(1000);
});
