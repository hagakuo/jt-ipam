import { test, expect, type Page } from "@playwright/test";
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * 相容 RustDesk 的網頁檔案傳輸（附錄 J）：對著測試靶（scripts/rustdesk-test-target）實際列目錄、下載、上傳。
 *
 * 需要（缺一就跳過）：
 *   E2E_ADMIN_PASS        管理員密碼
 *   E2E_RD_IP_ID          seed_jtipam.py 接好的那筆 IP 記錄 id（seed 也會打開「允許網頁檔案傳輸」）
 *   E2E_RD_PASSWORD       受控端的永久密碼（測試靶是 Rd-Test-2026）
 *   E2E_RD_PEER_CONTAINER 受控端容器名稱（rdtest-client），用來在受控端放測試檔、核對上傳結果
 * ⚠️ 前端要同源（vite preview 的 proxy），同 rustdesk-web.spec.ts。
 */
const PASS = process.env.E2E_ADMIN_PASS || "";
const IPID = process.env.E2E_RD_IP_ID || "";
const RDPW = process.env.E2E_RD_PASSWORD || "";
const PEER = process.env.E2E_RD_PEER_CONTAINER || "";
test.skip(!PASS || !IPID || !RDPW || !PEER, "需要 E2E_ADMIN_PASS、E2E_RD_IP_ID、E2E_RD_PASSWORD 與 E2E_RD_PEER_CONTAINER");

const sh = (cmd: string) => execSync(`docker exec ${PEER} sh -c ${JSON.stringify(cmd)}`).toString();
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

async function login(page: Page) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(process.env.E2E_ADMIN_USER || "admin");
  await page.getByPlaceholder(/密碼|Password/).fill(PASS);
  await page.getByRole("button", { name: "登入", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.includes("/login"));
}

test("檔案傳輸：列出家目錄、下載內容一致（含多塊的大檔）、上傳到受控端、同名時先問", async ({ page }) => {
  test.setTimeout(180_000);
  // 受控端放兩個已知內容的檔案；清掉上一輪上傳的
  sh("printf 'jt-ipam e2e download\\n' > /root/e2e-dl.txt; head -c 3000000 /dev/urandom > /root/e2e-big.bin; rm -f /root/e2e-up.txt");
  const peerSha = Object.fromEntries(sh("sha256sum /root/e2e-dl.txt /root/e2e-big.bin").trim().split("\n")
    .map((l) => { const [h, f] = l.split(/\s+/); return [f.split("/").pop()!, h]; }));
  const dir = mkdtempSync(join(tmpdir(), "rdfile-"));
  const upPath = join(dir, "e2e-up.txt");
  writeFileSync(upPath, "uploaded by jt-ipam e2e\n");

  await page.setViewportSize({ width: 1400, height: 950 });
  await login(page);
  await page.goto(`/rustdesk/${IPID}/files`);
  // 連線表單上說明稽核是瀏覽器自報的（J.6）
  await expect(page.getByTestId("rdfile-audit-note")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("rdfile-password").locator("input").fill(RDPW);
  await page.getByTestId("rdfile-connect").click();
  await expect(page.getByText("e2e-dl.txt")).toBeVisible({ timeout: 40_000 });

  for (const name of ["e2e-dl.txt", "e2e-big.bin"]) {
    const row = page.locator("tr", { hasText: name }).first();
    const [dl] = await Promise.all([page.waitForEvent("download", { timeout: 60_000 }), row.getByTestId("rdfile-download").click()]);
    expect(dl.suggestedFilename()).toBe(name);
    expect(sha(readFileSync((await dl.path())!)), `${name} 下載後內容要一致`).toBe(peerSha[name]);
  }

  await page.locator('input[type="file"]').setInputFiles(upPath);
  await expect.poll(() => sh("cat /root/e2e-up.txt 2>/dev/null || true"), { timeout: 30_000 }).toBe("uploaded by jt-ipam e2e\n");

  // 同名再傳一次：先問「覆蓋／略過」，選略過
  await page.locator('input[type="file"]').setInputFiles(upPath);
  await expect(page.getByTestId("rdfile-conflict")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("rdfile-conflict")).toContainText("e2e-up.txt");
  await page.getByTestId("rdfile-conflict-skip").click();

  await page.getByTestId("rdfile-disconnect").click();
  sh("rm -f /root/e2e-dl.txt /root/e2e-big.bin /root/e2e-up.txt");
});
