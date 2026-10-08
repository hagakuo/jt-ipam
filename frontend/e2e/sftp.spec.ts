/**
 * SFTP：用真實瀏覽器連上一台真的 SFTP 伺服器，實際列目錄、下載、上傳。
 *
 * 「檔案有沒有真的傳過去」只有端到端才問得出來 —— 介面顯示「已上傳」而檔案是空的、
 * 或下載下來少了幾個 chunk，兩者在畫面上看起來都一樣正常。
 */
import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "";
const TARGET_IP_ID = process.env.E2E_SFTP_IP_ID || "";
// 這台 SFTP 目標由 e2e/fixtures/sftp-target.py 起（見該檔開頭的用法）
const SFTP_ROOT = process.env.E2E_SFTP_ROOT || "";
const SFTP_USER = process.env.E2E_SFTP_USER || "tester";
const SFTP_PASS = process.env.E2E_SFTP_PASS || "TestPass!2026";
const SFTP_PORT = process.env.E2E_SFTP_PORT || "2222";

test.skip(!ADMIN_PASS || !TARGET_IP_ID || !SFTP_ROOT,
  "需要 E2E_ADMIN_PASS、E2E_SFTP_IP_ID 與 E2E_SFTP_ROOT");
test.setTimeout(180_000);

// 測試自己產生的東西要自己收乾淨。累積下來的檔案會把清單撐到一頁裝不下，
// 於是「剛上傳的那一列看得見嗎」這種斷言會為了完全無關的理由失敗 ——
// 今天為此誤判了三次，每次都以為是產品壞了。
test.afterAll(() => {
  if (!SFTP_ROOT) return;
  for (const name of readdirSync(SFTP_ROOT)) {
    if (!/^(drop-[ab]|dropdir|mixed|uploaded|deldir|repro|hol|slow|big)-/.test(name)) continue;
    rmSync(join(SFTP_ROOT, name), { recursive: true, force: true });
  }
});

async function login(page: any) {
  await page.goto("/login");
  await page.getByPlaceholder(/帳號|Username/).fill(ADMIN_USER);
  await page.getByPlaceholder(/密碼|Password/).fill(ADMIN_PASS);
  await page.getByRole("button", { name: /登入/ }).click();
  await page.waitForURL((u: URL) => !u.pathname.includes("/login"));
}

async function connect(page: any) {
  await login(page);
  await page.goto(`/sftp/${TARGET_IP_ID}`);
  // 連線表單的版面與 SSH 終端機一致：卡片標題「SFTP 連線到 <ip>」
  await expect(page.getByText(/SFTP 連線到/)).toBeVisible();
  // 有已存帳密時會自動選取（與 SSH 一致），此時手動欄位不會出現 —— 兩種情況都要能連
  const manual = page.getByPlaceholder("root");
  if (await manual.isVisible().catch(() => false)) {
    await manual.fill(SFTP_USER);
    // 密碼欄（第一個 password 型別的輸入框）
    await page.locator('input[type="password"]').first().fill(SFTP_PASS);
  }
  await page.locator(".n-input-number input").first().fill(SFTP_PORT);
  await page.keyboard.press("Tab");
  await page.getByRole("button", { name: "連線" }).click();
  // 連上後會自動列出根目錄
  await expect(page.getByText("nginx.conf").or(page.getByText("etc"))).toBeVisible({ timeout: 20_000 });
}


/** 填「新增資料夾 / 重新命名」的對話框（v0.5.166 起不再用 window.prompt）。 */
async function fillNameDialog(page: any, name: string) {
  const dlg = page.locator(".n-modal");
  await expect(dlg).toBeVisible();
  await dlg.locator("input").first().fill(name);
  await dlg.getByRole("button", { name: "確定" }).first().click();
  await expect(dlg).toBeHidden({ timeout: 20_000 });
}

test("連線後可以列出遠端目錄", async ({ page }) => {
  await connect(page);
  const body = await page.locator("body").innerText();
  expect(body, "看不到遠端的檔案").toContain("app.log");
  expect(body, "看不到目錄").toContain("etc");
  // 含中文的檔名不可以變成亂碼
  expect(body, "中文檔名壞掉").toContain("readme-中文.txt");
  await page.screenshot({ path: "test-results/sftp-list.png" });
});

test("目錄與檔案的名稱要對齊（檔案左邊留同寬的空位）", async ({ page }) => {
  await connect(page);
  // 用量的，不用看的：曾經因為 emoji 寬度、以及 scoped CSS 套不到 render function
  // 產生的元素，兩次都差了 16～17px，而截圖乍看之下很像對齊了
  const rows = await page.locator(".sftp-name").all();
  const xs: number[] = [];
  for (const r of rows.slice(0, 6)) {
    const box = await r.locator("span").last().boundingBox();
    if (box) xs.push(Math.round(box.x));
  }
  expect(xs.length, "抓不到名稱欄").toBeGreaterThan(1);
  expect(new Set(xs).size, `名稱起始位置不一致：${xs}`).toBe(1);
});

test("檔案操作區的版面：外框、狀態列在框外、控制項同高、按鈕都有 icon", async ({ page }) => {
  await connect(page);
  // 外框把「遠端主機的內容」框起來；狀態列講的是連線，刻意留在框外
  const panel = await page.locator(".sftp-panel").boundingBox();
  const status = await page.locator(".sftp-toolbar").boundingBox();
  expect(panel && status, "抓不到面板或狀態列").toBeTruthy();
  expect(status!.y + status!.height, "狀態列被包進框裡了").toBeLessThanOrEqual(panel!.y + 1);
  const border = await page.locator(".sftp-panel")
    .evaluate((e) => getComputedStyle(e).borderTopWidth);
  expect(parseFloat(border), "面板沒有外框").toBeGreaterThan(0);

  // 路徑欄與篩選欄同高（篩選欄曾經是 small，矮一截）
  const pathH = (await page.locator(".sftp-pathbar .n-input").first().boundingBox())!.height;
  const filtH = (await page.locator(".sftp-pathbar .n-input").last().boundingBox())!.height;
  expect(Math.abs(pathH - filtH), `路徑欄 ${pathH} vs 篩選欄 ${filtH}`).toBeLessThanOrEqual(1);

  // 這排按鈕每一顆都要有 icon
  for (const name of [/上一層/, /重新整理/, /新增資料夾/, /上傳檔案/]) {
    expect(await page.getByRole("button", { name }).first().locator("svg").count(),
      `按鈕 ${name} 少了 icon`).toBeGreaterThan(0);
  }
});

test("篩選只縮小目前目錄的清單，並說出篩掉了多少", async ({ page }) => {
  await connect(page);
  const total = await page.locator("tbody tr").count();
  await page.getByPlaceholder(/篩選這個目錄/).fill("app.log");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  // 只顯示一部分卻不說，會讓人以為目錄裡就只有這些
  await expect(page.locator(".sftp-filter-note")).toContainText(String(total));
  await page.getByPlaceholder(/篩選這個目錄/).fill("");
  await expect(page.locator("tbody tr")).toHaveCount(total);
});

test("批次移動與批次刪除都真的作用在遠端", async ({ page }) => {
  // 準備三個檔案 + 一個空的目的地資料夾，全部直接寫在遠端根目錄上。
  // 目的地要先清空：留著上一輪搬過去的同名檔，這次的搬移會因為「已存在」而失敗，
  // 而後面的 existsSync 又剛好是 true —— 測試會綠得毫無意義。
  rmSync(`${SFTP_ROOT}/batch-dest`, { recursive: true, force: true });
  mkdirSync(`${SFTP_ROOT}/batch-dest`, { recursive: true });
  for (const n of ["b1.txt", "b2.txt", "b3.txt"]) {
    writeFileSync(`${SFTP_ROOT}/${n}`, `x-${n}\n`, "utf-8");
  }
  await connect(page);

  // 勾兩個 → 批次移動
  for (const n of ["b1.txt", "b2.txt"]) {
    await page.locator("tr", { hasText: n }).locator(".n-checkbox").first().click();
  }
  await expect(page.getByText(/已選 2 項/)).toBeVisible();
  await page.getByRole("button", { name: "移動" }).click();
  // 對話框：可直接打路徑（也可以點下方目錄樹）
  const moveDlg = page.locator(".n-modal");
  await expect(moveDlg).toBeVisible();
  await moveDlg.locator("input").first().fill("/batch-dest");
  await page.getByRole("button", { name: /移到這裡/ }).click();
  await expect(page.locator("table").getByText("b1.txt")).toBeHidden({ timeout: 20_000 });
  expect(existsSync(`${SFTP_ROOT}/batch-dest/b1.txt`), "b1 沒有真的搬過去").toBe(true);
  expect(existsSync(`${SFTP_ROOT}/batch-dest/b2.txt`), "b2 沒有真的搬過去").toBe(true);
  expect(existsSync(`${SFTP_ROOT}/b1.txt`), "原位置還留著").toBe(false);

  // 剩下的那個 → 批次刪除
  await page.locator("tr", { hasText: "b3.txt" }).locator(".n-checkbox").first().click();
  await page.getByRole("button", { name: "刪除", exact: true }).first().click();
  await page.getByRole("button", { name: /確[定認]|是/ }).last().click();
  await expect(page.locator("table").getByText("b3.txt")).toBeHidden({ timeout: 20_000 });
  expect(existsSync(`${SFTP_ROOT}/b3.txt`), "b3 沒有真的刪掉").toBe(false);
});

test("拖曳多個檔案進來會全部上傳到目前目錄", async ({ page }) => {
  await connect(page);
  // 檔名每次不同 —— 用固定檔名時，上一輪留下的同名檔會讓「表格出現這一列」在拖曳前
  // 就已經成立，測試於是搶在寫入完成前去讀檔，讀到空字串（這條實際踩過）
  const a = `drop-a-${Date.now()}.txt`;
  const bn = `drop-b-${Date.now()}.txt`;

  // 用真的 DataTransfer 觸發 dragenter/drop —— 檔案有沒有落地，回頭讀磁碟才算數
  const dt = await page.evaluateHandle(([na, nb]) => {
    const d = new DataTransfer();
    d.items.add(new File(["A\n"], na, { type: "text/plain" }));
    d.items.add(new File(["B\n"], nb, { type: "text/plain" }));
    return d;
  }, [a, bn]);
  await page.locator(".sftp-panel").dispatchEvent("dragenter", { dataTransfer: dt });
  // 拖曳中要看得出來會放到哪裡，否則使用者不知道自己放對地方沒有
  await expect(page.locator(".sftp-dropzone")).toBeVisible();
  await page.locator(".sftp-panel").dispatchEvent("drop", { dataTransfer: dt });

  await expect(page.locator("table").getByText(bn)).toBeVisible({ timeout: 30_000 });
  expect(readFileSync(`${SFTP_ROOT}/${a}`, "utf-8"), "第一個檔案沒落地或內容不對").toBe("A\n");
  expect(readFileSync(`${SFTP_ROOT}/${bn}`, "utf-8"), "第二個檔案沒落地或內容不對").toBe("B\n");
});

test("上傳中顯示速率與剩餘時間；停住時講「停住了」", async ({ page }) => {
  await connect(page);
  // 用 CDP 的網路節流讓 20 MB 傳個十幾秒，速率才看得到（本機直傳一下子就完了）
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Network.enable");
  await cdp.send("Network.emulateNetworkConditions",
    { offline: false, latency: 20, downloadThroughput: -1, uploadThroughput: 4 * 1024 * 1024 });
  const name = `big-rate-${Date.now()}.bin`;
  await page.locator('input[type="file"]').first().setInputFiles(
    { name, mimeType: "application/octet-stream", buffer: Buffer.alloc(20 * 1024 * 1024, 7) });
  const rate = page.getByTestId("sftp-upload-rate");
  await expect(rate).toHaveText(/(KB|MB)\/s · 剩約/, { timeout: 15_000 });
  await cdp.send("Network.emulateNetworkConditions",
    { offline: false, latency: 20, downloadThroughput: -1, uploadThroughput: 1 });
  await expect(rate).toHaveText(/停住了/, { timeout: 20_000 });
  await cdp.send("Network.emulateNetworkConditions",
    { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  await expect(page.locator("table").getByText(name)).toBeVisible({ timeout: 60_000 });
});

test("同名檔案：先問；兩份都留、覆蓋、略過都照選的做，原檔不會被清空", async ({ page }) => {
  await connect(page);
  const name = `uploaded-conflict-${Date.now()}.txt`;
  const dup = name.replace(/\.txt$/, " (1).txt");
  writeFileSync(`${SFTP_ROOT}/${name}`, "OLD\n", "utf-8");
  await page.getByRole("button", { name: "重新整理" }).click();
  const input = page.locator('input[type="file"]').first();
  const dlg = page.getByTestId("sftp-conflict");
  const upload = async (body: string) => input.setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(body) });

  // ① 兩份都留：新檔改名，原檔不動
  await upload("NEW1\n");
  await expect(dlg).toBeVisible({ timeout: 15_000 });
  await expect(dlg).toContainText(name);
  await page.getByTestId("sftp-conflict-rename").click();
  await expect(page.locator("table").getByText(dup)).toBeVisible({ timeout: 20_000 });
  expect(readFileSync(`${SFTP_ROOT}/${name}`, "utf-8")).toBe("OLD\n");
  expect(readFileSync(`${SFTP_ROOT}/${dup}`, "utf-8")).toBe("NEW1\n");

  // ② 略過：什麼都不動
  await upload("NEW2\n");
  await expect(dlg).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("sftp-conflict-skip").click();
  await expect(page.getByText(/略過 1 個同名檔案/)).toBeVisible({ timeout: 10_000 });
  expect(readFileSync(`${SFTP_ROOT}/${name}`, "utf-8")).toBe("OLD\n");

  // ③ 覆蓋：換成新內容，不留暫存檔
  await upload("NEW3\n");
  await expect(dlg).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("sftp-conflict-overwrite").click();
  await expect.poll(() => readFileSync(`${SFTP_ROOT}/${name}`, "utf-8"), { timeout: 20_000 }).toBe("NEW3\n");
  expect(readdirSync(SFTP_ROOT).filter((n) => n.includes(".jtipam-upload-"))).toEqual([]);
});

test("多個同名檔案：勾「其餘也這樣處理」只問一次", async ({ page }) => {
  await connect(page);
  const ts = Date.now();
  const names = [`uploaded-many-a-${ts}.txt`, `uploaded-many-b-${ts}.txt`];
  for (const n of names) writeFileSync(`${SFTP_ROOT}/${n}`, "OLD\n", "utf-8");
  await page.getByRole("button", { name: "重新整理" }).click();
  await page.locator('input[type="file"]').first().setInputFiles(
    names.map((n) => ({ name: n, mimeType: "text/plain", buffer: Buffer.from("NEW\n") })));
  const dlg = page.getByTestId("sftp-conflict");
  await expect(dlg).toBeVisible({ timeout: 15_000 });
  await dlg.getByText("其餘同名的檔案也這樣處理").click();
  await page.getByTestId("sftp-conflict-overwrite").click();
  for (const n of names) {
    await expect.poll(() => readFileSync(`${SFTP_ROOT}/${n}`, "utf-8"), { timeout: 20_000 }).toBe("NEW\n");
  }
  await expect(dlg).toBeHidden();
});

test("資料夾＋檔案一起拖：整個資料夾連同內容上傳，檔案也完整落地", async ({ page }) => {
  await connect(page);
  // 客戶實機情境：從桌面同時拖一個資料夾和一個檔案進來。
  // macOS 交出來的資料夾 `File.size` 是 256，只有 `webkitGetAsEntry()` 分得出來。
  const stamp = Date.now();
  const folder = `dropdir-${stamp}`;
  const name = `mixed-${stamp}.bin`;
  const size = 700_000;

  const dt = await page.evaluateHandle(([dirName, fname, n]) => {
    // 用原型換掉：`DataTransferItemList` 每次取用都給新的包裝物件，
    // 直接對取出來的項目指派會安靜消失。
    const dir = {
      isFile: false, isDirectory: true, name: dirName,
      createReader: () => {
        let done = false;
        return {
          readEntries: (ok: (e: unknown[]) => void) => {
            if (done) { ok([]); return; }
            done = true;
            ok([
              { isFile: true, isDirectory: false, name: "inside.txt",
                file: (cb: (f: File) => void) => cb(new File(["hello\n"], "inside.txt")) },
              { isFile: false, isDirectory: true, name: "nested",
                createReader: () => {
                  let d2 = false;
                  return { readEntries: (ok2: (e: unknown[]) => void) => {
                    if (d2) { ok2([]); return; }
                    d2 = true;
                    ok2([{ isFile: true, isDirectory: false, name: "deep.txt",
                           file: (cb: (f: File) => void) => cb(new File(["deep\n"], "deep.txt")) }]);
                  } };
                } },
            ]);
          },
        };
      },
    };
    const bytes = new Uint8Array(n as number);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = i % 251;
    const plain = new File([bytes], fname as string);
    const kinds: Record<string, unknown> = { [dirName as string]: dir };
    Object.defineProperty(DataTransferItem.prototype, "webkitGetAsEntry", {
      configurable: true,
      value(this: DataTransferItem) {
        const f = this.getAsFile();
        const named = f ? kinds[f.name] : null;
        return named ?? { isFile: true, isDirectory: false, name: f?.name,
                          file: (cb: (x: File) => void) => cb(f as File) };
      },
    });
    const d = new DataTransfer();
    d.items.add(new File([new Uint8Array(256)], dirName as string));
    d.items.add(plain);
    return d;
  }, [folder, name, size]);

  await page.locator(".sftp-panel").dispatchEvent("dragenter", { dataTransfer: dt });
  await page.locator(".sftp-panel").dispatchEvent("drop", { dataTransfer: dt });

  // 1) 資料夾連同巢狀內容都要出現在遠端
  await expect(page.locator("table").last().getByText(folder)).toBeVisible({ timeout: 60_000 });
  expect(readFileSync(`${SFTP_ROOT}/${folder}/inside.txt`, "utf-8")).toBe("hello\n");
  expect(readFileSync(`${SFTP_ROOT}/${folder}/nested/deep.txt`, "utf-8")).toBe("deep\n");
  // 2) 一起拖進來的檔案要完整落地 —— 位元組數與內容都要對，不能是 0 位元組
  const got = readFileSync(`${SFTP_ROOT}/${name}`);
  expect(got.length, "檔案落地了但大小不對（0 位元組＝上傳迴圈中途斷掉）").toBe(size);
  for (const off of [0, 1, 255, 256, 262_143, 262_144, size - 1]) {
    expect(got[off], `第 ${off} 個位元組不對`).toBe(off % 251);
  }
  // 3) 連線必須還活著
  await expect(page.getByText("連線已中斷")).toHaveCount(0);
  await page.getByRole("button", { name: /重新整理/ }).click();
  // 重新整理後還能列出東西就夠了 —— 落地的正確性上面已經逐位元組比對過。
  // 不要對「某一列在第幾個 <table> 裡」下斷言：Naive 的表格會依欄位固定與捲動
  // 拆成多個 table，列數一多就換位置，測試會為了無關的原因失敗。
  await expect(page.locator(".sftp-panel").getByText(folder).first()).toBeVisible({ timeout: 20_000 });
});

test("上傳檔案選取框可以複選", async ({ page }) => {
  await connect(page);
  // 只能單選的話，要傳十個檔案就得開十次對話框
  await expect(page.locator('input[type="file"]')).toHaveAttribute("multiple", /.*/);
});

test("可以進到子目錄再回上一層", async ({ page }) => {
  await connect(page);
  await page.getByText("etc", { exact: false }).first().click();
  await expect(page.getByText("nginx.conf")).toBeVisible({ timeout: 15_000 });
  await page.getByRole("button", { name: "上一層" }).click();
  await expect(page.getByText("app.log")).toBeVisible({ timeout: 15_000 });
});

test("打錯路徑的錯誤，在成功切換目錄後要消失", async ({ page }) => {
  // 使用者回報（2026-09-26）：打錯成 /rmnt 之後改回正確路徑、清單也列出來了，
  // 上方紅框卻還寫著「找不到 /rmnt」—— 指令失敗寫進紅框，之後成功沒人清掉
  await connect(page);
  const path = page.locator(".sftp-pathbar input").first();
  const good = await path.inputValue();
  await path.fill("/no-such-dir-e2e");
  await path.press("Enter");
  const banner = page.locator(".n-alert", { hasText: "no-such-dir-e2e" });
  await expect(banner).toBeVisible({ timeout: 10_000 });
  await path.fill(good);
  await path.press("Enter");
  await expect(page.getByText("readme-中文.txt")).toBeVisible();
  await expect(banner).toBeHidden();
});

test("下載的檔案內容與遠端一致", async ({ page }) => {
  await connect(page);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator("tr", { hasText: "readme-中文.txt" }).getByRole("button", { name: "下載" }).click(),
  ]);
  const p = await download.path();
  const got = readFileSync(p!, "utf-8");
  // 位元組要一模一樣 —— 少一個 chunk 或編碼轉錯，畫面上都看不出來
  expect(got).toBe("這是一份含中文檔名與內容的測試檔\n");
});

test("上傳的檔案真的出現在遠端，而且內容正確", async ({ page }) => {
  await connect(page);
  const tmp = join(tmpdir(), "jt-ipam-e2e-upload");
  if (!existsSync(tmp)) mkdirSync(tmp, { recursive: true });
  // 檔名每次不同 —— 用固定檔名的話，上一輪留下的同名檔會讓「表格出現這一列」一開始
  // 就成立，測試於是搶在寫入完成前去讀檔，讀到寫到一半的內容（這條實際上踩過）
  const name = `uploaded-中文-${Date.now()}.conf`;
  const src = `${tmp}/${name}`;
  const payload = "上傳測試\n".repeat(300);
  writeFileSync(src, payload, "utf-8");

  await page.setInputFiles('input[type="file"]', src);
  // 只認表格裡那一列 —— 右上角的提示訊息也含同一個檔名，不能拿它當作「真的傳上去了」
  await expect(page.locator("table").getByText(name)).toBeVisible({ timeout: 30_000 });

  // 直接讀遠端根目錄下的檔案 —— 介面說「已上傳」不算數，檔案在不在才算
  const landed = readFileSync(`${SFTP_ROOT}/${name}`, "utf-8");
  expect(landed).toBe(payload);
  await page.screenshot({ path: "test-results/sftp-upload.png" });
});

test("新增資料夾、改名、刪除都真的作用在遠端", async ({ page }) => {
  await connect(page);
  // 三個操作都會改變遠端主機的檔案系統 —— 每一步都回頭看磁碟，不看畫面提示。
  // 瀏覽器原生對話框不該再出現：出現就代表哪裡還在用 window.prompt。
  let nativeDialog = false;
  page.on("dialog", async (d: any) => { nativeDialog = true; await d.dismiss(); });

  await page.getByRole("button", { name: "新增資料夾" }).click();
  await fillNameDialog(page, "e2e-新資料夾");
  await expect(page.locator("table").getByText("e2e-新資料夾")).toBeVisible({ timeout: 15_000 });
  expect(existsSync(`${SFTP_ROOT}/e2e-新資料夾`), "遠端沒有真的建出資料夾").toBe(true);

  await page.locator("tr", { hasText: "e2e-新資料夾" })
    .getByRole("button", { name: "重新命名" }).click();
  await fillNameDialog(page, "e2e-改名後");
  await expect(page.locator("table").getByText("e2e-改名後")).toBeVisible({ timeout: 15_000 });
  expect(existsSync(`${SFTP_ROOT}/e2e-改名後`), "遠端沒有真的改名").toBe(true);
  expect(existsSync(`${SFTP_ROOT}/e2e-新資料夾`), "舊名字還留著").toBe(false);

  await page.locator("tr", { hasText: "e2e-改名後" })
    .getByRole("button", { name: "刪除" }).click();
  await page.getByRole("button", { name: /確[定認]|是/ }).last().click();
  await expect(page.locator("table").getByText("e2e-改名後")).toBeHidden({ timeout: 15_000 });
  expect(existsSync(`${SFTP_ROOT}/e2e-改名後`), "遠端沒有真的刪掉").toBe(false);
  expect(nativeDialog, "還有地方在用瀏覽器原生對話框").toBe(false);
});

test("SFTP 是獨立開關：關掉之後只有 SFTP 入口消失，SSH 還在", async ({ page }) => {
  // 開關存不存得住只有走完「改→存→重載」才知道；只看畫面切換到了不算數
  await login(page);
  const url = `/addresses/${TARGET_IP_ID}`;
  await page.goto(url);
  await expect(page.getByRole("button", { name: "SFTP 檔案" })).toBeVisible();

  await page.getByRole("button", { name: "編輯" }).first().click();
  await page.getByText("啟用 SFTP 檔案傳輸").scrollIntoViewIfNeeded();
  await page.locator(".n-form-item", { hasText: "啟用 SFTP 檔案傳輸" })
    .locator(".n-switch").click();
  await page.getByRole("button", { name: /儲存|保存/ }).first().click();

  await page.goto(url);                               // 重載：值真的存進資料庫了嗎
  await expect(page.getByRole("button", { name: "SFTP 檔案" })).toBeHidden({ timeout: 15_000 });
  await expect(page.getByRole("button", { name: "SSH 連線" })).toBeVisible();  // SSH 不受影響

  // 收尾：開回來，讓其他測試（與後續手動操作）看到的狀態不變
  await page.getByRole("button", { name: "編輯" }).first().click();
  await page.getByText("啟用 SFTP 檔案傳輸").scrollIntoViewIfNeeded();
  await page.locator(".n-form-item", { hasText: "啟用 SFTP 檔案傳輸" })
    .locator(".n-switch").click();
  await page.getByRole("button", { name: /儲存|保存/ }).first().click();
  await page.goto(url);
  await expect(page.getByRole("button", { name: "SFTP 檔案" })).toBeVisible({ timeout: 15_000 });
});

test("刪除有內容的資料夾：先問過，確認後連同內容一起刪", async ({ page }) => {
  // 這是使用者實際回報的畫面：按刪除只得到一句「失敗：Failure」。
  // 原因是 SFTP v3 沒有「目錄非空」這個狀態碼，伺服器只能回通用失敗，
  // 於是畫面上既沒說原因、也沒說下一步。
  const dir = `deldir-${Date.now()}`;
  mkdirSync(`${SFTP_ROOT}/${dir}/inner`, { recursive: true });
  writeFileSync(`${SFTP_ROOT}/${dir}/f1.txt`, "x");
  writeFileSync(`${SFTP_ROOT}/${dir}/inner/f2.txt`, "x");

  await login(page);
  await connect(page);

  const row = page.locator("tbody tr", { hasText: dir }).first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.getByRole("button", { name: "刪除" }).click();
  await page.getByRole("button", { name: /^確定$|^確認$/ }).first().click();

  // 要出現「不是空的」的說明，而且講得出項目數 —— 不能只丟伺服器那句 Failure
  const dlg = page.locator(".n-modal", { hasText: "不是空的" });
  await expect(dlg).toBeVisible({ timeout: 15_000 });
  await expect(dlg).toContainText("2");
  await expect(dlg).not.toContainText("Failure");

  await dlg.getByRole("button", { name: "連同內容一起刪除" }).click();

  // 斷言在遠端檔案系統上真的沒了，而不是相信畫面說「已刪除」
  await expect.poll(() => existsSync(`${SFTP_ROOT}/${dir}`), { timeout: 20_000 })
    .toBe(false);
});

test("斷線後整塊面板都要遮住，而且真的點不動", async ({ page }) => {
  // 使用者回報「沒有遮罩好」：斷線後只有路徑列與表格變灰，底部分頁列、錯誤列
  // 仍然是亮的，而且逐塊套 pointer-events 總會漏掉一塊 —— 「能點但送不出去」
  // 比「明顯不能點」更難懂。
  await login(page);
  await connect(page);

  await page.getByRole("button", { name: "中斷連線" }).click();
  await expect(page.getByText("已關閉")).toBeVisible({ timeout: 10_000 });

  // 遮罩要蓋住整塊面板，而不是零星幾塊
  const mask = page.locator(".sftp-offline-mask");
  await expect(mask).toBeVisible();
  const panel = page.locator(".sftp-panel");
  const [mb, pb] = [await mask.boundingBox(), await panel.boundingBox()];
  expect(mb!.width).toBeGreaterThanOrEqual(pb!.width - 2);
  expect(mb!.height).toBeGreaterThanOrEqual(pb!.height - 2);

  // 面板裡的控制項一律不可互動 —— 用實際命中測試，不是看它有沒有變灰
  for (const name of ["上一層", "重新整理", "新增資料夾", "上傳檔案"]) {
    const btn = page.locator(".sftp-panel").getByRole("button", { name }).first();
    if (await btn.count()) {
      await expect(btn).not.toBeInViewport({ ratio: 1 }).catch(() => {});
      const hit = await btn.evaluate((el) => {
        const r = el.getBoundingClientRect();
        const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
        return top?.closest(".sftp-offline-mask") !== null || getComputedStyle(el).pointerEvents === "none";
      });
      expect(hit, `「${name}」在斷線後仍然可以點`).toBe(true);
    }
  }

  // 遮罩上的重新連線要能用（否則使用者只能重整頁面）
  await expect(mask.getByRole("button", { name: "重新連線" })).toBeEnabled();
});
