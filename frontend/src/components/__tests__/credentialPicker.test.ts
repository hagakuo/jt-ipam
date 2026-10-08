/**
 * 六個主控台的「已存帳密」下拉都要能選「用別組帳密」。
 *
 * 使用者回報（2026-08-31）：「我只能選存過的，沒辦法建新的認證。」
 * 原本清空的方式是下拉右邊那個**只有 hover 才出現的 ✕** —— 打開下拉只看到已存的那一筆，
 * 自然會以為沒有別的路。可發現性不是「做得到」就算數。
 *
 * 六個主控台是同一種互動，只改一個等於留下五個不一致的地方。
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONSOLES = [
  "SshTerminal.vue", "SftpBrowser.vue", "RdpScreen.vue",
  "VncScreen.vue", "NoVncScreen.vue", "BmcScreen.vue",
];

describe.each(CONSOLES)("%s 的帳密下拉", (file) => {
  const src = readFileSync(join(root, file), "utf-8");

  it("下拉裡要有「使用其他帳密」這個選項", () => {
    expect(src.includes("ssh.cred_manual"),
      "只剩 hover 才看得到的 ✕ 可以清空 —— 使用者找不到，就等於做不到").toBe(true);
  });

  it("那個選項的值要是 null（＝回到手動輸入）", () => {
    const i = src.indexOf("ssh.cred_manual");
    expect(i).toBeGreaterThan(-1);
    expect(src.slice(i, i + 120)).toContain("null");
  });
});

/**
 * 勾「記住帳密」連線時，新存的那一筆要**同時**出現在下拉的選項裡。
 *
 * 使用者回報（2026-09-24）：noVNC 的已存帳密下拉顯示成一串 UUID。原因是存完只把
 * 選取值設成新的 id、沒有重新載入清單 —— 下拉找不到對應的選項，就把值原樣印出來。
 * 連線一失敗回到表單就會看到（那次正是 PVE 認證失敗）。SSH／RDP 存完都會重新載入，
 * 只有 noVNC 漏了。
 */
describe.each(CONSOLES)("%s 存完帳密", (file) => {
  const src = readFileSync(join(root, file), "utf-8");
  const m = src.match(/await create\w*Credential\(/);

  it.skipIf(!m)("存完要重新載入清單（否則下拉只剩一串 UUID）", () => {
    const at = src.indexOf(m![0]);
    const after = src.slice(at, at + 900);
    expect(after, "存完帳密之後同一段流程裡要呼叫 loadCreds()").toMatch(/loadCreds\(\)/);
  });
});

/**
 * 「已存帳密／已存密碼」那一列只在**真的存過**時才出現。
 *
 * 使用者回報（2026-10-05，RustDesk 網頁連線）：還沒存過任何密碼，表單上卻有一列「已存密碼」下拉，打開只有
 * 「使用其他密碼（手動輸入）」。下拉的選項永遠含有那個手動選項，所以 `credOptions.length` 永遠 ≥ 1 ——
 * 條件要看已存的清單本身。七個主控台是同一種互動，一起守。
 */
const ALL_CONSOLES: [string, string][] = [
  ["SshTerminal.vue", "savedCreds"], ["SftpBrowser.vue", "creds"], ["RdpScreen.vue", "savedCreds"],
  ["VncScreen.vue", "savedCreds"], ["NoVncScreen.vue", "savedCreds"], ["BmcScreen.vue", "creds"],
  ["RustDeskScreen.vue", "savedCreds"],
];

describe.each(ALL_CONSOLES)("%s 的已存帳密列", (file, list) => {
  const src = readFileSync(join(root, file), "utf-8");

  it("沒存過任何一筆時不出現（條件看已存清單，不看含手動選項的下拉選項）", () => {
    const row = src.match(/<div v-if="([^"]+)" class="[\w-]*saved-row"/);
    expect(row, "找不到已存帳密那一列").not.toBeNull();
    expect(row![1]).not.toContain("credOptions");
    expect(row![1]).toBe(`${list}.length`);
  });
});
