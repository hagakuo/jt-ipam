/**
 * 上傳送出迴圈中途失敗時，**一定要告訴伺服器**。
 *
 * 送出迴圈裡的 `file.slice(...).arrayBuffer()` 是會丟例外的：檔案在拖進來之後被移走、
 * 外接磁碟斷線、iCloud 上的檔案還沒下載回本機…都會在讀到一半時失敗。少了保護的話，
 * 例外會直接跳出上傳函式，`put_abort` 不會送出 —— 伺服器還在等那些永遠不會來的位元組，
 * 使用者看到的是「上傳沒反應，然後整條連線斷掉」，而真正的原因在自己那台機器上。
 *
 * 這裡用原始碼檢查：要真的重現「讀到一半失敗」需要一個會半途壞掉的 File，
 * jsdom 造不出來；而缺陷的本質就是「那個迴圈沒有被包起來」，直接對著它斷言最不失真。
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "..", "SftpBrowser.vue"), "utf-8");

/** 取出 putOneFile 的內容（到下一個 function 宣告為止）。 */
function putOneFileBody(): string {
  const i = src.indexOf("async function putOneFile");
  expect(i, "putOneFile 改名了，請一起更新這個測試").toBeGreaterThan(-1);
  const rest = src.slice(i);
  const j = rest.indexOf("\nasync function uploadFiles");
  return j > 0 ? rest.slice(0, j) : rest;
}

describe("SFTP 上傳中途失敗", () => {
  it("送出迴圈被 try 包住，讀檔失敗不會直接跳出函式", () => {
    const body = putOneFileBody();
    // 迴圈寫法改過一次（for → while），只認其中一種會讓這個守門安靜失效 ——
    // 兩種都認，找不到就明講是這個測試該更新，不要假裝通過。
    const loop = Math.max(body.indexOf("for (let off = 0"), body.indexOf("while (off < file.size)"));
    expect(loop, "找不到送出迴圈：改寫法了嗎？請一起更新這個測試").toBeGreaterThan(-1);
    const before = body.slice(0, loop);
    expect(before.includes("try {"),
      "送出迴圈沒有被 try 包住：讀檔失敗會略過 put_abort，伺服器會一直等下去").toBe(true);
  });

  it("任何一種放棄都會送出 put_abort", () => {
    const body = putOneFileBody();
    expect(body.includes('send({ type: "put_abort"'),
      "放棄上傳時沒有通知伺服器").toBe(true);
    // put_abort 要在「拋出錯誤」之前 —— 先拋就永遠送不出去了
    expect(body.indexOf('"put_abort"')).toBeLessThan(body.lastIndexOf("throw new Error"));
  });

  it("讀不到檔案要說是讀不到，不要含糊地說連線中斷", () => {
    const body = putOneFileBody();
    expect(body.includes("sftp.unreadable_item"),
      "讀檔失敗回報成「連線已中斷」會讓人去查網路，真正的原因卻在自己這台機器上").toBe(true);
  });
});
