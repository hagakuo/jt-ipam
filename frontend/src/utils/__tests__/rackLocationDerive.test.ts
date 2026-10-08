/**
 * 選了機櫃就要能推出地點 —— 不可以反過來要求「先選地點」。
 *
 * 使用者兩次指出同一件事：「我有選機櫃 不一定要選地點」「還沒選地點 應該也要可以直接選機櫃」。
 * 機櫃本來就屬於某個地點，那是查得到的答案，不該丟回去問人。
 *
 * 這裡用原始碼檢查：兩個入口（裝置清單、裝置詳細資料）**都**要解開，而且都要帶出地點。
 * 同一個物件有兩處編輯介面時，只改一處是常見的漏 —— 這正是要守的東西。
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FILES = ["views/Devices.vue", "components/DeviceEditModal.vue"];

describe.each(FILES)("%s 的機櫃欄位", (rel) => {
  const src = readFileSync(join(root, rel), "utf-8");

  it("不可以因為沒選地點就把機櫃反灰", () => {
    expect(src.includes(':disabled="!form.location_id"'),
      "機櫃被地點擋住了：地點是機櫃查得到的，不該要求先選").toBe(false);
  });

  it("不可以再叫人「請先選地點」", () => {
    expect(src.includes("rack_pick_location_first"),
      "還留著「請先選地點」的提示").toBe(false);
  });

  it("選了機櫃要把地點帶出來", () => {
    const i = src.indexOf("function onRackChange");
    expect(i, "找不到 onRackChange").toBeGreaterThan(-1);
    const body = src.slice(i, i + 600);
    expect(body.includes("location_id"),
      "選機櫃之後沒有把地點填上，兩個欄位會不一致").toBe(true);
  });
});
