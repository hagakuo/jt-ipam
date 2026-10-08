/**
 * 拖資料夾進來時，要把整棵樹展開成「檔案 + 相對路徑」。
 *
 * 兩件事測起來最重要，因為它們錯了都是**安靜地少東西**：
 * 1. `readEntries()` 一次不保證回傳全部 —— 只讀一次的話大資料夾會少檔案而且不會有錯誤。
 * 2. 超過上限時要**說出來**，不能安靜截斷（那會讓人以為全部都傳上去了）。
 */
import { describe, it, expect } from "vitest";
import {
  collectDroppedFiles, dirsToCreate, MAX_FILES_PER_DROP, type EntryLike,
} from "@/utils/dropWalk";

function file(name: string, size = 3): EntryLike {
  return { isFile: true, isDirectory: false, name, file: (ok) => ok(new File(["abc".slice(0, size)], name)) };
}

/** 目錄：刻意每次只吐一批，最後回空陣列 —— 與瀏覽器的實際行為一致。 */
function dir(name: string, children: EntryLike[], batch = 2): EntryLike {
  return {
    isFile: false, isDirectory: true, name,
    createReader: () => {
      let i = 0;
      return {
        readEntries: (ok) => {
          const slice = children.slice(i, i + batch);
          i += batch;
          ok(slice);
        },
      };
    },
  };
}

describe("collectDroppedFiles", () => {
  it("資料夾會被展開，路徑帶著資料夾名", async () => {
    const tree = dir("proj", [file("a.txt"), dir("sub", [file("b.txt")])]);
    const r = await collectDroppedFiles([new File([], "proj")], [tree]);
    expect(r.files.map((f) => f.path).sort()).toEqual(["proj/a.txt", "proj/sub/b.txt"]);
    expect(r.skippedDirs).toBe(0);
  });

  it("readEntries 分批回傳時不可以漏檔案", async () => {
    const many = Array.from({ length: 7 }, (_, i) => file(`f${i}.txt`));
    const tree = dir("big", many, 2);          // 一次只吐 2 個
    const r = await collectDroppedFiles([new File([], "big")], [tree]);
    expect(r.files).toHaveLength(7);
  });

  it("資料夾與檔案混拖：兩者都要收", async () => {
    const r = await collectDroppedFiles(
      [new File([], "d"), new File(["x"], "loose.bin")],
      [dir("d", [file("in.txt")]), file("loose.bin")],
    );
    expect(r.files.map((f) => f.path).sort()).toEqual(["d/in.txt", "loose.bin"]);
  });

  it("拿不到 entry 時照舊當一般檔案收下", async () => {
    const r = await collectDroppedFiles([new File(["x"], "plain.txt")], [null]);
    expect(r.files.map((f) => f.path)).toEqual(["plain.txt"]);
  });

  it("名稱含路徑分隔字元或 .. 一律不收", async () => {
    const tree = dir("p", [file("../escape"), file("a/b"), file("ok.txt")]);
    const r = await collectDroppedFiles([new File([], "p")], [tree]);
    expect(r.files.map((f) => f.path)).toEqual(["p/ok.txt"]);
    expect(r.droppedOverLimit).toBe(2);
  });

  it("超過上限要回報，不可以安靜截斷", async () => {
    const many = Array.from({ length: MAX_FILES_PER_DROP + 5 }, (_, i) => file(`f${i}`));
    const r = await collectDroppedFiles([new File([], "huge")], [dir("huge", many, 50)]);
    expect(r.files).toHaveLength(MAX_FILES_PER_DROP);
    expect(r.droppedOverLimit).toBeGreaterThan(0);
  });

  it("讀不到的檔案跳過就好，不影響其他檔案", async () => {
    const bad: EntryLike = { isFile: true, name: "bad", file: (_ok, err) => err?.(new Error("nope")) };
    const r = await collectDroppedFiles([new File([], "d")], [dir("d", [bad, file("good.txt")])]);
    expect(r.files.map((f) => f.path)).toEqual(["d/good.txt"]);
  });
});

describe("dirsToCreate", () => {
  it("父目錄一定排在子目錄前面", () => {
    const dirs = dirsToCreate([
      { file: new File([], "x"), path: "a/b/c/x.txt" },
      { file: new File([], "y"), path: "a/y.txt" },
    ]);
    expect(dirs).toEqual(["a", "a/b", "a/b/c"]);
  });

  it("根目錄下的檔案不需要建目錄", () => {
    expect(dirsToCreate([{ file: new File([], "x"), path: "x.txt" }])).toEqual([]);
  });
});
