import { describe, expect, it } from "vitest";
import { sortEntries, type SortableEntry } from "@/utils/sftpSort";

const ITEMS: SortableEntry[] = [
  { name: "beta.txt", is_dir: false, size: 300, mtime: 300 },
  { name: "alpha", is_dir: true, size: null, mtime: 100 },
  { name: "gamma.log", is_dir: false, size: 100, mtime: 200 },
  { name: "delta", is_dir: true, size: null, mtime: 400 },
];

const names = (s: SortableEntry[]) => s.map((e) => e.name);

describe("sortEntries", () => {
  it("資料夾優先：資料夾在前，各組內照名稱", () => {
    expect(names(sortEntries(ITEMS, { key: "name", order: "ascend", dirsFirst: true })))
      .toEqual(["alpha", "delta", "beta.txt", "gamma.log"]);
  });

  it("資料夾優先在降冪時仍然優先 —— 這正是把分組寫進比較函式會做錯的地方", () => {
    const out = sortEntries(ITEMS, { key: "name", order: "descend", dirsFirst: true });
    expect(names(out)).toEqual(["delta", "alpha", "gamma.log", "beta.txt"]);
    expect(out.slice(0, 2).every((e) => e.is_dir)).toBe(true);
  });

  it("混合排序：只看欄位，資料夾不特別待遇", () => {
    expect(names(sortEntries(ITEMS, { key: "name", order: "ascend", dirsFirst: false })))
      .toEqual(["alpha", "beta.txt", "delta", "gamma.log"]);
  });

  it("依大小排序時，資料夾沒有大小 → 當成最小且行為穩定", () => {
    expect(names(sortEntries(ITEMS, { key: "size", order: "ascend", dirsFirst: false })))
      .toEqual(["alpha", "delta", "gamma.log", "beta.txt"]);
  });

  it("依修改時間排序", () => {
    expect(names(sortEntries(ITEMS, { key: "mtime", order: "descend", dirsFirst: false })))
      .toEqual(["delta", "beta.txt", "gamma.log", "alpha"]);
  });

  it("同值時用名稱收斂，順序不會每次重新整理就跳動", () => {
    const same: SortableEntry[] = [
      { name: "b", is_dir: false, size: 10, mtime: 1 },
      { name: "a", is_dir: false, size: 10, mtime: 1 },
    ];
    expect(names(sortEntries(same, { key: "size", order: "ascend", dirsFirst: true })))
      .toEqual(["a", "b"]);
  });

  it("不改動傳進來的陣列（呼叫端還在用同一份資料）", () => {
    const input = [...ITEMS];
    sortEntries(input, { key: "name", order: "ascend", dirsFirst: true });
    expect(names(input)).toEqual(names(ITEMS));
  });
});
