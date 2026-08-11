import { describe, expect, it } from "vitest";

import { MAX_PORTS, parsePorts } from "../ports";

describe("parsePorts", () => {
  it("單一埠與範圍可以混用", () => {
    expect(parsePorts("8006, 22-23").ports).toEqual([8006, 22, 23]);
  });

  it("範圍用 - （nmap／ufw 的慣例）", () => {
    expect(parsePorts("80-83").ports).toEqual([80, 81, 82, 83]);
  });

  it("重複的埠只算一次", () => {
    expect(parsePorts("22, 22-24, 23").ports).toEqual([22, 23, 24]);
  });

  it("看不懂的片段要回報，不是默默丟掉", () => {
    // 這正是原本的問題：Number("22:23") 是 NaN，被過濾掉且畫面毫無說明
    const r = parsePorts("443, 22:23, abc");
    expect(r.ports).toEqual([443]);
    expect(r.invalid).toEqual(["22:23", "abc"]);
  });

  it("反向範圍算輸入錯誤，不自動交換", () => {
    const r = parsePorts("23-22");
    expect(r.ports).toEqual([]);
    expect(r.invalid).toEqual(["23-22"]);
  });

  it("超出範圍的埠號不接受", () => {
    expect(parsePorts("0, 65536, 70000").invalid).toEqual(["0", "65536", "70000"]);
  });

  it("超過上限要標記出來（這是診斷工具，不是連接埠掃描器）", () => {
    const r = parsePorts("1-100");
    expect(r.ports).toHaveLength(MAX_PORTS);
    expect(r.overflow).toBe(true);
  });
});
