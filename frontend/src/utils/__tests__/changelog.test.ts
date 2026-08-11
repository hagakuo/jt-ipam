import { describe, expect, it } from "vitest";

import { fmtChangeVal } from "../changelog";

describe("fmtChangeVal", () => {
  it("switch_port 用 @ 分隔裝置與埠號", () => {
    expect(fmtChangeVal("switch_port", "switch-003 / eth1/0/2")).toBe("switch-003@eth1/0/2");
  });

  it("埠號自己的斜線不能被動到", () => {
    // 只換第一個 " / "：全換會把 eth1/0/2 拆成 eth1@0@2
    expect(fmtChangeVal("switch_port", "switch-006 / Eth1/5")).toBe("switch-006@Eth1/5");
    expect(fmtChangeVal("switch_port", "sw / a/b/c/d")).toBe("sw@a/b/c/d");
  });

  it("沒有分隔符就原樣顯示", () => {
    expect(fmtChangeVal("switch_port", "switch-003")).toBe("switch-003");
  });

  it("其他欄位不套用這個格式", () => {
    expect(fmtChangeVal("hostname", "a / b")).toBe("a / b");
  });

  it("空值顯示為 ∅（看得出是「本來沒有」而不是漏印）", () => {
    expect(fmtChangeVal("switch_port", null)).toBe("∅");
  });
});
