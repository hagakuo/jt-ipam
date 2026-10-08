import { describe, it, expect } from "vitest";
import { cellText, columnsForExport } from "../tableExport";

describe("tableExport", () => {
  // 「未裝 Agent 的 IP」匯出的子網路／區段／單位一直是空白：欄位 key 是 subnet，
  // 資料欄位卻叫 subnet_cidr。畫面用 render 顯示所以看不出來（2026-09-27 發現）。
  it("欄位可以自帶匯出值（exportValue），不必讓 key 剛好等於資料欄位名", () => {
    const cols = columnsForExport([
      { title: "子網路", key: "subnet", render: () => null, exportValue: (r: any) => r.subnet_cidr },
      { title: "IP", key: "ip" },
      { title: () => "操作", key: "actions" },
    ]);
    expect(cols.map((c) => c.key)).toEqual(["subnet", "ip"]);
    const row = { ip: "198.51.100.7", subnet_cidr: "198.51.100.0/24" };
    expect(cellText(row, cols[0])).toBe("198.51.100.0/24");
    expect(cellText(row, cols[1])).toBe("198.51.100.7");
  });

  it("沒有值就是空字串；陣列用逗號接", () => {
    expect(cellText({}, { key: "x", label: "x" })).toBe("");
    expect(cellText({ x: ["a", "b"] }, { key: "x", label: "x" })).toBe("a, b");
  });
});
