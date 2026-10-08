/**
 * 客戶回報：「我有選機櫃，不一定要選地點！機櫃不是本身就會對應地點嗎？」——
 * 完全正確。選機櫃的下拉甚至顯示成「公司主機房 / R1」，地點就在眼前，
 * 卻還要求再選一次才給存。
 */
import { describe, expect, it } from "vitest";
import { resolveRackLocation } from "../rackLocation";

const RACKS = [
  { id: "r1", location_id: "loc-a" },
  { id: "r2", location_id: "loc-b" },
  { id: "orphan", location_id: null },
];

describe("機櫃與地點的關聯", () => {
  it("選了機櫃沒填地點 → 用機櫃的地點，不該擋下來", () => {
    expect(resolveRackLocation("r1", null, RACKS)).toEqual({ ok: true, location_id: "loc-a" });
  });

  it("兩邊都填且一致 → 照填的存", () => {
    expect(resolveRackLocation("r1", "loc-a", RACKS)).toEqual({ ok: true, location_id: "loc-a" });
  });

  it("兩邊矛盾 → 不猜，讓使用者自己修", () => {
    expect(resolveRackLocation("r1", "loc-b", RACKS)).toEqual({ ok: false, reason: "mismatch" });
  });

  it("沒選機櫃 → 地點照使用者填的（含清空）", () => {
    expect(resolveRackLocation(null, "loc-a", RACKS)).toEqual({ ok: true, location_id: "loc-a" });
    expect(resolveRackLocation(null, null, RACKS)).toEqual({ ok: true, location_id: null });
  });

  it("機櫃自己沒有地點 → 不擋，也不編造一個", () => {
    expect(resolveRackLocation("orphan", null, RACKS)).toEqual({ ok: true, location_id: null });
    // 機櫃沒地點時，使用者填的地點就是唯一資訊，不該被判成矛盾
    expect(resolveRackLocation("orphan", "loc-a", RACKS)).toEqual({ ok: true, location_id: "loc-a" });
  });

  it("找不到的機櫃 id → 當成沒有地點資訊，不要炸掉", () => {
    expect(resolveRackLocation("ghost", null, RACKS)).toEqual({ ok: true, location_id: null });
  });
});
