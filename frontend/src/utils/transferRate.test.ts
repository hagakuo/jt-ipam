import { describe, expect, it } from "vitest";
import { RateMeter } from "./transferRate";

describe("RateMeter", () => {
  it("averages the recent window", () => {
    const m = new RateMeter(5000);
    m.add(0, 0);
    m.add(5_000_000, 1000);
    m.add(10_000_000, 2000);
    expect(m.rate(2000)).toBe(5_000_000);
    expect(m.eta(20_000_000, 2000)).toBe(2);
  });

  it("is unknown during the first second", () => {
    const m = new RateMeter();
    m.add(0, 0);
    m.add(100, 500);
    expect(m.rate(500)).toBeNull();
  });

  it("falls toward zero when the transfer stalls", () => {
    const m = new RateMeter(5000);
    m.add(0, 0);
    m.add(10_000_000, 2000);
    expect(m.rate(2000)).toBe(5_000_000);
    expect(m.rate(10_000)).toBe(0);           // 停了 8 秒：窗裡沒有新的進度
    expect(m.eta(20_000_000, 10_000)).toBeNull();
  });

  it("starts over when the count goes backwards (next file)", () => {
    const m = new RateMeter();
    m.add(0, 0);
    m.add(9_000_000, 3000);
    m.add(1_000_000, 4000);
    m.add(3_000_000, 5000);
    expect(m.rate(5000)).toBe(2_000_000);
  });
});
