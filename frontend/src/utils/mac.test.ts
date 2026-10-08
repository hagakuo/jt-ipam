import { describe, expect, it } from "vitest";
import { isRandomMac, normalizeMac } from "./mac";

describe("normalizeMac", () => {
  it("accepts the common spellings", () => {
    for (const s of ["00:00:5E:00:53:01", "00-00-5e-00-53-01", "0000.5e00.5301", "00005e005301", " 00:00:5e:00:53:01 "]) {
      expect(normalizeMac(s)).toBe("00:00:5e:00:53:01");
    }
  });
  it("rejects things that are not a MAC", () => {
    for (const s of ["", "192.0.2.1", "00:00:5e:00:53", "zz:00:5e:00:53:01", "host-00005e005301", null]) {
      expect(normalizeMac(s as string)).toBeNull();
    }
  });
});

describe("isRandomMac", () => {
  it("flags locally administered (private Wi-Fi) addresses", () => {
    expect(isRandomMac("02:00:5e:00:53:01")).toBe(true);
    expect(isRandomMac("da:a1:19:00:00:01")).toBe(true);   // a → bit 1 set
    expect(isRandomMac("06:00:5e:00:53:42")).toBe(true);
    expect(isRandomMac("00:00:5e:00:53:42")).toBe(false);  // vendor-burned
    expect(isRandomMac("00:00:5e:00:53:01")).toBe(false);
    expect(isRandomMac("not a mac")).toBe(false);
  });
});
