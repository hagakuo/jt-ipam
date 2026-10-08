import { describe, expect, it } from "vitest";
import { decodeNmapEscapes, serviceKind } from "../nmapText";

describe("decodeNmapEscapes", () => {
  it("把 nmap 轉義的 UTF-8 中文網頁標題解回文字", () => {
    // 「裂縫」的 UTF-8：E8 A3 82 E7 B8 AB
    expect(decodeNmapEscapes("\\xE8\\xA3\\x82\\xE7\\xB8\\xAB - dev")).toBe("裂縫 - dev");
  });
  it("不是合法 UTF-8 就原樣留著，不要猜", () => {
    expect(decodeNmapEscapes("bad \\xFF\\xFE end")).toBe("bad \\xFF\\xFE end");
  });
  it("沒有轉義的文字不動", () => {
    expect(decodeNmapEscapes("Welcome to nginx")).toBe("Welcome to nginx");
  });
});

describe("serviceKind", () => {
  it("依服務名稱分類", () => {
    expect(serviceKind("ssh")).toBe("remote");
    expect(serviceKind("vnc")).toBe("remote");
    expect(serviceKind("http")).toBe("web");
    expect(serviceKind("ldap")).toBe("data");
    expect(serviceKind("ipp")).toBe("file");
    expect(serviceKind("something")).toBe("other");
  });
});
