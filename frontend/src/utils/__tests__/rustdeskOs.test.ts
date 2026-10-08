import { describe, expect, it } from "vitest";
import { rustdeskOs } from "@/utils/rustdeskOs";

describe("RustDesk 回報的作業系統字串", () => {
  it("Windows：去掉版本與組建號的尾巴，平台照舊", () => {
    expect(rustdeskOs("windows / Windows 11 Pro - 11 (26200)")).toEqual(["Windows 11 Pro", "windows"]);
  });

  it("Linux：「Linux 24.04 Ubuntu」重排成「Ubuntu 24.04」，平台一律是 linux（使用者 2026-10-07）", () => {
    expect(rustdeskOs("ubuntu / Linux 24.04 Ubuntu")).toEqual(["Ubuntu 24.04", "linux"]);
    expect(rustdeskOs("debian / Linux 12 Debian")).toEqual(["Debian 12", "linux"]);
    expect(rustdeskOs("fedora / Linux 40 Fedora Linux")).toEqual(["Fedora Linux 40", "linux"]);
    // 沒有版本號的照原樣，平台仍是 linux
    expect(rustdeskOs("arch / Linux Arch Linux")).toEqual(["Arch Linux", "linux"]);
  });

  it("macOS 與沒有平台前綴的照舊", () => {
    expect(rustdeskOs("macos / MacOS 15.7.5")).toEqual(["MacOS 15.7.5", "macos"]);
    expect(rustdeskOs("Windows 10 Pro")).toEqual(["Windows 10 Pro", ""]);
    expect(rustdeskOs("")).toEqual(["", ""]);
  });
});
