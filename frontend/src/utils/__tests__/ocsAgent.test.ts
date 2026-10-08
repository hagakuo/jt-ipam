/**
 * OCS 代理版本的原始字串很長（OCS-NG_unified_unix_agent_v2.10.0），版本號在最後，
 * 欄位一窄就被截掉，剛好看不到最重要的那段（使用者 2026-09-24 回報）。
 */
import { describe, it, expect } from "vitest";
import { shortOcsAgent } from "../ocsAgent";

describe("shortOcsAgent", () => {
  it.each([
    ["OCS-NG_unified_unix_agent_v2.10.0", "Unix 2.10.0"],
    ["OCS-NG_unified_unix_agent_v2.8.0", "Unix 2.8.0"],
    ["OCS-NG_WINDOWS_AGENT_v2.11.0.1", "Windows 2.11.0.1"],
    ["OCS-NG_windows_client_v2.3.1.0", "Windows 2.3.1.0"],
    ["OCS-NG_MacOSX_Agent_v2.9.1", "macOS 2.9.1"],
    ["OCS-NG_Android_agent_v2.7", "Android 2.7"],
  ])("%s → %s", (raw, short) => {
    expect(shortOcsAgent(raw)).toBe(short);
  });

  it("認不得的格式原樣回傳，不硬猜", () => {
    expect(shortOcsAgent("some-custom-agent")).toBe("some-custom-agent");
  });

  it("空值回空字串", () => {
    expect(shortOcsAgent(null)).toBe("");
    expect(shortOcsAgent(undefined)).toBe("");
  });
});
