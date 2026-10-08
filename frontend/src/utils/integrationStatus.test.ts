import { describe, expect, it } from "vitest";
import { lnmsStatusLabel, wazuhStatusLabel } from "./integrationStatus";

const dict: Record<string, string> = {
  "wazuh_admin.status_active": "上線",
  "wazuh_admin.status_disconnected": "離線",
  "wazuh_admin.status_never_connected": "從未連線",
  "topology.status_up": "上線",
  "topology.status_down": "離線",
};
const t = (k: string) => dict[k] ?? k;

describe("wazuhStatusLabel", () => {
  it("translates the agent states Wazuh reports", () => {
    expect(wazuhStatusLabel(t, "disconnected")).toBe("離線");
    expect(wazuhStatusLabel(t, "active")).toBe("上線");
    expect(wazuhStatusLabel(t, "never_connected")).toBe("從未連線");
  });

  it("keeps an unknown state as is rather than showing the key", () => {
    expect(wazuhStatusLabel(t, "updating")).toBe("updating");
  });

  it("shows a dash when there is no state", () => {
    expect(wazuhStatusLabel(t, null)).toBe("—");
    expect(wazuhStatusLabel(t, "")).toBe("—");
  });
});

describe("lnmsStatusLabel", () => {
  it("maps LibreNMS 1/0 and up/down", () => {
    expect(lnmsStatusLabel(t, 1)).toBe("上線");
    expect(lnmsStatusLabel(t, "0")).toBe("離線");
    expect(lnmsStatusLabel(t, "UP")).toBe("上線");
    expect(lnmsStatusLabel(t, null)).toBe("—");
  });
});
