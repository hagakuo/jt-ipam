/**
 * 調查的各段文字：畫面與四種匯出共用同一份。
 *
 * 守的是：沒資料的段落不出現（畫面不放空標題）、矛盾清單照後端算的翻譯、
 * 每一段讀的欄位跟後端回傳的一致（匯出第一版就是欄位名猜錯，整排「—」）。
 */
import { describe, expect, it } from "vitest";
import zh from "../../i18n/zh-TW.json";
import {
  conflictLines, fwSeenLabel, headSections, kindReasonText, midSections, monitorLines, tailSections,
  type SectionHelpers,
} from "../investigateSections";

function lookup(key: string): string | undefined {
  let o: any = zh;
  for (const p of key.split(".")) {
    if (!o || typeof o !== "object" || !(p in o)) return undefined;
    o = o[p];
  }
  return typeof o === "string" ? o : undefined;
}

/** 用真的 zh-TW 字串（含 {參數} 代入），順便驗證用到的鍵都存在 */
const h: SectionHelpers = {
  t: (key, params) => {
    const raw = lookup(key);
    if (raw === undefined) return `<<${key}>>`;
    return raw.replace(/\{(\w+)\}/g, (_m, k) => String(params?.[k] ?? `{${k}}`));
  },
  te: (key) => lookup(key) !== undefined,
  fmt: (iso) => (iso ? `T(${iso})` : "—"),
};

const bare = { found: true, ip: "198.51.100.77", address: {}, monitoring: {}, conflicts: [] };

const full = {
  ...bare,
  conflicts: [
    { code: "names", params: { n: 2, names: ["db01", "web01"] } },
    { code: "reservation_mac", params: { reserved: "00:11:22:99:99:99", current: "00:11:22:33:44:77" } },
    { code: "something_new", params: {} },
  ],
  identity: { device_kind: "windows", device_model: "Dell OptiPlex", os_guess: "Microsoft Windows 11",
              os_family: "windows", kind_reason: "wazuh:windows", nic_vendor: "Intel", mac_random: true },
  monitoring: {
    librenms: { hostname: "win11-desk-01", status: "1", matched_by: "primary_ip" },
    zabbix: [{ name: "Win11 Desk 01", status: "monitored", available: "up", maintenance: true }],
  },
  agents: {
    ocs: { os: "Microsoft Windows 11 Pro", tag: "HQ-IT", last_inventory: "2026-10-05T01:00:00Z",
           system: "Dell Inc. OptiPlex 7090", serial: "ABC123", cpu: "Intel Core i7-11700", memory_mb: 16384 },
    rustdesk: [{ id: "123456789", online: true, os: "Windows 11", match_status: "matched", key_problem: true }],
  },
  probe: { at: "2026-10-05T02:00:00Z", device_type: "windows", services: ["3389/tcp ms-wbt-server"] },
  virtualization: { vm: "win11-vm", kind: "vm", platform: "proxmox", node: "pve1", status: "running" },
  dhcp: { in_lease: true, reserved: true, in_pool: true,
          reservations: [{ mac: "00:11:22:33:44:77", source_name: "dc01-dhcp" }],
          leases: [{ source_type: "windows_dhcp", source_name: "dc01-dhcp", last_seen: "2026-10-05T03:00:00Z" }],
          pools: [{ source_type: "kea_dhcp", start: "198.51.100.50", end: "198.51.100.99" }] },
  switch_ports: [{ switch: "access-sw-1", port: "Gi1/0/7", vlan: 10, source: "librenms" }],
  fw_evidence: [{ key: "arp:mikrotik", kind: "arp", vendor: "mikrotik", at: "2026-10-05T04:00:00Z", aging: true }],
  last_seen: { minutes: 30, rows: [{ source: "scanner", at: "2026-10-05T04:00:00Z", verdict: "fresh" },
                                   { source: "lease:pfsense", at: "2026-10-04T04:00:00Z", verdict: "ignored" }] },
  firewall_refs: { aliases: [{ source_type: "fortigate", firewall: "fg-1", name: "h-win11" }],
                   rules: [{ source_type: "paloalto", firewall: "pa-1", action: "allow", src: "any",
                             dst: "win11", descr: "allow-win11" }] },
  dhcp_rogue: [{ role: "offered", server_ip: "198.51.100.254", offered_ip: "198.51.100.77", server_marked: false }],
  anomalies: [{ category: "ip_conflicts", macs: ["00:11:22:33:44:77", "02:00:00:00:00:01"] }],
  ai_findings: [{ severity: "medium", title: "RDP 對外開放", at: "2026-10-05T05:00:00Z" }],
  console_sessions: [{ at: "2026-10-05T06:00:00Z", kind: "rdp", user: "admin", actor_ip: "192.0.2.50",
                       remote_user: "alice", duration_seconds: 3725.4 }],
};

describe("沒有資料的段落不出現", () => {
  it("只有基本資料的位址：一個新段落都沒有", () => {
    expect(headSections(bare, h)).toEqual([]);
    expect(midSections(bare, h)).toEqual([]);
    expect(tailSections(bare, h)).toEqual([]);
    expect(conflictLines(bare, h)).toEqual([]);
  });

  it("查不到的位址也是空的", () => {
    expect(midSections({ found: false }, h)).toEqual([]);
    expect(conflictLines(null, h)).toEqual([]);
  });
});

describe("矛盾清單", () => {
  it("照後端的 code 翻譯；不認得的 code 原樣顯示而不是空白", () => {
    const lines = conflictLines(full, h);
    expect(lines[0]).toBe("各來源回報的主機名稱不一致（2 種）");
    expect(lines[1]).toContain("00:11:22:99:99:99");
    expect(lines[1]).toContain("00:11:22:33:44:77");
    expect(lines[2]).toBe("something_new");
  });
});

describe("每一段的文字", () => {
  const all = [...headSections(full, h), ...midSections(full, h), ...tailSections(full, h)];
  const text = all.flatMap((s) => s.lines).join("\n");

  it("用到的翻譯鍵都存在（沒有 <<鍵>> 漏出來）", () => {
    expect(text).not.toContain("<<");
    expect(all.map((s) => s.title).join()).not.toContain("<<");
  });

  it("段落順序與畫面一致", () => {
    expect(all.map((s) => s.key)).toEqual([
      "identity", "agents", "probe", "virt", "dhcp", "switch", "fw_evidence", "last_seen",
      "fw_refs", "dhcp_rogue", "anomalies", "ai_findings", "console",
    ]);
  });

  it("設備識別帶出類型、依據、網卡廠牌與隨機 MAC", () => {
    const ident = headSections(full, h)[0].lines.join("\n");
    expect(ident).toContain("Windows 主機");
    expect(ident).toContain("Wazuh 代理");
    expect(ident).toContain("Intel");
    expect(ident).toContain("隨機");
  });

  it("各段讀的是後端的欄位", () => {
    expect(text).toContain("HQ-IT");
    expect(text).toContain("RustDesk 123456789");
    expect(text).toContain("Key 錯誤");
    expect(text).toContain("3389/tcp ms-wbt-server");
    expect(text).toContain("win11-vm（虛擬機 · KVM）");
    expect(text).toContain("198.51.100.50 - 198.51.100.99");
    expect(text).toContain("access-sw-1 · Gi1/0/7 · VLAN 10");
    expect(text).toContain("ARP 表（MikroTik）");
    expect(text).toContain("DHCP 租約（pfSense）");
    expect(text).toContain("h-win11");
    expect(text).toContain("allow-win11");
    expect(text).toContain("198.51.100.254");
    expect(text).toContain("IP 衝突");
    expect(text).toContain("RDP 對外開放");
    expect(text).toContain("alice");
    expect(text).toContain("T(2026-10-05T06:00:00Z)");     // 時間一律經由呼叫端的格式（fmtDateTime）
  });

  it("清單類段落的標題帶筆數，混合資料的段落不帶", () => {
    const by = Object.fromEntries(all.map((s) => [s.key, s.count]));
    expect(by.switch).toBe(1);
    expect(by.console).toBe(1);
    expect(by.agents).toBeUndefined();
    expect(by.dhcp).toBeUndefined();
  });

  it("遠端連線記錄帶連了多久（有結束記錄才有）", () => {
    const sec = all.find((s) => s.key === "console")!;
    expect(sec.lines[0]).toContain("連線 01:02:05");
  });
});

describe("輔助", () => {
  it("沒有依據＝沿用探測／定期偵測的判讀", () => {
    expect(kindReasonText(null, h)).toContain("探測");
    expect(kindReasonText("librenms:VigorAP903", h)).toContain("VigorAP903");
  });

  it("監控涵蓋列出 Zabbix，LibreNMS 標出是依位址對到的", () => {
    const lines = monitorLines(full, h, (s) => String(s), (s) => String(s));
    expect(lines.some((l) => l.startsWith("Zabbix Win11 Desk 01（監控中）") && l.includes("維護中"))).toBe(true);
    expect(lines.some((l) => l.includes("依位址比對"))).toBe(true);
  });

  it("防火牆證據的廠牌名稱包含 MikroTik（以前印成原始的 mikrotik）", () => {
    expect(fwSeenLabel("vpn:mikrotik", h.t)).toBe("VPN 連線（MikroTik）");
    expect(fwSeenLabel("scanner", h.t)).toBe("scanner");
  });
});
