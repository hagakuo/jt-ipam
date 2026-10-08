/**
 * 上線判定（前端）：逐來源證據。
 *
 * 後端把防火牆給的 ARP／DHCP 租約／VPN 連線從 `last_seen_scanner` 拆成 `arp_seen`
 * 的逐來源時間之後，**前端如果沒跟著改，狀態燈會整片變灰** —— 資料還在，只是
 * 沒人去讀那個新欄位。這幾個測試就是守這件事。
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  classifyAddressLiveness,
  isArpOnlyEvidence,
  livenessSources,
  onlineGraceMinutes,
} from "../useLivenessSettings";

const nowIso = () => new Date().toISOString();
const agoIso = (min: number) => new Date(Date.now() - min * 60000).toISOString();

beforeEach(() => {
  onlineGraceMinutes.value = 30;
  livenessSources.value = ["scanner", "librenms", "wazuh", "arp:opnsense"];
});

describe("classifyAddressLiveness", () => {
  it("AdGuard 的 DNS 時間不算上線證據（它只代表設定裡有這個 IP，關機的機器也一直有）", () => {
    expect(classifyAddressLiveness({ last_seen_dns: nowIso() })).toBe("offline");
    expect(isArpOnlyEvidence({ last_seen_arp: nowIso(), last_seen_dns: nowIso() })).toBe(true);
  });

  it("防火牆 ARP 看得到就是上線（以前這筆資料在 last_seen_scanner 裡）", () => {
    expect(classifyAddressLiveness({ arp_seen: { "arp:opnsense": nowIso() } }))
      .toBe("online");
  });

  it("沒被勾選的來源不算數", () => {
    livenessSources.value = ["scanner", "librenms"];
    expect(classifyAddressLiveness({ arp_seen: { "arp:opnsense": nowIso() } }))
      .toBe("offline");
  });

  it("DHCP 租約預設不在勾選清單裡 → 不會讓它變上線", () => {
    expect(classifyAddressLiveness({ arp_seen: { "lease:opnsense": nowIso() } }))
      .toBe("offline");
  });

  it("Wazuh 的 keep-alive 算上線", () => {
    expect(classifyAddressLiveness({ last_seen_wazuh: agoIso(5) })).toBe("online");
  });

  it("過期的防火牆 ARP 一樣會掉到離線", () => {
    expect(classifyAddressLiveness({ arp_seen: { "arp:opnsense": agoIso(600) } }))
      .toBe("offline");
  });

  it("沒有任何證據、又刻意不偵測 → 未知（不是紅燈）", () => {
    expect(classifyAddressLiveness({ exclude_from_ping: true })).toBe("unknown");
  });
});

describe("isArpOnlyEvidence", () => {
  it("只有 LibreNMS 的 ARP 撐著 → 要標出來（它沒有時間概念）", () => {
    expect(isArpOnlyEvidence({ last_seen_arp: nowIso() })).toBe(true);
  });

  it("防火牆的 ARP 表會逾時淘汰 → 有它撐著就不算「只靠 ARP」", () => {
    expect(isArpOnlyEvidence({
      last_seen_arp: nowIso(), arp_seen: { "arp:pfsense": nowIso() },
    })).toBe(false);
  });

  it("但 DHCP 租約不算 —— 租期比開機時間長得多", () => {
    expect(isArpOnlyEvidence({
      last_seen_arp: nowIso(), arp_seen: { "lease:pfsense": nowIso() },
    })).toBe(true);
  });
});
