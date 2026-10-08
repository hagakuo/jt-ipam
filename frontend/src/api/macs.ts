import { apiClient } from "@/api/client";

/** 上線依據（與 IP 清單同一顆燈，見 LiveStatusDot / classifyAddressLiveness） */
export type LiveEvidence = Record<string, any> | null;

export interface MacIpRow {
  ip: string; ip_id: string | null; subnet_id: string | null; subnet_cidr: string | null;
  hostname: string | null; deleted: boolean; current: boolean;
  first_seen: string | null; last_seen: string | null; evidence: string[]; live: LiveEvidence;
}
export interface MacEvent {
  id: string; at: string; kind: "assigned" | "released"; ip: string; ip_id: string | null;
  other_mac: string | null; other_random: boolean; source: string; event_type: string;
}
export interface MacHistory {
  mac: string; vendor: string | null; random: boolean; restricted: boolean;
  current: { ip: string; ip_id: string; subnet_cidr: string; hostname: string | null; device_id: string | null;
             device_name: string | null; mac_source: string | null; dhcp_reserved: boolean }[];
  ips: MacIpRow[]; ips_total: number;
  events: MacEvent[]; events_total: number;
  switch_ports: { switch: string | null; switch_device_id: string | null; port: string | null; vlan: number | null;
                  source: string; first_seen: string | null; last_seen: string | null }[];
  device_ports: { device_id: string; device_name: string; port: string }[];
  dhcp_reservations: { ip: string; hostname: string | null; source_type: string; source_name: string | null;
                       description: string | null }[];
  vms: { vm_id: string; vm_name: string; cluster: string; interface: string; status: string }[];
  related: { mac: string; ip: string; ip_id: string; at: string; random: boolean; reason: string }[];
}

/** 以一個 MAC 為中心的完整歷程（任何寫法都可以，伺服器端正規化） */
export async function getMacHistory(mac: string): Promise<MacHistory> {
  const { data } = await apiClient.get<MacHistory>(`/api/v1/macs/${encodeURIComponent(mac)}/history`);
  return data;
}
