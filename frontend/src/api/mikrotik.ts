import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// MikroTik RouterOS 整合。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface MikroTikRouter {
  id: string;
  name: string;
  api_url: string;
  api_username: string;
  enabled: boolean;
  verify_tls: boolean;
  sync_interval_seconds: number;
  sync_dhcp: boolean;
  sync_dhcp_ranges: boolean;
  sync_firewall: boolean;
  sync_nat: boolean;
  sync_address_lists: boolean;
  sync_vpn: boolean;
  /** 預設關：全表 ARP 在大型路由器上可能是上萬列 */
  sync_arp: boolean;
  /** 第二階段：實體介面寫進對應裝置的連接埠、/ip/neighbor（LLDP/CDP/MNDP）鄰居 */
  sync_interfaces: boolean;
  sync_neighbors: boolean;
  /** 預設關：bridge host 表（FDB）在大型 bridge 上可能是上萬列 */
  sync_fdb: boolean;
  /** 這台路由器＝哪一台 jt-ipam 裝置；沒指定時由 API 位址對到的 IP 所屬裝置帶入 */
  device_id: string | null;
  /** CPU 超過這個百分比就停掉本輪剩下的區段 */
  cpu_load_limit: number;
  section_delay_ms: number;
  max_response_mb: number;
  description: string | null;
  scope_subnet_ids: string[] | null;
  routeros_version: string | null;
  board_name: string | null;
  last_sync_at: string | null;
  last_error: string | null;
  /** 逐區段耗時／CPU；`stopped` 代表本輪因為 CPU 超標提早停止 */
  last_cost: Record<string, unknown> | null;
}

export interface MikroTikWrite {
  name: string;
  api_url: string;
  api_username: string;
  api_password?: string;
  enabled?: boolean;
  verify_tls?: boolean;
  sync_interval_seconds?: number;
  sync_dhcp?: boolean;
  sync_dhcp_ranges?: boolean;
  sync_firewall?: boolean;
  sync_nat?: boolean;
  sync_address_lists?: boolean;
  sync_vpn?: boolean;
  sync_arp?: boolean;
  sync_interfaces?: boolean;
  sync_neighbors?: boolean;
  sync_fdb?: boolean;
  device_id?: string | null;
  cpu_load_limit?: number;
  section_delay_ms?: number;
  max_response_mb?: number;
  description?: string;
  scope_subnet_ids?: string[];
}

/**
 * 連線診斷。比其他整合多回 `rows` 與 `seconds` —— 客戶的 MikroTik 是主力路由器，
 * 「要不要開 ARP 這一段」要由看得到數字的人決定。
 */
export interface MikroTikDiagnosis {
  api_url: string;
  version: string | null;
  board_name: string | null;
  identity: string | null;
  cpu_load: number | null;
  cpu_load_after?: number | null;
  free_memory: number | null;
  total_memory: number | null;
  uptime: string | null;
  ok_count: number;
  checks: {
    endpoint: string; ok: boolean; rows?: number; seconds?: number;
    absent?: boolean; error?: string;
  }[];
}

export interface MikroTikRule {
  id: string; table_name: string; chain: string | null; position: number;
  action: string | null; disabled: boolean;
  src_address: string | null; dst_address: string | null;
  protocol: string | null; src_port: string | null; dst_port: string | null;
  in_interface: string | null; out_interface: string | null;
  to_addresses: string | null; to_ports: string | null; comment: string | null;
}

export interface MikroTikAddressListEntry {
  id: string; list_name: string; address: string;
  dynamic: boolean; timeout: string | null; comment: string | null;
}

/** `/ip/neighbor` 鏡像；`device_*`：依鄰居宣告的位址或 MAC 對到的裝置（對到多台不填） */
export interface MikroTikNeighbor {
  interface: string; address: string | null; mac: string | null; identity: string | null;
  platform: string | null; board: string | null; version: string | null;
  remote_interface: string | null; discovered_by: string | null; last_seen_at: string | null;
  device_id: string | null; device_name: string | null;
}

export async function listMikroTik(): Promise<Paginated<MikroTikRouter>> {
  const { data } = await apiClient.get<Paginated<MikroTikRouter>>("/api/v1/mikrotik", {
    params: { page: 1, page_size: 200 },
  });
  return data;
}

export async function createMikroTik(p: MikroTikWrite): Promise<MikroTikRouter> {
  const { data } = await apiClient.post<MikroTikRouter>("/api/v1/mikrotik", p);
  return data;
}

export async function updateMikroTik(
  id: string, p: Partial<MikroTikWrite>,
): Promise<MikroTikRouter> {
  const { data } = await apiClient.patch<MikroTikRouter>(`/api/v1/mikrotik/${id}`, p);
  return data;
}

export async function deleteMikroTik(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/mikrotik/${id}`);
}

export async function testMikroTik(id: string): Promise<MikroTikDiagnosis> {
  const { data } = await apiClient.post<MikroTikDiagnosis>(`/api/v1/mikrotik/${id}/test`);
  return data;
}

export async function syncMikroTik(id: string): Promise<{ task_id: string }> {
  const { data } = await apiClient.post(`/api/v1/mikrotik/${id}/sync`);
  return data;
}

export async function listMikroTikRules(
  id: string, table?: string,
): Promise<MikroTikRule[]> {
  const { data } = await apiClient.get<{ items: MikroTikRule[] }>(
    `/api/v1/mikrotik/${id}/rules`, { params: table ? { table } : undefined });
  return data.items ?? [];
}

export async function listMikroTikAddressLists(
  id: string, listName?: string,
): Promise<MikroTikAddressListEntry[]> {
  const { data } = await apiClient.get<{ items: MikroTikAddressListEntry[] }>(
    `/api/v1/mikrotik/${id}/address-lists`,
    { params: listName ? { list_name: listName } : undefined });
  return data.items ?? [];
}

export async function listMikroTikNeighbors(id: string): Promise<MikroTikNeighbor[]> {
  const { data } = await apiClient.get<{ items: MikroTikNeighbor[] }>(`/api/v1/mikrotik/${id}/neighbors`);
  return data.items ?? [];
}
