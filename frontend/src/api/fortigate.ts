import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// FortiGate 整合（Beta）。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface FortiGateFirewall {
  id: string;
  name: string;
  api_url: string;
  enabled: boolean;
  verify_tls: boolean;
  vdoms: string[] | null;
  sync_dhcp: boolean;
  sync_dhcp_ranges: boolean;
  sync_arp: boolean;
  sync_vpn: boolean;
  sync_policies: boolean;
  sync_nat: boolean;
  sync_addresses: boolean;
  sync_interval_seconds: number;
  description: string | null;
  scope_subnet_ids: string[] | null;
  last_sync_at: string | null;
  last_error: string | null;
}

export interface FortiGateWrite {
  name: string;
  api_url: string;
  api_token?: string;
  enabled?: boolean;
  verify_tls?: boolean;
  vdoms?: string[] | null;
  sync_dhcp?: boolean;
  sync_dhcp_ranges?: boolean;
  sync_arp?: boolean;
  sync_vpn?: boolean;
  sync_policies?: boolean;
  sync_nat?: boolean;
  sync_addresses?: boolean;
  sync_interval_seconds?: number;
  description?: string;
  scope_subnet_ids?: string[];
}

/** 連線診斷：逐端點回報是否可讀與筆數 */
export interface FortiGateDiagnosis {
  api_url: string;
  vdoms: string[];
  ok_count: number;
  checks: { endpoint: string; ok: boolean; rows?: number; error?: string }[];
}

export interface FortiGatePolicy {
  id: string; vdom: string; policyid: string; name: string | null;
  status: string | null; action: string | null;
  srcintf: string | null; dstintf: string | null;
  srcaddr: string | null; dstaddr: string | null;
  service: string | null; nat: boolean | null; comments: string | null;
}

export interface FortiGateAddressObject {
  id: string; vdom: string; name: string; kind: string;
  obj_type: string | null; value: string | null;
  members: string[] | null; comment: string | null;
}

export async function listFortiGate(): Promise<Paginated<FortiGateFirewall>> {
  const { data } = await apiClient.get<Paginated<FortiGateFirewall>>("/api/v1/fortigate", {
    params: { page: 1, page_size: 200 },
  });
  return data;
}

export async function createFortiGate(p: FortiGateWrite): Promise<FortiGateFirewall> {
  const { data } = await apiClient.post<FortiGateFirewall>("/api/v1/fortigate", p);
  return data;
}

export async function updateFortiGate(id: string, p: Partial<FortiGateWrite>): Promise<FortiGateFirewall> {
  const { data } = await apiClient.patch<FortiGateFirewall>(`/api/v1/fortigate/${id}`, p);
  return data;
}

export async function deleteFortiGate(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/fortigate/${id}`);
}

export async function testFortiGate(id: string): Promise<FortiGateDiagnosis> {
  const { data } = await apiClient.post<FortiGateDiagnosis>(`/api/v1/fortigate/${id}/test`);
  return data;
}

export async function syncFortiGate(id: string): Promise<{ task_id: string }> {
  const { data } = await apiClient.post(`/api/v1/fortigate/${id}/sync`);
  return data;
}

export async function listFortiGatePolicies(id: string, vdom?: string): Promise<FortiGatePolicy[]> {
  const { data } = await apiClient.get<{ items: FortiGatePolicy[] }>(
    `/api/v1/fortigate/${id}/policies`, { params: vdom ? { vdom } : undefined });
  return data.items ?? [];
}

export async function listFortiGateAddresses(id: string, vdom?: string): Promise<FortiGateAddressObject[]> {
  const { data } = await apiClient.get<{ items: FortiGateAddressObject[] }>(
    `/api/v1/fortigate/${id}/addresses`, { params: vdom ? { vdom } : undefined });
  return data.items ?? [];
}
