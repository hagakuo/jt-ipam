import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// Palo Alto（PAN-OS）整合。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface PaloAltoFirewall {
  id: string;
  name: string;
  api_url: string;
  enabled: boolean;
  verify_tls: boolean;
  /** REST URI 的版本段（如 v11.1）。留空＝自動偵測 */
  api_version: string | null;
  vsys_list: string[] | null;
  sync_dhcp: boolean;
  sync_arp: boolean;
  sync_policies: boolean;
  sync_nat: boolean;
  sync_addresses: boolean;
  /** 站對站 VPN（IPsec，show vpn flow）：預設開，拓樸圖據此畫出與對端之間的 VPN */
  sync_vpn?: boolean;
  sync_interval_seconds: number;
  description: string | null;
  scope_subnet_ids: string[] | null;
  last_sync_at: string | null;
  last_error: string | null;
}

export interface PaloAltoWrite {
  name: string;
  api_url: string;
  api_key?: string;
  enabled?: boolean;
  verify_tls?: boolean;
  api_version?: string | null;
  /** PATCH 的 null 是「不修改」→ 要改回自動偵測得用這個旗標 */
  clear_api_version?: boolean;
  vsys_list?: string[] | null;
  sync_dhcp?: boolean;
  sync_arp?: boolean;
  sync_policies?: boolean;
  sync_nat?: boolean;
  sync_addresses?: boolean;
  sync_vpn?: boolean;
  sync_interval_seconds?: number;
  description?: string;
  scope_subnet_ids?: string[];
}

/** 連線診斷：逐端點回報是否可讀與筆數（沒有實機時，這是唯一能對齊欄位的辦法） */
export interface PaloAltoDiagnosis {
  api_url: string;
  api_version: string;
  vsys: string[];
  ok_count: number;
  checks: { endpoint: string; ok: boolean; rows?: number; error?: string }[];
}

export interface PaloAltoPolicy {
  id: string; vsys: string; name: string; position: number;
  action: string | null; disabled: boolean;
  from_zone: string | null; to_zone: string | null;
  source: string | null; destination: string | null;
  application: string | null; service: string | null; description: string | null;
}

export interface PaloAltoAddressObject {
  id: string; vsys: string; name: string; kind: string;
  obj_type: string | null; value: string | null;
  members: string[] | null; description: string | null;
}

export async function listPaloAlto(): Promise<Paginated<PaloAltoFirewall>> {
  const { data } = await apiClient.get<Paginated<PaloAltoFirewall>>("/api/v1/paloalto", {
    params: { page: 1, page_size: 200 },
  });
  return data;
}

export async function createPaloAlto(p: PaloAltoWrite): Promise<PaloAltoFirewall> {
  const { data } = await apiClient.post<PaloAltoFirewall>("/api/v1/paloalto", p);
  return data;
}

export async function updatePaloAlto(
  id: string, p: Partial<PaloAltoWrite>,
): Promise<PaloAltoFirewall> {
  const { data } = await apiClient.patch<PaloAltoFirewall>(`/api/v1/paloalto/${id}`, p);
  return data;
}

export async function deletePaloAlto(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/paloalto/${id}`);
}

export async function testPaloAlto(id: string): Promise<PaloAltoDiagnosis> {
  const { data } = await apiClient.post<PaloAltoDiagnosis>(`/api/v1/paloalto/${id}/test`);
  return data;
}

export async function syncPaloAlto(id: string): Promise<{ task_id: string }> {
  const { data } = await apiClient.post(`/api/v1/paloalto/${id}/sync`);
  return data;
}

export async function listPaloAltoPolicies(
  id: string, vsys?: string,
): Promise<PaloAltoPolicy[]> {
  const { data } = await apiClient.get<{ items: PaloAltoPolicy[] }>(
    `/api/v1/paloalto/${id}/policies`, { params: vsys ? { vsys } : undefined });
  return data.items ?? [];
}

export async function listPaloAltoAddresses(
  id: string, vsys?: string,
): Promise<PaloAltoAddressObject[]> {
  const { data } = await apiClient.get<{ items: PaloAltoAddressObject[] }>(
    `/api/v1/paloalto/${id}/addresses`, { params: vsys ? { vsys } : undefined });
  return data.items ?? [];
}
