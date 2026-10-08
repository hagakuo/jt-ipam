import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// Zabbix 整合。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface ZabbixInstance {
  id: string;
  name: string;
  api_url: string;
  enabled: boolean;
  verify_tls: boolean;
  api_user: string | null;
  has_api_token: boolean;
  has_api_password: boolean;
  scope_subnet_ids: string[] | null;
  sync_interval_seconds: number;
  description: string | null;
  last_sync_at: string | null;
  last_error: string | null;
}

export interface ZabbixWrite {
  name: string;
  api_url: string;
  api_token?: string;
  api_user?: string;
  api_password?: string;
  enabled?: boolean;
  verify_tls?: boolean;
  scope_subnet_ids?: string[];
  sync_interval_seconds?: number;
  description?: string;
}

export interface ZabbixHealth {
  version?: string;
  hosts_readable?: boolean;
  host_count?: number | null;
  error?: string;
}

export interface ZabbixHost {
  id: string;
  hostid: string;
  host: string;
  name: string | null;
  status: string | null;
  available: string | null;
  maintenance: boolean;
  ip: string | null;
  dns: string | null;
  groups: string[] | null;
  tags: { tag: string; value?: string }[] | null;
  ip_address_id: string | null;
  synced_at: string | null;
}

export interface ZabbixGapRow {
  ip_address_id: string;
  ip: string | null;
  hostname: string | null;
}

export async function listZabbix(): Promise<Paginated<ZabbixInstance>> {
  const { data } = await apiClient.get("/api/v1/zabbix", { params: { page_size: 200 } });
  return data;
}

export async function createZabbix(payload: ZabbixWrite): Promise<ZabbixInstance> {
  const { data } = await apiClient.post("/api/v1/zabbix", payload);
  return data;
}

export async function updateZabbix(id: string, payload: Partial<ZabbixWrite>): Promise<ZabbixInstance> {
  const { data } = await apiClient.patch(`/api/v1/zabbix/${id}`, payload);
  return data;
}

export async function deleteZabbix(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/zabbix/${id}`);
}

export async function testZabbix(id: string): Promise<ZabbixHealth> {
  const { data } = await apiClient.post(`/api/v1/zabbix/${id}/test`);
  return data;
}

export async function syncZabbix(id: string): Promise<{ task_id: string }> {
  const { data } = await apiClient.post(`/api/v1/zabbix/${id}/sync`);
  return data;
}

export async function listZabbixHosts(id: string, q?: string): Promise<{ items: ZabbixHost[] }> {
  const { data } = await apiClient.get(`/api/v1/zabbix/${id}/hosts`, { params: q ? { q } : {} });
  return data;
}

export async function zabbixCoverageGap(
  id: string, subnetIds?: string[],
): Promise<{ items: ZabbixGapRow[]; count: number; scope: string }> {
  const { data } = await apiClient.get(`/api/v1/zabbix/${id}/coverage-gap`, {
    params: subnetIds?.length ? { subnet_ids: subnetIds } : {},
  });
  return data;
}
