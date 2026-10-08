import { apiClient } from "@/api/client";
import { LONG_OP_TIMEOUT_MS } from "@/api/integrations";
import type { Paginated } from "@/types";

// 獨立的 DHCP 伺服器（issue #45）：Kea（jt-ipam 拉 JSON 控制 API）與 ISC DHCP（掃描代理讀檔回報）。

export interface KeaDhcpServer {
  id: string;
  name: string;
  api_url: string;
  verify_tls: boolean;
  username: string | null;
  has_password: boolean;
  enabled: boolean;
  sync_scopes: boolean;
  sync_leases: boolean;
  sync_interval_seconds: number;
  description: string | null;
  scope_subnet_ids: string[] | null;
  last_sync_at: string | null;
  last_error: string | null;
  last_summary: {
    mode?: "agent" | "direct"; version?: string | null; subnets?: number;
    pools?: number; reservations?: number; leases?: number;
    leases_unsupported?: boolean; leases_truncated?: boolean; host_cmds?: boolean;
  } | null;
}

export interface KeaDhcpWrite {
  name: string;
  api_url: string;
  verify_tls?: boolean;
  username?: string | null;
  password?: string;
  enabled?: boolean;
  sync_scopes?: boolean;
  sync_leases?: boolean;
  sync_interval_seconds?: number;
  description?: string;
  scope_subnet_ids?: string[];
}

export interface KeaTestResult {
  mode: "agent" | "direct"; version: string | null; subnets: number; pools: number;
  reservations: number; leases_supported: boolean;
}

export interface IscFileStatus { path: string | null; ok: boolean; error: string | null; size: number | null; mtime: number | null }

export interface IscDhcpServer {
  id: string;
  name: string;
  agent_id: string | null;
  agent_name: string | null;
  agent_version: string | null;
  agent_last_seen_at: string | null;
  enabled: boolean;
  sync_scopes: boolean;
  sync_leases: boolean;
  report_interval_seconds: number;
  description: string | null;
  scope_subnet_ids: string[] | null;
  last_sync_at: string | null;
  last_error: string | null;
  file_status: { conf?: IscFileStatus; leases?: IscFileStatus } | null;
  last_summary: { pools?: number; reservations?: number; leases?: number;
                  reported_pools?: number; reported_reservations?: number; reported_leases?: number } | null;
}

export interface IscDhcpWrite {
  name: string;
  agent_id: string | null;
  enabled?: boolean;
  sync_scopes?: boolean;
  sync_leases?: boolean;
  report_interval_seconds?: number;
  description?: string;
  scope_subnet_ids?: string[];
}

const KEA = "/api/v1/kea-dhcp/servers";
const ISC = "/api/v1/isc-dhcp/servers";

export async function listKea(): Promise<Paginated<KeaDhcpServer>> {
  return (await apiClient.get<Paginated<KeaDhcpServer>>(KEA, { params: { page: 1, page_size: 200 } })).data;
}
export async function createKea(p: KeaDhcpWrite): Promise<KeaDhcpServer> {
  return (await apiClient.post<KeaDhcpServer>(KEA, p)).data;
}
export async function updateKea(id: string, p: Partial<KeaDhcpWrite>): Promise<KeaDhcpServer> {
  return (await apiClient.patch<KeaDhcpServer>(`${KEA}/${id}`, p)).data;
}
export async function deleteKea(id: string): Promise<void> {
  await apiClient.delete(`${KEA}/${id}`);
}
export async function testKea(id: string): Promise<KeaTestResult> {
  // 連不上的主機要等到後端 30 秒的連線逾時才有原因可講；用預設 15 秒只會看到前端自己的逾時
  return (await apiClient.post<KeaTestResult>(`${KEA}/${id}/test`, undefined, { timeout: LONG_OP_TIMEOUT_MS })).data;
}
export async function syncKea(id: string): Promise<{ task_id: string }> {
  return (await apiClient.post(`${KEA}/${id}/sync`)).data;
}

export async function listIsc(): Promise<Paginated<IscDhcpServer>> {
  return (await apiClient.get<Paginated<IscDhcpServer>>(ISC, { params: { page: 1, page_size: 200 } })).data;
}
export async function createIsc(p: IscDhcpWrite): Promise<IscDhcpServer> {
  return (await apiClient.post<IscDhcpServer>(ISC, p)).data;
}
export async function updateIsc(id: string, p: Partial<IscDhcpWrite>): Promise<IscDhcpServer> {
  return (await apiClient.patch<IscDhcpServer>(`${ISC}/${id}`, p)).data;
}
export async function deleteIsc(id: string): Promise<void> {
  await apiClient.delete(`${ISC}/${id}`);
}
