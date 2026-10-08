import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";
import type { MissingPage, MissingQuery } from "@/composables/useRemoteMissing";

// OCS Inventory NG 整合。路徑帶 /api/v1 前綴（baseURL 為 /）。
// 與其他整合最大不同：帳密選用（OCS REST 預設無驗證）。

export interface OcsServer {
  id: string;
  name: string;
  source_type: string;
  base_url: string | null;
  enabled: boolean;
  verify_tls: boolean;
  api_username: string | null;
  /** 有沒有設密碼（後端不回明文） */
  has_password: boolean;
  sync_interval_seconds: number;
  stale_after_days: number;
  sync_networks: boolean;
  sync_bios: boolean;
  /** 預設關：軟體讓每台 ~2 KB → ~80 KB */
  sync_software: boolean;
  scope_subnet_ids?: string[] | null;
  detected_version: string | null;
  last_sync_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  last_cost: Record<string, unknown> | null;
}

export interface OcsWrite {
  name: string;
  base_url: string;
  enabled?: boolean;
  verify_tls?: boolean;
  api_username?: string | null;
  api_password?: string;
  /** 明確清掉已存帳密（改回無驗證） */
  clear_credentials?: boolean;
  sync_interval_seconds?: number;
  stale_after_days?: number;
  sync_networks?: boolean;
  sync_bios?: boolean;
  sync_software?: boolean;
  scope_subnet_ids?: string[];
}

export interface OcsDiagnosis {
  base_url: string | null;
  source_type: string;
  reachable?: boolean;
  computer_count?: number | null;
  incremental?: boolean;
  auth_required?: boolean;
  /** true = 這套 OCS 沒帶憑證也讀得到 → 該警告站台 */
  unauthenticated_access?: boolean;
}

export async function listOcs(): Promise<Paginated<OcsServer>> {
  const { data } = await apiClient.get<Paginated<OcsServer>>("/api/v1/ocs", {
    params: { page: 1, page_size: 200 },
  });
  return data;
}

export async function createOcs(p: OcsWrite): Promise<OcsServer> {
  const { data } = await apiClient.post<OcsServer>("/api/v1/ocs", p);
  return data;
}

export async function updateOcs(id: string, p: Partial<OcsWrite>): Promise<OcsServer> {
  const { data } = await apiClient.patch<OcsServer>(`/api/v1/ocs/${id}`, p);
  return data;
}

export async function deleteOcs(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/ocs/${id}`);
}

export async function testOcs(id: string): Promise<OcsDiagnosis> {
  const { data } = await apiClient.post<OcsDiagnosis>(`/api/v1/ocs/${id}/test`);
  return data;
}

export async function syncOcs(id: string): Promise<{ task_id: string }> {
  const { data } = await apiClient.post(`/api/v1/ocs/${id}/sync`);
  return data;
}

/** OCS 盤點到的電腦，一台一筆（一台電腦的多個 IP 彙整在 ips）。 */
export interface OcsAgent {
  ocs_id: number | null;
  name: string | null;
  ips: string[];
  ip_address_ids: string[];
  os: string | null;
  agent_version: string | null;
  tag: string | null;
  last_inventory: string | null;
}

/** 有主機名稱、卻從來沒被 OCS 盤點過的 IP（同 Wazuh 的 MissingAgent）。 */
export interface OcsMissingAgent {
  ip_address_id: string;
  ip: string | null;
  hostname: string | null;
  // 所屬範圍（依區段／子網路／單位篩選用）
  subnet_id?: string | null;
  subnet_cidr?: string | null;
  section_id?: string | null;
  section_name?: string | null;
  customer_id?: string | null;
  customer_name?: string | null;
  // 設備類型欄（掃描代理判讀出的類型與型號）
  device_kind?: string | null;
  device_model?: string | null;
}

export async function listOcsAgents(): Promise<{ items: OcsAgent[]; total: number }> {
  const { data } = await apiClient.get("/api/v1/ocs/agents");
  return data;
}

/** 帶 page ＝ 伺服器端分頁：篩選、排序、篩選選項都由後端算（見 useRemoteMissing）。 */
export async function listOcsMissingAgentsPage(params: MissingQuery): Promise<MissingPage<OcsMissingAgent>> {
  const { data } = await apiClient.get<MissingPage<OcsMissingAgent>>("/api/v1/ocs/missing-agents", { params });
  return data;
}
