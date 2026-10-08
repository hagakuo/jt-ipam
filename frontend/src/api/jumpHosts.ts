import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// 跳板主機（issue #24 階段一）。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface JumpHost {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_kind: "key" | "password";
  enabled: boolean;
  /** 同時允許的主控台連線數（多個 session 共用一條 SSH 連線） */
  max_sessions: number;
  description: string | null;
  /** 已釘選的主機金鑰指紋；空＝尚未信任，連線會被擋下 */
  host_key_fingerprint: string | null;
  /** 有沒有設過金鑰／密碼（不會回內容） */
  has_secret: boolean;
  last_ok_at: string | null;
  last_error: string | null;
}

export interface JumpHostWrite {
  name: string;
  host: string;
  port?: number;
  username: string;
  auth_kind?: "key" | "password";
  private_key?: string;
  password?: string;
  enabled?: boolean;
  max_sessions?: number;
  description?: string;
  host_key_fingerprint?: string | null;
}

/** 測試連線：未釘選指紋前只取指紋、不送帳密 */
export interface JumpHostProbe {
  host: string;
  port: number;
  fingerprint: string;
  pinned: string | null;
  /** 指紋是否與釘選的相符；尚未釘選為 null */
  matches: boolean | null;
  authenticated: boolean;
  server_version?: string | null;
  note?: string;
}

export interface JumpHostUsage {
  subnets: { id: string; cidr: string }[];
  ips: { id: string; ip: string }[];
}

export async function listJumpHosts(): Promise<Paginated<JumpHost>> {
  const { data } = await apiClient.get<Paginated<JumpHost>>("/api/v1/jump-hosts", {
    params: { page: 1, page_size: 200 },
  });
  return data;
}

export async function createJumpHost(p: JumpHostWrite): Promise<JumpHost> {
  const { data } = await apiClient.post<JumpHost>("/api/v1/jump-hosts", p);
  return data;
}

export async function updateJumpHost(id: string, p: Partial<JumpHostWrite>): Promise<JumpHost> {
  const { data } = await apiClient.patch<JumpHost>(`/api/v1/jump-hosts/${id}`, p);
  return data;
}

export async function deleteJumpHost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/jump-hosts/${id}`);
}

export async function testJumpHost(id: string): Promise<JumpHostProbe> {
  const { data } = await apiClient.post<JumpHostProbe>(`/api/v1/jump-hosts/${id}/test`);
  return data;
}

export async function jumpHostUsage(id: string): Promise<JumpHostUsage> {
  const { data } = await apiClient.get<JumpHostUsage>(`/api/v1/jump-hosts/${id}/usage`);
  return data;
}
