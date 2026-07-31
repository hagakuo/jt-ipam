import { apiClient } from "@/api/client";
import type { Paginated } from "@/types";

// API 權杖（自助）。路徑帶 /api/v1 前綴（baseURL 為 /）。

export interface ApiToken {
  id: string;
  name: string;
  token_prefix: string;
  scopes: string[];
  object_filters: Record<string, unknown> | null;
  expires_at: string;
  last_used_at: string | null;
  last_used_ip: string | null;
  revoked_at: string | null;
  created_at: string;
}

/** 建立成功時一次性回傳明文 token，之後再也拿不到。 */
export interface ApiTokenCreated {
  id: string;
  name: string;
  token: string;
  token_prefix: string;
  expires_at: string;
  scopes: string[];
}

export interface ApiTokenCreate {
  name: string;
  expires_in_days: number;
  /** 留空＝不限制（沿用擁有者權限）；["read"]＝唯讀。目前只支援這兩種。 */
  scopes: string[];
}

export async function listApiTokens(page = 1, pageSize = 200): Promise<Paginated<ApiToken>> {
  const { data } = await apiClient.get("/api/v1/api-tokens", {
    params: { page, page_size: pageSize },
  });
  return data;
}

export async function createApiToken(payload: ApiTokenCreate): Promise<ApiTokenCreated> {
  const { data } = await apiClient.post("/api/v1/api-tokens", payload);
  return data;
}

export async function revokeApiToken(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/api-tokens/${id}`);
}
