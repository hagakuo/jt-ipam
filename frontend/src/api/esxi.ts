import { apiClient } from "./client";

/**
 * ESXi / vCenter 整合（vSphere SOAP）。
 * 路徑要自帶 /api/v1 首碼（client 的 baseURL 是 "/"）。
 */
export interface ESXiInstance {
  id: string;
  name: string;
  api_url: string;
  extra_api_urls?: string | null;
  username: string;
  enabled: boolean;
  verify_tls: boolean;
  sync_interval_seconds: number;
  scope_subnet_ids?: string[] | null;
  description?: string | null;
  cluster_id?: string | null;
  last_sync_at?: string | null;
  last_error?: string | null;
}

export interface ESXiDiagStep { step: string; ok: boolean; detail: string }

/**
 * 新增／編輯送出的欄位。
 *
 * 原本是 `Record<string, unknown>` —— 送什麼都合法，所以少送、多送、打錯字都不會被
 * 型別擋下（客戶回報的 422 就是後端 schema 少一個鍵，前端這邊完全無感）。收緊型別
 * 能擋掉拼錯，但**擋不掉前後端不同步**：那只有實際打到後端 schema 的測試抓得到，
 * 見 `backend/tests/test_esxi_endpoint_fields.py`。
 */
export interface ESXiPayload {
  name: string;
  api_url: string;
  /** 備援位址（換行或逗號分隔）；沒填送 null */
  extra_api_urls: string | null;
  username: string;
  /** 編輯時留空＝不變更，因此是選填 */
  password?: string;
  enabled: boolean;
  verify_tls: boolean;
  sync_interval_seconds: number;
  scope_subnet_ids: string[] | null;
  description: string | null;
}

export const ESXi = {
  async list(): Promise<ESXiInstance[]> {
    const { data } = await apiClient.get("/api/v1/esxi");
    return data;
  },
  async create(payload: ESXiPayload): Promise<ESXiInstance> {
    const { data } = await apiClient.post("/api/v1/esxi", payload);
    return data;
  },
  async update(id: string, payload: Partial<ESXiPayload>): Promise<ESXiInstance> {
    const { data } = await apiClient.patch(`/api/v1/esxi/${id}`, payload);
    return data;
  },
  async remove(id: string): Promise<void> {
    await apiClient.delete(`/api/v1/esxi/${id}`);
  },
  async test(id: string): Promise<{ ok: boolean; steps: ESXiDiagStep[] }> {
    const { data } = await apiClient.post(`/api/v1/esxi/${id}/test`);
    return data;
  },
  async sync(id: string): Promise<Record<string, number>> {
    const { data } = await apiClient.post(`/api/v1/esxi/${id}/sync`);
    return data;
  },
};
