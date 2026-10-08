import { apiClient } from "@/api/client";

/** 子網路內的位址範圍（集區）—— GitHub issue #40。子網路維持 CIDR，範圍是它裡面的一段。 */
export type IPRangePurpose = "dhcp" | "reserved" | "other";

export interface IPRange {
  id: string;
  subnet_id: string;
  start_ip: string;
  end_ip: string;
  purpose: IPRangePurpose;
  name: string | null;
  description: string | null;
  /** 範圍內有幾個位址、其中幾個已有 IP 記錄、下一個還沒有記錄的位址 */
  size: number;
  used: number;
  first_free: string | null;
  /** 由偵測到的 DHCP 發放範圍自動建立（跟著上游走，不能手動改／刪）與它的來源 */
  auto?: boolean;
  source_label?: string | null;
}

export type IPRangeInput = Pick<IPRange, "start_ip" | "end_ip" | "purpose"> &
  Partial<Pick<IPRange, "name" | "description">>;

export async function listIPRanges(subnetId: string): Promise<IPRange[]> {
  const { data } = await apiClient.get<IPRange[]>(`/api/v1/subnets/${subnetId}/ranges`);
  return data;
}
export async function createIPRange(subnetId: string, body: IPRangeInput): Promise<IPRange> {
  const { data } = await apiClient.post<IPRange>(`/api/v1/subnets/${subnetId}/ranges`, body);
  return data;
}
export async function updateIPRange(subnetId: string, id: string, body: Partial<IPRangeInput>): Promise<IPRange> {
  const { data } = await apiClient.patch<IPRange>(`/api/v1/subnets/${subnetId}/ranges/${id}`, body);
  return data;
}
export async function deleteIPRange(subnetId: string, id: string): Promise<void> {
  await apiClient.delete(`/api/v1/subnets/${subnetId}/ranges/${id}`);
}

/** 各用途在位址圖上的標示色（格子底下那條線），與清單的標籤同色 */
export const RANGE_COLORS: Record<IPRangePurpose, string> = {
  dhcp: "#06b6d4",
  reserved: "#ec4899",
  other: "#94a3b8",
};
