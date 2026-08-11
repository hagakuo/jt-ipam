import { apiClient } from "@/api/client";

export interface RelationNode {
  type: "section" | "subnet" | "ip" | "vm" | "vmnode" | "device" | "rack" | "location";
  id: string;
  label: string;
  sub?: string | null;
  /** proxmox / vmware —— 決定節點標籤與要連到哪一個虛擬化頁面 */
  platform?: string | null;
  /** 這個裝置節點其實是一台虛擬機（由後端推導） */
  is_vm?: boolean;
}

export async function getAddressRelations(id: string): Promise<RelationNode[]> {
  const { data } = await apiClient.get<{ chain: RelationNode[] }>(
    `/api/v1/addresses/${id}/relations`,
  );
  return data.chain;
}

export async function getDeviceRelations(id: string): Promise<RelationNode[]> {
  const { data } = await apiClient.get<{ chain: RelationNode[] }>(
    `/api/v1/devices/${id}/relations`,
  );
  return data.chain;
}
