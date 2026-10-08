import { apiClient } from "@/api/client";

export interface CytoscapeNode {
  data: {
    id: string;
    label: string;
    type: string;
    vendor?: string | null;
    model?: string | null;
    rack_id?: string | null;
    location_id?: string | null;
  };
}

export interface CytoscapeEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label?: string;
    // l2 = FDB 存取層（機器 ↔ 交換器埠）、l2_uplink = 交換器之間的骨幹
    kind: "cable" | "wireless" | "vpn" | "l3" | "l2" | "l2_uplink" | "vm_host";
    /** 這條線是誰說的：人為登記 / 第三方監控 / 被動學到 / 我們自己推的 */
    evidence?: "asserted" | "monitored" | "learned" | "inferred";
    type?: string;
    color?: string | null;
    status?: string;
    distance_m?: number | null;
    ssid?: string | null;
  };
}

export interface TopologyData {
  nodes: CytoscapeNode[];
  edges: CytoscapeEdge[];
  /** 裝置太多（超過後端上限）時不建圖，只回這個：畫面請使用者先用子網路篩選 */
  too_large?: { devices: number; limit: number };
}

export async function getTopology(params: {
  locationId?: string;
  subnetIds?: string[];
  includeWireless?: boolean;
  includeVpn?: boolean;
  includeL3?: boolean;
  includeFdb?: boolean;
  includeVms?: boolean;
  onlineOnly?: boolean;
} = {}): Promise<TopologyData> {
  const { data } = await apiClient.get<TopologyData>("/api/v1/topology", {
    params: {
      location_id: params.locationId,
      subnet_id: params.subnetIds && params.subnetIds.length ? params.subnetIds : undefined,
      include_wireless: params.includeWireless ?? true,
      include_vpn: params.includeVpn ?? true,
      include_l3: params.includeL3 ?? true,
      include_fdb: params.includeFdb ?? true,
      include_vms: params.includeVms ?? false,
      online_only: params.onlineOnly ?? false,
    },
    paramsSerializer: { indexes: null },  // subnet_id 重複 key
  });
  return data;
}
