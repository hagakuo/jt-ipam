/**
 * 「狀態」欄：跟 IP 清單同一顆燈號（LiveStatusDot）、同一套上線規則（classifyAddressLiveness）。
 * 顯示、排序（上線 → 近期出現 → 離線 → 未知）與匯出的文字都在這裡，
 * 用到的清單（Wazuh、OCS 的「未裝 Agent 的 IP」）共用這一份。
 */
import { h } from "vue";
import LiveStatusDot from "@/components/LiveStatusDot.vue";
import { classifyAddressLiveness, type LivenessKind } from "@/composables/useLivenessSettings";
import { withExportValue } from "@/utils/tableExport";

const RANK: Record<LivenessKind, number> = { online: 0, stale: 1, offline: 2, unknown: 3 };

export function livenessColumn(title: string, t: (key: string) => string): any {
  return withExportValue({
    title, key: "status", width: 80, titleAlign: "center", align: "center",
    sorter: (a: any, b: any) => RANK[classifyAddressLiveness(a)] - RANK[classifyAddressLiveness(b)],
    render: (r: any) => h(LiveStatusDot, { address: r }),
  }, (r: any) => t(`visualisation.${classifyAddressLiveness(r)}`));
}
