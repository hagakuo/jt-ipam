<script setup lang="ts">
/**
 * IP 角色標記（清單視覺化）：閘道 / DHCP 伺服器 / 在 DHCP 範圍內。
 * 用緊湊 icon（+tooltip）呈現，避免寬文字標籤把 IP 欄擠成一條線。
 * 旗標由後端讀取端推導（is_gateway / is_dhcp_server / dhcp_server_auto / in_dhcp_range /
 * in_dhcp_lease / dhcp_observed_at）。
 *
 * 「有沒有登記」與「有沒有真的在發」是兩回事，兩個都要看得到：
 * 掃描代理實際收到它的 DHCPOFFER，但沒有被標記為 DHCP 伺服器 → 紅色警示（非法 DHCP）。
 * hideRange=true 時不畫「DHCP 範圍」點（給本身已有 DHCP 欄位的表格，如子網路詳細資料）。
 */
import { NIcon, NTooltip } from "naive-ui";
import { useI18n } from "vue-i18n";
import { GatewayIcon, DhcpServerIcon, ReservedIcon, UnregisteredIcon } from "@/icons";
import { fmtDateTime } from "@/utils/datetime";

const props = withDefaults(defineProps<{ row: any; hideRange?: boolean }>(), { hideRange: false });
const { t } = useI18n();
const r = () => props.row || {};
const isDhcpServer = () => r().is_dhcp_server || r().dhcp_server_auto;
const inRange = () => !props.hideRange && (r().in_dhcp_range || r().in_dhcp_lease);
// 實際觀測到在回應 DHCP
const observedAt = () => r().dhcp_observed_at as string | null | undefined;
// 觀測到、但沒有被標記為 DHCP 伺服器 → 就是非法 DHCP
const isRogueDhcp = () => !!observedAt() && !isDhcpServer();
// DHCP 上把這個位址綁給某張網卡 —— 位址不會被回收給別台
const isReserved = () => !!r().dhcp_reserved;
// 由整合自動建進來、沒有人登記過的位址（DHCP 租約／虛擬化回報／掃描代理探索）。
// 這種紀錄跟「有人登記過」在意義上差很多：它可能是私接的機器，只是剛好拿到租約、
// 或剛好被掃到。而且一旦被建進 IPAM，就不會再出現在「未授權 IP」異常偵測裡
// （那道偵測看的是「看得到、IPAM 沒有」）—— 所以它必須在清單上一眼認得出來。
const AUTO_SOURCES = ["opnsense", "pfsense", "proxmox", "vmware", "scanner", "librenms_arp"];
const isAutoAdded = () => AUTO_SOURCES.includes(String(r().discovery_source ?? ""));
// 來源名稱照翻譯（librenms_arp → LibreNMS ARP）；沒有翻譯的才大寫原樣顯示
const srcLabel = () => {
  const v = String(r().discovery_source ?? "");
  const key = `addresses.source_${v}`;
  const out = t(key);
  return out === key ? v.toUpperCase() : out;
};
</script>

<template>
  <span v-if="r().is_gateway || isDhcpServer() || inRange() || observedAt() || isReserved() || isAutoAdded()"
        class="ip-roles">
    <!-- 自動收錄、未經登記 —— 用紫色（提醒而非錯誤，跟指示計同色）並講清楚它的來歷 -->
    <n-tooltip v-if="isAutoAdded()" :delay="150">
      <template #trigger><n-icon :size="15" color="#8b5cf6" class="r-ic"><UnregisteredIcon /></n-icon></template>
      {{ t("addresses.role_auto_added") }} —
      {{ t("addresses.role_auto_added_hint", { src: srcLabel() }) }}
    </n-tooltip>
    <n-tooltip v-if="r().is_gateway" :delay="150">
      <template #trigger><n-icon :size="15" color="#2080f0" class="r-ic"><GatewayIcon /></n-icon></template>
      {{ t("addresses.role_gateway") }} — {{ t("addresses.role_gateway_hint") }}
    </n-tooltip>
    <n-tooltip v-if="isDhcpServer()" :delay="150">
      <template #trigger>
        <n-icon :size="15" :color="observedAt() ? '#18a058' : '#f0a020'" class="r-ic">
          <DhcpServerIcon />
        </n-icon>
      </template>
      {{ t("addresses.role_dhcp_server") }} —
      {{ r().is_dhcp_server ? t("addresses.role_dhcp_server_manual") : t("addresses.role_dhcp_server_auto") }}
      <template v-if="observedAt()">
        <br>{{ t("addresses.role_dhcp_observed", { at: fmtDateTime(observedAt()!) }) }}
      </template>
    </n-tooltip>
    <!-- 觀測到在發 DHCP，卻沒有被登記 —— 這是最該被看見的一種 -->
    <n-tooltip v-if="isRogueDhcp()" :delay="150">
      <template #trigger><n-icon :size="15" color="#d03050" class="r-ic"><DhcpServerIcon /></n-icon></template>
      {{ t("addresses.role_dhcp_rogue") }} —
      {{ t("addresses.role_dhcp_observed", { at: fmtDateTime(observedAt()!) }) }}
      <br>{{ t("addresses.role_dhcp_rogue_hint") }}
    </n-tooltip>
    <n-tooltip v-if="isReserved()" :delay="150">
      <template #trigger><n-icon :size="14" color="#18a058" class="r-ic"><ReservedIcon /></n-icon></template>
      {{ t("addresses.dhcp_reserved_tag") }} — {{ t("addresses.dhcp_reserved_hint") }}
    </n-tooltip>
    <n-tooltip v-if="inRange()" :delay="150">
      <template #trigger><span class="r-dot" /></template>
      {{ t("addresses.role_dhcp_range") }} — {{ t("addresses.role_dhcp_range_hint") }}
    </n-tooltip>
  </span>
</template>

<style scoped>
.ip-roles { display: inline-flex; align-items: center; gap: 3px; margin-left: 6px; vertical-align: middle; flex: none; }
.r-ic { display: inline-flex; }
.r-dot { width: 7px; height: 7px; border-radius: 50%; background: #909399; display: inline-block; }
</style>
