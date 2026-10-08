<script setup lang="ts">
/**
 * 掃描代理判讀出的設備類型圖示（IP 的 device_kind，見後端 services/device_identity）。
 * 類型名稱沿用 IP 探測的譯名（identify.type.*），兩處講的是同一套判讀、用同一組字。
 */
import { computed } from "vue";
import { NIcon } from "naive-ui";
import { useI18n } from "vue-i18n";
import {
  Computer, CubeDots, HardDrive, Headset, Industry, ModernTv, Network, NetworkLeft, PcFirewall, Printer,
  Server, SmartphoneDevice, VideoCamera, Wifi,
} from "@iconoir/vue";

const props = defineProps<{ kind?: string | null; size?: number }>();
const { t, te } = useI18n();

const ICONS: Record<string, unknown> = {
  router: Network, switch: NetworkLeft, firewall: PcFirewall, wireless_ap: Wifi, printer: Printer,
  camera: VideoCamera, voip: Headset, storage: HardDrive, hypervisor: CubeDots, media: ModernTv,
  specialized: Industry, server: Server, windows: Computer, mobile: SmartphoneDevice,
};
const icon = computed(() => (props.kind ? ICONS[props.kind] : undefined));
const label = computed(() => {
  if (!props.kind) return "";
  const key = `identify.type.${props.kind}`;
  return te(key) ? t(key) : props.kind;
});
defineExpose({ label });
</script>

<template>
  <n-icon v-if="icon" :size="size || 16" :title="label" :aria-label="label" class="dk-icon">
    <component :is="icon" />
  </n-icon>
</template>

<style scoped>
.dk-icon { flex: none; opacity: .85; }
</style>
