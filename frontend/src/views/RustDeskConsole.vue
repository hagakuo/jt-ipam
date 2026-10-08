<script setup lang="ts">
/** 另開分頁的全頁「相容 RustDesk 的網頁連線」畫面。載入 IP 後渲染全高 RustDeskScreen。 */
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { useI18n } from "vue-i18n";
import { NSpin, NResult } from "naive-ui";
import { getAddress } from "@/api/addresses";
import RustDeskScreen from "@/components/RustDeskScreen.vue";
import type { IPAddress } from "@/types";

const route = useRoute();
const { t } = useI18n();
const addr = ref<IPAddress | null>(null);
const loading = ref(true);
const failed = ref(false);

onMounted(async () => {
  try {
    addr.value = await getAddress(String(route.params.id));
    if (addr.value?.ip) document.title = `RustDesk · ${addr.value.ip}`;
  } catch {
    failed.value = true;
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="rdw-page">
    <n-spin v-if="loading" :show="true" style="margin:80px auto;display:block" />
    <n-result v-else-if="failed || !addr" status="403" :title="t('rdweb.err_generic')" />
    <RustDeskScreen v-else :address-id="addr.id" :ip="addr.ip" :hostname="addr.hostname"
                    :device-name="addr.device_name" :peer-id="addr.rustdesk?.id ?? null" full-height />
  </div>
</template>

<style scoped>
/* 獨立全頁 route（不在 MainLayout 內），需自己跟著主題上底色。 */
.rdw-page { position: fixed; inset: 0; display: flex; flex-direction: column;
  padding: 16px; box-sizing: border-box; overflow: hidden; background: #eef1f8; color: #1f2937; }
html[data-theme="dark"] .rdw-page { background: #070b14; color: #e8f0fb; }
</style>
