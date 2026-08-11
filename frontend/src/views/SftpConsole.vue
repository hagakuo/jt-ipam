<script setup lang="ts">
/** 另開視窗的全頁 SFTP 檔案瀏覽器（與 SshConsole 同一個做法）。 */
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { useI18n } from "vue-i18n";
import { NSpin, NResult } from "naive-ui";
import { getAddress } from "@/api/addresses";
import SftpBrowser from "@/components/SftpBrowser.vue";
import type { IPAddress } from "@/types";

const route = useRoute();
const { t } = useI18n();
const addr = ref<IPAddress | null>(null);
const loading = ref(true);
const failed = ref(false);

onMounted(async () => {
  try {
    addr.value = await getAddress(String(route.params.id));
    if (addr.value?.ip) document.title = `SFTP · ${addr.value.ip}`;
  } catch {
    failed.value = true;
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="sftp-page">
    <n-spin v-if="loading" :show="true" style="margin:80px auto;display:block" />
    <n-result v-else-if="failed || !addr" status="403" :title="t('ssh.err_generic')" />
    <SftpBrowser v-else :address-id="addr.id" :host="String(addr.ip).split('/')[0]"
                 :hostname="addr.hostname" :device-name="addr.device_name" full-height />
  </div>
</template>

<style scoped>
/* 與 SshConsole 同一套：獨立全頁 route（不在 MainLayout 的 n-layout 內），
   所以要自己跟著主題上底色，否則深色模式下淺色文字會落在白底上。
   position:fixed + inset:0 精準填滿視窗，捲動交給裡面的表格。 */
.sftp-page { position: fixed; inset: 0; display: flex; flex-direction: column;
  padding: 16px; box-sizing: border-box; overflow: hidden; background: #eef1f8; color: #1f2937; }
html[data-theme="dark"] .sftp-page { background: #070b14; color: #e8f0fb; }
</style>
