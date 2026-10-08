<script setup lang="ts">
/**
 * Recog 指紋庫（rapid7/recog）：版本、筆數、每個指紋檔、立即檢查更新。
 *
 * 比照「MAC 製造商資料庫 (OUI)」頁：版本資訊頁只列 Recog 的版本，詳細資訊與更新在這一頁
 * （使用者要求：細節跟更新不應該放在版本頁）。
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import {
  NCard, NSpace, NIcon, NTag, NButton, NAlert, NDescriptions, NDescriptionsItem, NDataTable, NInput,
  useMessage, type DataTableColumns,
} from "naive-ui";
import { IdentifyIcon, RefreshIcon } from "@/icons";
import { fmtDateTime } from "@/utils/datetime";
import { getRecogStatus, updateRecog, type RecogDbRow, type RecogStatus } from "@/api/system";
import { apiErrMsg } from "@/api/client";
import { autoSort } from "@/composables/useTableSort";

const { t } = useI18n();
const msg = useMessage();
const st = ref<(RecogStatus & { database_list: RecogDbRow[] }) | null>(null);
const busy = ref(false);
const q = ref("");

async function load() {
  try { st.value = await getRecogStatus(); }
  catch (e) { msg.error(apiErrMsg(e)); }
}

async function checkNow() {
  busy.value = true;
  try {
    const r = await updateRecog();
    if (r.result.status === "updated") msg.success(t("version.recog_updated", { v: r.result.release ?? "" }));
    else if (r.result.status === "up_to_date") msg.success(t("version.recog_up_to_date", { v: r.result.release ?? "" }));
    else msg.error(t("version.recog_error", { e: r.result.error ?? "" }), { duration: 10000, closable: true });
    await load();
  } catch (e) {
    msg.error(apiErrMsg(e), { duration: 10000, closable: true });
  } finally {
    busy.value = false;
  }
}

const rows = computed(() => {
  const s = q.value.trim().toLowerCase();
  const all = st.value?.database_list ?? [];
  return s ? all.filter((d) => [d.key, d.protocol, d.database_type].some((x) => (x ?? "").toLowerCase().includes(s))) : all;
});
const cols = computed<DataTableColumns<RecogDbRow>>(() => autoSort([
  { title: t("recog_admin.col_key"), key: "key", minWidth: 220, ellipsis: { tooltip: true } },
  { title: t("recog_admin.col_protocol"), key: "protocol", width: 120, render: (r) => r.protocol ?? "—" },
  { title: t("recog_admin.col_type"), key: "database_type", width: 120, render: (r) => r.database_type ?? "—" },
  { title: t("recog_admin.col_count"), key: "fingerprints", width: 110, align: "right",
    render: (r) => r.fingerprints.toLocaleString() },
]));

onMounted(() => { void load(); });
</script>

<template>
  <n-card>
    <template #header>
      <n-space align="center" :wrap-item="false">
        <n-icon :size="22"><IdentifyIcon /></n-icon>
        <span>{{ t("recog_admin.title") }}</span>
      </n-space>
    </template>

    <n-space vertical :size="16">
      <n-alert type="info" :show-icon="true" style="max-width: 860px">
        {{ t("recog_admin.intro") }}
        <div style="margin-top: 6px">{{ t("recog_admin.schedule_note") }}</div>
      </n-alert>

      <n-descriptions bordered :column="1" size="small" label-align="right" label-placement="left"
                      style="max-width: 720px" data-testid="recog-status">
        <n-descriptions-item :label="t('recog_admin.version')">
          <n-tag size="small" :type="st?.installed ? 'success' : 'warning'" :bordered="false">
            {{ st?.installed ? st.release : t("version.optional_absent") }}
          </n-tag>
          <span v-if="st?.latest && st.latest !== st.release" class="rc-note">
            {{ t("version.recog_latest", { v: st.latest }) }}
          </span>
        </n-descriptions-item>
        <n-descriptions-item :label="t('recog_admin.fingerprints')">
          {{ st?.installed ? t("recog_admin.fp_count", { n: st.fingerprints.toLocaleString(), d: st.databases }) : "—" }}
        </n-descriptions-item>
        <n-descriptions-item :label="t('recog_admin.installed_at')">
          {{ st?.updated_at ? fmtDateTime(st.updated_at) : "—" }}
        </n-descriptions-item>
        <n-descriptions-item :label="t('recog_admin.checked_at')">
          {{ st?.checked_at ? fmtDateTime(st.checked_at) : "—" }}
          <div v-if="st?.error" class="rc-err" data-testid="recog-error">{{ t("version.recog_error", { e: st.error }) }}</div>
        </n-descriptions-item>
        <n-descriptions-item :label="t('recog_admin.source')">
          <a v-if="st" :href="st.project_url" target="_blank" rel="noopener" class="rc-link">github.com/rapid7/recog</a>
          <span v-if="st" class="rc-note">{{ st.license }}</span>
        </n-descriptions-item>
      </n-descriptions>

      <n-space :wrap-item="false" align="center">
        <n-button type="primary" :loading="busy" data-testid="recog-update" @click="checkNow">
          <template #icon><n-icon><RefreshIcon /></n-icon></template>
          {{ t("version.recog_check_now") }}
        </n-button>
      </n-space>
      <div class="rc-hint">{{ t("version.recog_offline_hint", { cmd: "python -m app.cli.recog update --file recog-content-<version>.zip" }) }}</div>

      <template v-if="st?.database_list?.length">
        <n-space align="center" :wrap-item="false" justify="space-between">
          <strong>{{ t("recog_admin.db_title") }}</strong>
          <n-input v-model:value="q" clearable size="small" style="width: 240px"
                   :placeholder="t('recog_admin.filter')" />
        </n-space>
        <n-data-table :columns="cols" :data="rows" :bordered="false" size="small"
                      :pagination="{ pageSize: 50, showSizePicker: false }" :scroll-x="580" />
      </template>
    </n-space>
  </n-card>
</template>

<style scoped>
.rc-note { margin-left: 8px; font-size: 12px; opacity: .7; }
.rc-link { color: #18a058; text-decoration: none; }
.rc-link:hover { text-decoration: underline; }
.rc-err { margin-top: 4px; font-size: 12px; color: #d03050; }
.rc-hint { font-size: 12px; opacity: .65; margin-top: -8px; }
</style>
