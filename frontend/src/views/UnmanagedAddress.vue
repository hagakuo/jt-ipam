<template>
  <!-- 未納管位址頁：IPAM 沒有這個位址的記錄，但看得到它在用（指示計的虛線格、IP 清單的未納管列點進來）。
       沒有記錄所以沒有欄位可以編，只列看到它的來源提供的資訊；右上可以探測、新增或返回（使用者 2026-10-07） -->
  <div class="um-page">
    <n-card :bordered="false" content-style="padding: 14px 16px">
      <div class="um-head">
        <div class="um-head__title" data-testid="um-title">
          <span class="um-dot" />
          <span class="um-ip">{{ ip }}</span>
          <n-tag size="small" type="warning">{{ t("visualisation.unmanaged") }}</n-tag>
        </div>
        <n-space :size="8" :wrap="true">
          <!-- 探測要管理員（跟 IP 頁一樣）；以位址探測，後端會確認位址在管理的子網路內 -->
          <n-button v-if="auth.me?.is_admin" size="small" data-testid="um-identify"
                    @click="router.push({ name: 'ip-identify', params: { ip } })">
            <template #icon><n-icon><IdentifyIcon /></n-icon></template>{{ t("identify.title") }}
          </n-button>
          <n-button v-if="auth.me?.can_edit !== false" type="primary" size="small" data-testid="um-create"
                    :disabled="!subnet" @click="createOpen = true">
            <template #icon><n-icon><PlusIcon /></n-icon></template>{{ t("unmanaged_page.create") }}
          </n-button>
          <n-button size="small" data-testid="um-back" @click="goBack">
            <template #icon><n-icon><ArrowLeftIcon /></n-icon></template>{{ t("common.back") }}
          </n-button>
        </n-space>
      </div>
      <p class="um-intro">{{ t("unmanaged_page.intro") }}</p>
    </n-card>

    <n-alert v-if="error" type="error" :bordered="false">{{ error }}</n-alert>

    <n-card size="small">
      <n-spin :show="loading">
        <n-alert v-if="!loading && !sighting" type="info" :bordered="false" style="margin-bottom: 12px"
                 data-testid="um-not-seen">
          {{ t("unmanaged_page.not_seen") }}
        </n-alert>
        <n-descriptions bordered :column="narrow ? 1 : 2" size="small" label-placement="left"
                        :label-style="{ whiteSpace: 'nowrap' }" data-testid="um-info">
          <n-descriptions-item :label="t('nav.subnets')">
            <a v-if="subnet" class="um-link" @click="router.push({ name: 'subnet-detail', params: { id: subnet.id } })">
              {{ subnet.cidr }}<template v-if="subnet.description"> · {{ subnet.description }}</template>
            </a>
            <template v-else>—</template>
          </n-descriptions-item>
          <n-descriptions-item :label="t('unmanaged_page.seen_by')">
            {{ sighting ? unmanagedSources(t, sighting.sources) : "—" }}
          </n-descriptions-item>
          <n-descriptions-item :label="t('unmanaged_page.last_seen')">
            <template v-if="sighting?.last_seen_at">
              {{ fmtDateTime(sighting.last_seen_at) }}<span class="um-muted">（{{ fmtRelative(sighting.last_seen_at) }}）</span>
            </template>
            <template v-else>—</template>
          </n-descriptions-item>
          <n-descriptions-item :label="t('addresses.hostname')">{{ sighting?.hostname || "—" }}</n-descriptions-item>
          <n-descriptions-item label="MAC">
            <template v-if="sighting?.mac">
              <span class="um-mono">{{ sighting.mac }}</span>
              <span v-if="sighting.vendor" class="um-muted">（{{ sighting.vendor }}）</span>
              <n-tag v-else-if="isRandomMac(sighting.mac)" size="small" :bordered="false" type="warning"
                     style="margin-left: 6px">{{ t("identify.mac_random_tag") }}</n-tag>
            </template>
            <template v-else>—</template>
          </n-descriptions-item>
          <n-descriptions-item :label="t('unmanaged_page.record')">{{ t("unmanaged_page.no_record") }}</n-descriptions-item>
        </n-descriptions>
      </n-spin>
    </n-card>

    <IPAddressEditModal v-if="subnet" v-model:show="createOpen" :address="null"
                        :create-context="{ subnet_id: subnet.id, ip }" @created="onCreated" />
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { NAlert, NButton, NCard, NDescriptions, NDescriptionsItem, NIcon, NSpace, NSpin, NTag } from "naive-ui";
import { ArrowLeft as ArrowLeftIcon } from "@iconoir/vue";
import { apiErrMsg } from "@/api/client";
import { listUnmanaged, type UnmanagedAddress } from "@/api/addresses";
import { getSubnet } from "@/api/subnets";
import IPAddressEditModal from "@/components/IPAddressEditModal.vue";
import { IdentifyIcon, PlusIcon } from "@/icons";
import { useAuthStore } from "@/stores/auth";
import type { IPAddress, Subnet } from "@/types";
import { fmtDateTime, fmtRelative } from "@/utils/datetime";
import { isRandomMac } from "@/utils/mac";
import { unmanagedSources } from "@/utils/unmanaged";

const route = useRoute();
const router = useRouter();
const { t } = useI18n();
const auth = useAuthStore();

const subnetId = computed(() => String(route.params.id ?? ""));
const ip = computed(() => String(route.params.ip ?? ""));
const subnet = ref<Subnet | null>(null);
const sighting = ref<UnmanagedAddress | null>(null);
const loading = ref(true);
const error = ref("");
const createOpen = ref(false);
const winW = ref(window.innerWidth);
const narrow = computed(() => winW.value < 720);
function onResize() { winW.value = window.innerWidth; }

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const [sn, rows] = await Promise.all([getSubnet(subnetId.value), listUnmanaged(subnetId.value)]);
    subnet.value = sn;
    sighting.value = rows.find((r) => r.ip === ip.value) ?? null;
  } catch (e) {
    error.value = apiErrMsg(e);
  } finally {
    loading.value = false;
  }
}

/** 新增完就換成那筆記錄的 IP 頁（這一頁的位址已經不是未納管了） */
function onCreated(created: IPAddress) {
  createOpen.value = false;
  void router.replace({ name: "address-detail", params: { id: created.id } });
}

function goBack() {
  if (window.history.state?.back) router.back();
  else void router.push({ name: "subnet-detail", params: { id: subnetId.value } });
}

watch([subnetId, ip], () => void load());
onMounted(() => { window.addEventListener("resize", onResize); void load(); });
onBeforeUnmount(() => window.removeEventListener("resize", onResize));
</script>

<style scoped>
.um-page { display: flex; flex-direction: column; gap: 12px; }
.um-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.um-head__title { display: inline-flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 600; }
.um-ip { font-variant-numeric: tabular-nums; }
.um-dot { display: inline-block; width: 12px; height: 12px; border-radius: 50%; box-sizing: border-box;
  border: 1.5px dashed #f59e0b; background: rgba(245, 158, 11, 0.16); flex: none; }
.um-intro { margin: 8px 0 0; font-size: 13px; opacity: .75; line-height: 1.6; }
.um-link { cursor: pointer; color: #18a058; }
.um-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.um-muted { opacity: .65; font-size: 12.5px; }
</style>
