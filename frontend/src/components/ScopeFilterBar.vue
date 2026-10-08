<script setup lang="ts">
/** 區段／子網路／單位／上線狀態篩選下拉（搭配 useRemoteMissing；選項由後端從整份缺口算好）。 */
import { computed } from "vue";
import { NSelect } from "naive-ui";
import { useI18n } from "vue-i18n";

type Opt = { label: string; value: string };
const props = defineProps<{ sectionOpts: Opt[]; subnetOpts: Opt[]; customerOpts: Opt[]; statusOpts?: Opt[] }>();
const section = defineModel<string | null>("section", { default: null });
const subnet = defineModel<string | null>("subnet", { default: null });
const customer = defineModel<string | null>("customer", { default: null });
const status = defineModel<string | null>("status", { default: null });
const { t } = useI18n();
// 狀態名稱與 IP 清單燈號的說明一致（visualisation.online／stale／offline／unknown）
const statusOptions = computed(() => (props.statusOpts ?? [])
  .map((o) => ({ value: o.value, label: t(`visualisation.${o.value}`) })));
</script>

<template>
  <!-- 外層要自己排成一列：n-select 是區塊元素，放進 n-space 的同一格會上下疊起來 -->
  <div class="scope-filter">
  <n-select v-model:value="section" :options="sectionOpts" clearable filterable
            :placeholder="t('scope_filter.section')" style="width: 170px" />
  <n-select v-model:value="subnet" :options="subnetOpts" clearable filterable
            :placeholder="t('scope_filter.subnet')" style="width: 190px" />
  <n-select v-model:value="customer" :options="customerOpts" clearable filterable
            :placeholder="t('scope_filter.customer')" style="width: 170px" />
  <n-select v-if="statusOpts" v-model:value="status" :options="statusOptions" clearable
            :placeholder="t('scope_filter.status')" style="width: 130px" data-testid="scope-status" />
  </div>
</template>

<style scoped>
.scope-filter { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
</style>
