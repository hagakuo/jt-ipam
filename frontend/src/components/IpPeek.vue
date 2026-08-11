<template>
  <div class="peek">
    <div class="peek-ip">{{ ip }}</div>
    <n-spin v-if="!data" :size="14" style="margin: 6px 0" />
    <div v-else-if="data.missing" class="peek-missing">{{ t("ip_peek.not_found") }}</div>
    <div v-else class="peek-rows">
      <div v-if="data.hostname" class="peek-row">
        <span class="k">{{ t("addresses.hostname") }}</span><span class="v">{{ data.hostname }}</span>
      </div>
      <!-- 這是兩個不同的欄位，不是一個狀態的兩個標籤：
           「狀態」是人登記的用途，「實際狀態」是監測量到的存活。兩個擠在同一列、
           又直接印英文原始值，看到的人只會覺得「怎麼又 active 又 unknown」。 -->
      <div class="peek-row">
        <span class="k">{{ t("addresses.state") }}</span>
        <span class="v">
          <n-tag size="tiny" :bordered="false" :type="data.state === 'active' ? 'success' : 'default'">
            {{ stateLabel(data.state) }}
          </n-tag>
        </span>
      </div>
      <div v-if="data.effective_status" class="peek-row">
        <span class="k">{{ t("addresses.effective_status") }}</span>
        <span class="v">
          <n-tag size="tiny" :bordered="false"
                 :type="String(data.effective_status).startsWith('online') ? 'success' : 'warning'">
            {{ effectiveLabel(data.effective_status) }}
          </n-tag>
        </span>
      </div>
      <div v-if="data.mac" class="peek-row">
        <span class="k">MAC</span><span class="v mono">{{ data.mac }}</span>
      </div>
      <div v-if="data.device_name" class="peek-row">
        <span class="k">{{ t("nav.devices") }}</span><span class="v">{{ data.device_name }}</span>
      </div>
      <div v-if="lastSeen" class="peek-row">
        <span class="k">{{ t("addresses.last_seen") }}</span><span class="v">{{ lastSeen }}</span>
      </div>
      <div v-if="roles.length" class="peek-row">
        <span class="k">{{ t("ip_peek.role") }}</span>
        <span class="v">
          <n-tag v-for="r in roles" :key="r" size="tiny" :bordered="false" type="info"
                 style="margin-right:4px">{{ r }}</n-tag>
        </span>
      </div>
      <div v-if="allocation" class="peek-row">
        <span class="k">{{ t("ip_peek.allocation") }}</span>
        <span class="v">
          <n-tag size="tiny" :bordered="false">{{ allocation }}</n-tag>
        </span>
      </div>
      <div v-if="data.description" class="peek-row">
        <span class="k">{{ t("common.description") }}</span>
        <span class="v">{{ data.description }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
// 依據資料裡的 IP 滑過去就看得到重點，不用先點進去才知道那是什麼機器。
// 查證的成本越低，使用者才越可能真的去查 —— 這整頁的重點就是「不要照單全收」。
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { NSpin, NTag } from "naive-ui";
import { fmtDateTime } from "@/utils/datetime";

export interface IpPeekData {
  missing?: boolean;
  is_gateway?: boolean | null;
  is_dhcp_server?: boolean | null;
  in_dhcp_range?: boolean | null;
  hostname?: string | null;
  state?: string | null;
  effective_status?: string | null;
  mac?: string | null;
  device_name?: string | null;
  description?: string | null;
  last_seen?: string | null;
}

const props = defineProps<{ ip: string; data?: IpPeekData | null }>();
const { t, te } = useI18n();

const lastSeen = computed(() => (props.data?.last_seen ? fmtDateTime(props.data.last_seen) : ""));

// 角色標籤：查證一筆「這台在發 DHCP」的發現時，這是最想先看到的一行
// 「角色」是這台機器在網路上扮演什麼（閘道、DHCP 伺服器）。
// 位址落在 DHCP 發放範圍**不是角色**，那是這個位址怎麼配發的 —— 兩件事混在同一列，
// 會讓人以為那台機器跟 DHCP 有什麼職務關係。分成兩列。
const roles = computed(() => {
  const d = props.data;
  if (!d) return [];
  const out: string[] = [];
  if (d.is_gateway) out.push(t("addresses.role_gateway"));
  if (d.is_dhcp_server) out.push(t("addresses.role_dhcp_server"));
  return out;
});
const allocation = computed(() => {
  const d = props.data;
  if (!d?.in_dhcp_range) return null;
  return t("addresses.dhcp_in_range_tag");
});
// 兩個欄位各有自己的字彙表；查不到就原樣顯示，不要憑空造字
function stateLabel(v?: string | null): string {
  const k = `addresses.state_${String(v || "")}`;
  return te(k) ? t(k) : String(v || "—");
}
// effective_status 帶著來源，如 "online (scanner)" —— 前段翻譯，來源原樣保留
function effectiveLabel(v?: string | null): string {
  const raw = String(v || "");
  const m = /^([a-z]+)(?:\s*\((.+)\))?$/.exec(raw);
  if (!m) return raw;
  const k = `addresses.effective_${m[1]}`;
  const base = te(k) ? t(k) : m[1];
  return m[2] ? `${base}（${m[2]}）` : base;
}

</script>

<style scoped>
.peek { min-width: 220px; max-width: 340px; font-size: 12px; }
.peek-ip {
  font-family: var(--font-mono, monospace); font-weight: 600; font-size: 13px;
  margin-bottom: 6px;
}
.peek-missing { color: var(--n-text-color-disabled); }
.peek-rows { display: flex; flex-direction: column; gap: 3px; }
.peek-row { display: flex; gap: 8px; align-items: baseline; }
.peek-row .k { flex: 0 0 auto; min-width: 62px; color: var(--n-text-color-disabled); }
.peek-row .v { flex: 1 1 auto; min-width: 0; word-break: break-word; }
.mono { font-family: var(--font-mono, monospace); }
</style>
