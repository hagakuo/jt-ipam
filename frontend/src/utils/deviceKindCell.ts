import { h, type VNodeChild } from "vue";
import type { DataTableColumn } from "naive-ui";
import DeviceKindIcon from "@/components/DeviceKindIcon.vue";
import { withExportValue } from "@/utils/tableExport";

/**
 * IP 清單的「設備類型」欄位內容（圖示＋名稱，滑過顯示型號）。
 *
 * 「IP 位址」頁與子網路頁的 IP 清單共用這一份：同一份資料兩個入口，欄位與顯示要一樣
 * （子網路頁曾經整個少了這一欄，使用者在 IP 詳細資料看得到、在子網路的清單卻選不到）。
 */
export function renderDeviceKind(
  r: { device_kind?: string | null; device_model?: string | null; __gap?: unknown },
  t: (k: string) => string, te: (k: string) => boolean,
): VNodeChild {
  if (r.__gap || !r.device_kind) return "—";
  const key = `identify.type.${r.device_kind}`;
  const label = te(key) ? t(key) : r.device_kind;
  return h("div", {
    style: "display:flex;align-items:center;gap:4px;min-width:0;white-space:nowrap",
    title: r.device_model ? `${label} · ${r.device_model}` : label,
  }, [
    h(DeviceKindIcon, { kind: r.device_kind, size: 16 }),
    h("span", { style: "overflow:hidden;text-overflow:ellipsis" }, label),
  ]);
}

/** 設備類型的顯示名稱（匯出、排序用；沒有類型回空字串） */
export function deviceKindLabel(
  kind: string | null | undefined, t: (k: string) => string, te: (k: string) => boolean,
): string {
  if (!kind) return "";
  const key = `identify.type.${kind}`;
  return te(key) ? t(key) : kind;
}

/**
 * 「設備類型」欄位：每一張以 IP 記錄為列的表格共用（使用者 2026-10-04：「有了設備類型欄位，很多相關頁面的
 * 欄位也要有此欄位可以選」）。列要帶 `device_kind`／`device_model`。前端排序依顯示名稱、沒有類型的排最後；
 * 伺服器端分頁的表格由 remoteSort 把排序交給後端（sort=device_kind）。記得把 "device_kind" 也加進欄位偏好。
 */
export function deviceKindColumn(
  t: (k: string) => string, te: (k: string) => boolean, width = 140,
): DataTableColumn<any> {
  const label = (r: any) => deviceKindLabel(r?.device_kind, t, te);
  return withExportValue<DataTableColumn<any>>({
    title: t("cols.device_kind"), key: "device_kind", width,
    sorter: (a: any, b: any) => {
      const x = label(a), y = label(b);
      if (!x || !y) return x ? -1 : y ? 1 : 0;
      return x.localeCompare(y);
    },
    render: (r: any) => renderDeviceKind(r, t, te),
  }, label);
}
