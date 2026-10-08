/**
 * 清單的 MAC 欄：MAC 在上、OUI 廠商小標籤在下（GitHub issue #38）。
 *
 * 以前廠商只在 IP 詳細頁看得到，清單上一眼看不出「這是哪家的設備」，要一筆一筆點進去。
 * 放在第二行而不是同一行：欄寬不必變寬；廠商名稱很長（Hewlett Packard Enterprise）時
 * 截斷並用 title 顯示全名。
 */
import { h, type VNodeChild } from "vue";

export function renderMacWithVendor(mac?: string | null, vendor?: string | null, empty = "—"): VNodeChild {
  if (!mac) return empty;
  if (!vendor) return mac;
  return h("div", { class: "mac-cell" }, [
    h("span", { class: "mac-cell__mac" }, mac),
    h("span", { class: "mac-cell__vendor", title: vendor }, vendor),
  ]);
}
