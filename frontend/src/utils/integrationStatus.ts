// 整合回報的狀態原始值（Wazuh 的 active／disconnected、LibreNMS 的 1／0）翻成使用者看得懂的文字。
// 以前只有 Wazuh 管理頁有翻，裝置詳情頁與調查報告直接印原始英文。
type T = (key: string) => string;

export function wazuhStatusLabel(t: T, s: string | null | undefined): string {
  if (!s) return "—";
  const key = `wazuh_admin.status_${s}`;
  const out = t(key);
  return out === key ? s : out;
}

// LibreNMS device status：1=up / 0=down
export function lnmsStatusLabel(t: T, s: unknown): string {
  if (s == null || s === "") return "—";
  const v = String(s);
  if (v === "1" || v.toLowerCase() === "up") return t("topology.status_up");
  if (v === "0" || v.toLowerCase() === "down") return t("topology.status_down");
  return v;
}
