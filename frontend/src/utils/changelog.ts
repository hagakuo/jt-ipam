/**
 * IP 異動記錄的值顯示。
 *
 * `switch_port` 在資料庫裡存成 `裝置 / 埠號`（例如 `switch-003 / eth1/0/2`），
 * 但畫面上一律用 `裝置@埠號` —— 與交換器位置的顯示一致。
 * **只換第一個 " / "**：埠號本身含有斜線（`eth1/0/2`），全換會把它拆爛。
 *
 * 抽成共用函式的理由：原本只有 IP 詳細資料頁有這段，調查視窗直接印原始值就露出了
 * 斜線格式。同一件事有兩處實作，遲早會有一處忘記跟上。
 */
export function fmtChangeVal(
  field: string | null | undefined,
  v: string | null | undefined,
): string {
  if (v == null) return "∅";
  if (field === "switch_port") {
    const idx = v.indexOf(" / ");
    if (idx >= 0) return v.slice(0, idx) + "@" + v.slice(idx + 3);
  }
  return v;
}
