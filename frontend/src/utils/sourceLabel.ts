/**
 * 來源代碼 → 顯示名稱（addresses.source_<代碼>）。IP 詳情與「IP 異動」頁共用，
 * 沒有翻譯的代碼原樣顯示（守門測試 i18n/__tests__/changeSourceLabels.test.ts 會擋下漏翻的來源）。
 */
export function sourceLabel(t: (key: string) => string, v: string | null | undefined): string {
  if (!v) return "—";
  const key = `addresses.source_${v}`;
  const out = t(key);
  return out === key ? v : out;
}
