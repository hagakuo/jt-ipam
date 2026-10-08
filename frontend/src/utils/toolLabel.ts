/**
 * 把 AI 工具名稱（如 `get_ip_detail`）轉成看得懂的說明。
 *
 * 刻意用「動詞＋名詞」組合而不是逐一列表：工具有 85 個而且會再增加，
 * 硬表一定會過時，屆時畫面就會顯示原始英文代號 —— 那對使用者沒有意義。
 *
 * 語言之間不只是換字：中文黏在一起（查詢IP詳細資料）、英文要空格（Look up IP details）、
 * 日文動詞在後（IP の詳細を照会）。所以組裝方式本身也是翻譯的一部分，
 * 交給 `tool_label.frame` 與 `tool_label.noun_join` 決定，這裡不寫死順序。
 */
type Translate = (key: string, params?: Record<string, unknown>) => string;
type Exists = (key: string) => boolean;

export function humanToolName(
  raw: string | undefined | null, t: Translate, te: Exists,
): string {
  if (!raw) return "";
  const parts = raw.toLowerCase().split(/[_\s]+/).filter(Boolean);
  if (!parts.length) return raw;

  const verbKey = `tool_verbs.${parts[0]}`;
  const verb = te(verbKey) ? t(verbKey) : "";
  // 查不到的字原樣留著 —— 寧可顯示英文代號，也不要憑空少掉一段意思
  const words = (verb ? parts.slice(1) : parts)
    .map((w) => (te(`tool_nouns.${w}`) ? t(`tool_nouns.${w}`) : w))
    .filter(Boolean);
  const nouns = words.join(t("tool_label.noun_join"));

  if (!verb) return nouns || raw;
  if (!nouns) return verb;
  return t("tool_label.frame", { verb, nouns });
}
