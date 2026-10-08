/**
 * OCS 代理版本：`OCS-NG_unified_unix_agent_v2.10.0` → `Unix 2.10.0`。
 *
 * 原始字串很長、版本號又在最後，欄位一窄就剛好把版本號截掉。畫面上顯示這個精簡版，
 * 完整字串放在 title 裡。認不得的格式原樣回傳 —— 猜錯平台比顯示長字串更糟。
 */
const PLATFORMS: [RegExp, string][] = [
  [/windows/i, "Windows"],
  [/mac\s*os|macosx|darwin/i, "macOS"],
  [/android/i, "Android"],
  [/unix|linux/i, "Unix"],
];

export function shortOcsAgent(raw: string | null | undefined): string {
  if (!raw) return "";
  const ver = raw.match(/_v?(\d+(?:\.\d+)+)\s*$/i)?.[1];
  const platform = PLATFORMS.find(([re]) => re.test(raw))?.[1];
  return ver && platform ? `${platform} ${ver}` : raw;
}
