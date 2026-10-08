import { i18n } from "@/i18n";

/**
 * 全站時間 / 日期格式化 helper。
 *
 * 後端統一給 ISO 8601 (UTC, e.g. "2026-05-27T05:19:41.328975Z")。
 * 前端統一用瀏覽器 locale 顯示，避免每個 view 自己拼字串。
 */

const PAD = (n: number) => n.toString().padStart(2, "0");

function _toDate(s: string | number | Date | null | undefined): Date | null {
  if (s == null || s === "") return null;
  const d = s instanceof Date ? s : new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "2026-05-27 13:15:30"(本地時區) */
export function fmtDateTime(
  s: string | number | Date | null | undefined,
  fallback = "—",
): string {
  const d = _toDate(s);
  if (!d) return fallback;
  return `${d.getFullYear()}-${PAD(d.getMonth() + 1)}-${PAD(d.getDate())} ` +
         `${PAD(d.getHours())}:${PAD(d.getMinutes())}:${PAD(d.getSeconds())}`;
}

/** "2026-05-27"(本地時區) */
export function fmtDate(
  s: string | number | Date | null | undefined,
  fallback = "—",
): string {
  const d = _toDate(s);
  if (!d) return fallback;
  return `${d.getFullYear()}-${PAD(d.getMonth() + 1)}-${PAD(d.getDate())}`;
}

/** "5 分鐘前" / "5 minutes ago" / "5 分前"；超過 30 天回 fmtDate。
 *
 * 用 Intl.RelativeTimeFormat 而不是自己串字：單複數（1 minute／2 minutes）與詞序
 * 是各語言自己的規則，寫死在這裡等於只有中文是對的 —— 日文介面的通知曾經顯示
 * 「3 分鐘前」。語系跟著 i18n 走，換語言時整個畫面本來就會重畫。 */
export function fmtRelative(
  s: string | number | Date | null | undefined,
  fallback = "—",
): string {
  const d = _toDate(s);
  if (!d) return fallback;
  const diff = Date.now() - d.getTime();
  if (diff < 0) return fmtDateTime(d);                            // 未來時間
  // i18n.global.locale 在 legacy 模式是字串、composition 模式是 ref —— 兩種都收
  const loc = (i18n.global as unknown as { locale: string | { value: string } }).locale;
  const tag = (typeof loc === "string" ? loc : loc?.value) || "zh-TW";
  const rtf = new Intl.RelativeTimeFormat(tag, { numeric: "auto" });
  const sec = Math.floor(diff / 1000);
  if (sec < 60)     return rtf.format(-sec, "second");
  const min = Math.floor(sec / 60);
  if (min < 60)     return rtf.format(-min, "minute");
  const hr  = Math.floor(min / 60);
  if (hr < 24)      return rtf.format(-hr, "hour");
  const day = Math.floor(hr / 24);
  if (day < 30)     return rtf.format(-day, "day");
  return fmtDate(d);
}

/** 連線時間的時鐘格式：65 → "00:01:05"；小時至少兩位，超過一天照樣累加（26:00:03） */
export function fmtClock(seconds: number | null | undefined): string {
  const sec = Math.max(0, Math.floor(Number(seconds) || 0));
  const two = (n: number) => String(n).padStart(2, "0");
  return `${two(Math.floor(sec / 3600))}:${two(Math.floor(sec / 60) % 60)}:${two(sec % 60)}`;
}

/** 秒數差人話：65 → "1m 5s" */
export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  const sec = Math.max(0, Math.floor(seconds));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}
