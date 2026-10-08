/**
 * 相容 RustDesk 的網頁連線：畫質、更新率、編碼偏好（規格附錄 I）。只放不碰畫面、不碰網路的邏輯；
 * 送 Misc.option 在 session.ts，選單在 RustDeskScreen.vue。
 *
 * - 畫質：低／平衡（預設）／最佳／自訂（10～100）。自訂時 image_quality 填 NotSet、custom_image_quality 填
 *   「數值左移 8 位元」（50 → 50 << 8，I.1）
 * - 更新率上限：15／30（預設）／60（custom_fps）
 * - 編碼偏好：自動（預設）／VP9／H.264／AV1，只列「瀏覽器的 WebCodecs 解得了、受控端也編得出來」的（I.2）
 * - 記在 localStorage 的只有這三個選項（畫質含自訂的數值），不涉及密碼；讀寫失敗都不影響連線
 * - 多人同時看同一台時，畫質以最後設定的為準（I.1）：選單旁有一行說明
 */
import { ImageQuality, PreferCodec, type Codec, type Decoding, type QualityOption, type SupportedEncoding } from "./messages";

export type QualityLevel = "low" | "balanced" | "best" | "custom";
export type CodecPref = "auto" | "vp9" | "h264" | "av1";

export interface QualitySettings {
  level: QualityLevel;
  /** 自訂畫質的數值（10～100，50 等於倍數 1.0） */
  custom: number;
  /** 更新率上限 */
  fps: number;
  codec: CodecPref;
}

export const QUALITY_LEVELS: readonly QualityLevel[] = ["low", "balanced", "best", "custom"];
export const FPS_CHOICES: readonly number[] = [15, 30, 60];
export const CODEC_PREFS: readonly CodecPref[] = ["auto", "vp9", "h264", "av1"];
export const CUSTOM_MIN = 10;
export const CUSTOM_MAX = 100;
export const DEFAULT_QUALITY: Readonly<QualitySettings> = { level: "balanced", custom: 50, fps: 30, codec: "auto" };
/** localStorage 的鍵：值只有 { level, custom, fps, codec } */
export const QUALITY_STORAGE_KEY = "jt-ipam.rdweb.quality";

const LEVEL_VALUE: Record<Exclude<QualityLevel, "custom">, number> = {
  low: ImageQuality.Low, balanced: ImageQuality.Balanced, best: ImageQuality.Best,
};
const PREFER_VALUE: Record<CodecPref, number> = {
  auto: PreferCodec.Auto, vp9: PreferCodec.VP9, h264: PreferCodec.H264, av1: PreferCodec.AV1,
};

export function clampCustom(v: number): number {
  if (!Number.isFinite(v)) return DEFAULT_QUALITY.custom;
  return Math.min(CUSTOM_MAX, Math.max(CUSTOM_MIN, Math.round(v)));
}

/** I.1：custom_image_quality 是數值左移 8 位元（50 → 12800）。 */
export function customImageQualityValue(v: number): number {
  return clampCustom(v) << 8;
}

/** 瀏覽器解得了嗎（VP9 必備，連線前已經確認過） */
function canDecode(c: CodecPref, d: Decoding): boolean {
  return c === "auto" || c === "vp9" || (c === "h264" ? d.h264 : c === "av1" ? d.av1 : false);
}

/** 受控端編得出來嗎（VP9 一定有；沒帶 encoding 的受控端當成只有 VP9） */
function canEncode(c: CodecPref, e: SupportedEncoding | null): boolean {
  return c === "auto" || c === "vp9" || (!!e && (c === "h264" ? e.h264 : c === "av1" ? e.av1 : false));
}

/** I.2：編碼偏好選單只列兩邊都支援的（「自動」一定在）。 */
export function codecChoices(d: Decoding, e: SupportedEncoding | null): CodecPref[] {
  return CODEC_PREFS.filter((c) => canDecode(c, d) && canEncode(c, e));
}

/**
 * 設定 → OptionMessage 的協定值。偏好的編碼瀏覽器解不了時改成「自動」；
 * 受控端編不出來（e 有給時）也改成「自動」。登入時還不知道受控端的 encoding（在登入回應裡），只看瀏覽器。
 */
export function toQualityOption(s: QualitySettings, d: Decoding, e?: SupportedEncoding | null): QualityOption {
  const usable = canDecode(s.codec, d) && (e === undefined || canEncode(s.codec, e));
  return {
    imageQuality: s.level === "custom" ? ImageQuality.NotSet : LEVEL_VALUE[s.level],
    customImageQuality: s.level === "custom" ? customImageQualityValue(s.custom) : 0,
    customFps: FPS_CHOICES.includes(s.fps) ? s.fps : DEFAULT_QUALITY.fps,
    prefer: PREFER_VALUE[usable ? s.codec : "auto"],
  };
}

/** 從 localStorage 讀；沒有、壞掉、讀不到（私密視窗、封鎖網站資料）都回預設值，不丟例外。 */
export function loadQuality(storage?: Storage | null): QualitySettings {
  const out: QualitySettings = { ...DEFAULT_QUALITY };
  try {
    const st = storage === undefined ? globalThis.localStorage : storage;
    const raw = st?.getItem(QUALITY_STORAGE_KEY);
    if (!raw) return out;
    const v = JSON.parse(raw) as Partial<Record<keyof QualitySettings, unknown>>;
    if (QUALITY_LEVELS.includes(v.level as QualityLevel)) out.level = v.level as QualityLevel;
    if (typeof v.custom === "number") out.custom = clampCustom(v.custom);
    if (typeof v.fps === "number" && FPS_CHOICES.includes(v.fps)) out.fps = v.fps;
    if (CODEC_PREFS.includes(v.codec as CodecPref)) out.codec = v.codec as CodecPref;
  } catch { /* 讀不到就用預設值 */ }
  return out;
}

/** 寫進 localStorage：只寫這三個選項。失敗回 false（不影響連線）。 */
export function saveQuality(s: QualitySettings, storage?: Storage | null): boolean {
  try {
    const st = storage === undefined ? globalThis.localStorage : storage;
    if (!st) return false;
    st.setItem(QUALITY_STORAGE_KEY, JSON.stringify({
      level: s.level, custom: clampCustom(s.custom), fps: s.fps, codec: s.codec,
    }));
    return true;
  } catch {
    return false;
  }
}

/** 效能列（延遲、位元率、每秒張數、編碼）要不要顯示：預設不顯示，畫質選單勾了才顯示。
 *  跟畫質選項分開一個鍵，值只有 "1"／"0"。 */
export const SHOW_STATS_STORAGE_KEY = "jt-ipam.rdweb.show_stats";

export function loadShowStats(storage?: Storage | null): boolean {
  try {
    const st = storage === undefined ? globalThis.localStorage : storage;
    return st?.getItem(SHOW_STATS_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

export function saveShowStats(v: boolean, storage?: Storage | null): boolean {
  try {
    const st = storage === undefined ? globalThis.localStorage : storage;
    if (!st) return false;
    st.setItem(SHOW_STATS_STORAGE_KEY, v ? "1" : "0");
    return true;
  } catch {
    return false;
  }
}

/** 狀態列顯示的編碼名稱 */
export function codecLabel(c: Codec | CodecPref | null | undefined): string {
  return ({ vp9: "VP9", vp8: "VP8", av1: "AV1", h264: "H.264", h265: "H.265" } as Record<string, string>)[c || ""] || "";
}

/**
 * I.2：實際的畫面更新率＝瀏覽器每秒解出幾張。每次 sample 給目前累計的張數與時間（毫秒）：
 * 第一次只記起點（回 null）；之後回這段期間的每秒張數。累計數變小（換了一條新的解碼管線）就重新記起點。
 */
export class FpsMeter {
  private last: { total: number; at: number } | null = null;

  sample(total: number, now: number): number | null {
    const prev = this.last;
    this.last = { total, at: now };
    if (!prev || total < prev.total || now <= prev.at) return null;
    return Math.round(((total - prev.total) * 1000) / (now - prev.at));
  }

  reset(): void {
    this.last = null;
  }
}
