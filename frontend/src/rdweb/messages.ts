/**
 * 相容 RustDesk 的網頁連線：配對後的對話訊息（Message）。欄位編號與型別照規格第 13 節，名稱自取。
 */
import {
  concat, fBool, fBytes, fMsg, fPacked, fSint, fStr, fStrAlways, fVarint, fVarintAlways, getBig, getBool, getBytes,
  getDouble, getInt, getMsgs, getSint, getStr, getUint, oneof, parse, type Fields,
} from "./pb";

/** Message 的 oneof 欄位 */
export const M = {
  signed_id: 3, public_key: 4, test_delay: 5, video_frame: 6, login_request: 7, login_response: 8, hash: 9,
  mouse_event: 10, cursor_data: 12, cursor_position: 13, cursor_id: 14, key_event: 15, misc: 19,
  message_box: 21, peer_info: 25, auth_2fa: 27,
  clipboard: 16, multi_clipboards: 28,            // 附錄 F（剪貼簿，內容的編解碼在 clipboard.ts）
} as const;
const M_FIELDS = Object.values(M);
export type MessageKind = keyof typeof M;

/** ControlKey（13） */
export const CK = {
  Alt: 1, CapsLock: 3, Control: 4, Delete: 5, Meta: 23, Shift: 29, NumLock: 63, CtrlAltDel: 100, LockScreen: 101,
} as const;

export const KeyboardMode = { Legacy: 0, Map: 1, Translate: 2 } as const;
export const BoolOption = { NotSet: 0, No: 1, Yes: 2 } as const;
export const PreferCodec = { Auto: 0, VP9: 1, H264: 2, H265: 3, VP8: 4, AV1: 5 } as const;
/** PermissionInfo.Permission */
export const Permission = { Keyboard: 0, Clipboard: 2, Audio: 3, File: 4, Restart: 5, Recording: 6, BlockInput: 7 };

export interface Decoded {
  kind: MessageKind | null;
  body: Uint8Array;     // oneof 的值（子訊息的位元組；cursor_id 是空的，值在 value）
  value?: bigint;
}

const KIND_BY_FIELD = new Map<number, MessageKind>(
  (Object.entries(M) as [MessageKind, number][]).map(([k, v]) => [v, k]));

/** Message → oneof 的種類與內容。認不得的種類 kind=null（忽略即可）。 */
export function decodeMessage(buf: Uint8Array): Decoded {
  const f = parse(buf);
  const field = oneof(f, M_FIELDS);
  if (field === null) return { kind: null, body: new Uint8Array(0) };
  const raw = f.get(field)!;
  const v = raw[raw.length - 1];
  if (typeof v === "bigint") return { kind: KIND_BY_FIELD.get(field)!, body: new Uint8Array(0), value: v };
  return { kind: KIND_BY_FIELD.get(field)!, body: v };
}

export function encodeMessage(kind: MessageKind, body: Uint8Array): Uint8Array {
  return fMsg(M[kind], body);
}

// ── 身分（6.1、6.2）──

export interface IdPk { id: string; pk: Uint8Array; kxVersion: number }

export function parseIdPk(buf: Uint8Array): IdPk {
  const f = parse(buf);
  return { id: getStr(f, 1), pk: getBytes(f, 2), kxVersion: getUint(f, 4) };
}

/** SignedId { id (1): bytes }：ed25519 簽章附訊息（IdPk） */
export function parseSignedId(body: Uint8Array): Uint8Array {
  return getBytes(parse(body), 1);
}

/** 6.3：PublicKey { asymmetric_value, symmetric_value }。不填 kx_version（＝0）。 */
export function encodePublicKey(ourPk: Uint8Array, sealed: Uint8Array): Uint8Array {
  return encodeMessage("public_key", concat(fBytes(1, ourPk), fBytes(2, sealed)));
}

// ── 登入（7）──

export interface Hash { salt: string; challenge: string }

export function parseHash(body: Uint8Array): Hash {
  const f = parse(body);
  return { salt: getStr(f, 1), challenge: getStr(f, 2) };
}

export interface Decoding { vp9: boolean; h264: boolean; vp8: boolean; av1: boolean }

export interface LoginOptions {
  peerId: string;
  password: Uint8Array;          // 7.2 的 h2（32 bytes）；沒有密碼時是空的
  myId: string;
  myName: string;
  sessionId: bigint;
  version: string;
  decoding: Decoding;
  viewOnly?: boolean;
  /** 附錄 F：剪貼簿開著（唯讀檢視時呼叫端要給 false） */
  clipboard?: boolean;
  /** 附錄 G.7：作業系統帳號密碼（Linux 受控端沒有桌面時，同一條連線第二次登入才給）；不給就不填欄位 12 */
  osLogin?: { username: string; password: string };
  /** 附錄 I：畫質、更新率、編碼偏好（協定值）。不給＝第一階段的行為（只送 supported_decoding，偏好 VP9） */
  quality?: QualityOption;
}

/**
 * 7.4、附錄 I.1：SupportedDecoding。能力欄位照瀏覽器實際能解的填（解不了的填 0）：
 * VP9 必備；H.265 沒有 WebCodecs 的 codec 字串（8.2），一律 0。
 */
export function encodeSupportedDecoding(d: Decoding, prefer: number): Uint8Array {
  return concat(
    fVarint(1, 1),                                  // ability_vp9：必備
    fVarint(2, d.h264 ? 1 : 0),
    fVarint(3, 0),                                  // ability_h265：解不了
    fVarint(4, prefer),
    fVarint(5, d.vp8 ? 1 : 0),
    fVarint(6, d.av1 ? 1 : 0),
    fVarint(8, 0),                                  // prefer_chroma = I420
  );
}

/** 附錄 I.1：ImageQuality（沒有 1） */
export const ImageQuality = { NotSet: 0, Low: 2, Balanced: 3, Best: 4 } as const;

/**
 * 附錄 I.1：OptionMessage 裡跟畫質有關的欄位，都是協定值。
 * - imageQuality：ImageQuality；用自訂時填 NotSet
 * - customImageQuality：已經左移 8 位元的值（例：50 → 50 << 8），0＝不用自訂
 * - customFps：每個觀看者的更新率上限（1～120），0＝不設
 * - prefer：SupportedDecoding.prefer（PreferCodec）
 */
export interface QualityOption {
  imageQuality: number;
  customImageQuality: number;
  customFps: number;
  prefer: number;
}

/**
 * OptionMessage 的畫質欄位（image_quality 1、custom_image_quality 6、supported_decoding 10、custom_fps 11）。
 * 只編 which 裡列出的；值是 0 的欄位照 proto3 不寫出（NotSet＝不變）。
 */
export function encodeQualityFields(q: QualityOption, decoding: Decoding,
                                    which: readonly (keyof QualityOption)[]): Uint8Array {
  const has = (k: keyof QualityOption) => which.includes(k);
  return concat(
    has("imageQuality") ? fVarint(1, q.imageQuality) : new Uint8Array(0),
    has("customImageQuality") ? fVarint(6, q.customImageQuality) : new Uint8Array(0),
    has("prefer") ? fMsg(10, encodeSupportedDecoding(decoding, q.prefer)) : new Uint8Array(0),
    has("customFps") ? fVarint(11, q.customFps) : new Uint8Array(0),
  );
}

/** 7.4：登入後改設定送 Misc { option (7): OptionMessage }（執行中只帶改變的欄位，附錄 I.1） */
export function encodeOptionMisc(option: Uint8Array): Uint8Array {
  return encodeMessage("misc", fMsg(7, option));
}

function encodeOption(o: { decoding: Decoding; viewOnly?: boolean; clipboard?: boolean;
                           quality?: QualityOption }): Uint8Array {
  // 附錄 I：畫質與更新率照目前的設定；ImageQuality 是 Balanced 時不送（官方客戶端也不送，I.1）：
  // 畫質對所有觀看者生效，平衡（預設）登入時不去蓋掉別人已經設的
  const q = o.quality;
  const quality = q ? encodeQualityFields(
    { ...q, imageQuality: q.imageQuality === ImageQuality.Balanced ? ImageQuality.NotSet : q.imageQuality },
    o.decoding, ["imageQuality", "customImageQuality", "customFps"]) : new Uint8Array(0);
  return concat(
    quality,
    // show_remote_cursor：設 Yes 受控端才會在它自己的游標移動時送 cursor_position（附錄 E 更正，取代 7.4 的「不填」）
    fVarint(3, BoolOption.Yes),
    fVarint(7, BoolOption.Yes),                     // disable_audio：第一階段不處理音訊
    fVarint(8, o.clipboard ? BoolOption.No : BoolOption.Yes),   // disable_clipboard：附錄 F 的開關
    fMsg(10, encodeSupportedDecoding(o.decoding, q ? q.prefer : PreferCodec.VP9)),
    fVarint(12, o.viewOnly ? BoolOption.Yes : 0),   // disable_keyboard：唯讀檢視時
  );
}

/** 7.3：union 欄位（檔案傳輸等）都不填＝遠端桌面。 */
export function encodeLoginRequest(o: LoginOptions): Uint8Array {
  const body = concat(
    fStr(1, o.peerId),
    fBytes(2, o.password),
    fStr(4, o.myId),
    fStr(5, o.myName),
    fMsg(6, encodeOption(o)),
    fBool(9, false),                                // video_ack_required
    fVarint(10, o.sessionId),
    fStr(11, o.version),
    // os_login (12) = OSLogin { username (1), password (2) }（附錄 G.7）；平常不填
    o.osLogin ? fMsg(12, concat(fStr(1, o.osLogin.username), fStr(2, o.osLogin.password))) : new Uint8Array(0),
    fStr(13, "Web"),
  );
  return encodeMessage("login_request", body);
}

export function encodeAuth2FA(code: string): Uint8Array {
  return encodeMessage("auth_2fa", fStr(1, code));
}

export interface DisplayInfo {
  x: number; y: number; width: number; height: number; name: string; cursorEmbedded: boolean; scale: number;
  /** 附錄 H.1：online（6） */
  online: boolean;
  /** 附錄 H.1：original_resolution（8）：改過解析度時是改之前的大小；0×0＝受控端的虛擬螢幕 */
  originalResolution: Resolution;
}

/** 附錄 H.1：Resolution { width (1), height (2) } */
export interface Resolution { width: number; height: number }

/** 附錄 I.1：SupportedEncoding { h264 (1), h265 (2), vp8 (3), av1 (4), i444 (5) }；VP9 一定有 */
export interface SupportedEncoding { h264: boolean; h265: boolean; vp8: boolean; av1: boolean }

/** 附錄 G.6：WindowsSessions { sessions (1): repeated WindowsSession { sid (1), name (2) }, current_sid (2) } */
export interface WindowsSessions {
  sessions: { sid: number; name: string }[];
  currentSid: number;
}

export interface PeerInfo {
  username: string; hostname: string; platform: string; displays: DisplayInfo[]; currentDisplay: number;
  version: string; platformAdditions: string;
  /** 附錄 G.6：PeerInfo.windows_sessions（欄位 13）；有的時候受控端要等 Misc.selected_sid 才送畫面 */
  windowsSessions?: WindowsSessions;
  /** 附錄 H.1：resolutions（11）：只是登入時那個螢幕支援的解析度 */
  resolutions: Resolution[];
  /** 附錄 I.1：encoding（10）：受控端能編哪些；沒帶時是 null（當成只有 VP9） */
  encoding: SupportedEncoding | null;
}

function parseResolution(f: Fields): Resolution {
  return { width: getInt(f, 1), height: getInt(f, 2) };
}

/**
 * SupportedResolutions { resolutions (1): repeated Resolution }（H.1）。PeerInfo.resolutions（11）與
 * SwitchDisplay.resolutions（7）都是這個包一層的格式（H.2）。0×0 的項目不列。
 */
function parseSupportedResolutions(b: Uint8Array): Resolution[] {
  return getMsgs(parse(b), 1).map(parseResolution).filter((r) => r.width > 0 && r.height > 0);
}

function parseEncoding(b: Uint8Array): SupportedEncoding {
  const f = parse(b);
  return { h264: getBool(f, 1), h265: getBool(f, 2), vp8: getBool(f, 3), av1: getBool(f, 4) };
}

function parseDisplay(f: Fields): DisplayInfo {
  return {
    x: getSint(f, 1), y: getSint(f, 2), width: getInt(f, 3), height: getInt(f, 4), name: getStr(f, 5),
    cursorEmbedded: getBool(f, 7), scale: getDouble(f, 9), online: getBool(f, 6),
    originalResolution: parseResolution(parse(getBytes(f, 8))),
  };
}

export function parsePeerInfo(body: Uint8Array): PeerInfo {
  const f = parse(body);
  const info: PeerInfo = {
    username: getStr(f, 1), hostname: getStr(f, 2), platform: getStr(f, 3),
    displays: getMsgs(f, 4).map(parseDisplay), currentDisplay: getInt(f, 5), version: getStr(f, 7),
    platformAdditions: getStr(f, 12),
    resolutions: parseSupportedResolutions(getBytes(f, 11)),
    encoding: f.has(10) ? parseEncoding(getBytes(f, 10)) : null,
  };
  if (f.has(13)) {
    const ws = parse(getBytes(f, 13));
    info.windowsSessions = {
      sessions: getMsgs(ws, 1).map((s) => ({ sid: getUint(s, 1), name: getStr(s, 2) })),
      currentSid: getUint(ws, 2),
    };
  }
  return info;
}

export type LoginResponse = { error: string } | { peerInfo: PeerInfo };

export function parseLoginResponse(body: Uint8Array): LoginResponse {
  const f = parse(body);
  const which = oneof(f, [1, 2]);
  if (which === 2) return { peerInfo: parsePeerInfo(getBytes(f, 2)) };
  return { error: getStr(f, 1) };
}

// ── 畫面（8.2）──

export type Codec = "vp9" | "h264" | "h265" | "vp8" | "av1";
const VIDEO_CODECS: [number, Codec][] = [[6, "vp9"], [10, "h264"], [11, "h265"], [12, "vp8"], [13, "av1"]];

export interface EncodedFrame { data: Uint8Array; key: boolean; pts: bigint }
export interface VideoFrameMsg { codec: Codec | null; frames: EncodedFrame[]; display: number }

export function parseVideoFrame(body: Uint8Array): VideoFrameMsg {
  const f = parse(body);
  const which = oneof(f, VIDEO_CODECS.map(([n]) => n));
  const codec = which === null ? null : VIDEO_CODECS.find(([n]) => n === which)![1];
  const frames = which === null ? [] : getMsgs(parse(getBytes(f, which)), 1).map((ef) => ({
    data: getBytes(ef, 1), key: getBool(ef, 2), pts: BigInt.asIntN(64, getBig(ef, 3)),
  }));
  return { codec, frames, display: getInt(f, 14) };
}

// ── 游標（8.4、附錄 E）──

/** CursorData { id (1) uint64, hotx (2) sint32, hoty (3) sint32, width (4) int32, height (5) int32, colors (6) bytes } */
export interface CursorDataMsg {
  id: bigint; hotx: number; hoty: number; width: number; height: number;
  colors: Uint8Array;        // zstd 壓縮過的 RGBA（解壓在 cursor.ts）
}

export function parseCursorData(body: Uint8Array): CursorDataMsg {
  const f = parse(body);
  return {
    id: BigInt.asUintN(64, getBig(f, 1)), hotx: getSint(f, 2), hoty: getSint(f, 3), width: getInt(f, 4),
    height: getInt(f, 5), colors: getBytes(f, 6),
  };
}

/** CursorPosition { x (1) sint32, y (2) sint32 }：受控端游標在虛擬桌面的座標。 */
export function parseCursorPosition(body: Uint8Array): { x: number; y: number } {
  const f = parse(body);
  return { x: getSint(f, 1), y: getSint(f, 2) };
}

// ── Misc（8.5、8.3、10）──

/** 附錄 H.2：受控端回的 SwitchDisplay（新螢幕的位置、大小、支援的解析度、原始解析度） */
export interface SwitchDisplayMsg {
  display: number; x: number; y: number; width: number; height: number; cursorEmbedded: boolean;
  resolutions: Resolution[]; originalResolution: Resolution;
}

export type Misc =
  | ({ type: "switch_display" } & SwitchDisplayMsg)
  | { type: "permission_info"; permission: number; enabled: boolean }
  | { type: "close_reason"; reason: string }
  | { type: "supported_encoding"; encoding: SupportedEncoding }
  // 附錄 K.1：Windows 免安裝受控端的權限狀態與提權結果（受控端每秒檢查，值有變化才送；false 與空字串也會送）
  | { type: "uac"; value: boolean }
  | { type: "foreground_window_elevated"; value: boolean }
  | { type: "elevation_response"; text: string }
  | { type: "portable_service_running"; value: boolean }
  | { type: "other" };

export function parseMisc(body: Uint8Array): Misc {
  const f = parse(body);
  // 30 capture_displays、34 supported_encoding、36 change_display_resolution、38 follow_current_display（附錄 H、I）
  // 15 uac、16 foreground_window_elevated、19 elevation_response、20 portable_service_running（附錄 K）
  const which = oneof(f, [5, 6, 7, 9, 10, 12, 15, 16, 19, 20, 30, 31, 34, 36, 38]);
  if (which === 15) return { type: "uac", value: getBool(f, 15) };
  if (which === 16) return { type: "foreground_window_elevated", value: getBool(f, 16) };
  if (which === 19) return { type: "elevation_response", text: getStr(f, 19) };
  if (which === 20) return { type: "portable_service_running", value: getBool(f, 20) };
  if (which === 5) {
    const s = parse(getBytes(f, 5));
    return { type: "switch_display", display: getInt(s, 1), x: getSint(s, 2), y: getSint(s, 3),
             width: getInt(s, 4), height: getInt(s, 5), cursorEmbedded: getBool(s, 6),
             resolutions: parseSupportedResolutions(getBytes(s, 7)),
             originalResolution: parseResolution(parse(getBytes(s, 8))) };
  }
  if (which === 34) return { type: "supported_encoding", encoding: parseEncoding(getBytes(f, 34)) };
  if (which === 6) {
    const p = parse(getBytes(f, 6));
    return { type: "permission_info", permission: getInt(p, 1), enabled: getBool(p, 2) };
  }
  if (which === 9) return { type: "close_reason", reason: getStr(f, 9) };
  return { type: "other" };
}

/** 10：控制端主動結束時送空字串的 close_reason。空字串也要寫出這個欄位（oneof）。 */
export function encodeCloseReason(reason: string): Uint8Array {
  return encodeMessage("misc", fStrAlways(9, reason));
}

/** 附錄 G.6：回答 windows_sessions 的 Misc.selected_sid（欄位 35，uint32）。在 oneof 裡，0 也要寫出。 */
export function encodeSelectedSid(sid: number): Uint8Array {
  return encodeMessage("misc", fVarintAlways(35, sid));
}

// ── 請求提權（附錄 K.1）──

/**
 * K.1：ElevationRequest { oneof union { direct (1): bool, logon (2): ElevationRequestWithLogon } }，
 * ElevationRequestWithLogon { username (1), password (2) }（兩個都是字串）。
 */
export type ElevationRequest =
  | { method: "direct" }
  | { method: "logon"; username: string; password: string };

/**
 * K.1：Misc.elevation_request（18）。
 * - direct = true：受控端以「以系統管理員身分執行」啟動輔助服務，受控端那台會跳 UAC，要有人在那台按「是」
 * - logon：用受控端那台的系統管理員帳號密碼啟動（網域帳號寫 網域\帳號），不需要有人在那台；
 *   子訊息在 oneof 裡，帳號密碼都空也要寫出這個欄位。帳號密碼只放進這一則（呼叫端加密後送給受控端）
 * 回覆是 Misc.elevation_response（19）；成功與否看之後的 portable_service_running（20）。
 */
export function encodeElevationRequest(r: ElevationRequest): Uint8Array {
  const body = r.method === "direct" ? fBool(1, true) : fMsg(2, concat(fStr(1, r.username), fStr(2, r.password)));
  return encodeMessage("misc", fMsg(18, body));
}

// ── 多螢幕（附錄 H）──

/** H.2：Misc.switch_display（5）：控制端只填 display，width／height 填 0（非 0 會順便改解析度） */
export function encodeSwitchDisplay(display: number): Uint8Array {
  return encodeMessage("misc", fMsg(5, fVarint(1, display)));
}

/** H.2：Misc.capture_displays（30）：CaptureDisplays { add (1), sub (2), set (3) }，本實作只用 set */
export function encodeCaptureDisplays(set: number[]): Uint8Array {
  return encodeMessage("misc", fMsg(30, fPacked(3, set)));
}

/** H.4：Misc.change_display_resolution（36）：DisplayResolution { display (1), resolution (2) } */
export function encodeChangeResolution(display: number, r: Resolution): Uint8Array {
  return encodeMessage("misc", fMsg(36, concat(fVarint(1, display),
                                                 fMsg(2, concat(fVarint(1, r.width), fVarint(2, r.height))))));
}

/**
 * 8.3、附錄 H.2：要求關鍵影格一律用 refresh_video_display（螢幕索引，0 也要寫出）。
 * 不用 refresh_video（Misc 10）：它會讓受控端所有螢幕、所有觀看者都重新開始。
 */
export function encodeRefreshVideo(display: number): Uint8Array {
  return encodeMessage("misc", fVarintAlways(31, display));
}

export function versionAtLeast(version: string, min: [number, number, number]): boolean {
  const parts = (version || "").split(/[.\-+]/).slice(0, 3).map((p) => parseInt(p, 10) || 0);
  while (parts.length < 3) parts.push(0);
  for (let i = 0; i < 3; i++) {
    if (parts[i] !== min[i]) return parts[i] > min[i];
  }
  return true;
}

// ── TestDelay（8.6）──

export function testDelayFromClient(body: Uint8Array): boolean {
  return getBool(parse(body), 2);
}

/** TestDelay { time (1), from_client (2), last_delay (3) 毫秒, target_bitrate (4) kbps }（附錄 I.1 拿來顯示） */
export function parseTestDelay(body: Uint8Array): { fromClient: boolean; lastDelay: number; targetBitrate: number } {
  const f = parse(body);
  return { fromClient: getBool(f, 2), lastDelay: getUint(f, 3), targetBitrate: getUint(f, 4) };
}

// ── MessageBox（8.7）──

export interface MessageBox { msgtype: string; title: string; text: string; link: string }

export function parseMessageBox(body: Uint8Array): MessageBox {
  const f = parse(body);
  return { msgtype: getStr(f, 1), title: getStr(f, 2), text: getStr(f, 3), link: getStr(f, 4) };
}

// ── 輸入（9）──

export function encodeMouseEvent(mask: number, x: number, y: number, modifiers: number[] = []): Uint8Array {
  return encodeMessage("mouse_event", concat(fVarint(1, mask), fSint(2, x), fSint(3, y), fPacked(4, modifiers)));
}

/** map 模式：chr＝受控端平台的實體按鍵代碼；modifiers 只放鎖定鍵。 */
export function encodeKeyMap(down: boolean, chr: number, modifiers: number[]): Uint8Array {
  // chr 在 oneof 裡：值為 0 時也要寫出（附錄 A 的 macOS 欄有 0x00＝KeyA）
  return encodeMessage("key_event", concat(fBool(1, down), fVarintAlways(4, chr), fPacked(8, modifiers),
                                           fVarint(9, KeyboardMode.Map)));
}

/** 9.3：Ctrl+Alt+Del。Windows 用 CtrlAltDel；其他平台用 Delete＋press＋[Alt, Control]。 */
export function encodeCtrlAltDel(platform: string): Uint8Array {
  if (platform === "Windows") {
    return encodeMessage("key_event", concat(fBool(1, true), fVarint(3, CK.CtrlAltDel),
                                             fVarint(9, KeyboardMode.Legacy)));
  }
  return encodeMessage("key_event", concat(fBool(2, true), fVarint(3, CK.Delete),
                                           fPacked(8, [CK.Alt, CK.Control]), fVarint(9, KeyboardMode.Legacy)));
}

export function encodeLockScreen(): Uint8Array {
  return encodeMessage("key_event", concat(fBool(1, true), fVarint(3, CK.LockScreen),
                                           fVarint(9, KeyboardMode.Legacy)));
}
