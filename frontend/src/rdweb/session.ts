/**
 * 相容 RustDesk 的網頁連線：控制端的協定流程（瀏覽器裡跑，後端只轉送密文）。
 *
 * 唯一依據是 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md。順序（6.3 的總表）：
 *   後端 → ready（hbbs 簽章過的受控端身分＋伺服器公鑰）
 *   受控端 → SignedId（明文）       ← 用 6.1 拿到的受控端 ed25519 公鑰驗
 *   控制端 → PublicKey（明文）      ← 金鑰交換 v0，之後兩個方向都改用 secretbox
 *   受控端 → Hash（密文，計數 1）
 *   控制端 → LoginRequest（密文，計數 1）
 *   ……之後全部是密文
 *
 * 不可以降級（6.5）：任何驗證失敗都中止並回報錯誤，不送空的 PublicKey，也不在沒有加密的情況下登入。
 * 瀏覽器 ↔ 後端的外層（2.3）：一則 binary＝一則 RustDesk 訊息；text 是 jt-ipam 的控制 JSON `{"t": …}`。
 *
 * 記住密碼（附錄 D）：給了 savedCredentialId 時，收到 Hash 後送 `login_assist`（credential_id、salt、challenge），
 * 後端回這一次連線的 h2（32 bytes，base64），照 7.3 放進 LoginRequest。密碼明文與 h1 都不會來到瀏覽器。
 * 後端回失敗、或對方回 Wrong Password：改請使用者輸入，這條連線不再用已存的密碼（D.4，不自動重試）。
 *
 * 受控端切換工作階段（附錄 G.5～G.7）：
 * - session_id 可以由外部給（同一個頁面的重連都沿用第一次的值）；只有使用者自己結束（close()）才送 close_reason
 * - 送空密碼等對方同意卻收到 No Password Access＝受控端在登入畫面，沒有同意視窗：改請使用者輸入密碼
 * - 登入回應帶 windows_sessions：交給畫面決定，選好之後送 Misc.selected_sid（不送受控端就不送畫面）
 * - Linux 受控端沒有桌面（Desktop session not ready 一類）：請使用者輸入作業系統帳號密碼，同一條連線再送一次
 *   LoginRequest（os_login）；作業系統帳號密碼只放進那一則加密的訊息，這裡不留
 *
 * 多螢幕（附錄 H，狀態在 displays.ts）：切換送 switch_display → capture_displays set=[n] → refresh_video_display(n)；
 * 不是目前螢幕的影格丟掉；連線中的 peer_info 只更新清單（目前選的不見了就切到主螢幕或 0）；要求關鍵影格帶目前的螢幕編號。
 * 畫質（附錄 I）：登入時照目前的設定填 OptionMessage；之後改了用 Misc.option 只送改變的欄位。
 * 請求提權（附錄 K，規則在 elevation.ts）：連線中收到的 Misc.uac／foreground_window_elevated／elevation_response／
 * portable_service_running 交給畫面；requestElevation 送 Misc.elevation_request（logon 的帳號密碼只放進那一則加密的
 * 訊息，這裡不留）；reportElevation 送稽核摘要給後端（`elevation_audit`：method、result、detail 四個欄位，不含帳號密碼）。
 */
import { base64ToBytes, keyExchangeV0, openSigned, passwordHash, randomSessionId, SecretBoxStream } from "./crypto";
import { MouseKind } from "./input";
import {
  decodeMessage, encodeAuth2FA, encodeCloseReason, encodeCtrlAltDel, encodeKeyMap, encodeLockScreen,
  encodeLoginRequest, encodeMouseEvent, encodePublicKey, encodeRefreshVideo, encodeSelectedSid, parseCursorData,
  parseCursorPosition, parseHash, parseIdPk, parseLoginResponse, parseMessageBox, parseMisc, parsePeerInfo,
  parseSignedId, parseVideoFrame, Permission, type Codec, type CursorDataMsg, type Decoded,
  type Decoding, type EncodedFrame, type MessageBox, type PeerInfo, type WindowsSessions,
  encodeCaptureDisplays, encodeChangeResolution, encodeOptionMisc, encodeQualityFields, encodeSwitchDisplay,
  parseTestDelay, type QualityOption, type Resolution, type SupportedEncoding,
  encodeElevationRequest, type ElevationRequest,
} from "./messages";
import {
  clipElevationDetail, ELEVATION_METHODS, ELEVATION_RESULTS, type ElevationMethod, type ElevationResult,
} from "./elevation";
import { DisplayTracker, type DisplayEventKind, type DisplayView } from "./displays";
import { PbError } from "./pb";
import { encodeClipboardOption } from "./clipboard";

/** 控制端宣稱的相容版本（7.3 的建議值） */
export const CLAIMED_VERSION = "1.4.1";
/** 7.3：會顯示在受控端的連線視窗與它的稽核裡 */
export const MY_ID = "jt-ipam";
/** 6.2：受控端送出 SignedId 後只等 18 秒；我們這邊等 SignedId 也用 18 秒 */
const SIGNED_ID_TIMEOUT_MS = 18_000;
/** 附錄 D.3：等後端回 login_assist 的時限。逾時就當成失敗、改請使用者輸入（受控端在等期間照常收 TestDelay） */
export const LOGIN_ASSIST_TIMEOUT_MS = 10_000;
/** 7.2：h2 是 32 bytes */
const H2_LENGTH = 32;

export type Phase =
  | "connecting" | "rendezvous" | "relay" | "paired" | "handshake" | "await_hash" | "need_password"
  | "logging_in" | "need_2fa" | "need_os_login" | "waiting_approval" | "connected" | "closed";

export interface CloseInfo {
  code?: string;              // 第 11 節的錯誤代碼（或 jt-ipam 外層的代碼）
  detail?: string;            // 原文
  params?: Record<string, unknown>;
  peerReason?: string;        // 受控端送的 close_reason
  byUser?: boolean;
}

/**
 * 為什麼要使用者輸入密碼：
 * - initial：一開始沒給
 * - wrong：手動輸入的密碼錯了（沿用同一個 Hash 重送，7.5）
 * - saved_rejected：已存的密碼被對方回 Wrong Password（附錄 D.4：已失效，不再自動重試）
 * - saved_failed：後端的 login_assist 回失敗（附錄 D.3／D.4），code 是錯誤代碼
 * - login_screen：送空密碼等對方同意，卻收到 No Password Access（附錄 G.5：受控端在登入畫面，沒有同意視窗）
 */
export type PasswordReason = "initial" | "wrong" | "saved_rejected" | "saved_failed" | "login_screen";

/**
 * 附錄 G.7：Linux 受控端沒有桌面、要作業系統帳號密碼的原因（LoginResponse.error）：
 * - not_ready：Desktop session not ready（RustDesk 密碼已通過或不需要）
 * - password_empty：Desktop session not ready, password empty（RustDesk 密碼也要）
 * - password_wrong：Desktop session not ready, password wrong（RustDesk 密碼錯，兩個都要重輸）
 * - xsession_failed：Desktop xsession failed（作業系統登入或啟動桌面失敗，重輸作業系統帳號密碼）
 */
export type OsLoginKind = "not_ready" | "password_empty" | "password_wrong" | "xsession_failed";
// Map 而不是物件：受控端送來的字串不可以比對到 constructor、toString 這類原型上的名字
const OS_LOGIN_ERRORS = new Map<string, OsLoginKind>([
  ["Desktop session not ready", "not_ready"],
  ["Desktop session not ready, password empty", "password_empty"],
  ["Desktop session not ready, password wrong", "password_wrong"],
  ["Desktop xsession failed", "xsession_failed"],
]);

export interface SessionEvents {
  phase?(p: Phase): void;
  needPassword?(reason: PasswordReason, code?: string): void;
  need2fa?(wrong: boolean): void;
  /** 附錄 G.7：要作業系統帳號密碼（連線不中斷，之後呼叫 loginOs） */
  needOsLogin?(kind: OsLoginKind): void;
  waitingApproval?(): void;
  connected?(info: PeerInfo): void;
  /** 附錄 G.6：登入回應帶了 windows_sessions；選好之後呼叫 selectWindowsSession，受控端才會送畫面 */
  windowsSessions?(ws: WindowsSessions): void;
  peerInfo?(info: PeerInfo): void;
  /** 只會收到目前螢幕的影格（附錄 H.2：別的螢幕的丟掉） */
  video?(codec: Codec, frames: EncodedFrame[], display: number): void;
  /** 附錄 H：螢幕清單、目前螢幕、座標換算的依據變了。removed 是被拔除的螢幕編號（kind 為 removed 時） */
  displays?(view: DisplayView, kind: DisplayEventKind, removed?: number): void;
  /** 附錄 I.1：TestDelay 回聲裡的延遲（毫秒）與目標位元率（kbps） */
  delay?(d: { lastDelay: number; targetBitrate: number }): void;
  /** 附錄 I.1：受控端在連線中告訴控制端它能編哪些（Misc.supported_encoding） */
  encoding?(e: SupportedEncoding): void;
  /** 8.4：新的游標形狀（colors 還是 zstd 壓縮過的，解壓與驗證在 cursor.ts） */
  cursorData?(c: CursorDataMsg): void;
  /** 8.4：改用之前收過的那個 id 的游標 */
  cursorId?(id: bigint): void;
  /** 8.4：受控端游標在虛擬桌面的座標（例如對方自己在動滑鼠） */
  cursorPosition?(p: { x: number; y: number }): void;
  keyboardPermission?(enabled: boolean): void;
  messageBox?(mb: MessageBox): void;
  /** 附錄 F：受控端的剪貼簿（原始的 oneof 內容，交給 clipboard.ts 解）。剪貼簿關著時不會呼叫 */
  clipboard?(kind: "clipboard" | "multi_clipboards", body: Uint8Array): void;
  closed?(info: CloseInfo): void;
  /** 附錄 J（檔案傳輸，fileSession.ts）：這裡不處理的訊息（file_action／file_response 等），解密後的整則 Message */
  unhandled?(plain: Uint8Array): void;
  /** 附錄 J.1：Misc.permission_info 的 File（4）：受控端在連線中開關了檔案傳輸權限 */
  filePermission?(enabled: boolean): void;
  /** 附錄 K.1：Misc.uac：受控端的 UAC 確認畫面是不是正在顯示（Windows 免安裝受控端才送） */
  uac?(showing: boolean): void;
  /** 附錄 K.1：Misc.foreground_window_elevated：受控端前景的視窗是不是以系統管理員權限執行 */
  foregroundElevated?(elevated: boolean): void;
  /** 附錄 K.1：Misc.elevation_response：請求提權的回覆（空字串＝已發出啟動，非空＝錯誤原文） */
  elevationResponse?(text: string): void;
  /** 附錄 K.1：Misc.portable_service_running：提權用的輔助服務是不是在跑 */
  portableService?(running: boolean): void;
}

export interface WebSocketLike {
  binaryType: string;
  readyState: number;
  /** 附錄 J：上傳時看瀏覽器的送出緩衝（受控端沒有流量控制） */
  bufferedAmount?: number;
  send(data: string | ArrayBufferLike | ArrayBufferView): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: unknown) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}

export interface SessionOptions {
  url: string;
  peerId: string;
  myName: string;
  decoding: Decoding;
  /** 一開始就給的密碼（空字串＝請對方按同意，7.7）；undefined＝收到 Hash 時再問 */
  password?: string;
  /** 附錄 D：用連線帳密金庫裡的這一筆登入（後端算 h2）。給了就不看 password */
  savedCredentialId?: string;
  viewOnly?: boolean;
  /** 附錄 F：剪貼簿開關的初始值（唯讀檢視時一律關） */
  clipboard?: boolean;
  /** 7.3 的 session_id。附錄 G.5：同一個頁面的重連都沿用第一次的值；不給就自己產生 */
  sessionId?: bigint;
  /** 附錄 I：畫質、更新率、編碼偏好（協定值）。登入時放進 LoginRequest.option；不給＝第一階段的行為 */
  quality?: QualityOption;
  /** 附錄 H.5：登入後要回到的螢幕（自動重連時用使用者原本選的；不存在或就是主螢幕時不切） */
  display?: number;
  events: SessionEvents;
  wsFactory?: (url: string) => WebSocketLike;
  /** 附錄 J.1：檔案傳輸的連線換掉 LoginRequest 的編碼（union file_transfer）；不給就是遠端桌面 */
  encodeLogin?: (o: Parameters<typeof encodeLoginRequest>[0]) => Uint8Array;
}

const OPEN = 1;

/** 會把這些 login error 當成「要求進一步動作」而不是失敗結束（7.5） */
const WRONG_PASSWORD = "Wrong Password";
const NEED_2FA = "2FA Required";
const WRONG_2FA = "Wrong 2FA Code";
const NO_PASSWORD_ACCESS = "No Password Access";

export class RdSession {
  phase: Phase = "connecting";
  peerInfo: PeerInfo | null = null;
  keyboardEnabled = true;
  /** 最後送出的滑鼠位置（受控端座標；附錄 E.2 用來分辨對方送來的 cursor_position 是不是我們的回音） */
  lastPointer: { x: number; y: number } | null = null;
  private ws: WebSocketLike;
  private peerSignPk: Uint8Array | null = null;     // 受控端長期的 ed25519 公鑰（6.1）
  private tx: SecretBoxStream | null = null;
  private rx: SecretBoxStream | null = null;
  private hash: { salt: string; challenge: string } | null = null;
  private pendingPassword: string | undefined;
  /** 附錄 D：這條連線還可以用的已存密碼；用過失敗就清掉（不自動重試） */
  private savedCredentialId: string | undefined;
  private assistPending = false;
  private assistTimer: ReturnType<typeof setTimeout> | null = null;
  /** 最近一次送出的 LoginRequest 用的是已存的密碼（收到 Wrong Password 時分辨「已失效」） */
  private lastLoginSaved = false;
  /** 最近一次送出的 LoginRequest 沒有密碼（等對方同意）：之後收到 No Password Access＝受控端在登入畫面（G.5） */
  private lastLoginEmpty = false;
  /**
   * 最近一次送出的 h2（只對這條連線的 challenge 有效）：G.7 在同一條連線補送作業系統帳號密碼時沿用，
   * 不必再要一次 login_assist 或再問一次 RustDesk 密碼。登入成功或連線結束就清掉。
   */
  private lastH2: Uint8Array | null = null;
  private readonly sessionId: bigint;
  private signedIdTimer: ReturnType<typeof setTimeout> | null = null;
  /** 附錄 H：螢幕清單與目前的螢幕 */
  private readonly disp = new DisplayTracker();
  /** 附錄 H.5：登入後要回到的螢幕（用過就清掉） */
  private returnTo: number | undefined;
  /** 附錄 I：目前的畫質設定（協定值）：登入時放進 LoginRequest.option，之後的變更跟它比 */
  private quality: QualityOption | undefined;
  private finished = false;
  private clipboardOn: boolean;

  constructor(private readonly opts: SessionOptions) {
    this.sessionId = opts.sessionId || randomSessionId();
    this.pendingPassword = opts.password;
    this.clipboardOn = !!opts.clipboard && !opts.viewOnly;
    this.savedCredentialId = opts.savedCredentialId || undefined;
    this.quality = opts.quality ? { ...opts.quality } : undefined;
    this.returnTo = opts.display;
    const factory = opts.wsFactory ?? ((u: string) => new WebSocket(u) as unknown as WebSocketLike);
    this.ws = factory(opts.url);
    this.ws.binaryType = "arraybuffer";
    this.ws.onmessage = (ev) => this.onWsMessage(ev.data);
    this.ws.onclose = () => this.finish({ code: this.phase === "connected" ? "rd_peer_closed" : "ws_closed" });
    this.ws.onerror = () => { /* onclose 會接著來 */ };
  }

  // ── 對外的動作 ──

  /** 送密碼登入（沿用同一個 Hash；7.5 密碼錯可以在同一條連線重試）。空字串＝請對方按同意。 */
  async login(password: string): Promise<void> {
    if (this.finished) return;
    if (!this.hash) {
      this.pendingPassword = password;
      return;
    }
    // 使用者自己輸入的密碼優先：還在等後端算已存密碼的話，那個回覆就不用了
    this.cancelAssist();
    const pw = password ? await passwordHash(password, this.hash.salt, this.hash.challenge) : new Uint8Array(0);
    if (this.finished) return;
    this.setPhase(password ? "logging_in" : "waiting_approval");
    this.sendLoginRequest(pw, false);
    pw.fill(0);
    if (!password) this.opts.events.waitingApproval?.();
  }

  submit2fa(code: string): void {
    if (this.finished || !this.tx) return;
    this.setPhase("logging_in");
    this.sendEncrypted(encodeAuth2FA(code.trim()));
  }

  /**
   * 附錄 G.7：在同一條連線再送一次 LoginRequest，帶作業系統帳號密碼（os_login）。
   * rustdeskPassword 有給就用這一次的 Hash 重新算 h2（password empty／wrong 時），沒給就沿用上一次送出的 h2。
   * 作業系統帳號密碼只放進這一則加密的訊息，不留在這裡。只在等作業系統登入時有作用。
   */
  async loginOs(username: string, osPassword: string, rustdeskPassword?: string): Promise<void> {
    if (this.finished || this.phase !== "need_os_login" || !this.hash) return;
    let pw: Uint8Array;
    let saved = false;
    if (rustdeskPassword) {
      pw = await passwordHash(rustdeskPassword, this.hash.salt, this.hash.challenge);
      if (this.finished || this.phase !== "need_os_login") { pw.fill(0); return; }
    } else {
      pw = this.lastH2 ? this.lastH2.slice() : new Uint8Array(0);
      saved = this.lastLoginSaved;
    }
    this.setPhase("logging_in");
    this.sendLoginRequest(pw, saved, { username, password: osPassword });
    pw.fill(0);
  }

  /** 附錄 G.6：回答 windows_sessions（Misc.selected_sid）。登入後才送。 */
  selectWindowsSession(sid: number): void {
    if (this.finished || this.phase !== "connected") return;
    this.sendEncrypted(encodeSelectedSid(sid));
    this.returnToChosenDisplay();          // H.5：受控端選好工作階段才開始送畫面，之後才切螢幕
  }

  /** 附錄 H：目前的螢幕狀態（登入前是 null） */
  get displayView(): DisplayView | null {
    return this.disp.count ? this.disp.view() : null;
  }

  /**
   * 附錄 H.2：切到第 n 個螢幕：switch_display（只填 display）→ capture_displays set=[n]（舊螢幕停止擷取）→
   * refresh_video_display(n)（要那個螢幕的關鍵影格）。目標就是目前的螢幕、或不存在時不送，回 false。
   */
  switchDisplay(n: number): boolean {
    if (this.phase !== "connected" || !this.disp.select(n)) return false;
    this.sendSwitch(n);
    this.opts.events.displays?.(this.disp.view(), "select");
    return true;
  }

  /**
   * 附錄 H.4：改目前螢幕的解析度（Misc.change_display_resolution）。受控端要鍵盤權限才會照做，
   * 失敗不回覆，結果從之後的 switch_display／peer_info 看。唯讀檢視、對方關閉控制權時不送。
   */
  changeResolution(r: Resolution): boolean {
    if (!this.canControl() || !this.disp.count || !(r.width > 0 && r.height > 0)) return false;
    this.sendEncrypted(encodeChangeResolution(this.disp.current, r));
    return true;
  }

  /**
   * 附錄 I：改畫質、更新率、編碼偏好。登入前只記下來（登入時放進 LoginRequest.option）；
   * 登入後用 Misc.option 只送改變的欄位。touched＝使用者這次明確選了的項目：值沒變也照送
   * （例如登入時沒送的「平衡」，受控端目前可能是別人設的畫質）。真的送出才回 true。
   */
  setQuality(next: QualityOption, touched: readonly (keyof QualityOption)[] = []): boolean {
    if (this.finished) return false;
    const sent = this.quality ?? next;
    this.quality = { ...next };
    if (this.phase !== "connected" || !this.tx) return false;
    const imageTouched = touched.includes("imageQuality") || touched.includes("customImageQuality");
    const which: (keyof QualityOption)[] = [];
    if (imageTouched || next.imageQuality !== sent.imageQuality || next.customImageQuality !== sent.customImageQuality) {
      // 設了 image_quality 時受控端不看 custom_image_quality；用自訂時 image_quality 是 NotSet（I.1）
      which.push(next.imageQuality ? "imageQuality" : "customImageQuality");
    }
    if (touched.includes("customFps") || next.customFps !== sent.customFps) which.push("customFps");
    if (touched.includes("prefer") || next.prefer !== sent.prefer) which.push("prefer");
    if (!which.length) return false;
    this.sendEncrypted(encodeOptionMisc(encodeQualityFields(next, this.opts.decoding, which)));
    return true;
  }

  /** 真的送出才回 true。滾輪的 x、y 是格數不是座標（9.1），不記成最後的滑鼠位置。 */
  sendMouse(mask: number, x: number, y: number, modifiers: number[] = []): boolean {
    if (!this.canControl()) return false;
    this.sendEncrypted(encodeMouseEvent(mask, x, y, modifiers));
    if ((mask & 7) !== MouseKind.Wheel) this.lastPointer = { x, y };
    return true;
  }

  sendKey(down: boolean, chr: number, modifiers: number[]): void {
    if (!this.canControl()) return;
    this.sendEncrypted(encodeKeyMap(down, chr, modifiers));
  }

  sendCtrlAltDel(): void {
    if (!this.canControl()) return;
    this.sendEncrypted(encodeCtrlAltDel(this.peerInfo?.platform || ""));
  }

  sendLockScreen(): void {
    if (!this.canControl()) return;
    this.sendEncrypted(encodeLockScreen());
  }

  get clipboardEnabled(): boolean {
    return this.clipboardOn;
  }

  /**
   * 附錄 F：切換剪貼簿。登入前只改登入時的 disable_clipboard；登入後送 Misc.option。
   * 受控端關閉之後仍然會寫入控制端送來的內容（F.1 第 6 點），所以關閉時 sendClipboard 也一併停止送出。
   */
  setClipboard(on: boolean): void {
    const v = on && !this.opts.viewOnly;
    if (v === this.clipboardOn || this.finished) return;
    this.clipboardOn = v;
    if (this.phase === "connected") this.sendEncrypted(encodeClipboardOption(v));
  }

  /** 附錄 F：送剪貼簿（clipboard.ts 編好的 Message）。只在登入後、剪貼簿開著時送；沒送出回 false。 */
  sendClipboard(msg: Uint8Array): boolean {
    if (this.phase !== "connected" || !this.clipboardOn) return false;
    this.sendEncrypted(msg);
    return true;
  }

  /** 8.3：要求關鍵影格（附錄 H.2：refresh_video_display 帶目前的螢幕編號）。 */
  requestKeyframe(): void {
    if (this.phase !== "connected") return;
    this.sendEncrypted(encodeRefreshVideo(this.disp.current));
  }

  /**
   * 附錄 K.1：請求提權（Misc.elevation_request）。只在可以控制時送（連線中、對方沒關閉控制權、不是唯讀檢視），
   * 檔案傳輸的連線不送；真的送出才回 true。logon 的帳號密碼只放進這一則加密的訊息，這裡不留也不告訴後端。
   */
  requestElevation(req: ElevationRequest): boolean {
    if (!this.canControl() || this.opts.encodeLogin) return false;
    this.sendEncrypted(encodeElevationRequest(req));
    return true;
  }

  /**
   * 附錄 K.2：提權的稽核摘要給後端（瀏覽器自報，沿用 file_audit 的作法，在一般遠端桌面連線上）：
   * 只有 t、method、result、detail 四個欄位，不含帳號密碼；detail 是受控端的錯誤原文，截到 200 個字元。
   * method／result 不在清單內、檔案傳輸的連線不送。
   */
  reportElevation(method: ElevationMethod, result: ElevationResult, detail = ""): void {
    if (this.finished || this.opts.encodeLogin) return;
    if (!ELEVATION_METHODS.includes(method) || !ELEVATION_RESULTS.includes(result)) return;
    this.sendControl({ t: "elevation_audit", method, result, detail: clipElevationDetail(String(detail)) });
  }

  /** 附錄 J（檔案傳輸）：送一則已經編好的 Message（一律加密）。登入後才送；沒送出回 false。 */
  sendMessage(plain: Uint8Array): boolean {
    if (this.phase !== "connected" || this.finished) return false;
    this.sendEncrypted(plain);
    return true;
  }

  /** 10：控制端主動結束：送空字串的 close_reason，再關 WebSocket。 */
  close(): void {
    if (this.finished) return;
    if (this.tx && this.ws.readyState === OPEN) {
      try { this.sendEncrypted(encodeCloseReason("")); } catch { /* 送不出去也要關 */ }
    }
    this.sendControl({ t: "close", reason: "user" });
    this.finish({ byUser: true });
  }

  // ── 內部 ──

  private canControl(): boolean {
    return this.phase === "connected" && this.keyboardEnabled && !this.opts.viewOnly;
  }

  private setPhase(p: Phase): void {
    if (this.phase === p || this.finished) return;
    this.phase = p;
    this.opts.events.phase?.(p);
  }

  private sendControl(obj: Record<string, unknown>): void {
    if (this.ws.readyState === OPEN) this.ws.send(JSON.stringify(obj));
  }

  private sendRaw(b: Uint8Array): void {
    if (this.ws.readyState === OPEN) this.ws.send(b);
  }

  /** 2.4：送出的訊息一律加密。 */
  private sendEncrypted(plain: Uint8Array): void {
    if (!this.tx) throw new Error("not encrypted yet");
    this.sendRaw(this.tx.seal(plain));
  }

  private fail(code: string, detail = ""): void {
    this.finish({ code, detail });
  }

  /**
   * 7.3：送 LoginRequest。password 是 7.2 的 h2（32 bytes），或空的（7.7 等對方同意）。
   * osLogin 只在 G.7 的第二次登入才給。呼叫端之後可以把 password 清掉（這裡留的是複本）。
   */
  private sendLoginRequest(password: Uint8Array, saved: boolean,
                           osLogin?: { username: string; password: string }): void {
    this.lastLoginSaved = saved;
    this.lastLoginEmpty = password.length === 0;
    const keep = password.length ? password.slice() : null;
    this.lastH2?.fill(0);
    this.lastH2 = keep;
    this.sendEncrypted((this.opts.encodeLogin ?? encodeLoginRequest)({
      peerId: this.opts.peerId, password, myId: MY_ID, myName: this.opts.myName,
      sessionId: this.sessionId, version: CLAIMED_VERSION, decoding: this.opts.decoding,
      viewOnly: this.opts.viewOnly, clipboard: this.clipboardOn, osLogin, quality: this.quality,
    }));
  }

  /** 附錄 H.2：切換螢幕的三則訊息，照這個順序。 */
  private sendSwitch(n: number): void {
    this.sendEncrypted(encodeSwitchDisplay(n));
    this.sendEncrypted(encodeCaptureDisplays([n]));
    this.sendEncrypted(encodeRefreshVideo(n));
  }

  /** 附錄 H.5：登入後回到使用者原本選的螢幕（還存在、而且不是目前的螢幕才切）。 */
  private returnToChosenDisplay(): void {
    const n = this.returnTo;
    this.returnTo = undefined;
    if (n !== undefined && !this.finished) this.switchDisplay(n);
  }

  /**
   * 附錄 H.1：連線中受控端再送的 peer_info 只帶螢幕清單（它的 current_display 一律是 0，不採用）。
   * 目前選的螢幕不見了：照 H.2 切到主螢幕（主螢幕也不在就切到 0），事件帶被拔除的編號。
   */
  private onDisplayList(list: PeerInfo["displays"]): void {
    if (!list.length) return;
    const gone = this.disp.update(list);
    if (!gone) {
      this.opts.events.displays?.(this.disp.view(), "update");
      return;
    }
    this.disp.select(gone.to);
    this.sendSwitch(gone.to);
    this.opts.events.displays?.(this.disp.view(), "removed", gone.removed);
  }

  private forgetH2(): void {
    this.lastH2?.fill(0);
    this.lastH2 = null;
  }

  private cancelAssist(): void {
    this.assistPending = false;
    if (this.assistTimer) clearTimeout(this.assistTimer);
    this.assistTimer = null;
  }

  /** 附錄 D.3：請後端用已存的密碼算這一次連線的 h2。 */
  private requestAssist(credentialId: string, h: { salt: string; challenge: string }): void {
    this.assistPending = true;
    this.setPhase("logging_in");
    this.sendControl({ t: "login_assist", credential_id: credentialId, salt: h.salt, challenge: h.challenge });
    this.assistTimer = setTimeout(() => {
      if (this.assistPending) this.onAssistReply({ ok: false, code: "rd_saved_password_unavailable" });
    }, LOGIN_ASSIST_TIMEOUT_MS);
  }

  /** 後端的 login_assist 回覆：成功就用 h2 登入；失敗就改請使用者輸入（D.4），這條連線不再用已存的密碼。 */
  private onAssistReply(obj: Record<string, unknown>): void {
    if (!this.assistPending) return;            // 沒有在等（已改用手動輸入、或重複的回覆）
    this.cancelAssist();
    const h2 = obj.ok === true ? base64ToBytes(String(obj.hash || "")) : null;
    if (!h2 || h2.length !== H2_LENGTH || !this.hash) {
      h2?.fill(0);
      this.savedCredentialId = undefined;
      const code = obj.ok === true ? "rd_saved_password_unavailable" : String(obj.code || "rd_saved_password_unavailable");
      this.setPhase("need_password");
      this.opts.events.needPassword?.("saved_failed", code);
      return;
    }
    this.sendLoginRequest(h2, true);
    h2.fill(0);
  }

  private finish(info: CloseInfo): void {
    if (this.finished) return;
    this.finished = true;
    if (this.signedIdTimer) clearTimeout(this.signedIdTimer);
    this.cancelAssist();
    this.savedCredentialId = undefined;
    this.phase = "closed";
    this.tx = null;
    this.rx = null;
    this.hash = null;
    this.forgetH2();
    this.pendingPassword = undefined;
    try { this.ws.close(); } catch { /* 已經關了 */ }
    this.opts.events.phase?.("closed");
    this.opts.events.closed?.(info);
  }

  private onWsMessage(data: unknown): void {
    if (this.finished) return;
    if (typeof data === "string") {
      this.onControl(data);
      return;
    }
    const buf = data instanceof ArrayBuffer ? new Uint8Array(data)
      : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : null;
    if (!buf) return;
    try {
      this.onBinary(buf);
    } catch (e) {
      if (e instanceof PbError) this.fail("rd_handshake_failed", e.message);
      else throw e;
    }
  }

  private onControl(text: string): void {
    let obj: Record<string, unknown>;
    try { obj = JSON.parse(text); } catch { return; }
    const t = obj.t;
    if (t === "stage") {
      const s = String(obj.stage || "");
      if (s === "rendezvous" || s === "relay" || s === "paired") this.setPhase(s);
    } else if (t === "ready") {
      this.onReady(String(obj.signed_id_pk || ""), String(obj.server_key || ""));
    } else if (t === "login_assist") {
      this.onAssistReply(obj);
    } else if (t === "error") {
      this.finish({ code: String(obj.code || "rd_internal"), detail: String(obj.detail || ""),
                    params: (obj.params as Record<string, unknown>) || undefined });
    } else if (t === "close") {
      this.finish({ code: obj.reason === "peer_closed" ? "rd_peer_closed" : undefined,
                    detail: String(obj.reason || "") });
    }
  }

  /** 6.1：驗 hbbs 簽章過的受控端身分，拿到受控端的 ed25519 公鑰。 */
  private onReady(signedB64: string, serverKeyB64: string): void {
    const signed = base64ToBytes(signedB64);
    if (!signed || !signed.length) {
      this.fail("rd_insecure_refused");
      return;
    }
    const serverKey = base64ToBytes(serverKeyB64);
    const msg = serverKey ? openSigned(signed, serverKey) : null;
    if (!msg) {
      this.fail("rd_bad_server_signature");
      return;
    }
    let idpk;
    try { idpk = parseIdPk(msg); } catch { this.fail("rd_bad_server_signature"); return; }
    if (idpk.id !== this.opts.peerId) {
      this.fail("rd_bad_server_signature", "id mismatch");
      return;
    }
    if (!idpk.pk.length) {
      this.fail("rd_insecure_refused");     // 上游會退回不加密，我們不退
      return;
    }
    if (idpk.pk.length !== 32) {
      this.fail("rd_bad_server_signature", "peer key length");
      return;
    }
    this.peerSignPk = idpk.pk;
    this.setPhase("handshake");
    this.signedIdTimer = setTimeout(() => {
      if (this.phase === "handshake") this.fail("rd_relay_timeout", "SignedId");
    }, SIGNED_ID_TIMEOUT_MS);
  }

  private onBinary(buf: Uint8Array): void {
    if (!this.peerSignPk) {
      this.fail("rd_handshake_failed", "message before ready");
      return;
    }
    if (!this.rx) {
      this.onSignedId(buf);
      return;
    }
    if (buf.length <= 1) return;            // 2.4：長度 ≤ 1 的不解密、不算計數
    const plain = this.rx.open(buf);
    if (!plain) {
      this.fail("rd_decrypt_failed");       // 計數器已經對不上，不再嘗試後面的訊息
      return;
    }
    this.onMessage(plain);
  }

  /** 6.2＋6.3：驗受控端的 SignedId，做金鑰交換 v0，送 PublicKey（這一則不加密）。 */
  private onSignedId(buf: Uint8Array): void {
    const m = decodeMessage(buf);
    if (m.kind !== "signed_id") {
      this.fail("rd_handshake_failed", m.kind || "unknown first message");
      return;
    }
    const msg = openSigned(parseSignedId(m.body), this.peerSignPk!);
    if (!msg) {
      this.fail("rd_bad_peer_signature");
      return;
    }
    const idpk = parseIdPk(msg);
    if (idpk.id !== this.opts.peerId || idpk.pk.length !== 32) {
      this.fail("rd_bad_peer_signature", "id or key mismatch");
      return;
    }
    if (this.signedIdTimer) clearTimeout(this.signedIdTimer);
    // 第一階段固定 kx_version 0（6.6）：不管受控端宣告支援到哪一版，都不填
    const kx = keyExchangeV0(idpk.pk);
    this.sendRaw(encodePublicKey(kx.ourPk, kx.sealed));
    this.tx = new SecretBoxStream(kx.key);
    this.rx = new SecretBoxStream(kx.key);
    kx.key.fill(0);
    this.setPhase("await_hash");
  }

  private onMessage(plain: Uint8Array): void {
    const m = decodeMessage(plain);
    switch (m.kind) {
      case "test_delay": {
        // 8.6：受控端送的（from_client = false）原封不動送回去；回聲裡的延遲與位元率給狀態列（附錄 I.1）
        const td = parseTestDelay(m.body);
        if (td.fromClient) return;
        this.sendEncrypted(plain);
        this.opts.events.delay?.({ lastDelay: td.lastDelay, targetBitrate: td.targetBitrate });
        return;
      }
      case "hash":
        this.onHash(parseHash(m.body));
        return;
      case "login_response":
        this.onLoginResponse(m.body);
        return;
      case "peer_info": {
        const update = parsePeerInfo(m.body);
        const info = this.mergePeerInfo(update);
        this.peerInfo = info;
        this.opts.events.peerInfo?.(info);
        if (this.phase === "connected") this.onDisplayList(update.displays);
        return;
      }
      case "video_frame": {
        if (this.phase !== "connected") return;
        const v = parseVideoFrame(m.body);
        // H.2：不是目前螢幕的影格丟掉（切換的空檔可能還有舊螢幕的幾張）
        if (v.codec && v.display === this.disp.current) this.opts.events.video?.(v.codec, v.frames, v.display);
        return;
      }
      case "misc":
        this.onMisc(m.body);
        return;
      case "message_box":
        this.opts.events.messageBox?.(parseMessageBox(m.body));
        return;
      case "cursor_data":
      case "cursor_id":
      case "cursor_position":
        if (this.phase === "connected") this.onCursor(m);
        return;
      case "clipboard":
      case "multi_clipboards":
        // 附錄 F：剪貼簿關著時不收（受控端照理不會送，但切換的當下可能還有在路上的）
        if (this.phase === "connected" && this.clipboardOn) this.opts.events.clipboard?.(m.kind, m.body);
        return;
      default:
        // 其他訊息：忽略（檔案傳輸的連線由 fileSession.ts 接手，附錄 J）
        this.opts.events.unhandled?.(plain);
        return;
    }
  }

  /** 8.4、附錄 E：游標訊息交給畫面。內容有問題就丟掉這則，不中斷連線（游標不是必要的）。 */
  private onCursor(m: Decoded): void {
    try {
      if (m.kind === "cursor_data") {
        this.opts.events.cursorData?.(parseCursorData(m.body));
      } else if (m.kind === "cursor_id") {
        if (m.value !== undefined) this.opts.events.cursorId?.(BigInt.asUintN(64, m.value));
      } else {
        this.opts.events.cursorPosition?.(parseCursorPosition(m.body));
      }
    } catch (e) {
      if (!(e instanceof PbError)) throw e;
    }
  }

  private onHash(h: { salt: string; challenge: string }): void {
    this.hash = h;
    if (this.savedCredentialId) {
      this.requestAssist(this.savedCredentialId, h);
    } else if (this.pendingPassword !== undefined) {
      const pw = this.pendingPassword;
      this.pendingPassword = undefined;
      void this.login(pw);
    } else {
      this.setPhase("need_password");
      this.opts.events.needPassword?.("initial");
    }
  }

  private onLoginResponse(body: Uint8Array): void {
    const r = parseLoginResponse(body);
    if ("peerInfo" in r) {
      this.sendControl({ t: "login_result", ok: true, error: "" });
      this.cancelAssist();
      this.savedCredentialId = undefined;
      this.peerInfo = r.peerInfo;
      this.hash = null;                     // 登入成功後不再需要
      this.forgetH2();
      // 檔案傳輸的連線（附錄 J，換了 encodeLogin 的）不收畫面，登入回覆可能沒有螢幕清單：不做下面的螢幕檢查
      const fileTransfer = !!this.opts.encodeLogin;
      if (!fileTransfer && !this.disp.login(r.peerInfo)) {
        // H.1：螢幕清單是空的：顯示「沒有螢幕」並結束
        try { this.sendEncrypted(encodeCloseReason("")); } catch { /* 送不出去也要關 */ }
        this.sendControl({ t: "close", reason: "no_display" });
        this.finish({ code: "rd_no_display" });
        return;
      }
      this.setPhase("connected");
      this.opts.events.connected?.(r.peerInfo);
      if (this.finished) return;
      if (!fileTransfer) this.opts.events.displays?.(this.disp.view(), "login");
      // G.6：受控端要等 Misc.selected_sid 才送畫面；H.5 的回到原本的螢幕也等選好之後
      if (r.peerInfo.windowsSessions) this.opts.events.windowsSessions?.(r.peerInfo.windowsSessions);
      else this.returnToChosenDisplay();
      return;
    }
    const err = r.error;
    // 2.3：給後端稽核與限流（後端只當參考）
    this.sendControl({ t: "login_result", ok: false, error: err });
    const osKind = OS_LOGIN_ERRORS.get(err);
    if (err === WRONG_PASSWORD) {
      const saved = this.lastLoginSaved;
      this.lastLoginSaved = false;
      // D.4：已存的密碼被拒＝已失效（對方可能改過密碼）。這條連線不再自動用它重試
      if (saved) this.savedCredentialId = undefined;
      this.setPhase("need_password");
      this.opts.events.needPassword?.(saved ? "saved_rejected" : "wrong");
    } else if (err === NEED_2FA || err === WRONG_2FA) {
      this.setPhase("need_2fa");
      this.opts.events.need2fa?.(err === WRONG_2FA);
    } else if (err === NO_PASSWORD_ACCESS && this.lastLoginEmpty) {
      // G.5：送空密碼等對方同意卻收到這個＝受控端在登入畫面（沒有同意視窗）：改請使用者輸入密碼（同一個 Hash）
      this.setPhase("need_password");
      this.opts.events.needPassword?.("login_screen");
    } else if (err === NO_PASSWORD_ACCESS) {
      this.setPhase("waiting_approval");
      this.opts.events.waitingApproval?.();
    } else if (osKind) {
      // G.7：Linux 受控端沒有桌面：請使用者輸入作業系統帳號密碼，同一條連線再登入一次（loginOs）
      if (osKind === "password_wrong" && this.lastLoginSaved) this.savedCredentialId = undefined;
      this.setPhase("need_os_login");
      this.opts.events.needOsLogin?.(osKind);
    } else {
      // 其他（錯太多次、桌面工作階段沒準備好、IP 不在允許清單……）：原文顯示，結束
      this.finish({ code: "rd_login_error", detail: err, params: { reason: err } });
    }
  }

  /**
   * 登入後單獨送來的 peer_info（8.1，附錄 C-4）語意是「更新螢幕資訊」：只帶螢幕清單、目前螢幕與平台附加資訊，
   * 其他欄位是空的。平台、版本、主機名稱、使用者一律以登入回應的 PeerInfo 為準 —— 整個取代的話 platform
   * 變空字串，鍵盤對照表就查不到任何按鍵（黑箱實測：第二個控制端連上時就會收到這種 peer_info）。
   * 它的 current_display 一律是 0（附錄 H.1），不採用：currentDisplay 維持登入時的主螢幕，目前螢幕在 displays.ts。
   */
  private mergePeerInfo(u: PeerInfo): PeerInfo {
    const prev = this.peerInfo;
    if (!prev) return u;
    const hasDisplays = u.displays.length > 0;
    return {
      ...prev,
      platformAdditions: u.platformAdditions || prev.platformAdditions,
      displays: hasDisplays ? u.displays : prev.displays,
    };
  }

  private onMisc(body: Uint8Array): void {
    const misc = parseMisc(body);
    if (misc.type === "close_reason") {
      this.finish({ code: "rd_peer_closed", detail: misc.reason, peerReason: misc.reason });
    } else if (misc.type === "permission_info") {
      if (misc.permission === Permission.Keyboard) {
        this.keyboardEnabled = misc.enabled;
        this.opts.events.keyboardPermission?.(misc.enabled);
      } else if (misc.permission === Permission.File) {
        this.opts.events.filePermission?.(misc.enabled);          // 附錄 J.1
      }
    } else if (misc.type === "switch_display") {
      // H.2：剛才要切的那個＝切換完成；目前螢幕、沒在等切換＝大小改了（不是切換）；其他是舊的回覆
      if (this.phase !== "connected") return;
      const kind = this.disp.onSwitch(misc);
      if (kind !== "stale") this.opts.events.displays?.(this.disp.view(), kind);
    } else if (misc.type === "supported_encoding") {
      this.opts.events.encoding?.(misc.encoding);
    } else if (this.phase === "connected") {
      // 附錄 K.1：受控端登入成功之後才檢查、才送（Windows 免安裝受控端）；規則在 elevation.ts
      if (misc.type === "uac") this.opts.events.uac?.(misc.value);
      else if (misc.type === "foreground_window_elevated") this.opts.events.foregroundElevated?.(misc.value);
      else if (misc.type === "elevation_response") this.opts.events.elevationResponse?.(misc.text);
      else if (misc.type === "portable_service_running") this.opts.events.portableService?.(misc.value);
    }
  }
}
