/**
 * 斷線後自動重新連線（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 G，jt-ipam 端的設計）。
 *
 * 這裡只放規則：哪些結束原因要重連（G.2）、間隔與次數（G.3）、重連時用什麼密碼、什麼時候清掉。
 * 開連線、畫面都在 RustDeskScreen.vue；每一次重連都是完整的新連線（新票證、新配對、新 Hash、新登入雜湊），
 * 由畫面照第一次連線的流程重做，這裡不碰協定。
 *
 * 密碼（G.3）：
 * - 使用者輸入的密碼只放在這個物件的欄位裡（頁面的記憶體），不寫進 localStorage／sessionStorage／IndexedDB
 *   或任何網址；使用者按「中斷」、取消自動重連、重試用完、離開頁面時清掉（連線以其他原因結束時也一併清掉）。
 * - 已存的密碼（附錄 D）只記金庫那一筆的 credential_id；每次重連照 D.3 重新 login_assist 拿這一次的 h2。
 * - 「記住密碼」只在使用者手動登入成功的那一次存；自動重連成功不重複存。
 *
 * G.5：受控端在任何平台切換工作階段（Windows 登出／切換使用者、Linux 各種桌面管理器、macOS 登入視窗）都是直接結束連線、
 * 不送任何訊息，所以「連上過、沒有 close_reason 的中斷」就是唯一的訊號，不靠比對文字；送了 close_reason 的一律不重連。
 * G.6：Windows 工作階段選擇的「要不要問」也放在這裡（pickWindowsSession）。
 */
import type { WindowsSessions } from "./messages";
import type { CloseInfo } from "./session";

/** G.3：第 k 次重連前等幾秒（共 8 次，大約一分鐘；GDM 登入後受控端要幾秒才回來） */
export const RECONNECT_DELAYS_S: readonly number[] = [1, 2, 3, 5, 5, 10, 10, 15];

/**
 * 換票證失敗時的代碼（瀏覽器自己的，不是第 11 節的代碼）：
 * - ticket_unavailable：沒有回應，或閘道錯誤（502／503／504）：jt-ipam 後端重新啟動中（G.1 的同一類情況）
 * - ticket_refused：其他（401／403 權限不足、404、409、429 限流……），重試也不會好（G.2）
 */
export const TICKET_UNAVAILABLE = "ticket_unavailable";
export const TICKET_REFUSED = "ticket_refused";
const GATEWAY_STATUS = new Set([502, 503, 504]);

/** 換票證失敗：依 HTTP 狀態碼（沒有回應時是 undefined）分類。detail 放要顯示的訊息。 */
export function ticketFailure(status: number | undefined, detail: string): CloseInfo {
  const unavailable = status === undefined || status === 0 || GATEWAY_STATUS.has(status);
  return { code: unavailable ? TICKET_UNAVAILABLE : TICKET_REFUSED, detail, params: { status: status ?? null } };
}

/**
 * 一列比對條件。全部有寫的欄位都符合才算。
 * - code：結束代碼；session.ts 沒帶代碼的結束（後端送 close 但不是 peer_closed）視同 ws_closed
 * - detail：原文（例如 7.5 的登入錯誤原文），字串＝完全相同，RegExp＝符合
 * - unless：原文符合其中任何一個就不算（字串＝完全相同，RegExp＝符合）
 * - peerReason：false＝受控端沒有送 close_reason 才算；true＝有送才算；不寫＝不管
 */
export interface CloseMatch {
  code: string;
  detail?: string | RegExp;
  unless?: readonly (string | RegExp)[];
  peerReason?: boolean;
}

/**
 * §7.1：受控端在送 Hash 之前就回 LoginResponse.error、接著關閉連線的兩種拒絕。
 * session.ts 收到登入回覆就以 rd_login_error（原文放 detail）結束，之後的關閉不會再算一次；
 * 受控端若改用 close_reason 說明，帶了 peerReason 的結束本來就不重連（G.2）。
 * - IP 不在受控端的允許清單：jt-ipam 伺服器的 IP 不會自己變，重試也不會好
 * - 受控端設定成主視窗開著才接受：要受控端那邊的人打開主視窗
 */
export const REFUSED_BEFORE_HASH: readonly string[] = [
  "Your ip is blocked by the peer",
  "The main window is not open",
];

/**
 * G.3：重連途中，登入回覆（§7.5 的 LoginResponse.error）預設當成「受控端還沒準備好」，只有這些要停止：
 * 需要使用者處理（密碼、兩步驟驗證、登入畫面、作業系統登入、受控端的主視窗），或重試也不會好
 * （錯誤次數限制、顯示環境不支援、不允許、IP 不在允許清單）。
 * 黑箱實測（2026-10-05）：受控端剛重新啟動時第一次登入回 connection refused，幾秒後再試就正常。
 * 第一次（手動）連線不經過這裡，登入錯誤照舊直接顯示。
 */
export const LOGIN_ERRORS_THAT_STOP: readonly (string | RegExp)[] = [
  "Wrong Password", "2FA Required", "Wrong 2FA Code",
  "No Password Access",                          // G.5：登入畫面的提示
  "Too many wrong attempts", "Please try 1 minute later",
  /^Desktop/,                                    // G.7：作業系統登入與沒有桌面的各種回覆
  "Wayland login screen is not supported", "x11 expected", /^Unsupported display server type/,
  /not allowed/i,
  ...REFUSED_BEFORE_HASH,                        // §7.1：Hash 之前送來的拒絕
];

/** G.2「中繼／網路類的錯誤」：對方或網路暫時不在，過一下可能就好 */
const NETWORK: readonly CloseMatch[] = [
  { code: "rd_hbbs_unreachable" },
  { code: "rd_rendezvous_timeout" },
  { code: "rd_offline" },              // 受控端暫時沒有向 hbbs 報到（重新啟動中）
  { code: "rd_hbbr_unreachable" },
  { code: "rd_relay_timeout" },        // 對方沒有接上中繼
];

/**
 * G.2：已經連上過（收到 peer_info）的連線意外中斷時，這些結束原因自動重連。
 * 新的「對方在切換工作階段」原因加一列即可。
 */
export const RETRY_AFTER_DROP: readonly CloseMatch[] = [
  // 受控端直接結束、沒說原因（G.1：在 GDM 登入後切到新的桌面工作階段）
  { code: "rd_peer_closed", peerReason: false },
  // 瀏覽器 ↔ jt-ipam 的 WebSocket 意外關閉（例如 jt-ipam 後端重新啟動）
  { code: "ws_closed" },
  ...NETWORK,
];

/**
 * G.3：重連途中，這些結束原因算「對方還沒回來」，繼續下一次；用完次數才顯示錯誤（帶最後一次的原文）。
 * 其他原因（停止清單裡的登入回覆、限流、簽章不符、權限不足……）立刻停止並照常顯示。
 */
export const RETRY_DURING_ATTEMPT: readonly CloseMatch[] = [
  ...RETRY_AFTER_DROP,
  // 登入回覆：Offline、connection refused 之類受控端還沒準備好的，除了停止清單以外都再試
  { code: "rd_login_error", unless: LOGIN_ERRORS_THAT_STOP },
  { code: TICKET_UNAVAILABLE },                     // jt-ipam 後端還在重新啟動
];

function textMatches(d: string, p: string | RegExp): boolean {
  return typeof p === "string" ? d === p : p.test(d);
}

function matchOne(info: CloseInfo, m: CloseMatch): boolean {
  if ((info.code || "ws_closed") !== m.code) return false;
  if (m.peerReason !== undefined && !!info.peerReason !== m.peerReason) return false;
  const d = (info.detail ?? "").trim();
  if (m.detail !== undefined && !textMatches(d, m.detail)) return false;
  if (m.unless?.some((p) => textMatches(d, p))) return false;
  return true;
}

export function matchesAny(info: CloseInfo, table: readonly CloseMatch[]): boolean {
  return !info.byUser && table.some((m) => matchOne(info, m));
}

/** G.2：曾經連上的連線以這個原因結束，要不要自動重連。使用者自己結束的一律不要。 */
export function retryAfterDrop(info: CloseInfo): boolean {
  return matchesAny(info, RETRY_AFTER_DROP);
}

/** G.3：重連的這一次以這個原因失敗，算不算「還沒回來」（繼續下一次）。 */
export function retryDuringAttempt(info: CloseInfo): boolean {
  return matchesAny(info, RETRY_DURING_ATTEMPT);
}

/**
 * 附錄 G.6：登入回應帶 windows_sessions 時，要不要問使用者。回傳要直接送出的 sid，null＝要問（預設選 current_sid）。
 * - 只有一個可選（或清單是空的）：直接送，不必問
 * - 這個頁面之前選過、而且受控端現在的 current_sid 就是它（選了別的工作階段、斷線重連回來）：直接送，不再詢問
 */
export function pickWindowsSession(ws: WindowsSessions, remembered: number | null): number | null {
  if (ws.sessions.length <= 1) return ws.sessions[0]?.sid ?? ws.currentSid;
  if (remembered !== null && remembered === ws.currentSid) return ws.currentSid;
  return null;
}

/** 重連時用的密碼（只在記憶體）。 */
export type ReconnectAuth =
  | { kind: "typed"; password: string }          // 使用者輸入的密碼；空字串＝請對方按同意（§7.7）
  | { kind: "saved"; credentialId: string };     // 附錄 D：每次重連重新 login_assist

/** 連線結束時的決定 */
export type EndDecision =
  | { kind: "wait"; attempt: number; delay: number }        // 倒數 delay 秒後第 attempt 次重連
  | { kind: "gave_up"; attempts: number; last: CloseInfo }  // 次數用完：顯示錯誤（帶最後一次的原因）
  | { kind: "stop" };                                       // 不重連：照現在的方式顯示結果

export interface ReconnectView {
  /** idle＝沒有在自動重連；waiting＝倒數中；trying＝這一次的連線進行中 */
  state: "idle" | "waiting" | "trying";
  attempt: number;          // 第幾次（1 起算），idle 時 0
  total: number;            // 總共幾次
  remaining: number;        // 倒數剩幾秒（waiting 時）
}

export interface AutoReconnectOptions {
  /** 開始第 n 次重連：開一條完整的新連線，照 auth 登入（null＝收到 Hash 時再問） */
  attempt(n: number, auth: ReconnectAuth | null): void;
  /** 倒數的秒數或狀態變了（畫面更新用） */
  change?(v: ReconnectView): void;
  delays?: readonly number[];
}

type Mode = "idle" | "live" | "waiting" | "trying";

export class AutoReconnect {
  private mode: Mode = "idle";
  private n = 0;
  private deadline = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private secret: ReconnectAuth | null = null;
  private toSave: string | null = null;
  private disposed = false;
  private readonly delays: readonly number[];

  constructor(private readonly opts: AutoReconnectOptions) {
    this.delays = opts.delays ?? RECONNECT_DELAYS_S;
  }

  get view(): ReconnectView {
    const state = this.mode === "waiting" || this.mode === "trying" ? this.mode : "idle";
    return {
      state,
      attempt: state === "idle" ? 0 : this.n,
      total: this.delays.length,
      remaining: state === "waiting" ? Math.max(0, Math.ceil((this.deadline - Date.now()) / 1000)) : 0,
    };
  }

  /** 重連時要用的密碼（只在記憶體） */
  get auth(): ReconnectAuth | null {
    return this.secret;
  }

  /** 這條連線是自動重連的其中一次（還沒連上） */
  get trying(): boolean {
    return this.mode === "trying";
  }

  /**
   * 使用者按「連線」：一次新的手動連線。清掉上一輪的狀態，記下這次用的密碼；
   * remember＝勾了「記住密碼」（登入成功後才存，D.2）。
   */
  begin(auth: ReconnectAuth | null, remember: boolean): void {
    if (this.disposed) return;
    this.clearTimer();
    this.mode = "idle";
    this.n = 0;
    this.secret = auth;
    this.toSave = remember && auth?.kind === "typed" && auth.password ? auth.password : null;
    this.emit();
  }

  /** 使用者在密碼框輸入後登入（手動登入；之後重連用這一組）。 */
  typed(password: string, remember: boolean): void {
    if (this.disposed) return;
    this.secret = { kind: "typed", password };
    this.toSave = remember && password ? password : null;
  }

  /**
   * 這條連線要使用者介入，停止自動重連（G.3）：
   * - password：Wrong Password、已存密碼不能用、要輸入密碼。記憶體裡的密碼已經不能用，一併清掉
   * - 2fa：2FA Required，顯示驗證碼輸入框
   * - approval：等對方同意（§7.7）；對方已經回來了，剩下的由對方決定
   * - os_login：G.7 要作業系統帳號密碼（RustDesk 密碼沒問題，記憶體裡的照留；作業系統帳號密碼不經過這裡）
   */
  interrupt(kind: "password" | "2fa" | "approval" | "os_login"): void {
    if (this.disposed) return;
    if (this.mode === "trying") {
      this.mode = "idle";
      this.n = 0;
    }
    if (kind === "password") {
      this.secret = null;
      this.toSave = null;
    }
    this.emit();
  }

  /** 登入成功（收到 peer_info）：計數歸零。回傳要記住的密碼：只有手動登入、勾了記住才有，自動重連成功不重複存。 */
  connected(): string | null {
    if (this.disposed) return null;
    this.clearTimer();
    this.mode = "live";
    this.n = 0;
    const pw = this.toSave;
    this.toSave = null;
    this.emit();
    return pw;
  }

  /** 連線結束（或開連線之前就失敗）。 */
  ended(info: CloseInfo): EndDecision {
    if (this.disposed) return { kind: "stop" };
    if (this.mode === "waiting") return { kind: "wait", attempt: this.n, delay: this.view.remaining };
    if (this.mode === "live" && retryAfterDrop(info)) return this.schedule(1);
    if (this.mode === "trying" && retryDuringAttempt(info)) {
      if (this.n < this.delays.length) return this.schedule(this.n + 1);
      const attempts = this.n;
      this.reset();
      return { kind: "gave_up", attempts, last: info };
    }
    this.reset();
    return { kind: "stop" };
  }

  /** 「立即重連」：倒數中才有作用。 */
  now(): void {
    if (this.mode !== "waiting" || this.disposed) return;
    this.clearTimer();
    this.fire();
  }

  /** 「取消」：停止自動重連、清掉記憶體裡的密碼。 */
  cancel(): void {
    this.reset();
  }

  /** 離開頁面：之後什麼都不做。 */
  dispose(): void {
    this.reset();
    this.disposed = true;
  }

  // ── 內部 ──

  private reset(): void {
    this.clearTimer();
    this.mode = "idle";
    this.n = 0;
    this.secret = null;
    this.toSave = null;
    this.emit();
  }

  private schedule(k: number): EndDecision {
    const delay = this.delays[k - 1];
    this.clearTimer();
    this.mode = "waiting";
    this.n = k;
    this.toSave = null;
    this.deadline = Date.now() + delay * 1000;
    this.tick();
    return { kind: "wait", attempt: k, delay };
  }

  /** 每次剩餘秒數換數字時醒來；背景分頁的計時器被放慢時，醒來就照實際時間算（到了就直接重連）。 */
  private tick(): void {
    const left = this.deadline - Date.now();
    if (left <= 0) {
      this.fire();
      return;
    }
    this.emit();
    this.timer = setTimeout(() => {
      this.timer = null;
      this.tick();
    }, left % 1000 || 1000);
  }

  private fire(): void {
    this.mode = "trying";
    this.emit();
    this.opts.attempt(this.n, this.secret);
  }

  private clearTimer(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private emit(): void {
    this.opts.change?.(this.view);
  }
}
