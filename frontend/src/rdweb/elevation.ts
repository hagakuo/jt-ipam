/**
 * Windows 免安裝受控端的系統管理員視窗、UAC 與請求提權（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 K）。
 *
 * 協定事實（K.1）：Windows 受控端沒有安裝成服務（免安裝執行）時以一般使用者權限執行，Windows 不讓它對
 * 「以系統管理員身分執行」的視窗送鍵盤滑鼠，UAC 確認畫面（安全桌面）也看不到、點不到；畫面照常傳送，所以使用者
 * 看到的是「畫面在動、但完全不能操作」。受控端每秒檢查一次、值有變化才送（Misc）：
 * - portable_service_running（20）：提權用的輔助服務是不是在跑（登入後第一次一定送一次目前的值）
 * - uac（15）／foreground_window_elevated（16）：UAC 確認畫面正在顯示／前景視窗是系統管理員權限
 * 請求提權送 Misc.elevation_request（18），回覆是 elevation_response（19）：空字串＝已發出啟動（還沒完成），
 * 非空＝錯誤原文；成功是接著收到 portable_service_running = true。
 *
 * 這裡只放規則（K.2）：狀態列標籤、提示、工具列選單的條件，送出後的回覆與 60 秒逾時，稽核訊息什麼時候送。
 * 協定的收送在 session.ts（requestElevation、reportElevation、各個事件），畫面在 RustDeskScreen.vue。
 *
 * - 帳號密碼（logon）只經過 request() 交給 send（加密後送給受控端），這裡不留、不放進狀態、不進稽核
 * - 稽核（瀏覽器自報）：送出請求時一則 requested、得到結果時一則 ok／error／timeout；detail 只有受控端的錯誤原文
 * - 每條連線都以這條連線收到的訊息為準：自動重連（附錄 G）或連線結束時 reset()，提權狀態與提示都不沿用
 */
import type { ElevationRequest, PeerInfo } from "./messages";

/** K.2：送出後這麼久還沒收到 portable_service_running = true 就算沒有完成（可以再試） */
export const ELEVATION_TIMEOUT_MS = 60_000;
/** K.2：稽核的 detail（受控端的錯誤原文）最多 200 個字元 */
export const ELEVATION_DETAIL_MAX = 200;

export type ElevationMethod = ElevationRequest["method"];
export type ElevationResult = "requested" | "ok" | "error" | "timeout";
export const ELEVATION_METHODS: readonly ElevationMethod[] = ["direct", "logon"];
export const ELEVATION_RESULTS: readonly ElevationResult[] = ["requested", "ok", "error", "timeout"];

/** detail 截到 ELEVATION_DETAIL_MAX 個字元（以 Unicode 字元計，不切斷代理對） */
export function clipElevationDetail(text: string): string {
  const cps = Array.from(text);
  return cps.length > ELEVATION_DETAIL_MAX ? cps.slice(0, ELEVATION_DETAIL_MAX).join("") : text;
}

/**
 * K.1：PeerInfo.platform_additions（JSON 字串）的 is_installed。
 * true／false 照實回；沒有這個鍵（非 Windows、或舊版）、JSON 壞掉、不是物件、值不是布林：回 null（不適用）。
 */
export function parseIsInstalled(platformAdditions: string): boolean | null {
  if (!platformAdditions) return null;
  let o: unknown;
  try { o = JSON.parse(platformAdditions); } catch { return null; }
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  if (!Object.prototype.hasOwnProperty.call(o, "is_installed")) return null;
  const v = (o as Record<string, unknown>).is_installed;
  return typeof v === "boolean" ? v : null;
}

/**
 * K.1／K.2：elevation_response 的常見原文，翻譯成說明（畫面另外附上原文）：
 * - no_permission：`No permission`（受控端不允許鍵盤控制）
 * - no_need：`No need to elevate`（已安裝，或輔助服務已經在跑）
 * - failed：以 `Failed to run portable service process` 開頭（例如 UAC 被按了「否」或帳號密碼錯）
 * 其他原文（含 `already running`，規格沒有說明它的意思）回 null：照原文顯示。
 */
export type ElevationErrorKind = "no_permission" | "no_need" | "failed";
export function classifyElevationError(text: string): ElevationErrorKind | null {
  const s = text.trim();
  if (s === "No permission") return "no_permission";
  if (s === "No need to elevate") return "no_need";
  if (s.startsWith("Failed to run portable service process")) return "failed";
  return null;
}

/**
 * 給畫面顯示的提權進度與結果：
 * - requesting：請求已送出，等受控端回 elevation_response
 * - sent：回覆是空字串＝已發出啟動，等 portable_service_running = true（direct 要受控端那台的人按 UAC 的「是」）
 * - ok：輔助服務在跑了
 * - error：回覆非空；reason 是常見原文的分類（null＝照原文顯示），text 是原文
 * - timeout：送出後 60 秒還沒成功
 */
export type ElevationNotice =
  | { kind: "requesting"; method: ElevationMethod }
  | { kind: "sent"; method: ElevationMethod }
  | { kind: "ok"; method: ElevationMethod }
  | { kind: "error"; method: ElevationMethod; text: string; reason: ElevationErrorKind | null }
  | { kind: "timeout"; method: ElevationMethod };

export interface ElevationState {
  /** 登入回應的 PeerInfo.platform（Windows 才有這些訊息） */
  platform: string;
  /** PeerInfo.platform_additions 的 is_installed；null＝不適用（沒有這個鍵） */
  installed: boolean | null;
  /** 這條連線收到的 portable_service_running */
  serviceRunning: boolean;
  /** 這條連線收到的 uac */
  uac: boolean;
  /** 這條連線收到的 foreground_window_elevated */
  foregroundElevated: boolean;
  notice: ElevationNotice | null;
}

/** 新連線的起始狀態（什麼都不知道：不顯示任何提權相關的東西） */
export function initialElevationState(): ElevationState {
  return { platform: "", installed: null, serviceRunning: false, uac: false, foregroundElevated: false, notice: null };
}

export interface ElevationUiContext {
  /** 畫面在「已連線」 */
  connected: boolean;
  /** 唯讀檢視 */
  viewOnly: boolean;
  /** 對方關閉了控制權（permission_info 的 Keyboard 為 false） */
  keyboardBlocked: boolean;
}

export interface ElevationUi {
  /** 狀態列標籤：portable＝「免安裝版」、elevated＝「免安裝版・已提權」、null＝不顯示 */
  tag: "portable" | "elevated" | null;
  /** 前景是系統管理員視窗的提示 */
  foregroundAlert: boolean;
  /** UAC 確認畫面的提示 */
  uacAlert: boolean;
  /** 工具列的「請求提權」下拉 */
  menu: boolean;
  /** 請求進行中（選單與提示裡的按鈕停用，不能再送一次） */
  busy: boolean;
}

/**
 * K.2 的顯示條件：
 * - 標籤：Windows 受控端、is_installed 為 false（輔助服務在跑時改成已提權）
 * - 前景／UAC 提示：收到 true，而且有控制權、不是唯讀檢視；輔助服務在跑時移除
 * - 工具列選單：Windows 免安裝受控端、輔助服務沒在跑、有控制權、不是唯讀檢視
 * Linux 等受控端不會送這些訊息，也沒有 is_installed：什麼都不顯示。
 */
export function elevationUi(s: ElevationState, c: ElevationUiContext): ElevationUi {
  const portable = s.platform === "Windows" && s.installed === false;
  const control = c.connected && !c.viewOnly && !c.keyboardBlocked;
  const live = control && !s.serviceRunning;
  return {
    tag: portable ? (s.serviceRunning ? "elevated" : "portable") : null,
    foregroundAlert: live && s.foregroundElevated,
    uacAlert: live && s.uac,
    menu: portable && live,
    busy: s.notice?.kind === "requesting" || s.notice?.kind === "sent",
  };
}

export interface ElevationHooks {
  /** 把請求交給 session.requestElevation（真的送出才回 true；唯讀、沒有控制權等情況回 false） */
  send(req: ElevationRequest): boolean;
  /** 稽核摘要交給 session.reportElevation（瀏覽器自報；不含帳號密碼） */
  audit(method: ElevationMethod, result: ElevationResult, detail: string): void;
  /** 狀態變了（畫面重畫） */
  change(s: ElevationState): void;
  /** 測試用；預設 ELEVATION_TIMEOUT_MS */
  timeoutMs?: number;
}

/**
 * 一條連線的提權狀態。事件照受控端送來的順序呼叫（login → service／uac／foreground／response …）。
 *
 * 結果與稽核：一個請求只記一次結果。逾時記 timeout 之後，受控端才回錯誤或才收到 portable_service_running = true
 * （例如受控端的人過了一分鐘才按 UAC）：照樣顯示並補記那個結果，因為提權確實發生了（或確實失敗了），稽核不可以漏。
 */
export class ElevationTracker {
  private s: ElevationState = initialElevationState();
  /** 送出了、還沒有結果（ok／error）的請求方式；逾時不清（之後還可能收到結果），reset 時清掉 */
  private awaiting: ElevationMethod | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly hooks: ElevationHooks) {}

  get state(): ElevationState {
    return this.s;
  }

  /** 新連線登入成功（登入回應的 PeerInfo）：平台與 is_installed 以這個為準 */
  login(info: PeerInfo): void {
    this.update({ platform: info.platform, installed: parseIsInstalled(info.platformAdditions) });
  }

  /** 連線中受控端再送的 peer_info：只有明確帶了 is_installed 才更新（只帶螢幕資訊的不動） */
  peerInfo(info: PeerInfo): void {
    const v = parseIsInstalled(info.platformAdditions);
    if (v !== null && v !== this.s.installed) this.update({ installed: v });
  }

  uac(showing: boolean): void {
    this.update({ uac: showing });
  }

  foreground(elevated: boolean): void {
    this.update({ foregroundElevated: elevated });
  }

  /**
   * portable_service_running。true：輔助服務在跑（之後鍵盤滑鼠與畫面改走它），移除前景／UAC 提示；
   * 有送出的請求就是成功。false：服務沒在跑（登入後第一次檢查、或服務結束），不影響進行中的請求。
   */
  service(running: boolean): void {
    if (!running) {
      this.update({ serviceRunning: false });
      return;
    }
    const patch: Partial<ElevationState> = { serviceRunning: true, uac: false, foregroundElevated: false };
    const method = this.awaiting;
    if (method) {
      this.finishRequest();
      patch.notice = { kind: "ok", method };
    }
    this.update(patch);
    if (method) this.hooks.audit(method, "ok", "");
  }

  /** elevation_response：空字串＝已發出啟動（等 portable_service_running）；非空＝錯誤原文。沒有在等的回覆不理。 */
  response(text: string): void {
    const method = this.awaiting;
    if (!method) return;
    if (!text) {
      if (this.s.notice?.kind === "requesting") this.update({ notice: { kind: "sent", method } });
      return;
    }
    this.finishRequest();
    this.update({ notice: { kind: "error", method, text, reason: classifyElevationError(text) } });
    this.hooks.audit(method, "error", clipElevationDetail(text));
  }

  /**
   * 請求提權。請求進行中（還沒有回覆或還在等服務啟動）不能再送；send 沒有送出（唯讀、沒有控制權）回 false、不記稽核。
   * logon 的帳號密碼只交給 send，這裡不留。
   */
  request(req: ElevationRequest): boolean {
    if (this.busy) return false;
    const method = req.method;
    if (!this.hooks.send(req)) return false;
    this.clearTimer();
    this.awaiting = method;
    this.timer = setTimeout(() => this.onTimeout(method), this.hooks.timeoutMs ?? ELEVATION_TIMEOUT_MS);
    this.update({ notice: { kind: "requesting", method } });
    this.hooks.audit(method, "requested", "");
    return true;
  }

  /** 使用者關掉結果的提示（ok／error／timeout）；進行中的不關 */
  dismiss(): void {
    if (!this.busy && this.s.notice) this.update({ notice: null });
  }

  /** 新連線或連線結束：一切重新判斷（附錄 G）。進行中的請求、計時器都清掉，不再記結果 */
  reset(): void {
    this.clearTimer();
    this.awaiting = null;
    this.s = initialElevationState();
    this.hooks.change(this.s);
  }

  private get busy(): boolean {
    const k = this.s.notice?.kind;
    return k === "requesting" || k === "sent";
  }

  private onTimeout(method: ElevationMethod): void {
    this.timer = null;
    if (this.awaiting !== method) return;
    this.update({ notice: { kind: "timeout", method } });
    this.hooks.audit(method, "timeout", "");
  }

  private finishRequest(): void {
    this.clearTimer();
    this.awaiting = null;
  }

  private clearTimer(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private update(patch: Partial<ElevationState>): void {
    this.s = { ...this.s, ...patch };
    this.hooks.change(this.s);
  }
}
