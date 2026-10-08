/**
 * 相容 RustDesk 的網頁連線：多螢幕（規格附錄 H）。只放不碰畫面、不碰網路的狀態，方便單元測試；
 * 送訊息在 session.ts，選單在 RustDeskScreen.vue。
 *
 * - 螢幕編號就是 PeerInfo.displays 的索引（H.1）。登入時的 current_display 是主螢幕，超出範圍當成 0
 * - 連線中受控端再送的 peer_info 只帶螢幕清單，它的 current_display 一律是 0，不拿來當目前螢幕（H.1）
 * - 目前選的螢幕不見了：切到主螢幕，主螢幕也不在就切到 0（H.1）
 * - 控制端送出切換就把目前螢幕改成目標（之後別的螢幕的影格都丟掉，H.2）；受控端回同一個編號的 switch_display
 *   才是切換完成。沒有在等切換時收到目前螢幕的 switch_display＝那個螢幕的大小改了，不是切換（H.2）
 * - 座標換算以目前螢幕的 x、y、width、height 為準（H.3）
 */
import type { DisplayInfo, PeerInfo, Resolution, SwitchDisplayMsg } from "./messages";

/** 目前螢幕的位置與大小（受控端虛擬桌面的座標；macOS 的 x、y 是邏輯點、寬高是像素，H.1） */
export interface DisplayGeometry {
  x: number; y: number; width: number; height: number; scale: number; cursorEmbedded: boolean;
}

/** 給畫面用的螢幕狀態（複本） */
export interface DisplayView {
  list: DisplayInfo[];
  /** 主螢幕：登入時的 current_display */
  primary: number;
  /** 目前選的螢幕 */
  current: number;
  geometry: DisplayGeometry;
  /** 目前螢幕支援的解析度（H.4：只來自登入的 PeerInfo.resolutions 與切換後的 SwitchDisplay.resolutions） */
  resolutions: Resolution[];
  /** 目前螢幕的原始解析度；0×0＝受控端的虛擬螢幕（H.1） */
  originalResolution: Resolution;
}

/**
 * 螢幕狀態變化的種類：
 * - login：登入成功
 * - update：連線中的 peer_info 更新了清單（目前的螢幕還在）
 * - select：控制端送出切換（之後別的螢幕的影格丟掉）
 * - switch：受控端回了切換完成的 switch_display
 * - resize：目前螢幕的大小改了（解析度被改、旋轉），不是切換
 * - removed：目前選的螢幕被拔除，已經改切到主螢幕或 0
 */
export type DisplayEventKind = "login" | "update" | "select" | "switch" | "resize" | "removed";

const NO_GEOMETRY: DisplayGeometry = { x: 0, y: 0, width: 0, height: 0, scale: 1, cursorEmbedded: false };
const ZERO: Resolution = { width: 0, height: 0 };

function geometryOf(d: { x: number; y: number; width: number; height: number; scale?: number;
                         cursorEmbedded: boolean }): DisplayGeometry {
  return { x: d.x, y: d.y, width: d.width, height: d.height, scale: d.scale || 1, cursorEmbedded: d.cursorEmbedded };
}

/** 登入回應的 PeerInfo → 螢幕狀態（清單是空的回 null）。DisplayTracker.login 與畫面的起始值共用。 */
export function viewFromPeerInfo(info: PeerInfo): DisplayView | null {
  const list = info.displays;
  if (!list.length) return null;
  const primary = info.currentDisplay >= 0 && info.currentDisplay < list.length ? info.currentDisplay : 0;
  const d = list[primary];
  return {
    list: list.slice(), primary, current: primary, geometry: geometryOf(d),
    resolutions: (info.resolutions || []).slice(), originalResolution: { ...(d.originalResolution || ZERO) },
  };
}

export class DisplayTracker {
  private list: DisplayInfo[] = [];
  private primary = 0;
  private cur = 0;
  /** 送出切換、還在等受控端回 switch_display 的目標 */
  private pending: number | null = null;
  private geom: DisplayGeometry = NO_GEOMETRY;
  private res: Resolution[] = [];
  private orig: Resolution = ZERO;

  get current(): number {
    return this.cur;
  }

  get count(): number {
    return this.list.length;
  }

  has(n: number): boolean {
    return Number.isInteger(n) && n >= 0 && n < this.list.length;
  }

  view(): DisplayView {
    return {
      list: this.list.slice(), primary: this.primary, current: this.cur, geometry: { ...this.geom },
      resolutions: this.res.slice(), originalResolution: { ...this.orig },
    };
  }

  /** 登入成功（H.1）。清單是空的回 false（顯示「沒有螢幕」並結束）。 */
  login(info: PeerInfo): boolean {
    const v = viewFromPeerInfo(info);
    if (!v) return false;
    this.list = v.list;
    this.primary = v.primary;
    this.cur = v.primary;
    this.pending = null;
    this.geom = v.geometry;
    this.res = v.resolutions;
    this.orig = v.originalResolution;
    return true;
  }

  /**
   * 連線中的 peer_info（H.1）：更新清單。空的清單不採用（附錄 C-4：有值才覆蓋）。
   * 目前選的螢幕不見了回 { removed, to }：呼叫端照 H.2 切到 to（主螢幕，主螢幕也不在就是 0）。
   */
  update(displays: DisplayInfo[]): { removed: number; to: number } | null {
    if (!displays.length) return null;
    this.list = displays.slice();
    if (this.cur < this.list.length) {
      const d = this.list[this.cur];
      this.geom = geometryOf(d);
      this.orig = { ...(d.originalResolution || ZERO) };
      return null;
    }
    return { removed: this.cur, to: this.primary < this.list.length ? this.primary : 0 };
  }

  /** 控制端要切到 n（H.2）。同一個或不存在回 false（目標就是目前那個螢幕時受控端什麼都不回，不用送）。 */
  select(n: number): boolean {
    if (!this.has(n) || n === this.cur) return false;
    this.cur = n;
    this.pending = n;
    const d = this.list[n];
    this.geom = geometryOf(d);           // 受控端回覆之前先用清單裡的位置與大小
    this.res = [];                       // 切換後的解析度清單等 SwitchDisplay.resolutions
    this.orig = { ...(d.originalResolution || ZERO) };
    return true;
  }

  /**
   * 受控端的 Misc.switch_display（H.2）：
   * - 編號就是剛才要切的那個：切換完成（switch）
   * - 編號是目前的螢幕、沒有在等切換：那個螢幕的大小改了（resize），不是切換
   * - 其他（例如連續切換時前一次的回覆）：stale，只更新清單裡那個螢幕的資料
   */
  onSwitch(sd: SwitchDisplayMsg): "switch" | "resize" | "stale" {
    const known = this.has(sd.display) ? this.list[sd.display] : null;
    // 回覆沒帶原始解析度時沿用清單裡的（0×0 在 H.1 是「虛擬螢幕」，不要因為沒帶就變成虛擬螢幕）
    const orig = sd.originalResolution.width > 0 && sd.originalResolution.height > 0
      ? { ...sd.originalResolution } : { ...(known?.originalResolution || ZERO) };
    if (known) {
      this.list[sd.display] = { ...known, x: sd.x, y: sd.y, width: sd.width, height: sd.height,
                                cursorEmbedded: sd.cursorEmbedded, originalResolution: orig };
    }
    if (sd.display !== this.cur) return "stale";
    const kind = this.pending === sd.display ? "switch" : "resize";
    this.pending = null;
    this.geom = geometryOf({ ...sd, scale: known?.scale });
    if (kind === "switch" || sd.resolutions.length) this.res = sd.resolutions.slice();
    this.orig = orig;
    return kind;
  }
}
