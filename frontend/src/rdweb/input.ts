/**
 * 相容 RustDesk 的網頁連線：滑鼠（規格第 9.1 節）。
 *
 * mask = (按鍵 << 3) | 種類。種類：移動 0、按下 1、放開 2、滾輪 3。
 * 按鍵：左 0x01、右 0x02、中 0x04、上一頁 0x08、下一頁 0x10。
 */

export const MouseKind = { Move: 0, Down: 1, Up: 2, Wheel: 3 } as const;
export const MouseButton = { Left: 0x01, Right: 0x02, Middle: 0x04, Back: 0x08, Forward: 0x10 } as const;

export function mouseMask(kind: number, button = 0): number {
  return (button << 3) | kind;
}

/** DOM MouseEvent.button（0 左、1 中、2 右、3 上一頁、4 下一頁）→ 規格的按鍵值；不認得回 0。 */
export function domButton(button: number): number {
  return ({ 0: MouseButton.Left, 1: MouseButton.Middle, 2: MouseButton.Right, 3: MouseButton.Back,
            4: MouseButton.Forward } as Record<number, number>)[button] ?? 0;
}

/** 滑鼠事件當下按住的修飾鍵（受控端只在「按下」參考）：Alt 1、Control 4、Shift 29、Meta 23。 */
export function mouseModifiers(e: { altKey: boolean; ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }): number[] {
  const out: number[] = [];
  if (e.altKey) out.push(1);
  if (e.ctrlKey) out.push(4);
  if (e.shiftKey) out.push(29);
  if (e.metaKey) out.push(23);
  return out;
}

export interface Rect { x: number; y: number; width: number; height: number }

/** 附錄 H.3：超出螢幕幾個受控端像素以內的點貼齊邊緣（更遠的不送） */
export const POINTER_SNAP_PX = 5;

/**
 * 9.1／附錄 H.3 座標換算：x = dx + round(px × dw / cw)，y 同理。display 是目前螢幕（DisplayInfo 的 x、y、width、height），
 * (px, py) 是滑鼠在畫面顯示區內的位置，(cw, ch) 是顯示區大小。
 * - 結果是受控端整個虛擬桌面的絕對座標（多螢幕時一定要加上原點，H.3）
 * - 最大值是 x + width − 1、y + height − 1（每個平台都一樣：右邊緣再過去就是隔壁的螢幕）
 * - 超出 5 個受控端像素以內貼齊邊緣，更遠的回 null（不送）；force（左鍵放開）照送，貼齊邊緣
 * - macOS（scale > 1）照樣是「螢幕 x ＋ 像素位移」，不自己除以 scale（受控端會除）
 */
export function mapPointer(px: number, py: number, cw: number, ch: number, display: Rect,
                           force = false): { x: number; y: number } | null {
  const w = cw > 0 ? cw : 1;
  const h = ch > 0 ? ch : 1;
  const x = display.x + Math.round((px * display.width) / w);
  const y = display.y + Math.round((py * display.height) / h);
  const maxX = display.x + Math.max(display.width, 1) - 1;
  const maxY = display.y + Math.max(display.height, 1) - 1;
  const far = x < display.x - POINTER_SNAP_PX || x > maxX + POINTER_SNAP_PX
    || y < display.y - POINTER_SNAP_PX || y > maxY + POINTER_SNAP_PX;
  if (far && !force) return null;
  return { x: Math.min(Math.max(x, display.x), maxX), y: Math.min(Math.max(y, display.y), maxY) };
}

/**
 * 9.1 的反向換算（附錄 E.2）：受控端虛擬桌面座標 → 畫面顯示區內的位置（CSS 像素）。
 * px = (x − dx) × cw / dw、py = (y − dy) × ch / dh；落在目前螢幕之外回 null（不畫）。
 */
export function unmapPointer(x: number, y: number, cw: number, ch: number,
                             display: Rect): { px: number; py: number } | null {
  if (display.width <= 0 || display.height <= 0) return null;
  // 同一個絕對空間（H.3）：先減掉目前螢幕的原點；右邊緣與下邊緣再過去就是別的螢幕
  if (x < display.x || y < display.y || x >= display.x + display.width || y >= display.y + display.height) return null;
  return {
    px: ((x - display.x) * cw) / display.width,
    py: ((y - display.y) * ch) / display.height,
  };
}

/**
 * 9.1 滾輪：x、y 是格數不是座標，一則只送 ±1。往下捲（deltaY > 0）送 y = −1；deltaX > 0 送 x = −1。
 * 依 delta 累積換算成多則：每 100 像素一格、一次最多 5 格。累積器跨事件保留（觸控板的小 delta 才不會每則都算一格）。
 */
export class WheelAccumulator {
  private ax = 0;
  private ay = 0;

  constructor(private readonly pixelsPerStep = 100, private readonly maxSteps = 5) {}

  /** deltaMode：0 像素、1 行、2 頁（照瀏覽器的 WheelEvent）。回傳要送的 [x, y] 序列。 */
  push(deltaX: number, deltaY: number, deltaMode = 0): Array<[number, number]> {
    const scale = deltaMode === 1 ? 40 : deltaMode === 2 ? 800 : 1;
    const dx = deltaX * scale;
    const dy = deltaY * scale;
    // 換方向就重新累積（不要讓反方向的殘值吃掉這一格）
    if (Math.sign(dx) && Math.sign(dx) !== Math.sign(this.ax)) this.ax = 0;
    if (Math.sign(dy) && Math.sign(dy) !== Math.sign(this.ay)) this.ay = 0;
    this.ax += dx;
    this.ay += dy;
    const out: Array<[number, number]> = [];
    const take = (acc: number, single: number): [number, number] => {
      const n = Math.min(this.maxSteps, Math.floor(Math.abs(acc) / this.pixelsPerStep));
      // 滑鼠滾輪一格在某些瀏覽器／系統不到 100 像素（例如 48、53）：單一事件夠大就至少算一格，
      // 否則要轉兩格才動一下。觸控板的小 delta 仍然累積。
      if (n === 0 && Math.abs(single) >= this.pixelsPerStep * 0.4) return [1, acc];
      return [n, n * this.pixelsPerStep * Math.sign(acc)];
    };
    const [ny, usedY] = take(this.ay, dy);
    this.ay -= usedY;
    const [nx, usedX] = take(this.ax, dx);
    this.ax -= usedX;
    // 一次超過上限的部分丟掉，不要累積成之後的暴衝
    if (ny === this.maxSteps) this.ay = 0;
    if (nx === this.maxSteps) this.ax = 0;
    const sy = usedY > 0 ? -1 : 1;
    const sx = usedX > 0 ? -1 : 1;
    for (let i = 0; i < ny; i++) out.push([0, sy]);
    for (let i = 0; i < nx; i++) out.push([sx, 0]);
    return out;
  }

  reset(): void {
    this.ax = 0;
    this.ay = 0;
  }
}
