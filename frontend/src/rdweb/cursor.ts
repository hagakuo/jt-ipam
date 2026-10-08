/**
 * 相容 RustDesk 的網頁連線：遠端游標（規格附錄 E；協定事實在 8.4、8.1，座標換算在 9.1）。
 *
 * 這裡只放不碰畫面的邏輯（方便單元測試），畫到 canvas 轉成 PNG 的那一段在最後的 renderCursorPng：
 * - cursor_data 的 colors 是 zstd 壓縮過的 RGBA。寬、高要在 1～256 之間，解壓後長度必須剛好是 width × height × 4，
 *   輸出上限 256×256×4 bytes；任何一項不合就丟掉這則，不丟例外（E.1、E.3）
 * - 依 id 快取，最多 64 個，超過丟最舊的；cursor_id 切到快取裡的那一個，找不到就維持目前的游標
 * - 依畫面縮放比例（1 個受控端像素佔幾個 CSS 像素，與 9.1 同一個比例）算 CSS 游標的尺寸與熱點；
 *   超過 128×128 等比縮小，熱點跟著縮；同一個 id、同一個比例只畫一次
 * - 全透明（所有 alpha 為 0）＝對方隱藏了游標
 * - cursor_position 是不是「對方自己在動」：與我們最後送出的滑鼠位置差超過 4 個受控端像素（E.2）
 */
import { Decompress } from "fzstd";
import type { CursorDataMsg } from "./messages";

/** E.1：寬、高的上限（下限 1） */
export const CURSOR_MAX_SIDE = 256;
/** E.1：解壓輸出的上限 */
export const CURSOR_MAX_BYTES = CURSOR_MAX_SIDE * CURSOR_MAX_SIDE * 4;
/** E.1：快取上限 */
export const CURSOR_CACHE_LIMIT = 64;
/** E.1：瀏覽器接受的 CSS 游標圖片上限 */
export const CSS_CURSOR_MAX = 128;
/** E.2：差幾個受控端像素以內算是我們自己送過去的回音 */
export const REMOTE_ECHO_TOLERANCE = 4;
/** E.2：多久沒有新的 cursor_position 就隱藏疊加層 */
export const REMOTE_CURSOR_TIMEOUT_MS = 3000;

export interface CursorShape {
  id: bigint;
  width: number;
  height: number;
  hotx: number;
  hoty: number;
  rgba: Uint8Array;          // width × height × 4
  transparent: boolean;      // 所有 alpha 都是 0
}

/** 縮放後的 CSS 游標尺寸與熱點（CSS 像素）。 */
export interface CursorGeometry { width: number; height: number; hotx: number; hoty: number }
export interface RenderedCursor extends CursorGeometry { url: string }
/** 把游標畫成指定尺寸的圖，回傳 data URL；畫不出來回 null。 */
export type CursorRenderer = (shape: CursorShape, geom: CursorGeometry) => string | null;

// ── zstd 解壓（標準 zstd frame，RFC 8878）──
//
// fzstd 沒有「輸出上限」參數，而且：不給輸出緩衝區時會照 frame 標頭宣告的大小配置記憶體（最多約 2 GB）；
// 給了緩衝區時回傳的是整個緩衝區，看不出實際解出幾個 bytes，超出時有些情況只是靜靜截斷；
// 串流介面也照標頭宣告的視窗配置，每個 block 的輸出最多到視窗大小（超過的部分靜靜丟掉）。
// 所以：先自己檢查 frame 標頭與每個 block 標頭，再把標頭改寫成「視窗＝預期長度＋1、不帶內容長度」交給串流介面，
// 逐塊累計輸出，一超過預期長度就中止。記憶體只跟 width × height × 4 有關，不受對方宣告的數字影響；
// 視窗比預期長度多 1，解出來比宣告的還長時一定看得到（不會被截斷成剛好的長度而矇混過去）。

const ZSTD_MAGIC = 0xfd2fb528;
const BLOCK_MAX = 128 * 1024;

interface FrameHeader {
  end: number;               // 第一個 block 的位置
  windowSize: number;
  contentSize: number | null;
  checksum: boolean;
}

/** 小端序無號整數（最多 8 bytes；超過 2^53 會失準，但那種值本來就不可能等於預期長度）。 */
function readLE(b: Uint8Array, pos: number, n: number): number {
  let v = 0;
  for (let i = 0; i < n; i++) v += b[pos + i] * 2 ** (8 * i);
  return v;
}

function readFrameHeader(b: Uint8Array): FrameHeader | null {
  if (b.length < 6 || readLE(b, 0, 4) !== ZSTD_MAGIC) return null;    // skippable frame 與其他格式都不收
  const fhd = b[4];
  if (fhd & 0x08) return null;                                          // 保留位元必須是 0
  const single = (fhd >> 5) & 1;
  const fcsSize = [single ? 1 : 0, 2, 4, 8][fhd >> 6];
  const didSize = [0, 1, 2, 4][fhd & 3];
  let pos = 5;
  let windowSize = 0;
  if (!single) {
    const wd = b[pos++];
    const base = 2 ** (10 + (wd >> 3));
    windowSize = base + (base / 8) * (wd & 7);
  }
  if (pos + didSize + fcsSize > b.length) return null;
  if (readLE(b, pos, didSize) !== 0) return null;                       // 不支援字典
  pos += didSize;
  let contentSize: number | null = null;
  if (fcsSize) {
    contentSize = readLE(b, pos, fcsSize) + (fcsSize === 2 ? 256 : 0);
    pos += fcsSize;
  }
  if (single) windowSize = contentSize ?? 0;
  return { end: pos, windowSize, contentSize, checksum: ((fhd >> 2) & 1) === 1 };
}

/**
 * 走過每個 block 標頭（不解壓）：大小不超過 block 上限、raw 與 RLE 的輸出加總不超過預期長度、
 * 最後一個 block（加上校驗碼）之後不可以還有資料（只收單一 frame）。
 */
function checkBlocks(b: Uint8Array, f: FrameHeader, expected: number): boolean {
  const blockMax = Math.min(f.windowSize, BLOCK_MAX);
  let pos = f.end;
  let known = 0;
  for (;;) {
    if (pos + 3 > b.length) return false;
    const h = b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16);
    pos += 3;
    const type = (h >> 1) & 3;
    const size = h >>> 3;
    if (type === 3 || size > blockMax) return false;
    if (type === 1) {                     // RLE：內容 1 byte，輸出 size bytes
      known += size;
      pos += 1;
    } else {                              // raw：內容與輸出都是 size bytes；compressed：內容 size bytes
      if (type === 0) known += size;
      pos += size;
    }
    if (pos > b.length || known > expected) return false;
    if (h & 1) break;
  }
  if (f.checksum) pos += 4;
  return pos === b.length;
}

/** 不小於 need 的最小 Window_Descriptor（Window_Size = 2^(10+e) + 2^(10+e)/8 × m）。 */
function windowDescriptorFor(need: number): number {
  for (let e = 0; e < 32; e++) {
    const base = 2 ** (10 + e);
    for (let m = 0; m < 8; m++) if (base + (base / 8) * m >= need) return (e << 3) | m;
  }
  return 0xff;
}

/** 合法的寬或高：1～256 的整數。 */
export function validCursorSide(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= CURSOR_MAX_SIDE;
}

/** 壓縮後合理的最大長度：zstd 對任何資料的膨脹都很小，超過這個數字一定不是正常的游標。 */
function maxCompressedSize(expected: number): number {
  return expected + (expected >> 8) + 128;
}

/**
 * E.1：解壓 cursor_data.colors。長度必須剛好是 width × height × 4（最多 256×256×4）；
 * 寬高超出範圍、格式不對、解出來太長或太短都回 null，不丟例外。
 */
export function inflateCursorPixels(colors: Uint8Array, width: number, height: number): Uint8Array | null {
  if (!validCursorSide(width) || !validCursorSide(height)) return null;
  const expected = width * height * 4;
  if (!colors.length || colors.length > maxCompressedSize(expected)) return null;
  try {
    const f = readFrameHeader(colors);
    if (!f) return null;
    if (f.contentSize !== null && f.contentSize !== expected) return null;
    if (!checkBlocks(colors, f, expected)) return null;
    // 改寫標頭：不是 single segment、不帶內容長度與字典 ID（fzstd 只拿它們決定視窗大小）、只保留校驗碼旗標，
    // 視窗＝不小於 expected＋1 的最小值。合法的輸出最多 expected bytes，往回參照不會超過它，解壓結果不變。
    const frame = new Uint8Array(6 + colors.length - f.end);
    frame.set(colors.subarray(0, 4));
    frame[4] = f.checksum ? 0x04 : 0;
    frame[5] = windowDescriptorFor(expected + 1);
    frame.set(colors.subarray(f.end), 6);
    const out = new Uint8Array(expected);
    let total = 0;
    let done = false;
    const z = new Decompress((chunk, final) => {
      if (total + chunk.length > expected) throw new RangeError("cursor larger than declared");
      out.set(chunk, total);
      total += chunk.length;
      if (final) done = true;
    });
    z.push(frame, true);
    return done && total === expected ? out : null;
  } catch {
    return null;
  }
}

/** E.1：全透明（所有 alpha 都是 0）＝對方隱藏了游標。 */
export function isFullyTransparent(rgba: Uint8Array): boolean {
  for (let i = 3; i < rgba.length; i += 4) if (rgba[i] !== 0) return false;
  return true;
}

/** cursor_data → 解壓、驗證過的游標；不合法回 null。 */
export function decodeCursor(cd: CursorDataMsg): CursorShape | null {
  const rgba = inflateCursorPixels(cd.colors, cd.width, cd.height);
  if (!rgba) return null;
  return {
    id: cd.id, width: cd.width, height: cd.height, hotx: cd.hotx, hoty: cd.hoty, rgba,
    transparent: isFullyTransparent(rgba),
  };
}

// ── 縮放 ──

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(Math.max(v, lo), hi);
}

/**
 * E.1：依畫面縮放比例算 CSS 游標的尺寸與熱點。超過 128×128 時等比縮到 128 以內，熱點跟著縮；
 * 熱點限制在圖片範圍內（瀏覽器不接受落在圖片外的熱點）。
 */
export function cssCursorGeometry(shape: { width: number; height: number; hotx: number; hoty: number },
                                  scale: number): CursorGeometry {
  let k = Number.isFinite(scale) && scale > 0 ? scale : 1;
  const longest = Math.max(shape.width, shape.height) * k;
  if (longest > CSS_CURSOR_MAX) k *= CSS_CURSOR_MAX / longest;
  const width = clamp(Math.round(shape.width * k), 1, CSS_CURSOR_MAX);
  const height = clamp(Math.round(shape.height * k), 1, CSS_CURSOR_MAX);
  return {
    width, height,
    hotx: clamp(Math.round(shape.hotx * k), 0, width - 1),
    hoty: clamp(Math.round(shape.hoty * k), 0, height - 1),
  };
}

/** 比例取到小數兩位當快取鍵：視窗拖動時細微的變化不必重畫。 */
function scaleKey(scale: number): number {
  return Number.isFinite(scale) && scale > 0 ? Math.max(1, Math.round(scale * 100)) : 100;
}

// ── 快取 ──

interface Entry { shape: CursorShape; rendered: Map<number, RenderedCursor | null> }

export class CursorCache {
  private readonly entries = new Map<bigint, Entry>();
  private cur: Entry | null = null;

  constructor(private readonly limit = CURSOR_CACHE_LIMIT, private readonly scalesPerCursor = 4) {}

  /** 目前的游標；還沒收到或已清掉時是 null（＝一般游標）。 */
  get current(): CursorShape | null {
    return this.cur?.shape ?? null;
  }

  get size(): number {
    return this.entries.size;
  }

  has(id: bigint): boolean {
    return this.entries.has(id);
  }

  /** cursor_data：放進快取並設為目前的游標。不合法就丟掉這則、維持原本的游標，回 false。 */
  receive(cd: CursorDataMsg): boolean {
    const shape = decodeCursor(cd);
    if (!shape) return false;
    const entry: Entry = { shape, rendered: new Map() };
    this.entries.delete(shape.id);          // 同一個 id 重送：換成新的，並算最新的一個
    this.entries.set(shape.id, entry);
    while (this.entries.size > this.limit) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.cur = entry;
    return true;
  }

  /** cursor_id：切到快取裡的那一個；找不到就維持目前的游標，回 false。 */
  select(id: bigint): boolean {
    const e = this.entries.get(id);
    if (!e) return false;
    this.cur = e;
    return true;
  }

  /** 斷線、重連、換螢幕：清掉快取，恢復一般游標。 */
  clear(): void {
    this.entries.clear();
    this.cur = null;
  }

  /** 目前的游標在這個比例下的圖（同一個 id、同一個比例只畫一次）。沒有游標或全透明回 null。 */
  rendered(scale: number, render: CursorRenderer): RenderedCursor | null {
    const e = this.cur;
    if (!e || e.shape.transparent) return null;
    const key = scaleKey(scale);
    const hit = e.rendered.get(key);
    if (hit !== undefined) return hit;
    const geom = cssCursorGeometry(e.shape, key / 100);
    const url = render(e.shape, geom);
    const r = url ? { ...geom, url } : null;
    e.rendered.set(key, r);
    while (e.rendered.size > this.scalesPerCursor) {
      const oldest = e.rendered.keys().next().value;
      if (oldest === undefined) break;
      e.rendered.delete(oldest);
    }
    return r;
  }

  /** 畫面元素的 CSS cursor 值：空字串＝一般游標、none＝對方隱藏了游標、否則是 url(…) 熱點, default。 */
  css(scale: number, render: CursorRenderer): string {
    const shape = this.current;
    if (!shape) return "";
    if (shape.transparent) return "none";
    const r = this.rendered(scale, render);
    return r ? `url("${r.url}") ${r.hotx} ${r.hoty}, default` : "";
  }
}

// ── E.2：對方自己移動游標 ──

/** cursor_position 與我們最後送出的滑鼠位置差超過容許值才算對方自己在動；我們還沒送過就一定是。 */
export function isRemoteMove(pos: { x: number; y: number }, lastSent: { x: number; y: number } | null,
                             tolerance = REMOTE_ECHO_TOLERANCE): boolean {
  if (!lastSent) return true;
  return Math.abs(pos.x - lastSent.x) > tolerance || Math.abs(pos.y - lastSent.y) > tolerance;
}

// ── 畫成 PNG（瀏覽器才有 canvas）──

/** 把 RGBA 畫到 canvas、縮放到 geom 的尺寸，轉成 PNG 的 data URL。 */
export function renderCursorPng(shape: CursorShape, geom: CursorGeometry): string | null {
  try {
    const src = document.createElement("canvas");
    src.width = shape.width;
    src.height = shape.height;
    const sctx = src.getContext("2d");
    if (!sctx) return null;
    const px = new Uint8ClampedArray(shape.rgba.buffer, shape.rgba.byteOffset, shape.rgba.byteLength);
    sctx.putImageData(new ImageData(px, shape.width, shape.height), 0, 0);
    if (geom.width === shape.width && geom.height === shape.height) return src.toDataURL("image/png");
    const dst = document.createElement("canvas");
    dst.width = geom.width;
    dst.height = geom.height;
    const dctx = dst.getContext("2d");
    if (!dctx) return null;
    // 縮小時平滑；放大時保留像素邊緣（游標放大後糊掉反而難看清）
    dctx.imageSmoothingEnabled = geom.width < shape.width;
    dctx.imageSmoothingQuality = "high";
    dctx.drawImage(src, 0, 0, geom.width, geom.height);
    return dst.toDataURL("image/png");
  } catch {
    return null;
  }
}
