/**
 * 相容 RustDesk 的網頁連線：遠端游標（規格附錄 E；協定事實 8.4，座標 9.1）。
 *
 * zstd 測試資料：「真的」那幾筆是用 zstd 1.5.5 命令列壓出來的（arrowPixels() 的內容）：
 *   ARROW_FCS     zstd -19 檔案：single segment、內容長度 1024、校驗碼，內容是一個 compressed block
 *   ARROW_STREAM  zstd -3 --no-content-size 從 stdin：沒有內容長度、宣告 2 MB 視窗
 *   BOMB          同上，內容是 1 MiB 的重複文字：125 bytes、8 個 compressed block
 *   QUAD          zstd -19 從 stdin，arrowPixels() 重複 4 次（4096 bytes）：單一 compressed block、宣告 8 MB 視窗
 * 其他的（raw 與 RLE block、各種壞掉的標頭）照 RFC 8878 的格式在這裡手工組。
 */
import { describe, expect, it, vi } from "vitest";
import {
  CSS_CURSOR_MAX, CURSOR_CACHE_LIMIT, CursorCache, cssCursorGeometry, decodeCursor, inflateCursorPixels,
  isFullyTransparent, isRemoteMove, type CursorRenderer,
} from "../cursor";
import { mapPointer, unmapPointer } from "../input";
import type { CursorDataMsg } from "../messages";

const unhex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));

const ARROW_FCS = unhex(
  "28b52ffd6400033d0100b2c30306e00f00604c0affffffffffffbf0810a41018a13ed0d70c27992427494e12221eb72c0324a7e375");
const ARROW_STREAM = unhex(
  "28b52ffd045865020060000000ff00ffffffffffffff1d00dd1d80f500128108000d011300084109808180048003c0212001301094004008" +
  "98006808440010083801705038208417080ee0de1b90884790ee24a00524a7e375");
const BOMB = unhex(
  "28b52ffd0458e40000a06a742d6970616d20637572736f7220626f6d62200100d2ff2f9f4c4c0000086f0100fcff3910024c000008700100" +
  "fcff3910024c0000086f0100fcff3910024c000008630100fcff3910024c0000086a0100fcff3910024c0000086f0100fcff3910024d0000" +
  "08700100fcff391002d0b2d158");
const QUAD = unhex(
  "28b52ffd0468950100b2c30306e00f00604c0affffffffffffbf0811a8304ad407b0d72c0710fefffffd7a06fd1b2091318999894c4e943c" +
  "669cc9403ecc71");

/** 16×16 的箭頭：x ≤ y 的三角形不透明（邊框黑、內部白），其餘全透明。 */
function arrowPixels(): Uint8Array {
  const w = 16, h = 16, px = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (x > y) continue;
      const i = (y * w + x) * 4;
      const v = x === 0 || x === y || y === h - 1 ? 0 : 255;
      px[i] = px[i + 1] = px[i + 2] = v;
      px[i + 3] = 255;
    }
  }
  return px;
}

type Block = { raw: Uint8Array } | { rle: number; size: number };

/**
 * 手工組一個 zstd frame（RFC 8878）。fcs 有給：帶 4 bytes 的內容長度；window 有給：用那個 Window_Descriptor，
 * 否則是 single segment（必須給 fcs）。checksum：最後補 4 bytes（fzstd 不驗，內容隨便）。
 */
function zframe(blocks: Block[], o: { fcs?: number; window?: number; checksum?: boolean; fhdExtra?: number } = {})
  : Uint8Array {
  const single = o.window === undefined;
  const fcsFlag = o.fcs !== undefined ? 2 : 0;
  const out: number[] = [0x28, 0xb5, 0x2f, 0xfd,
    (fcsFlag << 6) | (single ? 0x20 : 0) | (o.checksum ? 0x04 : 0) | (o.fhdExtra ?? 0)];
  if (!single) out.push(o.window!);
  if (o.fcs !== undefined) out.push(o.fcs & 0xff, (o.fcs >>> 8) & 0xff, (o.fcs >>> 16) & 0xff, (o.fcs >>> 24) & 0xff);
  blocks.forEach((b, i) => {
    const last = i === blocks.length - 1 ? 1 : 0;
    const [type, size] = "raw" in b ? [0, b.raw.length] : [1, b.size];
    const h = (size << 3) | (type << 1) | last;
    out.push(h & 0xff, (h >> 8) & 0xff, (h >> 16) & 0xff);
    if ("raw" in b) out.push(...b.raw);
    else out.push(b.rle);
  });
  if (o.checksum) out.push(1, 2, 3, 4);
  return Uint8Array.from(out);
}

/** 1×1、指定顏色的游標（raw block）。 */
function cd(id: number | bigint, rgba = [255, 0, 0, 255], extra: Partial<CursorDataMsg> = {}): CursorDataMsg {
  return { id: BigInt(id), hotx: 0, hoty: 0, width: 1, height: 1,
           colors: zframe([{ raw: Uint8Array.from(rgba) }], { fcs: 4 }), ...extra };
}

/** w×h、每個像素都一樣的游標（RLE block 只能重複單一 byte，所以用灰階＋同樣的 alpha）。 */
function solid(id: number, w: number, h: number, hotx = 0, hoty = 0, byte = 0x80): CursorDataMsg {
  return { id: BigInt(id), hotx, hoty, width: w, height: h,
           colors: zframe([{ rle: byte, size: w * h * 4 }], { fcs: w * h * 4 }) };
}

describe("解壓（E.1）", () => {
  it("真的 zstd（single segment、有內容長度與校驗碼）解得回原本的 RGBA", () => {
    expect(inflateCursorPixels(ARROW_FCS, 16, 16)).toEqual(arrowPixels());
  });

  it("沒有內容長度、宣告 2 MB 視窗的串流 frame 也解得開", () => {
    expect(inflateCursorPixels(ARROW_STREAM, 16, 16)).toEqual(arrowPixels());
  });

  it("raw 與 RLE block、有無校驗碼都可以", () => {
    const px = Uint8Array.from([1, 2, 3, 4, 9, 9, 9, 9]);
    expect(inflateCursorPixels(zframe([{ raw: px.subarray(0, 4) }, { rle: 9, size: 4 }], { fcs: 8 }), 2, 1))
      .toEqual(px);
    expect(inflateCursorPixels(zframe([{ raw: px }], { window: 0, checksum: true }), 1, 2)).toEqual(px);
  });

  it("解壓長度不符就丟掉，不丟例外", () => {
    // 宣告的內容長度不符
    expect(inflateCursorPixels(ARROW_FCS, 16, 15)).toBeNull();
    // 沒有宣告：解完才知道比預期長、比預期短
    expect(inflateCursorPixels(ARROW_STREAM, 16, 15)).toBeNull();
    expect(inflateCursorPixels(ARROW_STREAM, 16, 17)).toBeNull();
    expect(inflateCursorPixels(zframe([{ raw: new Uint8Array(12) }], { window: 0 }), 2, 2)).toBeNull();
    expect(inflateCursorPixels(zframe([{ raw: new Uint8Array(20) }], { window: 0 }), 2, 2)).toBeNull();
  });

  it("解出來比預期長一定看得到：單一 block 不會被截斷成剛好的長度（含宣告的內容長度說謊）", () => {
    const quad = new Uint8Array(4096);
    for (let i = 0; i < 4; i++) quad.set(arrowPixels(), i * 1024);
    expect(inflateCursorPixels(QUAD, 32, 32)).toEqual(quad);
    expect(inflateCursorPixels(QUAD, 16, 16)).toBeNull();
    // 同樣的 block，改成 single segment、宣告內容長度 1024（2 bytes 欄位＋256；實際 4096）
    const lie = Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd, 0x64, 0x00, 0x03, ...QUAD.subarray(6)]);
    expect(inflateCursorPixels(lie, 16, 16)).toBeNull();
    // 宣告得比實際長：解不滿
    const lieLong = ARROW_FCS.slice();
    lieLong[5] = 0x00; lieLong[6] = 0x07;            // → 2048（實際 1024）
    expect(inflateCursorPixels(lieLong, 16, 32)).toBeNull();
  });

  it("寬高超出 1～256 就丟掉", () => {
    for (const [w, h] of [[0, 16], [16, 0], [257, 1], [1, 257], [-1, 4], [1.5, 2], [NaN, 1], [Infinity, 1]]) {
      expect(inflateCursorPixels(ARROW_FCS, w, h)).toBeNull();
    }
    // 邊界：256×256 剛好是上限，可以
    const max = zframe([{ rle: 7, size: 131072 }, { rle: 7, size: 131072 }], { fcs: 262144 });
    const px = inflateCursorPixels(max, 256, 256);
    expect(px?.length).toBe(256 * 256 * 4);
    expect(px?.every((b) => b === 7)).toBe(true);
  });

  it("壓縮資料膨脹超過上限：宣告的在解壓前擋下", () => {
    // 宣告 2 GB 的內容長度
    expect(inflateCursorPixels(zframe([{ rle: 0, size: 4 }], { fcs: 0x7fffffff, window: 0x58 }), 256, 256))
      .toBeNull();
    // 沒有宣告長度，RLE block 加起來 384 KB（超過 256×256×4）：走 block 標頭時就擋下，不必解壓
    const rle = zframe([{ rle: 1, size: 131072 }, { rle: 1, size: 131072 }, { rle: 1, size: 131072 }],
                       { window: 20 << 3 });
    expect(inflateCursorPixels(rle, 256, 256)).toBeNull();
    // 單一 block 超過 block 上限（128 KB）
    expect(inflateCursorPixels(zframe([{ rle: 1, size: 0x1fffff }], { window: 20 << 3 }), 256, 256)).toBeNull();
  });

  it("壓縮資料膨脹超過上限：compressed block 解到一半超過就中止（1 MiB 的炸彈）", () => {
    expect(inflateCursorPixels(BOMB, 256, 256)).toBeNull();
    expect(inflateCursorPixels(BOMB, 16, 16)).toBeNull();
    expect(inflateCursorPixels(ARROW_STREAM, 8, 8)).toBeNull();     // 1024 bytes 塞進宣告的 256
  });

  it("記憶體不跟著對方宣告的視窗走：宣告 2^41 的視窗（fzstd 自己會拒絕配置）照樣解得開", () => {
    const px = Uint8Array.from([5, 6, 7, 8]);
    expect(inflateCursorPixels(zframe([{ raw: px }], { window: 0xff }), 1, 1)).toEqual(px);
    expect(inflateCursorPixels(zframe([{ rle: 3, size: 4096 }], { window: 30 << 3 }), 32, 32)?.length).toBe(4096);
  });

  it("格式不對、截斷、多餘的資料都丟掉，不丟例外", () => {
    const bad: Uint8Array[] = [
      new Uint8Array(0),
      Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
      ARROW_FCS.subarray(0, ARROW_FCS.length - 5),                    // 截斷
      ARROW_FCS.subarray(0, 8),
      Uint8Array.from([...ARROW_FCS, ...ARROW_FCS]),                  // 第二個 frame
      Uint8Array.from([...ARROW_FCS, 0]),                             // 多一個 byte
      Uint8Array.from([0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 1, 2, 3, 4]),   // skippable frame
      zframe([{ raw: new Uint8Array(4) }], { fcs: 4, fhdExtra: 0x08 }),     // 保留位元
      zframe([{ raw: new Uint8Array(4) }], { fcs: 4, fhdExtra: 0x01 }),     // 字典 ID 旗標（後面那個 byte 被當成 ID）
      new Uint8Array(4096 + 4096),                                     // 比任何正常的壓縮結果都長
    ];
    const reserved = zframe([{ raw: new Uint8Array(4) }], { fcs: 4 });
    reserved[9] |= 0x06;                                                // block 類型 3（保留）
    bad.push(reserved);
    for (const b of bad) {
      expect(() => inflateCursorPixels(b, 1, 1)).not.toThrow();
      expect(inflateCursorPixels(b, 1, 1)).toBeNull();
    }
    expect(inflateCursorPixels(ARROW_FCS.subarray(0, ARROW_FCS.length - 5), 16, 16)).toBeNull();
    const flipped = ARROW_FCS.slice();
    flipped[20] ^= 0xff;                                               // 壓縮內容被改壞
    expect(() => inflateCursorPixels(flipped, 16, 16)).not.toThrow();
  });

  it("decodeCursor 帶出熱點、尺寸與 id", () => {
    const s = decodeCursor({ id: 2n ** 63n + 5n, hotx: -2, hoty: 3, width: 16, height: 16, colors: ARROW_FCS });
    expect(s).toMatchObject({ id: 2n ** 63n + 5n, hotx: -2, hoty: 3, width: 16, height: 16, transparent: false });
    expect(decodeCursor({ id: 1n, hotx: 0, hoty: 0, width: 16, height: 15, colors: ARROW_FCS })).toBeNull();
  });
});

describe("快取（E.1）", () => {
  it(`最多 ${CURSOR_CACHE_LIMIT} 個，超過丟最舊的`, () => {
    const c = new CursorCache();
    for (let i = 0; i <= CURSOR_CACHE_LIMIT; i++) expect(c.receive(cd(i))).toBe(true);
    expect(c.size).toBe(CURSOR_CACHE_LIMIT);
    expect(c.has(0n)).toBe(false);
    expect(c.has(1n)).toBe(true);
    expect(c.has(BigInt(CURSOR_CACHE_LIMIT))).toBe(true);
    expect(c.current?.id).toBe(BigInt(CURSOR_CACHE_LIMIT));
  });

  it("cursor_id 切到快取裡的那一個；找不到就維持目前的游標", () => {
    const c = new CursorCache();
    c.receive(cd(10));
    c.receive(cd(11));
    expect(c.select(10n)).toBe(true);
    expect(c.current?.id).toBe(10n);
    expect(c.select(99n)).toBe(false);
    expect(c.current?.id).toBe(10n);
  });

  it("同一個 id 重送：換成新的形狀，並算最新的一個（不會先被丟掉）", () => {
    const c = new CursorCache(3);
    c.receive(cd(1, [1, 1, 1, 255]));
    c.receive(cd(2));
    c.receive(cd(3));
    c.receive(cd(1, [9, 9, 9, 255]));
    c.receive(cd(4));
    expect(c.has(1n)).toBe(true);
    expect(c.has(2n)).toBe(false);
    c.select(1n);
    expect(Array.from(c.current!.rgba)).toEqual([9, 9, 9, 255]);
  });

  it("不合法的 cursor_data 丟掉這則、維持原本的游標，也不進快取", () => {
    const c = new CursorCache();
    c.receive(cd(1));
    expect(c.receive(cd(2, undefined, { width: 2 }))).toBe(false);
    expect(c.receive(cd(3, undefined, { colors: BOMB, width: 256, height: 256 }))).toBe(false);
    expect(c.current?.id).toBe(1n);
    expect(c.has(2n)).toBe(false);
    expect(c.size).toBe(1);
  });

  it("清掉之後恢復一般游標", () => {
    const c = new CursorCache();
    c.receive(cd(1));
    c.clear();
    expect(c.current).toBeNull();
    expect(c.size).toBe(0);
    expect(c.css(1, () => "data:x")).toBe("");
    expect(c.select(1n)).toBe(false);
  });
});

describe("縮放與熱點（E.1）", () => {
  const s32 = { width: 32, height: 32, hotx: 10, hoty: 5 };

  it("依比例縮放，熱點跟著縮放", () => {
    expect(cssCursorGeometry(s32, 1)).toEqual({ width: 32, height: 32, hotx: 10, hoty: 5 });
    expect(cssCursorGeometry(s32, 2)).toEqual({ width: 64, height: 64, hotx: 20, hoty: 10 });
    expect(cssCursorGeometry(s32, 1.5)).toEqual({ width: 48, height: 48, hotx: 15, hoty: 8 });
    expect(cssCursorGeometry(s32, 0.5)).toEqual({ width: 16, height: 16, hotx: 5, hoty: 3 });
  });

  it(`超過 ${CSS_CURSOR_MAX}×${CSS_CURSOR_MAX} 等比縮到上限以內，熱點跟著縮`, () => {
    expect(cssCursorGeometry(s32, 6)).toEqual({ width: 128, height: 128, hotx: 40, hoty: 20 });
    expect(cssCursorGeometry({ width: 64, height: 16, hotx: 63, hoty: 15 }, 3))
      .toEqual({ width: 128, height: 32, hotx: 126, hoty: 30 });
    expect(cssCursorGeometry({ width: 256, height: 256, hotx: 128, hoty: 64 }, 1))
      .toEqual({ width: 128, height: 128, hotx: 64, hoty: 32 });
  });

  it("熱點限制在圖片範圍內；比例異常時當成 1；最小 1×1", () => {
    expect(cssCursorGeometry({ width: 32, height: 32, hotx: 40, hoty: -3 }, 1))
      .toEqual({ width: 32, height: 32, hotx: 31, hoty: 0 });
    expect(cssCursorGeometry(s32, 0)).toEqual(cssCursorGeometry(s32, 1));
    expect(cssCursorGeometry(s32, NaN)).toEqual(cssCursorGeometry(s32, 1));
    expect(cssCursorGeometry(s32, 0.001)).toEqual({ width: 1, height: 1, hotx: 0, hoty: 0 });
  });

  it("同一個 id、同一個比例只畫一次；比例變了才重畫", () => {
    const c = new CursorCache();
    c.receive(solid(7, 32, 32, 10, 5));
    const render = vi.fn<CursorRenderer>(() => "data:image/png;base64,AAAA");
    expect(c.css(2, render)).toBe('url("data:image/png;base64,AAAA") 20 10, default');
    expect(c.css(2, render)).toBe('url("data:image/png;base64,AAAA") 20 10, default');
    expect(c.css(2.001, render)).toBe('url("data:image/png;base64,AAAA") 20 10, default');   // 取到小數兩位
    expect(render).toHaveBeenCalledTimes(1);
    expect(render.mock.calls[0][1]).toEqual({ width: 64, height: 64, hotx: 20, hoty: 10 });
    c.css(1, render);
    expect(render).toHaveBeenCalledTimes(2);
    // 切到別的游標再切回來：之前畫好的還在，不必重畫
    c.receive(solid(8, 16, 16));
    c.css(2, render);
    expect(render).toHaveBeenCalledTimes(3);
    expect(render.mock.calls[2][0].id).toBe(8n);
    c.select(7n);
    expect(c.css(2, render)).toBe('url("data:image/png;base64,AAAA") 20 10, default');
    expect(render).toHaveBeenCalledTimes(3);
  });

  it("畫不出來就用一般游標", () => {
    const c = new CursorCache();
    c.receive(solid(1, 8, 8));
    expect(c.css(1, () => null)).toBe("");
  });
});

describe("全透明＝對方隱藏了游標（E.1）", () => {
  it("判定", () => {
    expect(isFullyTransparent(new Uint8Array(64))).toBe(true);
    expect(isFullyTransparent(Uint8Array.from([255, 255, 255, 0, 9, 9, 9, 0]))).toBe(true);
    expect(isFullyTransparent(Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 1]))).toBe(false);
  });

  it("全透明的游標：本地游標改成 none，不畫圖", () => {
    const c = new CursorCache();
    expect(c.receive(solid(1, 16, 16, 0, 0, 0))).toBe(true);
    expect(c.current?.transparent).toBe(true);
    const render = vi.fn<CursorRenderer>(() => "data:x");
    expect(c.css(1, render)).toBe("none");
    expect(c.rendered(1, render)).toBeNull();
    expect(render).not.toHaveBeenCalled();
  });
});

describe("對方自己移動游標（E.2）", () => {
  it("與最後送出的位置差超過 4 個受控端像素才算", () => {
    expect(isRemoteMove({ x: 100, y: 100 }, null)).toBe(true);
    expect(isRemoteMove({ x: 104, y: 96 }, { x: 100, y: 100 })).toBe(false);
    expect(isRemoteMove({ x: 100, y: 100 }, { x: 100, y: 100 })).toBe(false);
    expect(isRemoteMove({ x: 105, y: 100 }, { x: 100, y: 100 })).toBe(true);
    expect(isRemoteMove({ x: 100, y: 95 }, { x: 100, y: 100 })).toBe(true);
  });

  it("9.1 的反向換算：虛擬桌面座標 → 畫面座標，落在目前螢幕之外不畫", () => {
    const d = { x: -1920, y: 0, width: 1920, height: 1080 };
    expect(unmapPointer(-960, 540, 960, 540, d)).toEqual({ px: 480, py: 270 });
    expect(unmapPointer(-1920, 0, 960, 540, d)).toEqual({ px: 0, py: 0 });
    expect(unmapPointer(-1, 1079, 960, 540, d)).toEqual({ px: 959.5, py: 539.5 });
    expect(unmapPointer(0, 540, 960, 540, d)).toBeNull();           // 右邊緣再過去就是別的螢幕（附錄 H.3）
    expect(unmapPointer(10, 540, 960, 540, d)).toBeNull();          // 右邊另一個螢幕
    expect(unmapPointer(-960, -1, 960, 540, d)).toBeNull();
    expect(unmapPointer(-960, 1081, 960, 540, d)).toBeNull();
    expect(unmapPointer(0, 0, 960, 540, { x: 0, y: 0, width: 0, height: 0 })).toBeNull();
  });

  it("與 mapPointer 互為反向（誤差在 1 個受控端像素以內）", () => {
    const d = { x: 1920, y: -200, width: 2560, height: 1440 };
    for (const [px, py] of [[0, 0], [123.4, 77.7], [640, 360], [1279, 719]]) {
      const p = mapPointer(px, py, 1280, 720, d)!;
      const back = unmapPointer(p.x, p.y, 1280, 720, d)!;
      expect(Math.abs(back.px - px)).toBeLessThanOrEqual(0.5 + 1e-9);
      expect(Math.abs(back.py - py)).toBeLessThanOrEqual(0.5 + 1e-9);
    }
  });
});
