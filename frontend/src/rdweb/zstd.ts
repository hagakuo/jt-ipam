/**
 * 相容 RustDesk 的網頁連線：有上限的 zstd 解壓（規格附錄 F.2：解壓後最多 1 MB；§12、附錄 E 的游標也用得到）。
 *
 * 解壓用 fzstd（MIT，純 JavaScript；站台的 CSP 沒有開 wasm-unsafe-eval，WebAssembly 版的函式庫不能用）。
 * fzstd 會照 frame 標頭宣告的大小配置記憶體（最多約 2 GB），所以交給它之前先自己走過一遍標頭
 * （RFC 8878 的 frame／block 格式）：宣告的內容大小超過上限、視窗大到不合理、格式不對的，直接拒絕；
 * 真正解壓時再逐個 block 累計輸出，一超過上限就中止，不會先把整份炸開才發現。
 */
import { Decompress } from "fzstd";

/** 沒有宣告內容大小的 frame（串流壓縮）以視窗大小配置記憶體；超過這個就不解（libzstd 預設等級是 2 MB） */
const MAX_WINDOW = 8 << 20;
/** RFC 8878：單一 block 解壓後最多 128 KB */
const MAX_BLOCK = 128 << 10;
const MAGIC = 0xfd2fb528;

export type ZstdResult = { ok: true; data: Uint8Array } | { ok: false; reason: "too_large" | "invalid" };

function u32(b: Uint8Array, p: number): number {
  return (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
}

/**
 * 走過所有 frame 的標頭與 block 標頭（不解壓）。回傳宣告的內容大小總和（沒有宣告的不算），
 * 格式不對回 "invalid"、宣告的大小或視窗太大回 "too_large"。
 */
function scanFrames(b: Uint8Array, maxBytes: number): "ok" | "too_large" | "invalid" {
  let p = 0;
  let declared = 0;
  if (!b.length) return "invalid";
  while (p < b.length) {
    if (p + 4 > b.length) return "invalid";
    const magic = u32(b, p);
    if (magic >>> 4 === 0x184d2a5) {              // skippable frame：4 bytes 長度＋內容
      if (p + 8 > b.length) return "invalid";
      p += 8 + u32(b, p + 4);
      if (p > b.length) return "invalid";
      continue;
    }
    if (magic !== MAGIC) return "invalid";
    p += 4;
    if (p >= b.length) return "invalid";
    const fhd = b[p++];
    const fcsFlag = fhd >> 6;
    const single = (fhd >> 5) & 1;
    const checksum = (fhd >> 2) & 1;
    if (fhd & 0x08) return "invalid";              // reserved bit
    let window = 0;
    if (!single) {
      if (p >= b.length) return "invalid";
      const wd = b[p++];
      const base = 2 ** (10 + (wd >> 3));
      window = base + (base / 8) * (wd & 7);
    }
    const dictBytes = [0, 1, 2, 4][fhd & 3];
    if (p + dictBytes > b.length) return "invalid";
    for (let i = 0; i < dictBytes; i++) if (b[p + i]) return "invalid";   // 要字典才解得開的不收
    p += dictBytes;
    const fcsBytes = fcsFlag === 0 ? single : 1 << fcsFlag;
    if (p + fcsBytes > b.length) return "invalid";
    if (fcsBytes) {
      let fcs = 0;
      for (let i = fcsBytes - 1; i >= 0; i--) fcs = fcs * 256 + b[p + i];
      if (fcsBytes === 2) fcs += 256;
      declared += fcs;
      if (declared > maxBytes) return "too_large";
      if (single) window = fcs;
    }
    p += fcsBytes;
    if (window > MAX_WINDOW) return "too_large";
    for (;;) {
      if (p + 3 > b.length) return "invalid";
      const bh = b[p] | (b[p + 1] << 8) | (b[p + 2] << 16);
      p += 3;
      const type = (bh >> 1) & 3;
      const size = bh >>> 3;
      if (type === 3 || size > MAX_BLOCK) return "invalid";
      p += type === 1 ? 1 : size;                  // RLE block 的內容只有 1 byte
      if (p > b.length) return "invalid";
      if (bh & 1) break;                           // last block
    }
    p += checksum ? 4 : 0;
    if (p > b.length) return "invalid";
  }
  return "ok";
}

class TooLarge extends Error {}

/** 解壓一份 zstd 資料（標準 frame，可以多個），輸出超過 maxBytes 就放棄。不丟例外。 */
export function zstdDecompress(data: Uint8Array, maxBytes: number): ZstdResult {
  const scan = scanFrames(data, maxBytes);
  if (scan !== "ok") return { ok: false, reason: scan };
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    const d = new Decompress((chunk) => {
      total += chunk.length;
      if (total > maxBytes) throw new TooLarge();
      if (chunk.length) chunks.push(chunk.slice());  // fzstd 之後可能重用底下的緩衝區
    });
    d.push(data, true);
  } catch (e) {
    return { ok: false, reason: e instanceof TooLarge ? "too_large" : "invalid" };
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return { ok: true, data: out };
}
