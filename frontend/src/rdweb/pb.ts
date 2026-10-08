/**
 * 相容 RustDesk 的網頁連線：最小的 protobuf 編解碼（只做用得到的部分）。
 *
 * 唯一依據是 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 第 3 節：
 * - proto3，未知欄位忽略；oneof 只會有一個欄位
 * - sint32／sint64 用 zigzag，int32／int64 不是；int32 的負值編成 10 bytes
 * - repeated 數值欄位送出用 packed，解碼兩種都收
 * - 值全是預設值的訊息編碼結果是 0 bytes；oneof 裡的子訊息可能是空的，要當成「有這個欄位」
 */

export type Wire = 0 | 1 | 2 | 5;
export type PbValue = bigint | Uint8Array;
export type Fields = Map<number, PbValue[]>;

export class PbError extends Error {}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

// ── 編碼 ──

/** varint；負值當 64 位元二補數（int32／int64 的負值 = 10 bytes）。 */
export function varint(value: number | bigint): Uint8Array {
  let n = BigInt(value);
  if (n < 0n) n += 1n << 64n;
  const out: number[] = [];
  do {
    let b = Number(n & 0x7fn);
    n >>= 7n;
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return Uint8Array.from(out);
}

/** sint32／sint64 的 zigzag（−1 → 1、100 → 200、−1920 → 3839）。 */
export function zigzag(n: number): number {
  return n >= 0 ? n * 2 : -n * 2 - 1;
}

export function unzigzag(n: bigint): number {
  const v = Number(n);
  return v % 2 === 0 ? v / 2 : -(v + 1) / 2;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function key(field: number, wire: Wire): Uint8Array {
  return varint((field << 3) | wire);
}

const EMPTY = new Uint8Array(0);

/** int32／int64／uint32／uint64／enum。預設值（0）不會編進傳輸格式。 */
export function fVarint(field: number, value: number | bigint): Uint8Array {
  if (!value) return EMPTY;
  return concat(key(field, 0), varint(value));
}

export function fSint(field: number, value: number): Uint8Array {
  if (!value) return EMPTY;
  return concat(key(field, 0), varint(zigzag(value)));
}

export function fBool(field: number, value: boolean): Uint8Array {
  return value ? concat(key(field, 0), Uint8Array.of(1)) : EMPTY;
}

export function fBytes(field: number, value: Uint8Array): Uint8Array {
  if (!value.length) return EMPTY;
  return concat(key(field, 2), varint(value.length), value);
}

export function fStr(field: number, value: string): Uint8Array {
  return fBytes(field, enc.encode(value));
}

/** oneof 裡的純量：即使是預設值（0、空字串）也要寫出，對方才知道是哪一個欄位。 */
export function fVarintAlways(field: number, value: number | bigint): Uint8Array {
  return concat(key(field, 0), varint(value));
}

export function fStrAlways(field: number, value: string): Uint8Array {
  const b = enc.encode(value);
  return concat(key(field, 2), varint(b.length), b);
}

/** 子訊息一律寫出（oneof 裡內容全是預設值的子訊息也要有這個欄位）。 */
export function fMsg(field: number, body: Uint8Array): Uint8Array {
  return concat(key(field, 2), varint(body.length), body);
}

/** repeated 數值／enum：packed（wire type 2）。空的就不寫。 */
export function fPacked(field: number, values: number[]): Uint8Array {
  if (!values.length) return EMPTY;
  const body = concat(...values.map((v) => varint(v)));
  return concat(key(field, 2), varint(body.length), body);
}

// ── 解碼 ──

function readVarint(buf: Uint8Array, pos: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    if (pos >= buf.length) throw new PbError("truncated varint");
    const b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return [result, pos];
    shift += 7n;
    if (shift >= 70n) throw new PbError("varint too long");
  }
}

/** 欄位編號 → 值的串列（varint 為 bigint，其餘為位元組）。 */
export function parse(buf: Uint8Array): Fields {
  const out: Fields = new Map();
  let pos = 0;
  while (pos < buf.length) {
    let k: bigint;
    [k, pos] = readVarint(buf, pos);
    const field = Number(k >> 3n);
    const wire = Number(k & 7n);
    if (field === 0) throw new PbError("field number 0");
    let v: PbValue;
    if (wire === 0) {
      [v, pos] = readVarint(buf, pos);
    } else if (wire === 1) {
      if (pos + 8 > buf.length) throw new PbError("truncated fixed64");
      v = buf.subarray(pos, pos + 8);
      pos += 8;
    } else if (wire === 2) {
      let len: bigint;
      [len, pos] = readVarint(buf, pos);
      const n = Number(len);
      if (pos + n > buf.length) throw new PbError("truncated length-delimited field");
      v = buf.subarray(pos, pos + n);
      pos += n;
    } else if (wire === 5) {
      if (pos + 4 > buf.length) throw new PbError("truncated fixed32");
      v = buf.subarray(pos, pos + 4);
      pos += 4;
    } else {
      throw new PbError(`unsupported wire type ${wire}`);
    }
    const list = out.get(field);
    if (list) list.push(v);
    else out.set(field, [v]);
  }
  return out;
}

/** 純量重複出現時以最後一個為準（proto3）。 */
function last(f: Fields, field: number): PbValue | undefined {
  const l = f.get(field);
  return l && l.length ? l[l.length - 1] : undefined;
}

export function has(f: Fields, field: number): boolean {
  return f.has(field);
}

export function getBig(f: Fields, field: number): bigint {
  const v = last(f, field);
  return typeof v === "bigint" ? v : 0n;
}

/** int32／uint32／enum。int32 的負值在傳輸格式裡是 64 位元二補數。 */
export function getInt(f: Fields, field: number): number {
  let v = getBig(f, field);
  if (v >= 1n << 63n) v -= 1n << 64n;
  return Number(BigInt.asIntN(32, v));
}

export function getUint(f: Fields, field: number): number {
  return Number(getBig(f, field));
}

export function getSint(f: Fields, field: number): number {
  return unzigzag(getBig(f, field));
}

export function getBool(f: Fields, field: number): boolean {
  return getBig(f, field) !== 0n;
}

export function getBytes(f: Fields, field: number): Uint8Array {
  const v = last(f, field);
  return v instanceof Uint8Array ? v : EMPTY;
}

export function getStr(f: Fields, field: number): string {
  return dec.decode(getBytes(f, field));
}

export function getDouble(f: Fields, field: number): number {
  const v = last(f, field);
  if (!(v instanceof Uint8Array) || v.length !== 8) return 0;
  return new DataView(v.buffer, v.byteOffset, 8).getFloat64(0, true);
}

/** repeated 子訊息。 */
export function getMsgs(f: Fields, field: number): Fields[] {
  return (f.get(field) || []).filter((v): v is Uint8Array => v instanceof Uint8Array).map(parse);
}

/** repeated 數值：packed 或逐個 varint 都收。 */
export function getRepeatedInts(f: Fields, field: number): number[] {
  const out: number[] = [];
  for (const v of f.get(field) || []) {
    if (typeof v === "bigint") {
      out.push(Number(v));
    } else {
      let pos = 0;
      while (pos < v.length) {
        let n: bigint;
        [n, pos] = readVarint(v, pos);
        out.push(Number(n));
      }
    }
  }
  return out;
}

/** oneof：在候選欄位裡找最後出現的那一個（回傳欄位編號；沒有就 null）。 */
export function oneof(f: Fields, candidates: readonly number[]): number | null {
  let found: number | null = null;
  for (const k of f.keys()) if (candidates.includes(k)) found = k;
  return found;
}
