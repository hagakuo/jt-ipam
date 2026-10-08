/**
 * 相容 RustDesk 的網頁連線：安全握手與加密（規格第 6、7.2 節）。全部在瀏覽器裡做，後端看不到。
 *
 * - 6.1／6.2：ed25519「簽章附訊息」（NaCl crypto_sign 的輸出格式：前 64 bytes 簽章、後面是訊息）
 * - 6.3：金鑰交換 v0：控制端產生對稱金鑰 K，用 NaCl box（MAC 在前，nonce 24 個 0）封給受控端
 * - 6.4：secretbox，兩個方向各一個 64 位元計數器，送出／解密前先加 1，nonce＝計數器 little-endian＋16 個 0
 * - 7.2：h1 = SHA-256(密碼 ‖ salt)、h2 = SHA-256(h1 ‖ challenge)；送原始 32 bytes
 */
import nacl from "tweetnacl";

const enc = new TextEncoder();

/** 6.4：nonce 24 bytes：前 8 bytes 是計數器的 little-endian，後 16 bytes 全是 0。 */
export function nonceFor(counter: bigint): Uint8Array {
  const n = new Uint8Array(24);
  let c = counter;
  for (let i = 0; i < 8; i++) {
    n[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  return n;
}

/** 一個方向的 secretbox。計數器從 0 開始，每則先加 1 再用（兩邊的第一則密文都是計數 1）。 */
export class SecretBoxStream {
  private counter = 0n;
  private readonly key: Uint8Array;

  constructor(key: Uint8Array) {
    if (key.length !== nacl.secretbox.keyLength) throw new Error("bad secretbox key");
    this.key = key.slice();             // 自己留一份：呼叫端會把原本那份清掉
  }

  seal(plain: Uint8Array): Uint8Array {
    this.counter += 1n;
    return nacl.secretbox(plain, nonceFor(this.counter), this.key);
  }

  /** 解不開回 null（呼叫端要中止：計數器已經對不上了）。 */
  open(cipher: Uint8Array): Uint8Array | null {
    this.counter += 1n;
    return nacl.secretbox.open(cipher, nonceFor(this.counter), this.key);
  }
}

/** 驗 ed25519 簽章附訊息，回傳訊息本體；驗不過回 null。 */
export function openSigned(signed: Uint8Array, publicKey: Uint8Array): Uint8Array | null {
  if (publicKey.length !== nacl.sign.publicKeyLength || signed.length < nacl.sign.signatureLength) return null;
  return nacl.sign.open(signed, publicKey);
}

export function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export interface KeyExchange {
  ourPk: Uint8Array;        // 臨時的 X25519 公鑰（PublicKey.asymmetric_value）
  sealed: Uint8Array;       // box(K) 48 bytes（PublicKey.symmetric_value）
  key: Uint8Array;          // 對稱金鑰 K（只留在記憶體）
}

/** 6.3：臨時 X25519 金鑰對＋32 bytes 隨機 K，K 用 box 封給受控端（nonce 24 個 0）。 */
export function keyExchangeV0(theirPk: Uint8Array): KeyExchange {
  const kp = nacl.box.keyPair();
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  const sealed = nacl.box(key, new Uint8Array(nacl.box.nonceLength), theirPk, kp.secretKey);
  kp.secretKey.fill(0);
  return { ourPk: kp.publicKey, sealed, key };
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  let len = 0;
  for (const p of parts) len += p.length;
  const buf = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

/** 7.2 第 1 步：h1 = SHA-256(UTF-8(密碼) ‖ UTF-8(salt))。h1 對同一台受控端等同密碼，不可以送出或存起來。 */
export function passwordHash1(password: string, salt: string): Promise<Uint8Array> {
  return sha256(enc.encode(password), enc.encode(salt));
}

/** 7.2 第 2 步：h2 = SHA-256(h1 ‖ UTF-8(challenge))。LoginRequest.password 填這 32 個原始位元組。 */
export function passwordHash2(h1: Uint8Array, challenge: string): Promise<Uint8Array> {
  return sha256(h1, enc.encode(challenge));
}

export async function passwordHash(password: string, salt: string, challenge: string): Promise<Uint8Array> {
  const h1 = await passwordHash1(password, salt);
  try {
    return await passwordHash2(h1, challenge);
  } finally {
    h1.fill(0);
  }
}

/** 7.3：這次連線的隨機非零 64 位元值。 */
export function randomSessionId(): bigint {
  for (;;) {
    const b = nacl.randomBytes(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    if (v) return v;
  }
}
