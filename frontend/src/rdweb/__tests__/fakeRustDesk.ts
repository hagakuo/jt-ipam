/**
 * 測試用：假的 WebSocket 與假的受控端（含 hbbs 的簽章），照規格 §6 的順序走完握手。
 * 檔案傳輸的測試（附錄 J.7）共用；不是測試檔本身（檔名沒有 .test）。
 */
import { expect } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fStr, fVarint, parse } from "../pb";
import { SecretBoxStream } from "../crypto";
import { decodeMessage, encodeMessage } from "../messages";
import type { WebSocketLike } from "../session";

export const PEER = "123456789";
export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

export class FakeWs implements WebSocketLike {
  binaryType = "blob";
  readyState = 1;
  bufferedAmount = 0;
  sentBin: Uint8Array[] = [];
  sentText: Record<string, unknown>[] = [];
  closed = false;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  send(data: string | ArrayBufferLike | ArrayBufferView): void {
    if (typeof data === "string") this.sentText.push(JSON.parse(data));
    else if (ArrayBuffer.isView(data)) this.sentBin.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice());
    else this.sentBin.push(new Uint8Array(data as ArrayBuffer).slice());
  }

  close(): void {
    this.closed = true;
    this.readyState = 3;
  }

  text(obj: unknown): void { this.onmessage?.({ data: JSON.stringify(obj) }); }
  bin(b: Uint8Array): void { this.onmessage?.({ data: b.slice().buffer }); }
  /** 後端那一端斷線 */
  drop(): void {
    this.readyState = 3;
    this.onclose?.({ code: 1006 });
  }
}

/** 一台假的受控端。open() 依序解開控制端送出的密文（計數器要一則一則對上）。 */
export class FakePeer {
  server = nacl.sign.keyPair();
  sign = nacl.sign.keyPair();
  box = nacl.box.keyPair();
  tx: SecretBoxStream | null = null;
  rx: SecretBoxStream | null = null;
  private cursor = 0;

  constructor(readonly ws: FakeWs) {}

  signedIdPk(): Uint8Array {
    return nacl.sign(concat(fStr(1, PEER), fBytes(2, this.sign.publicKey)), this.server.secretKey);
  }

  signedIdMessage(): Uint8Array {
    const idpk = concat(fStr(1, PEER), fBytes(2, this.box.publicKey));
    return encodeMessage("signed_id", fBytes(1, nacl.sign(idpk, this.sign.secretKey)));
  }

  /** 後端送 ready、受控端送 SignedId、控制端回 PublicKey（明文）之後兩邊改用 secretbox。 */
  handshake(): void {
    this.ws.text({ t: "stage", stage: "paired" });
    this.ws.text({ t: "ready", signed_id_pk: b64(this.signedIdPk()), server_key: b64(this.server.publicKey),
                   peer_id: PEER, transport: "tcp" });
    this.ws.bin(this.signedIdMessage());
    expect(this.ws.sentBin.length).toBe(1);
    const m = decodeMessage(this.ws.sentBin[0]);
    expect(m.kind).toBe("public_key");
    const f = parse(m.body);
    const key = nacl.box.open(f.get(2)![0] as Uint8Array, new Uint8Array(24), f.get(1)![0] as Uint8Array,
                              this.box.secretKey);
    expect(key).not.toBeNull();
    this.tx = new SecretBoxStream(key!);
    this.rx = new SecretBoxStream(key!);
    this.cursor = 1;
  }

  /** 受控端 → 控制端（加密） */
  send(plain: Uint8Array): void {
    this.ws.bin(this.tx!.seal(plain));
  }

  /** 控制端送出、還沒看過的訊息（解密後的明文） */
  drain(): Uint8Array[] {
    const out: Uint8Array[] = [];
    while (this.cursor < this.ws.sentBin.length) {
      const plain = this.rx!.open(this.ws.sentBin[this.cursor++]);
      expect(plain).not.toBeNull();
      out.push(plain!);
    }
    return out;
  }

  hash(): void {
    this.send(encodeMessage("hash", concat(fStr(1, "aB3dE9"), fStr(2, "x7Kq2Z"))));
  }

  /** 登入成功：LoginResponse.peer_info */
  loginOk(platform = "Linux"): void {
    this.send(encodeMessage("login_response", fMsg(2, concat(fStr(2, "pc"), fStr(3, platform), fStr(7, "1.4.1")))));
  }

  loginError(text: string): void {
    this.send(encodeMessage("login_response", fStr(1, text)));
  }

  /** Misc.permission_info { permission, enabled } */
  permission(permission: number, enabled: boolean): void {
    this.send(encodeMessage("misc", fMsg(6, concat(fVarint(1, permission), fVarint(2, enabled ? 1 : 0)))));
  }
}
