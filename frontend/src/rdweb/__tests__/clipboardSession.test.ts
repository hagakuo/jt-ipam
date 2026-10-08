/**
 * 相容 RustDesk 的網頁連線：剪貼簿開關在連線流程裡的行為（附錄 F.2、F.3「關閉時不送」）。
 * 模擬受控端的作法與 session.test.ts 相同（各自一份，兩個檔案互不相依）。
 */
import { describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fStr, fVarint, parse } from "../pb";
import { SecretBoxStream } from "../crypto";
import { decodeMessage, encodeMessage } from "../messages";
import { encodeClipboardBytes } from "../clipboard";
import { RdSession, type SessionEvents, type WebSocketLike } from "../session";

const PEER = "123456789";
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const last = <T,>(a: T[]): T => a[a.length - 1];
const utf8 = (s: string) => new Uint8Array(new TextEncoder().encode(s));

class FakeWs implements WebSocketLike {
  binaryType = "blob";
  readyState = 1;
  sentBin: Uint8Array[] = [];
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  send(data: string | ArrayBufferLike | ArrayBufferView): void {
    if (typeof data !== "string") this.sentBin.push(new Uint8Array(data as ArrayBuffer));
  }
  close(): void { this.readyState = 3; }
  text(obj: unknown): void { this.onmessage?.({ data: JSON.stringify(obj) }); }
  bin(b: Uint8Array): void { this.onmessage?.({ data: b.slice().buffer }); }
}

/** 走完握手（6）到收到 Hash 之前；回傳受控端這一側的加解密 */
function handshake(opts: { clipboard?: boolean; viewOnly?: boolean }, events: SessionEvents = {}) {
  const server = nacl.sign.keyPair();
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  const ws = new FakeWs();
  const s = new RdSession({
    url: "wss://x", peerId: PEER, myName: "alice", password: "pw",
    decoding: { vp9: true, h264: false, vp8: false, av1: false }, ...opts, events, wsFactory: () => ws,
  });
  ws.text({ t: "ready", signed_id_pk: b64(nacl.sign(concat(fStr(1, PEER), fBytes(2, sign.publicKey)), server.secretKey)),
            server_key: b64(server.publicKey) });
  const idpk = concat(fStr(1, PEER), fBytes(2, box.publicKey));
  ws.bin(encodeMessage("signed_id", fBytes(1, nacl.sign(idpk, sign.secretKey))));
  const pk = parse(decodeMessage(ws.sentBin[0]).body);
  const key = nacl.box.open(pk.get(2)![0] as Uint8Array, new Uint8Array(24), pk.get(1)![0] as Uint8Array,
                            box.secretKey)!;
  const tx = new SecretBoxStream(key);
  const rx = new SecretBoxStream(key);
  const open = (c: Uint8Array) => decodeMessage(rx.open(c)!);
  return { ws, s, seal: (m: Uint8Array) => tx.seal(m), open };
}

/** 登入並取出 LoginRequest 的 OptionMessage */
async function login(opts: { clipboard?: boolean; viewOnly?: boolean }, events: SessionEvents = {}) {
  const env = handshake(opts, events);
  env.ws.bin(env.seal(encodeMessage("hash", concat(fStr(1, "aB3dE9"), fStr(2, "x7Kq2Z")))));
  await vi.waitFor(() => expect(env.ws.sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
  const lr = env.open(env.ws.sentBin[1]);
  expect(lr.kind).toBe("login_request");
  const option = parse(parse(lr.body).get(6)![0] as Uint8Array);
  return { ...env, option };
}

async function connected(opts: { clipboard?: boolean; viewOnly?: boolean }, events: SessionEvents = {}) {
  const env = await login(opts, events);
  const disp = concat(fVarint(3, 1280), fVarint(4, 800));
  env.ws.bin(env.seal(encodeMessage("login_response", fMsg(2, concat(fStr(3, "Linux"), fMsg(4, disp))))));
  expect(env.s.phase).toBe("connected");
  return env;
}

const clipMsg = (text: string) => encodeMessage("multi_clipboards", fMsg(1, fBytes(2, utf8(text))));

describe("登入時的 disable_clipboard（§7.4、F.2）", () => {
  it("開＝No（1）、關＝Yes（2）、唯讀檢視一律 Yes", async () => {
    expect((await login({ clipboard: true })).option.get(8)![0]).toBe(1n);
    expect((await login({ clipboard: false })).option.get(8)![0]).toBe(2n);
    expect((await login({})).option.get(8)![0]).toBe(2n);
    const vo = await login({ clipboard: true, viewOnly: true });
    expect(vo.option.get(8)![0]).toBe(2n);
    expect(vo.option.get(12)![0]).toBe(2n);           // disable_keyboard
    expect(vo.s.clipboardEnabled).toBe(false);
  });

  it("登入前切換：照新的值登入，不送 Misc", async () => {
    const env = handshake({ clipboard: true });
    env.s.setClipboard(false);
    expect(env.ws.sentBin).toHaveLength(1);         // 只有 PublicKey
    env.ws.bin(env.seal(encodeMessage("hash", concat(fStr(1, "s"), fStr(2, "c")))));
    await vi.waitFor(() => expect(env.ws.sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    const lr = env.open(env.ws.sentBin[1]);
    expect(parse(parse(lr.body).get(6)![0] as Uint8Array).get(8)![0]).toBe(2n);
  });
});

describe("登入後（F.1、F.2）", () => {
  it("剪貼簿開著：收到的交給 clipboard 事件、送得出去", async () => {
    const got: Array<[string, Uint8Array]> = [];
    const { ws, s, seal, open } = await connected({ clipboard: true }, { clipboard: (k, b) => got.push([k, b]) });
    ws.bin(seal(clipMsg("from peer")));
    ws.bin(seal(encodeMessage("clipboard", fBytes(2, utf8("legacy")))));
    expect(got.map(([k]) => k)).toEqual(["multi_clipboards", "clipboard"]);
    const n = ws.sentBin.length;
    expect(s.sendClipboard(encodeClipboardBytes(utf8("to peer")))).toBe(true);
    expect(ws.sentBin.length).toBe(n + 1);
    expect(open(last(ws.sentBin)).kind).toBe("multi_clipboards");
  });

  it("執行中關閉：送 Misc.option（disable_clipboard = Yes），之後兩個方向都停", async () => {
    const got = vi.fn();
    const { ws, s, seal, open } = await connected({ clipboard: true }, { clipboard: got });
    s.setClipboard(false);
    const m = open(last(ws.sentBin));
    expect(m.kind).toBe("misc");
    expect(parse(parse(m.body).get(7)![0] as Uint8Array).get(8)![0]).toBe(2n);
    // F.1 第 6 點：受控端關閉後仍會寫入控制端送的內容，所以控制端自己不能再送
    const n = ws.sentBin.length;
    expect(s.sendClipboard(encodeClipboardBytes(utf8("x")))).toBe(false);
    expect(ws.sentBin.length).toBe(n);
    ws.bin(seal(clipMsg("still in flight")));
    expect(got).not.toHaveBeenCalled();
    // 重新打開
    s.setClipboard(true);
    expect(parse(parse(open(last(ws.sentBin)).body).get(7)![0] as Uint8Array).get(8)![0]).toBe(1n);
    expect(s.sendClipboard(encodeClipboardBytes(utf8("y")))).toBe(true);
  });

  it("同樣的值不重送 Misc；唯讀檢視打不開", async () => {
    const { ws, s } = await connected({ clipboard: true });
    const n = ws.sentBin.length;
    s.setClipboard(true);
    expect(ws.sentBin.length).toBe(n);
    const vo = await connected({ clipboard: false, viewOnly: true });
    const m = vo.ws.sentBin.length;
    vo.s.setClipboard(true);
    expect(vo.s.clipboardEnabled).toBe(false);
    expect(vo.ws.sentBin.length).toBe(m);
    expect(vo.s.sendClipboard(encodeClipboardBytes(utf8("z")))).toBe(false);
  });

  it("登入前不送剪貼簿", () => {
    const { ws, s } = handshake({ clipboard: true });
    expect(s.sendClipboard(encodeClipboardBytes(utf8("early")))).toBe(false);
    expect(ws.sentBin).toHaveLength(1);
  });
});
