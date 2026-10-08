/**
 * 相容 RustDesk 的網頁連線：控制端流程（6、7、8、10）。模擬一個受控端：用 tweetnacl 自己產生
 * hbbs 的簽章金鑰、受控端的長期簽章金鑰與臨時 X25519 金鑰，照規格的順序走完握手與登入。
 */
import { describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fSint, fStr, fVarint, fVarintAlways, getStr, parse } from "../pb";
import { nonceFor, SecretBoxStream } from "../crypto";
import { decodeMessage, encodeMessage } from "../messages";
import { LOGIN_ASSIST_TIMEOUT_MS, RdSession, type CloseInfo, type SessionEvents, type WebSocketLike } from "../session";

const PEER = "123456789";
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
/** 密碼雜湊走 WebCrypto（非同步）：等到送出第 n 則 binary */
const untilSent = (ws: { sentBin: unknown[] }, n: number) =>
  vi.waitFor(() => expect(ws.sentBin.length).toBeGreaterThanOrEqual(n), { timeout: 2000, interval: 5 });
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
/** 7.2 的測試向量：密碼 Pa55-word、salt aB3dE9、challenge x7Kq2Z */
const H2 = "78b83fce809b76e7359978565022d729350f6e725f68f65e85448190884bb03f";
const last = <T,>(a: T[]): T => a[a.length - 1];

class FakeWs implements WebSocketLike {
  binaryType = "blob";
  readyState = 1;
  sentBin: Uint8Array[] = [];
  sentText: Record<string, unknown>[] = [];
  closed = false;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  send(data: string | ArrayBufferLike | ArrayBufferView): void {
    if (typeof data === "string") this.sentText.push(JSON.parse(data));
    else this.sentBin.push(new Uint8Array(data as ArrayBuffer));
  }

  close(): void {
    this.closed = true;
    this.readyState = 3;
  }

  text(obj: unknown): void { this.onmessage?.({ data: JSON.stringify(obj) }); }
  bin(b: Uint8Array): void { this.onmessage?.({ data: b.slice().buffer }); }
}

/** 一台假的受控端（含 hbbs 的簽章）。 */
class Peer {
  server = nacl.sign.keyPair();
  sign = nacl.sign.keyPair();
  box = nacl.box.keyPair();
  tx: SecretBoxStream | null = null;
  rx: SecretBoxStream | null = null;

  signedIdPk(id = PEER, pk: Uint8Array = this.sign.publicKey, by = this.server.secretKey): Uint8Array {
    return nacl.sign(concat(fStr(1, id), fBytes(2, pk)), by);
  }

  signedIdMessage(id = PEER, by = this.sign.secretKey): Uint8Array {
    const idpk = concat(fStr(1, id), fBytes(2, this.box.publicKey));
    return encodeMessage("signed_id", fBytes(1, nacl.sign(idpk, by)));
  }

  /** 收到控制端的 PublicKey：打開 K，建立兩個方向的 secretbox。 */
  acceptPublicKey(raw: Uint8Array): void {
    const m = decodeMessage(raw);
    expect(m.kind).toBe("public_key");
    const f = parse(m.body);
    const ourPk = f.get(1)![0] as Uint8Array;
    const sealed = f.get(2)![0] as Uint8Array;
    expect(sealed.length).toBe(48);
    expect(f.has(3)).toBe(false);                     // 不填 kx_version
    const key = nacl.box.open(sealed, new Uint8Array(24), ourPk, this.box.secretKey);
    expect(key).not.toBeNull();
    this.tx = new SecretBoxStream(key!);
    this.rx = new SecretBoxStream(key!);
  }

  seal(msg: Uint8Array): Uint8Array { return this.tx!.seal(msg); }
  open(c: Uint8Array): ReturnType<typeof decodeMessage> & { plain: Uint8Array } {
    const plain = this.rx!.open(c);
    expect(plain).not.toBeNull();
    return { ...decodeMessage(plain!), plain: plain! };
  }
}

function hashMsg(salt = "aB3dE9", challenge = "x7Kq2Z"): Uint8Array {
  return encodeMessage("hash", concat(fStr(1, salt), fStr(2, challenge)));
}

function loginError(text: string): Uint8Array {
  return encodeMessage("login_response", fStr(1, text));
}

function peerInfoMsg(): Uint8Array {
  const disp = concat(fVarint(3, 1280), fVarint(4, 800));
  return encodeMessage("login_response", fMsg(2, concat(fStr(2, "pc"), fStr(3, "Linux"), fMsg(4, disp),
                                                        fStr(7, "1.4.1"))));
}

function start(events: SessionEvents = {}, password?: string, savedCredentialId?: string) {
  const ws = new FakeWs();
  const closes: CloseInfo[] = [];
  const s = new RdSession({
    url: "wss://x/api/v1/addresses/1/rustdesk/ws?ticket=t", peerId: PEER, myName: "alice (jt-ipam)",
    decoding: { vp9: true, h264: false, vp8: false, av1: false }, password, savedCredentialId,
    events: { ...events, closed: (i) => { closes.push(i); events.closed?.(i); } },
    wsFactory: () => ws,
  });
  return { ws, s, closes };
}

async function handshake(password?: string, events: SessionEvents = {}, savedCredentialId?: string) {
  const peer = new Peer();
  const env = start(events, password, savedCredentialId);
  env.ws.text({ t: "stage", stage: "rendezvous" });
  env.ws.text({ t: "ready", signed_id_pk: b64(peer.signedIdPk()), server_key: b64(peer.server.publicKey),
                peer_id: PEER, transport: "tcp" });
  env.ws.bin(peer.signedIdMessage());
  expect(env.ws.sentBin).toHaveLength(1);
  peer.acceptPublicKey(env.ws.sentBin[0]);
  return { ...env, peer };
}

describe("安全握手（6）", () => {
  it("SignedId → PublicKey（明文）→ Hash（密文計數 1）→ LoginRequest（密文計數 1）", async () => {
    const { ws, s, peer } = await handshake("Pa55-word");
    expect(s.phase).toBe("await_hash");
    ws.bin(peer.seal(hashMsg()));
    await untilSent(ws, 2);
    expect(ws.sentBin).toHaveLength(2);
    // 控制端的第一則密文用計數 1
    const key = (peer as unknown as { tx: { key: Uint8Array } }).tx.key;
    expect(nacl.secretbox.open(ws.sentBin[1], nonceFor(1n), key)).not.toBeNull();
    const m = peer.open(ws.sentBin[1]);
    expect(m.kind).toBe("login_request");
    const f = parse(m.body);
    expect(getStr(f, 1)).toBe(PEER);
    expect(hex(f.get(2)![0] as Uint8Array)).toBe("78b83fce809b76e7359978565022d729350f6e725f68f65e85448190884bb03f");
    expect(getStr(f, 5)).toBe("alice (jt-ipam)");
  });

  it("hbbs 的簽章不對就中止，不送任何東西給受控端", () => {
    const peer = new Peer();
    const { ws, closes } = start();
    const forged = peer.signedIdPk(PEER, peer.sign.publicKey, nacl.sign.keyPair().secretKey);
    ws.text({ t: "ready", signed_id_pk: b64(forged), server_key: b64(peer.server.publicKey), peer_id: PEER });
    expect(closes[0].code).toBe("rd_bad_server_signature");
    expect(ws.sentBin).toHaveLength(0);
    expect(ws.closed).toBe(true);
  });

  it("簽章過的身分是別的 ID", () => {
    const peer = new Peer();
    const { ws, closes } = start();
    ws.text({ t: "ready", signed_id_pk: b64(peer.signedIdPk("999999999")), server_key: b64(peer.server.publicKey) });
    expect(closes[0].code).toBe("rd_bad_server_signature");
  });

  it("沒有受控端公鑰就拒絕降級", () => {
    const peer = new Peer();
    const { ws, closes } = start();
    const noPk = nacl.sign(fStr(1, PEER), peer.server.secretKey);
    ws.text({ t: "ready", signed_id_pk: b64(noPk), server_key: b64(peer.server.publicKey) });
    expect(closes[0].code).toBe("rd_insecure_refused");
    const r2 = start();
    r2.ws.text({ t: "ready", signed_id_pk: "", server_key: b64(peer.server.publicKey) });
    expect(r2.closes[0].code).toBe("rd_insecure_refused");
  });

  it("SignedId 不是受控端的金鑰簽的：不送 PublicKey（不降級）", () => {
    const peer = new Peer();
    const { ws, closes } = start();
    ws.text({ t: "ready", signed_id_pk: b64(peer.signedIdPk()), server_key: b64(peer.server.publicKey) });
    ws.bin(peer.signedIdMessage(PEER, nacl.sign.keyPair().secretKey));
    expect(closes[0].code).toBe("rd_bad_peer_signature");
    expect(ws.sentBin).toHaveLength(0);
  });

  it("第一則不是 SignedId", () => {
    const peer = new Peer();
    const { ws, closes } = start();
    ws.text({ t: "ready", signed_id_pk: b64(peer.signedIdPk()), server_key: b64(peer.server.publicKey) });
    ws.bin(hashMsg());
    expect(closes[0].code).toBe("rd_handshake_failed");
  });

  it("解密失敗就中止", async () => {
    const { ws, peer, closes } = await handshake();
    const c = peer.seal(hashMsg());
    c[5] ^= 0xff;
    ws.bin(c);
    expect(closes[0].code).toBe("rd_decrypt_failed");
  });

  it("長度 ≤ 1 的訊息不解密、不算計數", async () => {
    const { ws, peer, s } = await handshake();
    ws.bin(new Uint8Array([0]));
    ws.bin(peer.seal(hashMsg()));
    expect(s.phase).toBe("need_password");
  });

  it("後端送的錯誤直接顯示", () => {
    const { ws, closes } = start();
    ws.text({ t: "error", code: "rd_offline", detail: "failure=2" });
    expect(closes[0]).toMatchObject({ code: "rd_offline", detail: "failure=2" });
  });
});

describe("登入（7）", () => {
  it("密碼錯：沿用同一個 Hash 重送，不必重新連線；回報結果給後端", async () => {
    const needPw = vi.fn();
    const connected = vi.fn();
    const { ws, s, peer } = await handshake("bad", { needPassword: needPw, connected });
    ws.bin(peer.seal(hashMsg()));
    await untilSent(ws, 2);
    peer.open(ws.sentBin[1]);
    ws.bin(peer.seal(loginError("Wrong Password")));
    expect(needPw).toHaveBeenCalledWith("wrong");
    expect(last(ws.sentText)).toEqual({ t: "login_result", ok: false, error: "Wrong Password" });
    await s.login("Pa55-word");
    const second = peer.open(ws.sentBin[2]);
    expect(second.kind).toBe("login_request");
    expect(hex(parse(second.body).get(2)![0] as Uint8Array))
      .toBe("78b83fce809b76e7359978565022d729350f6e725f68f65e85448190884bb03f");
    ws.bin(peer.seal(peerInfoMsg()));
    expect(connected).toHaveBeenCalled();
    expect(s.phase).toBe("connected");
    expect(last(ws.sentText)).toEqual({ t: "login_result", ok: true, error: "" });
  });

  it("沒給密碼：收到 Hash 時才問", async () => {
    const needPw = vi.fn();
    const { ws, peer } = await handshake(undefined, { needPassword: needPw });
    ws.bin(peer.seal(hashMsg()));
    expect(needPw).toHaveBeenCalledWith("initial");
    expect(ws.sentBin).toHaveLength(1);           // 還沒送 LoginRequest
  });

  it("空密碼：密碼欄位是空的，等對方同意", async () => {
    const waiting = vi.fn();
    const { ws, peer, s } = await handshake("", { waitingApproval: waiting });
    ws.bin(peer.seal(hashMsg()));
    await untilSent(ws, 2);
    const m = peer.open(ws.sentBin[1]);
    expect(parse(m.body).has(2)).toBe(false);
    expect(waiting).toHaveBeenCalled();
    expect(s.phase).toBe("waiting_approval");
  });

  it("兩步驟驗證", async () => {
    const need2fa = vi.fn();
    const { ws, peer, s } = await handshake("Pa55-word", { need2fa });
    ws.bin(peer.seal(hashMsg()));
    await untilSent(ws, 2);
    peer.open(ws.sentBin[1]);
    ws.bin(peer.seal(loginError("2FA Required")));
    expect(need2fa).toHaveBeenCalledWith(false);
    s.submit2fa(" 123456 ");
    const m = peer.open(ws.sentBin[2]);
    expect(m.kind).toBe("auth_2fa");
    expect(getStr(parse(m.body), 1)).toBe("123456");
    ws.bin(peer.seal(loginError("Wrong 2FA Code")));
    expect(need2fa).toHaveBeenLastCalledWith(true);
  });

  it("其他登入錯誤：原文顯示並結束（Desktop session not ready 一類改走作業系統登入，見 sessionSwitch.test.ts）", async () => {
    const { ws, peer, closes } = await handshake("Pa55-word");
    ws.bin(peer.seal(loginError("Desktop xorg not found")));
    expect(closes[0]).toMatchObject({ code: "rd_login_error", detail: "Desktop xorg not found" });
  });
});

describe("登入後（8、9、10）", () => {
  async function connected(events: SessionEvents = {}) {
    const env = await handshake("Pa55-word", events);
    env.ws.bin(env.peer.seal(hashMsg()));
    await untilSent(env.ws, 2);
    env.peer.open(env.ws.sentBin[1]);
    env.ws.bin(env.peer.seal(peerInfoMsg()));
    return env;
  }

  it("TestDelay 原封不動送回（加密後）", async () => {
    const { ws, peer } = await connected();
    const td = encodeMessage("test_delay", concat(fVarint(1, 1759000000000), fVarint(3, 20), fVarint(4, 3000)));
    const before = ws.sentBin.length;
    ws.bin(peer.seal(td));
    expect(ws.sentBin.length).toBe(before + 1);
    expect(peer.open(last(ws.sentBin)).plain).toEqual(td);
    // from_client = true 的不送回
    ws.bin(peer.seal(encodeMessage("test_delay", concat(fVarint(1, 1), fVarint(2, 1)))));
    expect(ws.sentBin.length).toBe(before + 1);
  });

  it("等待輸入密碼時也照常回 TestDelay（7.7）", async () => {
    const { ws, peer } = await handshake();
    ws.bin(peer.seal(hashMsg()));
    const td = encodeMessage("test_delay", fVarint(1, 5));
    ws.bin(peer.seal(td));
    expect(peer.open(last(ws.sentBin)).plain).toEqual(td);
  });

  it("畫面交給 video 事件", async () => {
    const video = vi.fn();
    const { ws, peer } = await connected({ video });
    const ef = concat(fBytes(1, new Uint8Array([9])), fVarint(2, 1), fVarint(3, 7));
    ws.bin(peer.seal(encodeMessage("video_frame", fMsg(6, fMsg(1, ef)))));
    expect(video).toHaveBeenCalledWith("vp9", [{ data: new Uint8Array([9]), key: true, pts: 7n }], 0);
  });

  it("滑鼠、Ctrl+Alt+Del；對方關閉控制權後不再送", async () => {
    const kb = vi.fn();
    const { ws, peer, s } = await connected({ keyboardPermission: kb });
    s.sendMouse(9, 10, 20, [4]);
    const m = peer.open(last(ws.sentBin));
    expect(m.kind).toBe("mouse_event");
    s.sendCtrlAltDel();
    const c = peer.open(last(ws.sentBin));
    expect(parse(c.body).get(3)![0]).toBe(5n);     // Linux：Delete＋press＋Alt、Control
    // PermissionInfo { Keyboard (0), enabled false }
    ws.bin(peer.seal(encodeMessage("misc", fMsg(6, fVarint(2, 0)))));
    expect(kb).toHaveBeenCalledWith(false);
    const n = ws.sentBin.length;
    s.sendMouse(9, 1, 1);
    s.sendKey(true, 38, []);
    expect(ws.sentBin.length).toBe(n);
  });

  it("單獨送來、只有螢幕資訊的 peer_info 不會把平台蓋掉（黑箱實測：第二個控制端連上時）", async () => {
    const pis: string[] = [];
    const { ws, peer, s } = await connected({ peerInfo: (pi) => pis.push(pi.platform) });
    const disp = concat(fVarint(3, 1920), fVarint(4, 1080), fStr(5, "screen"));
    // 平台欄位就算有值也不採用（附錄 C-4：一律以登入回應為準）
    ws.bin(peer.seal(encodeMessage("peer_info", concat(fStr(3, "Windows"), fMsg(4, disp)))));
    expect(pis).toEqual(["Linux"]);
    expect(s.peerInfo?.platform).toBe("Linux");
    expect(s.peerInfo?.version).toBe("1.4.1");
    expect(s.peerInfo?.displays[0].width).toBe(1920);
    s.sendCtrlAltDel();                            // 仍然依 Linux 的規則送
    expect(parse(peer.open(last(ws.sentBin)).body).get(3)![0]).toBe(5n);
  });

  it("要求關鍵影格", async () => {
    const { ws, peer, s } = await connected();
    s.requestKeyframe();
    const m = peer.open(last(ws.sentBin));
    expect(m.kind).toBe("misc");
    expect(parse(m.body).get(31)![0]).toBe(0n);
  });

  it("對方結束：顯示 close_reason", async () => {
    const { ws, peer, closes } = await connected();
    ws.bin(peer.seal(encodeMessage("misc", concat(Uint8Array.of(9 << 3 | 2, 3), new TextEncoder().encode("bye")))));
    expect(closes[0]).toMatchObject({ code: "rd_peer_closed", peerReason: "bye" });
  });

  it("控制端結束：送空的 close_reason、通知後端、關 WebSocket", async () => {
    const { ws, peer, s, closes } = await connected();
    s.close();
    const m = peer.open(last(ws.sentBin));
    expect(m.kind).toBe("misc");
    expect(parse(m.body).get(9)![0]).toEqual(new Uint8Array(0));
    expect(last(ws.sentText)).toEqual({ t: "close", reason: "user" });
    expect(ws.closed).toBe(true);
    expect(closes[0].byUser).toBe(true);
  });

  it("登入時要求受控端送它自己的游標位置：LoginRequest.option.show_remote_cursor = Yes（附錄 E 更正）", async () => {
    const { ws, peer } = await handshake("Pa55-word");
    ws.bin(peer.seal(hashMsg()));
    await untilSent(ws, 2);
    const m = peer.open(ws.sentBin[1]);
    expect(m.kind).toBe("login_request");
    const opt = parse(parse(m.body).get(6)![0] as Uint8Array);
    expect(opt.get(3)).toEqual([2n]);
    expect(opt.get(7)).toEqual([2n]);              // 其他選項照舊
    expect(opt.get(8)).toEqual([2n]);
  });

  it("游標訊息（8.4、附錄 E）：cursor_data、cursor_id、cursor_position 交給畫面", async () => {
    const cursorData = vi.fn(), cursorId = vi.fn(), cursorPosition = vi.fn();
    const { ws, peer } = await connected({ cursorData, cursorId, cursorPosition });
    const colors = Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3]);
    ws.bin(peer.seal(encodeMessage("cursor_data", concat(fVarint(1, 2n ** 63n + 5n), fSint(2, -2), fSint(3, 7),
                                                          fVarint(4, 16), fVarint(5, 24), fBytes(6, colors)))));
    expect(cursorData).toHaveBeenCalledWith({ id: 2n ** 63n + 5n, hotx: -2, hoty: 7, width: 16, height: 24, colors });
    ws.bin(peer.seal(fVarintAlways(14, 0)));        // oneof 的純量：0 也會寫出
    ws.bin(peer.seal(fVarint(14, 2n ** 64n - 1n)));
    expect(cursorId.mock.calls).toEqual([[0n], [2n ** 64n - 1n]]);
    ws.bin(peer.seal(encodeMessage("cursor_position", concat(fSint(1, -1920), fSint(2, 100)))));
    expect(cursorPosition).toHaveBeenCalledWith({ x: -1920, y: 100 });
  });

  it("游標訊息內容有問題：丟掉這則，連線不中斷", async () => {
    const cursorData = vi.fn(), cursorPosition = vi.fn();
    const { ws, peer, s, closes } = await connected({ cursorData, cursorPosition });
    ws.bin(peer.seal(encodeMessage("cursor_data", Uint8Array.from([0x08, 0xff]))));          // 截斷的 varint
    ws.bin(peer.seal(encodeMessage("cursor_position", Uint8Array.from([0x0a, 0x05, 1]))));   // 長度超出
    expect(cursorData).not.toHaveBeenCalled();
    expect(cursorPosition).not.toHaveBeenCalled();
    expect(closes).toHaveLength(0);
    expect(s.phase).toBe("connected");
    ws.bin(peer.seal(encodeMessage("cursor_position", fSint(1, 3))));
    expect(cursorPosition).toHaveBeenCalledWith({ x: 3, y: 0 });
  });

  it("登入前的游標訊息不理", async () => {
    const cursorPosition = vi.fn();
    const { ws, peer } = await handshake(undefined, { cursorPosition });
    ws.bin(peer.seal(hashMsg()));
    ws.bin(peer.seal(encodeMessage("cursor_position", fSint(1, 3))));
    expect(cursorPosition).not.toHaveBeenCalled();
  });

  it("sendMouse 真的送出才回 true，並記下最後送出的滑鼠位置（滾輪的格數不算）", async () => {
    const { ws, peer, s } = await connected();
    expect(s.lastPointer).toBeNull();
    expect(s.sendMouse(0, 100, 200)).toBe(true);
    expect(s.lastPointer).toEqual({ x: 100, y: 200 });
    expect(s.sendMouse(3, 0, -1)).toBe(true);       // 滾輪
    expect(s.lastPointer).toEqual({ x: 100, y: 200 });
    expect(s.sendMouse(10, 5, 6)).toBe(true);       // 左鍵放開
    expect(s.lastPointer).toEqual({ x: 5, y: 6 });
    ws.bin(peer.seal(encodeMessage("misc", fMsg(6, fVarint(2, 0)))));   // 對方關閉控制權
    expect(s.sendMouse(0, 50, 50)).toBe(false);
    expect(s.lastPointer).toEqual({ x: 5, y: 6 });
  });
});

describe("記住密碼（附錄 D）", () => {
  const CRED = "7d4f9a52-0000-4000-8000-000000000001";
  const assists = (ws: FakeWs) => ws.sentText.filter((x) => x.t === "login_assist");

  it("收到 Hash 先請後端算 h2，再照 7.3 送 LoginRequest（瀏覽器拿不到密碼）", async () => {
    const connected = vi.fn();
    const { ws, s, peer } = await handshake(undefined, { connected }, CRED);
    ws.bin(peer.seal(hashMsg()));
    expect(assists(ws)).toEqual([{ t: "login_assist", credential_id: CRED, salt: "aB3dE9", challenge: "x7Kq2Z" }]);
    expect(ws.sentBin).toHaveLength(1);           // 還沒送 LoginRequest
    expect(s.phase).toBe("logging_in");
    ws.text({ t: "login_assist", ok: true, hash: b64(unhex(H2)) });
    expect(ws.sentBin).toHaveLength(2);
    const m = peer.open(ws.sentBin[1]);
    expect(m.kind).toBe("login_request");
    expect(hex(parse(m.body).get(2)![0] as Uint8Array)).toBe(H2);
    expect(getStr(parse(m.body), 1)).toBe(PEER);
    ws.bin(peer.seal(peerInfoMsg()));
    expect(connected).toHaveBeenCalled();
    expect(last(ws.sentText)).toEqual({ t: "login_result", ok: true, error: "" });
  });

  it("後端回失敗：改請使用者輸入（帶錯誤代碼），手動輸入照樣可以登入", async () => {
    const needPw = vi.fn();
    const { ws, s, peer } = await handshake(undefined, { needPassword: needPw }, CRED);
    ws.bin(peer.seal(hashMsg()));
    ws.text({ t: "login_assist", ok: false, code: "rd_saved_password_decrypt" });
    expect(needPw).toHaveBeenCalledWith("saved_failed", "rd_saved_password_decrypt");
    expect(s.phase).toBe("need_password");
    expect(ws.sentBin).toHaveLength(1);
    await s.login("Pa55-word");
    const m = peer.open(ws.sentBin[1]);
    expect(hex(parse(m.body).get(2)![0] as Uint8Array)).toBe(H2);
    expect(assists(ws)).toHaveLength(1);
  });

  it("已存的密碼被對方拒絕：回報已失效，不再自動重試（D.4），結果照樣回報給後端", async () => {
    const needPw = vi.fn();
    const { ws, s, peer } = await handshake(undefined, { needPassword: needPw }, CRED);
    ws.bin(peer.seal(hashMsg()));
    ws.text({ t: "login_assist", ok: true, hash: b64(new Uint8Array(32).fill(7)) });
    peer.open(ws.sentBin[1]);
    ws.bin(peer.seal(loginError("Wrong Password")));
    expect(needPw).toHaveBeenLastCalledWith("saved_rejected");
    expect(last(ws.sentText)).toEqual({ t: "login_result", ok: false, error: "Wrong Password" });
    expect(assists(ws)).toHaveLength(1);
    // 使用者改輸入新密碼：又錯一次時是一般的「密碼錯誤」，仍然不會再去拿已存的
    await s.login("still-wrong");
    peer.open(ws.sentBin[2]);
    ws.bin(peer.seal(loginError("Wrong Password")));
    expect(needPw).toHaveBeenLastCalledWith("wrong");
    expect(assists(ws)).toHaveLength(1);
  });

  it("回來的雜湊不是 32 bytes：當成失敗，不送 LoginRequest", async () => {
    const needPw = vi.fn();
    const { ws, peer } = await handshake(undefined, { needPassword: needPw }, CRED);
    ws.bin(peer.seal(hashMsg()));
    ws.text({ t: "login_assist", ok: true, hash: b64(new Uint8Array(16)) });
    expect(needPw).toHaveBeenCalledWith("saved_failed", "rd_saved_password_unavailable");
    expect(ws.sentBin).toHaveLength(1);
  });

  it("後端一直沒回：逾時改請使用者輸入；之後才到的回覆不理會", async () => {
    const needPw = vi.fn();
    const { ws, peer } = await handshake(undefined, { needPassword: needPw }, CRED);
    vi.useFakeTimers();
    try {
      ws.bin(peer.seal(hashMsg()));
      vi.advanceTimersByTime(LOGIN_ASSIST_TIMEOUT_MS + 1);
      expect(needPw).toHaveBeenCalledWith("saved_failed", "rd_saved_password_unavailable");
      ws.text({ t: "login_assist", ok: true, hash: b64(unhex(H2)) });
      expect(ws.sentBin).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("沒有在等的時候收到 login_assist 回覆：不理會", async () => {
    const { ws, peer, s } = await handshake();
    ws.bin(peer.seal(hashMsg()));
    ws.text({ t: "login_assist", ok: true, hash: b64(unhex(H2)) });
    expect(ws.sentBin).toHaveLength(1);
    expect(s.phase).toBe("need_password");
  });
});
