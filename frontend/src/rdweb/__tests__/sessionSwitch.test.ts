/**
 * 受控端切換工作階段時的連線流程（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 G.5～G.7）：
 * - G.5：session_id 在同一個頁面的重連沿用；打算重連時不送 close_reason；登入畫面相關的回應
 * - G.6：Windows 的工作階段選擇（PeerInfo.windows_sessions → Misc.selected_sid）
 * - G.7：Linux 受控端沒有桌面時的作業系統登入（同一條連線再送一次 LoginRequest，帶 os_login）
 * 模擬受控端的作法與 session.test.ts 相同（各自一份，互不相依）。
 */
import { describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fStr, fVarint, getStr, parse } from "../pb";
import { SecretBoxStream } from "../crypto";
import { decodeMessage, encodeLoginRequest, encodeMessage, encodeSelectedSid, parsePeerInfo } from "../messages";
import { RdSession, type CloseInfo, type SessionEvents, type WebSocketLike } from "../session";
import { pickWindowsSession, retryAfterDrop, retryDuringAttempt } from "../reconnect";

const PEER = "123456789";
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const last = <T,>(a: T[]): T => a[a.length - 1];
/** 7.2 的測試向量：密碼 Pa55-word、salt aB3dE9、challenge x7Kq2Z */
const H2 = "78b83fce809b76e7359978565022d729350f6e725f68f65e85448190884bb03f";

class FakeWs implements WebSocketLike {
  binaryType = "blob";
  readyState = 1;
  sentBin: Uint8Array[] = [];
  sentText: Record<string, unknown>[] = [];
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  send(data: string | ArrayBufferLike | ArrayBufferView): void {
    if (typeof data === "string") this.sentText.push(JSON.parse(data));
    else this.sentBin.push(new Uint8Array(data as ArrayBuffer));
  }
  close(): void { this.readyState = 3; }
  text(obj: unknown): void { this.onmessage?.({ data: JSON.stringify(obj) }); }
  bin(b: Uint8Array): void { this.onmessage?.({ data: b.slice().buffer }); }
}

interface Opts { password?: string; savedCredentialId?: string; sessionId?: bigint }

/** 走完握手（6）並送出 Hash；回傳受控端這一側的加解密 */
function start(opts: Opts, events: SessionEvents = {}) {
  const server = nacl.sign.keyPair();
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  const ws = new FakeWs();
  const closes: CloseInfo[] = [];
  const s = new RdSession({
    url: "wss://x", peerId: PEER, myName: "alice (jt-ipam)", decoding: { vp9: true, h264: false, vp8: false, av1: false },
    ...opts, events: { ...events, closed: (i) => { closes.push(i); events.closed?.(i); } }, wsFactory: () => ws,
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
  const seal = (m: Uint8Array) => tx.seal(m);
  const open = (c: Uint8Array) => decodeMessage(rx.open(c)!);
  ws.bin(seal(encodeMessage("hash", concat(fStr(1, "aB3dE9"), fStr(2, "x7Kq2Z")))));
  return { ws, s, seal, open, closes };
}

const untilSent = (ws: FakeWs, n: number) =>
  vi.waitFor(() => expect(ws.sentBin.length).toBeGreaterThanOrEqual(n), { timeout: 2000, interval: 5 });
const loginError = (text: string) => encodeMessage("login_response", fStr(1, text));
const display = concat(fVarint(3, 1280), fVarint(4, 800));
function peerInfo(extra: Uint8Array = new Uint8Array(0)): Uint8Array {
  return encodeMessage("login_response", fMsg(2, concat(fStr(3, "Windows"), fMsg(4, display), extra)));
}
/** WindowsSessions { sessions (1): repeated WindowsSession { sid (1), name (2) }, current_sid (2) } */
function windowsSessions(list: [number, string][], current: number): Uint8Array {
  return fMsg(13, concat(...list.map(([sid, name]) => fMsg(1, concat(fVarint(1, sid), fStr(2, name)))),
                         fVarint(2, current)));
}

/** 登入並收到第一個 LoginRequest */
async function loggedIn(opts: Opts = { password: "Pa55-word" }, events: SessionEvents = {}) {
  const env = start(opts, events);
  await untilSent(env.ws, 2);
  const first = parse(env.open(env.ws.sentBin[1]).body);
  return { ...env, first };
}

describe("G.5：重連沿用同一個 session_id，打算重連時不送 close_reason", () => {
  it("給了 sessionId 就用它（LoginRequest 欄位 10）；兩條連線用同一個值", async () => {
    const a = await loggedIn({ password: "Pa55-word", sessionId: 0x1234_5678_9abc_def0n });
    const b = await loggedIn({ password: "Pa55-word", sessionId: 0x1234_5678_9abc_def0n });
    expect(a.first.get(10)![0]).toBe(0x1234_5678_9abc_def0n);
    expect(b.first.get(10)![0]).toBe(0x1234_5678_9abc_def0n);
    expect(getStr(a.first, 4)).toBe("jt-ipam");
    expect(getStr(b.first, 5)).toBe("alice (jt-ipam)");
  });

  it("沒給就自己產生一個非零的值", async () => {
    const a = await loggedIn();
    expect(typeof a.first.get(10)![0]).toBe("bigint");
    expect(a.first.get(10)![0]).not.toBe(0n);
  });

  it("受控端直接斷線、後端轉告 peer_closed：都不送 close_reason（受控端收到會刪掉工作階段記錄）", async () => {
    const a = await loggedIn();
    a.ws.bin(a.seal(peerInfo()));
    const n = a.ws.sentBin.length;
    a.ws.text({ t: "close", reason: "peer_closed" });
    expect(a.ws.sentBin.length).toBe(n);
    expect(a.closes[0]).toMatchObject({ code: "rd_peer_closed" });
    expect(a.closes[0].peerReason).toBeUndefined();

    const b = await loggedIn();
    b.ws.bin(b.seal(peerInfo()));
    const m = b.ws.sentBin.length;
    b.ws.onclose?.({});
    expect(b.ws.sentBin.length).toBe(m);
    expect(b.closes[0]).toMatchObject({ code: "rd_peer_closed" });
    expect(b.ws.sentText.some((x) => x.t === "close")).toBe(false);
  });

  it("送空密碼等對方同意，卻收到 No Password Access：受控端在登入畫面（沒有同意視窗），改請使用者輸入密碼", async () => {
    const needPassword = vi.fn();
    const waitingApproval = vi.fn();
    const a = await loggedIn({ password: "" }, { needPassword, waitingApproval });
    expect(a.first.has(2)).toBe(false);
    expect(waitingApproval).toHaveBeenCalledTimes(1);
    a.ws.bin(a.seal(loginError("No Password Access")));
    expect(needPassword).toHaveBeenCalledWith("login_screen");
    expect(a.s.phase).toBe("need_password");
    expect(a.closes).toEqual([]);
    await a.s.login("Pa55-word");                      // 同一條連線、同一個 Hash
    const second = parse(a.open(last(a.ws.sentBin)).body);
    expect(hex(second.get(2)![0] as Uint8Array)).toBe(H2);
  });

  it("送了密碼卻收到 No Password Access（對方設成只能按同意）：照舊等待對方同意", async () => {
    const needPassword = vi.fn();
    const waitingApproval = vi.fn();
    const a = await loggedIn({ password: "Pa55-word" }, { needPassword, waitingApproval });
    a.ws.bin(a.seal(loginError("No Password Access")));
    expect(waitingApproval).toHaveBeenCalled();
    expect(needPassword).not.toHaveBeenCalled();
    expect(a.s.phase).toBe("waiting_approval");
  });

  it("Wayland login screen is not supported：結束並保留原文（不重連）", async () => {
    const a = await loggedIn();
    a.ws.bin(a.seal(loginError("Wayland login screen is not supported")));
    expect(a.closes[0]).toMatchObject({ code: "rd_login_error", detail: "Wayland login screen is not supported" });
    expect(retryAfterDrop(a.closes[0])).toBe(false);
    expect(retryDuringAttempt(a.closes[0])).toBe(false);
  });

  it("登入後的 message_box（Wayland 要對方同意分享畫面）照常交給畫面，連線繼續等", async () => {
    const messageBox = vi.fn();
    const a = await loggedIn({ password: "Pa55-word" }, { messageBox });
    a.ws.bin(a.seal(peerInfo()));
    a.ws.bin(a.seal(encodeMessage("message_box", concat(fStr(1, "nook-nocancel-hasclose"), fStr(2, "Wayland"),
      fStr(3, "Please Select the screen to be shared(Operate on the peer side).")))));
    expect(messageBox).toHaveBeenCalledWith({ msgtype: "nook-nocancel-hasclose", title: "Wayland",
      text: "Please Select the screen to be shared(Operate on the peer side).", link: "" });
    expect(a.s.phase).toBe("connected");
    expect(a.closes).toEqual([]);
  });

  it.each(["Closed manually by the peer", "Connection not allowed", "Closed due to inactivity"])(
    "受控端送了 close_reason「%s」：不重連", async (reason) => {
      const a = await loggedIn();
      a.ws.bin(a.seal(peerInfo()));
      a.ws.bin(a.seal(encodeMessage("misc", concat(Uint8Array.of(9 << 3 | 2, reason.length),
                                                   new TextEncoder().encode(reason)))));
      expect(a.closes[0]).toMatchObject({ code: "rd_peer_closed", peerReason: reason });
      expect(retryAfterDrop(a.closes[0])).toBe(false);
    });
});

describe("G.6：Windows 的工作階段選擇", () => {
  it("PeerInfo.windows_sessions（欄位 13）解析出工作階段與目前的 sid；沒有就是 undefined", () => {
    const pi = parsePeerInfo(concat(fStr(3, "Windows"), windowsSessions([[1, "Console"], [3, "RDP alice"]], 1)));
    expect(pi.windowsSessions).toEqual({ sessions: [{ sid: 1, name: "Console" }, { sid: 3, name: "RDP alice" }],
                                         currentSid: 1 });
    expect(parsePeerInfo(fStr(3, "Windows")).windowsSessions).toBeUndefined();
  });

  it("Misc.selected_sid（欄位 35）：0 也要寫出", () => {
    for (const sid of [0, 1, 7]) {
      const m = decodeMessage(encodeSelectedSid(sid));
      expect(m.kind).toBe("misc");
      expect(parse(m.body).get(35)).toEqual([BigInt(sid)]);
    }
  });

  it("登入回應帶 windows_sessions：交給畫面；選了之後送 Misc.selected_sid", async () => {
    const windows = vi.fn();
    const a = await loggedIn({ password: "Pa55-word" }, { windowsSessions: windows });
    a.ws.bin(a.seal(peerInfo(windowsSessions([[1, "Console"], [3, "RDP alice"]], 3))));
    expect(windows).toHaveBeenCalledWith({ sessions: [{ sid: 1, name: "Console" }, { sid: 3, name: "RDP alice" }],
                                           currentSid: 3 });
    const n = a.ws.sentBin.length;
    a.s.selectWindowsSession(3);
    expect(a.ws.sentBin.length).toBe(n + 1);
    const m = a.open(last(a.ws.sentBin));
    expect(m.kind).toBe("misc");
    expect(parse(m.body).get(35)).toEqual([3n]);
  });

  it("沒有 windows_sessions 時不呼叫；登入前不送 selected_sid", async () => {
    const windows = vi.fn();
    const a = await loggedIn({ password: "Pa55-word" }, { windowsSessions: windows });
    const n = a.ws.sentBin.length;
    a.s.selectWindowsSession(1);                       // 還沒登入
    expect(a.ws.sentBin.length).toBe(n);
    a.ws.bin(a.seal(peerInfo()));
    expect(windows).not.toHaveBeenCalled();
  });

  it("要不要問使用者：只有一個就直接選它；記住的 sid 正好是目前的就直接選；其他情況要問", () => {
    const two = { sessions: [{ sid: 1, name: "Console" }, { sid: 3, name: "RDP" }], currentSid: 1 };
    expect(pickWindowsSession({ sessions: [{ sid: 5, name: "Console" }], currentSid: 5 }, null)).toBe(5);
    expect(pickWindowsSession({ sessions: [], currentSid: 2 }, null)).toBe(2);
    expect(pickWindowsSession(two, null)).toBeNull();
    expect(pickWindowsSession(two, 1)).toBe(1);        // 選了別的、重連後 current_sid 變成它：直接送
    expect(pickWindowsSession(two, 3)).toBeNull();     // 記住的不是目前的：再問一次
  });
});

describe("G.7：Linux 受控端沒有桌面時的作業系統登入", () => {
  it.each<[string, string]>([
    ["Desktop session not ready", "not_ready"],
    ["Desktop session not ready, password empty", "password_empty"],
    ["Desktop session not ready, password wrong", "password_wrong"],
    ["Desktop xsession failed", "xsession_failed"],
  ])("%s：要作業系統帳號密碼（%s），連線不中斷", async (err, kind) => {
    const needOsLogin = vi.fn();
    const a = await loggedIn({ password: "Pa55-word" }, { needOsLogin });
    a.ws.bin(a.seal(loginError(err)));
    expect(needOsLogin).toHaveBeenCalledWith(kind);
    expect(a.s.phase).toBe("need_os_login");
    expect(a.closes).toEqual([]);
    expect(last(a.ws.sentText)).toEqual({ t: "login_result", ok: false, error: err });
  });

  it.each(["Desktop session another user login", "Desktop xorg not found", "Desktop none"])(
    "%s：結束並顯示原文（不重試）", async (err) => {
      const needOsLogin = vi.fn();
      const a = await loggedIn({ password: "Pa55-word" }, { needOsLogin });
      a.ws.bin(a.seal(loginError(err)));
      expect(needOsLogin).not.toHaveBeenCalled();
      expect(a.closes[0]).toMatchObject({ code: "rd_login_error", detail: err });
      expect(retryDuringAttempt(a.closes[0])).toBe(false);
    });

  it("受控端送來的字串剛好是原型上的名字（constructor、toString）：不會被當成作業系統登入", async () => {
    for (const err of ["constructor", "toString", "__proto__"]) {
      const needOsLogin = vi.fn();
      const a = await loggedIn({ password: "Pa55-word" }, { needOsLogin });
      a.ws.bin(a.seal(loginError(err)));
      expect(needOsLogin).not.toHaveBeenCalled();
      expect(a.closes[0]).toMatchObject({ code: "rd_login_error", detail: err });
    }
  });

  it("同一條連線再送一次 LoginRequest，帶 os_login（欄位 12）；沒有重輸 RustDesk 密碼就沿用原本的雜湊", async () => {
    const a = await loggedIn({ password: "Pa55-word" }, { needOsLogin: () => undefined });
    expect(hex(a.first.get(2)![0] as Uint8Array)).toBe(H2);
    expect(a.first.has(12)).toBe(false);
    a.ws.bin(a.seal(loginError("Desktop session not ready")));
    const n = a.ws.sentBin.length;
    await a.s.loginOs("bob", "os-secret");
    expect(a.ws.sentBin.length).toBe(n + 1);
    const m = a.open(last(a.ws.sentBin));
    expect(m.kind).toBe("login_request");
    const f = parse(m.body);
    expect(hex(f.get(2)![0] as Uint8Array)).toBe(H2);
    const os = parse(f.get(12)![0] as Uint8Array);
    expect(getStr(os, 1)).toBe("bob");
    expect(getStr(os, 2)).toBe("os-secret");
    expect(a.s.phase).toBe("logging_in");
    // 作業系統帳號密碼只在加密通道裡：給後端的控制訊息裡沒有
    expect(JSON.stringify(a.ws.sentText)).not.toContain("os-secret");
    expect(JSON.stringify(a.ws.sentText)).not.toContain("bob");
    a.ws.bin(a.seal(peerInfo()));
    expect(a.s.phase).toBe("connected");
  });

  it("RustDesk 密碼也要重輸（password empty／wrong）：用這一次的 challenge 重新算雜湊", async () => {
    const a = await loggedIn({ password: "" }, { needOsLogin: () => undefined });
    expect(a.first.has(2)).toBe(false);
    a.ws.bin(a.seal(loginError("Desktop session not ready, password empty")));
    await a.s.loginOs("bob", "os-secret", "Pa55-word");
    const f = parse(a.open(last(a.ws.sentBin)).body);
    expect(hex(f.get(2)![0] as Uint8Array)).toBe(H2);
    expect(getStr(parse(f.get(12)![0] as Uint8Array), 1)).toBe("bob");
  });

  it("用已存的密碼登入時：沿用後端算好的那一個 h2，不再要一次", async () => {
    const a = start({ savedCredentialId: "cred-1" }, { needOsLogin: () => undefined });
    a.ws.text({ t: "login_assist", ok: true, hash: b64(unhex(H2)) });
    expect(a.ws.sentBin).toHaveLength(2);
    expect(hex(parse(a.open(a.ws.sentBin[1]).body).get(2)![0] as Uint8Array)).toBe(H2);
    a.ws.bin(a.seal(loginError("Desktop session not ready")));
    await a.s.loginOs("bob", "os-secret");
    const f = parse(a.open(last(a.ws.sentBin)).body);
    expect(hex(f.get(2)![0] as Uint8Array)).toBe(H2);
    expect(a.ws.sentText.filter((x) => x.t === "login_assist")).toHaveLength(1);
  });

  it("沒有在等作業系統登入時 loginOs 不做事", async () => {
    const a = await loggedIn();
    const n = a.ws.sentBin.length;
    await a.s.loginOs("bob", "x");
    expect(a.ws.sentBin.length).toBe(n);
  });

  it("LoginRequest 的 os_login 編碼：OSLogin { username (1), password (2) }", () => {
    const base = { peerId: PEER, password: new Uint8Array(0), myId: "jt-ipam", myName: "a", sessionId: 1n,
                   version: "1.4.1", decoding: { vp9: true, h264: false, vp8: false, av1: false } };
    const without = parse(decodeMessage(encodeLoginRequest(base)).body);
    expect(without.has(12)).toBe(false);
    const withOs = parse(decodeMessage(encodeLoginRequest({ ...base, osLogin: { username: "u", password: "p" } })).body);
    const os = parse(withOs.get(12)![0] as Uint8Array);
    expect(getStr(os, 1)).toBe("u");
    expect(getStr(os, 2)).toBe("p");
  });
});
