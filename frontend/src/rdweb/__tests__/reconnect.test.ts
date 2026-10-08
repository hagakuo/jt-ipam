/**
 * 斷線後自動重新連線（附錄 G）：哪些結束原因要重連、間隔與次數、何時停止、密碼放在哪裡、何時清掉。
 * 最後一段把規則接到真正的 RdSession（模擬受控端的作法與 session.test.ts 相同，各自一份、互不相依），
 * 驗證每一次重連都是新的 Hash、新的登入雜湊，已存的密碼每次都重新要 h2。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fStr, fVarint, parse } from "../pb";
import { SecretBoxStream } from "../crypto";
import { decodeMessage, encodeCloseReason, encodeMessage } from "../messages";
import { RdSession, type CloseInfo, type SessionEvents, type WebSocketLike } from "../session";
import {
  AutoReconnect, RECONNECT_DELAYS_S, retryAfterDrop, retryDuringAttempt, ticketFailure, TICKET_REFUSED,
  TICKET_UNAVAILABLE, type ReconnectAuth, type ReconnectView,
} from "../reconnect";

const PW = "Pa55-word";

function controller() {
  const attempts: { n: number; auth: ReconnectAuth | null; at: number }[] = [];
  const views: ReconnectView[] = [];
  const c = new AutoReconnect({
    attempt: (n, auth) => attempts.push({ n, auth, at: Date.now() }),
    change: (v) => views.push(v),
  });
  return { c, attempts, views };
}

/** 手動連線並登入成功（之後的意外中斷才會重連） */
function live(auth: ReconnectAuth | null = { kind: "typed", password: PW }, remember = false) {
  const env = controller();
  env.c.begin(auth, remember);
  env.c.connected();
  return env;
}

describe("G.2：哪些結束原因要自動重連", () => {
  it.each<[string, CloseInfo]>([
    ["受控端直接結束、沒說原因（G.1 的情況）", { code: "rd_peer_closed" }],
    ["後端轉告受控端結束（close: peer_closed）", { code: "rd_peer_closed", detail: "peer_closed" }],
    ["瀏覽器與 jt-ipam 的 WebSocket 意外關閉", { code: "ws_closed" }],
    ["沒有代碼的結束（視同 WebSocket 關閉）", {}],
    ["連不上 hbbs", { code: "rd_hbbs_unreachable", detail: "connection refused" }],
    ["hbbs 沒有回應", { code: "rd_rendezvous_timeout" }],
    ["對方暫時離線", { code: "rd_offline" }],
    ["連不上 hbbr", { code: "rd_hbbr_unreachable" }],
    ["中繼沒有配對成功", { code: "rd_relay_timeout" }],
  ])("%s：重連", (_why, info) => {
    expect(retryAfterDrop(info)).toBe(true);
  });

  it.each<[string, CloseInfo]>([
    ["使用者自己按中斷、關閉分頁", { byUser: true }],
    ["使用者自己結束（即使帶了代碼）", { byUser: true, code: "rd_peer_closed" }],
    ["受控端送了 close_reason", { code: "rd_peer_closed", detail: "對方按了中斷", peerReason: "對方按了中斷" }],
    ["解碼器不支援", { code: "rd_decoder_unsupported" }],
    ["權限不足（票證端點 401／403）", ticketFailure(403, "forbidden")],
    ["受控端金鑰不符", { code: "rd_peer_key_mismatch" }],
    ["沒有權限", { code: "rd_not_permitted" }],
    ["限流", { code: "rd_rate_limited" }],
    ["錯太多次", { code: "rd_login_error", detail: "Too many wrong attempts" }],
    ["一分鐘後再試", { code: "rd_login_error", detail: "Please try 1 minute later" }],
    ["伺服器簽章不對", { code: "rd_bad_server_signature" }],
    ["解密失敗", { code: "rd_decrypt_failed" }],
    ["握手失敗", { code: "rd_handshake_failed" }],
    ["票證無效", { code: "rd_ticket_invalid" }],
    ["伺服器拒絕", { code: "rd_relay_refused", detail: "refused" }],
    ["後端未預期錯誤", { code: "rd_internal" }],
  ])("%s：不重連", (_why, info) => {
    expect(retryAfterDrop(info)).toBe(false);
  });

  it("從沒連上過（連線、配對、登入階段就失敗）：不重連、照常顯示錯誤", () => {
    const { c, attempts } = controller();
    c.begin({ kind: "typed", password: PW }, false);
    expect(c.ended({ code: "rd_relay_timeout" })).toEqual({ kind: "stop" });
    expect(c.ended({ code: "rd_peer_closed" })).toEqual({ kind: "stop" });
    expect(attempts).toEqual([]);
    expect(c.auth).toBeNull();
  });

  it("第一次（手動）連線的登入錯誤照舊直接顯示：connection refused 也不自動重試", () => {
    const { c, attempts } = controller();
    c.begin({ kind: "typed", password: PW }, false);
    const info = { code: "rd_login_error", detail: "connection refused", params: { reason: "connection refused" } };
    expect(retryAfterDrop(info)).toBe(false);
    expect(c.ended(info)).toEqual({ kind: "stop" });
    expect(attempts).toEqual([]);
  });

  it("換票證失敗的分類：沒有回應與閘道錯誤＝後端重新啟動中；其他是重試也不會好的", () => {
    for (const s of [undefined, 0, 502, 503, 504]) expect(ticketFailure(s, "").code).toBe(TICKET_UNAVAILABLE);
    for (const s of [400, 401, 403, 404, 409, 429, 500]) expect(ticketFailure(s, "").code).toBe(TICKET_REFUSED);
    expect(ticketFailure(503, "伺服器忙碌").detail).toBe("伺服器忙碌");
  });
});

describe("G.3：重連的過程", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("間隔 1、2、3、5、5、10、10、15 秒，共 8 次；用完才顯示錯誤，帶最後一次的原因", () => {
    const { c, attempts } = live();
    const start = Date.now();
    expect(c.ended({ code: "rd_peer_closed" })).toEqual({ kind: "wait", attempt: 1, delay: 1 });
    let prev = start;
    const gaps: number[] = [];
    for (let k = 1; k <= 8; k++) {
      const d = RECONNECT_DELAYS_S[k - 1];
      vi.advanceTimersByTime(d * 1000 - 1);
      expect(attempts).toHaveLength(k - 1);             // 還沒到
      vi.advanceTimersByTime(1);
      expect(attempts).toHaveLength(k);
      expect(attempts[k - 1].n).toBe(k);
      expect(c.view).toMatchObject({ state: "trying", attempt: k, total: 8 });
      gaps.push((attempts[k - 1].at - prev) / 1000);
      prev = attempts[k - 1].at;
      const last = { code: "rd_offline", detail: `第 ${k} 次` };
      const r = c.ended(last);
      if (k < 8) expect(r).toEqual({ kind: "wait", attempt: k + 1, delay: RECONNECT_DELAYS_S[k] });
      else expect(r).toEqual({ kind: "gave_up", attempts: 8, last });
    }
    expect(gaps).toEqual([1, 2, 3, 5, 5, 10, 10, 15]);
    vi.advanceTimersByTime(10 * 60_000);
    expect(attempts).toHaveLength(8);                    // 不會有第 9 次
    expect(c.view.state).toBe("idle");
    expect(c.auth).toBeNull();                           // 重試用完：清掉記憶體裡的密碼
  });

  it("倒數的秒數每秒更新", () => {
    const { c, views } = live();
    c.ended({ code: "ws_closed" });
    vi.advanceTimersByTime(1000);                        // 第 1 次
    c.ended({ code: "rd_relay_timeout" });               // 第 2 次：2 秒
    vi.advanceTimersByTime(2000);
    c.ended({ code: "rd_relay_timeout" });               // 第 3 次：3 秒
    views.length = 0;
    expect(c.view).toMatchObject({ state: "waiting", attempt: 3, remaining: 3 });
    vi.advanceTimersByTime(1000);
    expect(c.view.remaining).toBe(2);
    vi.advanceTimersByTime(1000);
    expect(c.view.remaining).toBe(1);
    vi.advanceTimersByTime(1000);
    expect(c.view.state).toBe("trying");
    expect(views.map((v) => `${v.state}:${v.remaining}`)).toEqual(["waiting:2", "waiting:1", "trying:0"]);
  });

  it.each<[string, CloseInfo]>([
    ["Offline（登入回應）", { code: "rd_login_error", detail: "Offline", params: { reason: "Offline" } }],
    // 黑箱實測（2026-10-05）：受控端剛重新啟動，配對成功後第一次登入回 connection refused，幾秒後再試就好
    ["connection refused（受控端程式剛啟動）",
      { code: "rd_login_error", detail: "connection refused", params: { reason: "connection refused" } }],
    ["其他不在停止清單的登入回覆", { code: "rd_login_error", detail: "Some other refusal" }],
    ["空白的登入回覆", { code: "rd_login_error", detail: "" }],
    ["受控端暫時離線（hbbs 判定）", { code: "rd_offline" }],
    ["中繼失敗", { code: "rd_relay_timeout" }],
    ["連不上中繼", { code: "rd_hbbr_unreachable" }],
    ["WebSocket 意外關閉", { code: "ws_closed" }],
    ["受控端在握手時就斷了", { code: "rd_peer_closed" }],
    ["jt-ipam 後端還在重新啟動（換票證沒有回應）", ticketFailure(undefined, "network")],
    ["jt-ipam 後端還在重新啟動（502）", ticketFailure(502, "bad gateway")],
  ])("重連途中遇到 %s：算「還沒回來」，繼續下一次", (_why, info) => {
    expect(retryDuringAttempt(info)).toBe(true);
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(c.ended(info)).toEqual({ kind: "wait", attempt: 2, delay: 2 });
    vi.advanceTimersByTime(2000);
    expect(attempts.map((a) => a.n)).toEqual([1, 2]);
  });

  it.each<[string, CloseInfo]>([
    // G.3：重連途中只有這些登入回覆停止（要使用者處理、或重試也不會好）
    ...[
      "Wrong Password", "2FA Required", "Wrong 2FA Code", "No Password Access",
      "Too many wrong attempts", "Please try 1 minute later",
      "Desktop session another user login", "Desktop xorg not found", "Desktop none", "Desktop session not ready",
      "Wayland login screen is not supported", "x11 expected", "Unsupported display server type wayland",
      "Connection not allowed", "Remote desktop is not allowed by the peer",
      // §7.1：Hash 之前送來的兩種拒絕（IP 不在允許清單、只有主視窗開著才接受）
      "Your ip is blocked by the peer", "The main window is not open",
    ].map((e): [string, CloseInfo] => [e, { code: "rd_login_error", detail: e, params: { reason: e } }]),
    ["jt-ipam 的限流", { code: "rd_rate_limited" }],
    ["票證端點 401", ticketFailure(401, "session expired")],
    ["受控端送了 close_reason", { code: "rd_peer_closed", peerReason: "拒絕" }],
    ["受控端金鑰不符", { code: "rd_peer_key_mismatch" }],
  ])("重連途中遇到 %s：停止並照常顯示原因", (_why, info) => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(c.ended(info)).toEqual({ kind: "stop" });
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(1);
    expect(c.auth).toBeNull();
  });

  it("重連時登入回 Wrong Password：停止自動重連，記憶體裡的密碼清掉（改請使用者輸入）", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.interrupt("password");
    expect(c.view.state).toBe("idle");
    expect(c.auth).toBeNull();
    // 使用者沒有輸入、對方之後把連線關了：照常顯示，不再重連
    expect(c.ended({ code: "rd_peer_closed" })).toEqual({ kind: "stop" });
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(1);
  });

  it("重連時要 2FA：停止自動重連；驗證碼通過後回到一般狀態，下次意外中斷從第 1 次開始", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.ended({ code: "rd_offline" });
    vi.advanceTimersByTime(2000);
    c.interrupt("2fa");
    expect(c.view.state).toBe("idle");
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(2);
    expect(c.auth).toEqual({ kind: "typed", password: PW });   // 密碼是對的，連線還在
    c.connected();
    expect(c.ended({ code: "rd_peer_closed" })).toEqual({ kind: "wait", attempt: 1, delay: 1 });
  });

  it("重連時受控端要作業系統帳號密碼（G.7）：停止自動重連；RustDesk 密碼照留，作業系統帳號密碼不經過這裡", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.interrupt("os_login");
    expect(c.view.state).toBe("idle");
    expect(c.auth).toEqual({ kind: "typed", password: PW });
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(1);
    expect(c.connected()).toBeNull();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(attempts[1].auth).toEqual({ kind: "typed", password: PW });   // 只有 RustDesk 密碼，沒有作業系統的
  });

  it("沒有密碼、等對方同意：照常進入等待同意，不再自動重連", () => {
    const { c, attempts } = live({ kind: "typed", password: "" });
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(attempts[0].auth).toEqual({ kind: "typed", password: "" });
    c.interrupt("approval");
    expect(c.ended({ code: "rd_peer_closed" })).toEqual({ kind: "stop" });
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(1);
  });

  it("使用者取消：停止，清掉記憶體裡的密碼", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    expect(c.view.state).toBe("waiting");
    c.cancel();
    expect(c.view).toMatchObject({ state: "idle", attempt: 0 });
    expect(c.auth).toBeNull();
    vi.advanceTimersByTime(10 * 60_000);
    expect(attempts).toEqual([]);
  });

  it("重連進行中取消：連線被使用者關掉，不再重連", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.cancel();
    expect(c.auth).toBeNull();
    expect(c.ended({ byUser: true })).toEqual({ kind: "stop" });
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(1);
  });

  it("使用者自己中斷：不重連，清掉密碼", () => {
    const { c, attempts } = live();
    expect(c.ended({ byUser: true })).toEqual({ kind: "stop" });
    expect(c.auth).toBeNull();
    vi.advanceTimersByTime(60_000);
    expect(attempts).toEqual([]);
  });

  it("受控端送了 close_reason：不重連，清掉密碼", () => {
    const { c } = live();
    expect(c.ended({ code: "rd_peer_closed", peerReason: "x" })).toEqual({ kind: "stop" });
    expect(c.auth).toBeNull();
  });

  it("離開頁面：倒數中也停止，密碼清掉，之後的呼叫都不做事", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    c.dispose();
    expect(c.auth).toBeNull();
    vi.advanceTimersByTime(60_000);
    expect(attempts).toEqual([]);
    c.begin({ kind: "typed", password: PW }, true);
    expect(c.auth).toBeNull();
    expect(c.connected()).toBeNull();
  });

  it("「立即重連」：不等倒數，馬上開始這一次", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.ended({ code: "rd_offline" });
    vi.advanceTimersByTime(2000);
    c.ended({ code: "rd_offline" });
    c.ended({ code: "rd_offline" }); // 倒數中重複收到結束：不影響
    expect(c.view).toMatchObject({ state: "waiting", attempt: 3 });
    c.now();
    expect(attempts.map((a) => a.n)).toEqual([1, 2, 3]);
    expect(c.view.state).toBe("trying");
    vi.advanceTimersByTime(60_000);
    expect(attempts).toHaveLength(3);                    // 原本的計時器不會再觸發一次
    c.now();                                             // 進行中按下沒有作用
    expect(attempts).toHaveLength(3);
  });

  it("連上之後計數歸零：之後再意外中斷，從第 1 次（1 秒）重新開始", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.ended({ code: "rd_offline" });
    vi.advanceTimersByTime(2000);
    c.ended({ code: "rd_offline" });
    vi.advanceTimersByTime(3000);
    expect(attempts.map((a) => a.n)).toEqual([1, 2, 3]);
    c.connected();
    expect(c.view.state).toBe("idle");
    expect(c.ended({ code: "rd_peer_closed" })).toEqual({ kind: "wait", attempt: 1, delay: 1 });
  });

  it("使用者輸入的密碼：每次重連都交給新的連線（只在記憶體）", () => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.ended({ code: "ws_closed" });
    vi.advanceTimersByTime(2000);
    expect(attempts.map((a) => a.auth)).toEqual([{ kind: "typed", password: PW }, { kind: "typed", password: PW }]);
  });

  it("已存的密碼：重連只交出 credential_id（瀏覽器照舊拿不到密碼或雜湊）", () => {
    const { c, attempts } = live({ kind: "saved", credentialId: "cred-1" });
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(attempts[0].auth).toEqual({ kind: "saved", credentialId: "cred-1" });
  });

  it("在密碼框改輸入的密碼：之後的重連用新的這一組", () => {
    const { c, attempts } = controller();
    c.begin(null, false);
    c.interrupt("password");             // 收到 Hash 時才問
    c.typed("new-pw", false);
    c.connected();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(attempts[0].auth).toEqual({ kind: "typed", password: "new-pw" });
  });
});

describe("G.3：記住密碼只在手動登入成功的那一次存", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("手動登入成功時交出要存的密碼；自動重連成功不會再存一次", () => {
    const { c } = controller();
    c.begin({ kind: "typed", password: PW }, true);
    expect(c.connected()).toBe(PW);
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    expect(c.connected()).toBeNull();
    c.ended({ code: "ws_closed" });
    vi.advanceTimersByTime(1000);
    expect(c.connected()).toBeNull();
  });

  it("沒勾記住、空白密碼、已存的密碼：都沒有要存的", () => {
    const a = controller();
    a.c.begin({ kind: "typed", password: PW }, false);
    expect(a.c.connected()).toBeNull();
    const b = controller();
    b.c.begin({ kind: "typed", password: "" }, true);
    expect(b.c.connected()).toBeNull();
    const s = controller();
    s.c.begin({ kind: "saved", credentialId: "cred-1" }, true);
    expect(s.c.connected()).toBeNull();
  });

  it("密碼框輸入並勾記住：登入成功才存；被拒絕就不存", () => {
    const { c } = controller();
    c.begin(null, true);
    c.typed("wrong", true);
    c.interrupt("password");             // Wrong Password
    c.typed(PW, true);
    expect(c.connected()).toBe(PW);
  });

  it("重連時改在密碼框輸入新密碼並勾記住（對方改過密碼）：那一次是手動登入，照樣存", () => {
    const { c } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.interrupt("password");
    c.typed("changed", true);
    expect(c.connected()).toBe("changed");
  });

  it("瀏覽器的儲存空間不放密碼", () => {
    localStorage.clear();
    sessionStorage.clear();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const { c } = live({ kind: "typed", password: PW }, true);
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.connected();
    c.ended({ code: "rd_peer_closed" });
    c.cancel();
    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    setItem.mockRestore();
  });
});

// ── 接上真正的 RdSession：每一次重連都是新的 Hash、新的登入雜湊 ──

const PEER = "123456789";
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
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
  /** 受控端或後端把連線關了（沒有 close_reason） */
  drop(): void { this.readyState = 3; this.onclose?.({}); }
}

/** 走完握手（6），回傳受控端這一側的加解密 */
function pair(ws: FakeWs) {
  const server = nacl.sign.keyPair();
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  ws.text({ t: "ready", signed_id_pk: b64(nacl.sign(concat(fStr(1, PEER), fBytes(2, sign.publicKey)), server.secretKey)),
            server_key: b64(server.publicKey) });
  const idpk = concat(fStr(1, PEER), fBytes(2, box.publicKey));
  ws.bin(encodeMessage("signed_id", fBytes(1, nacl.sign(idpk, sign.secretKey))));
  const pk = parse(decodeMessage(ws.sentBin[0]).body);
  const key = nacl.box.open(pk.get(2)![0] as Uint8Array, new Uint8Array(24), pk.get(1)![0] as Uint8Array,
                            box.secretKey)!;
  const tx = new SecretBoxStream(key);
  const rx = new SecretBoxStream(key);
  return { seal: (m: Uint8Array) => tx.seal(m), open: (c: Uint8Array) => decodeMessage(rx.open(c)!) };
}

const hashMsg = (challenge: string) => encodeMessage("hash", concat(fStr(1, "aB3dE9"), fStr(2, challenge)));
const peerInfo = () => encodeMessage("login_response",
  fMsg(2, concat(fStr(3, "Linux"), fMsg(4, concat(fVarint(3, 1280), fVarint(4, 800))))));

/** 畫面那一側的最小版本：每次（手動或自動）都開一條新的 RdSession，結束交給 AutoReconnect 決定。 */
function harness(first: ReconnectAuth, opts: { viewOnly?: boolean; clipboard?: boolean } = {},
                 extra: SessionEvents = {}) {
  const sockets: FakeWs[] = [];
  const sessions: RdSession[] = [];
  const decisions: string[] = [];
  const infos: CloseInfo[] = [];
  const open = (auth: ReconnectAuth | null) => {
    const ws = new FakeWs();
    sockets.push(ws);
    const s = new RdSession({
      url: `wss://x/ws?ticket=t${sockets.length}`, peerId: PEER, myName: "alice (jt-ipam)",
      decoding: { vp9: true, h264: false, vp8: false, av1: false },
      password: auth?.kind === "typed" ? auth.password : undefined,
      savedCredentialId: auth?.kind === "saved" ? auth.credentialId : undefined,
      viewOnly: opts.viewOnly, clipboard: opts.clipboard,
      events: {
        ...extra,
        connected: () => { rc.connected(); },
        closed: (info) => { infos.push(info); decisions.push(rc.ended(info).kind); },
      },
      wsFactory: () => ws,
    });
    sessions.push(s);
  };
  const rc = new AutoReconnect({ attempt: (_n, auth) => open(auth) });
  rc.begin(first, false);
  open(first);
  return { rc, sockets, sessions, decisions, infos };
}

/** 讓第 i 條連線的受控端送 Hash，等瀏覽器送出登入（或 login_assist） */
async function login(ws: FakeWs, challenge: string) {
  const peer = pair(ws);
  ws.bin(peer.seal(hashMsg(challenge)));
  return peer;
}

describe("每一次重連都是完整的新連線（G.3）", () => {
  afterEach(() => { vi.useRealTimers(); });

  it("已存的密碼：每次重連都在新的連線上重新送 login_assist，帶這一次的 challenge", async () => {
    vi.useFakeTimers();
    const h = harness({ kind: "saved", credentialId: "cred-1" });
    const p1 = await login(h.sockets[0], "c1AAAA");
    const assists = (ws: FakeWs) => ws.sentText.filter((x) => x.t === "login_assist");
    expect(assists(h.sockets[0])).toEqual([{ t: "login_assist", credential_id: "cred-1", salt: "aB3dE9", challenge: "c1AAAA" }]);
    h.sockets[0].text({ t: "login_assist", ok: true, hash: b64(new Uint8Array(32).fill(1)) });
    h.sockets[0].bin(p1.seal(peerInfo()));
    expect(h.sessions[0].phase).toBe("connected");

    h.sockets[0].drop();                                   // 受控端切到新的桌面工作階段
    expect(h.decisions).toEqual(["wait"]);
    expect(h.sockets).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.sockets).toHaveLength(2);                     // 新的連線（新票證、新配對）
    await login(h.sockets[1], "c2BBBB");
    expect(assists(h.sockets[1])).toEqual([{ t: "login_assist", credential_id: "cred-1", salt: "aB3dE9", challenge: "c2BBBB" }]);
    // 瀏覽器送出的東西裡沒有密碼或 h1
    expect(JSON.stringify(h.sockets.flatMap((w) => w.sentText))).not.toContain(PW);
  });

  it("使用者輸入的密碼：每次重連都用新的 challenge 重新算登入雜湊，選項沿用（唯讀檢視、剪貼簿）", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const h = harness({ kind: "typed", password: PW }, { viewOnly: false, clipboard: false });
    const p1 = await login(h.sockets[0], "AAAAAA");
    await vi.waitFor(() => expect(h.sockets[0].sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    const lr1 = parse(p1.open(h.sockets[0].sentBin[1]).body);
    const first = hex(lr1.get(2)![0] as Uint8Array);
    expect(first).toHaveLength(64);
    expect(first).not.toBe(H2);
    h.sockets[0].bin(p1.seal(peerInfo()));

    h.sockets[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.sockets).toHaveLength(2);
    const p2 = await login(h.sockets[1], "x7Kq2Z");
    await vi.waitFor(() => expect(h.sockets[1].sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    const lr2 = parse(p2.open(h.sockets[1].sentBin[1]).body);
    expect(hex(lr2.get(2)![0] as Uint8Array)).toBe(H2);   // 7.2 的測試向量：用這一次的 challenge 算的
    const option = parse(lr2.get(6)![0] as Uint8Array);
    expect(option.get(8)![0]).toBe(2n);                   // 剪貼簿維持關閉（disable_clipboard = Yes）
    expect(option.has(12)).toBe(false);                    // 不是唯讀檢視
  });

  it("重連時對方回 Wrong Password：停止自動重連，等使用者輸入", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const asked: string[] = [];
    const h = harness({ kind: "typed", password: PW }, {},
                      { needPassword: (reason) => { asked.push(reason); h.rc.interrupt("password"); } });
    const p1 = await login(h.sockets[0], "x7Kq2Z");
    await vi.waitFor(() => expect(h.sockets[0].sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    h.sockets[0].bin(p1.seal(peerInfo()));
    h.sockets[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    const p2 = await login(h.sockets[1], "x7Kq2Z");
    await vi.waitFor(() => expect(h.sockets[1].sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    h.sockets[1].bin(p2.seal(encodeMessage("login_response", fStr(1, "Wrong Password"))));
    expect(asked).toEqual(["wrong"]);
    expect(h.rc.auth).toBeNull();
    expect(h.rc.view.state).toBe("idle");
    h.sockets[1].drop();
    expect(h.decisions).toEqual(["wait", "stop"]);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.sockets).toHaveLength(2);
  });
});

// ── §7.1：受控端在 Hash 之前送來的拒絕（G.3：重連途中立刻停止，不試滿 8 次） ──

const REFUSED_BEFORE_HASH = ["Your ip is blocked by the peer", "The main window is not open"];

describe("§7.1 的兩種拒絕：重連途中立刻停止", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it.each(REFUSED_BEFORE_HASH)("規則：重連途中登入回 %s 不算「還沒回來」", (text) => {
    expect(retryDuringAttempt({ code: "rd_login_error", detail: text, params: { reason: text } })).toBe(false);
    // 前後多了空白也一樣（比對前會去掉頭尾空白）
    expect(retryDuringAttempt({ code: "rd_login_error", detail: ` ${text} ` })).toBe(false);
  });

  it.each(REFUSED_BEFORE_HASH)("重連途中收到 %s：停止，交回原本的結束原因（畫面照常顯示原文）", (text) => {
    const { c, attempts } = live();
    c.ended({ code: "rd_peer_closed" });
    vi.advanceTimersByTime(1000);
    c.ended({ code: "rd_offline" });                     // 第 1 次：還沒回來
    vi.advanceTimersByTime(2000);
    expect(attempts).toHaveLength(2);
    expect(c.ended({ code: "rd_login_error", detail: text, params: { reason: text } })).toEqual({ kind: "stop" });
    expect(c.view.state).toBe("idle");
    expect(c.auth).toBeNull();
    vi.advanceTimersByTime(10 * 60_000);
    expect(attempts).toHaveLength(2);                    // 不會有第 3 次，更不會試滿 8 次
  });

  it.each(REFUSED_BEFORE_HASH)("第一次（手動）連線收到 %s：照舊直接顯示，不自動重試", (text) => {
    const { c, attempts } = controller();
    c.begin({ kind: "typed", password: PW }, false);
    expect(c.ended({ code: "rd_login_error", detail: text, params: { reason: text } })).toEqual({ kind: "stop" });
    vi.advanceTimersByTime(10 * 60_000);
    expect(attempts).toEqual([]);
  });
});

describe("§7.1 的兩種拒絕：接上真正的 RdSession（登入回覆與關閉兩條路都停止）", () => {
  afterEach(() => { vi.useRealTimers(); });

  /** 手動連上，受控端直接結束，等到第 1 次重連開了新的連線 */
  async function reconnecting() {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const h = harness({ kind: "typed", password: PW });
    const p1 = await login(h.sockets[0], "x7Kq2Z");
    await vi.waitFor(() => expect(h.sockets[0].sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    h.sockets[0].bin(p1.seal(peerInfo()));
    expect(h.sessions[0].phase).toBe("connected");
    h.sockets[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.sockets).toHaveLength(2);
    return h;
  }

  it.each(REFUSED_BEFORE_HASH)("受控端在 Hash 之前回 LoginResponse「%s」接著關閉：停止，結束原因是登入錯誤原文", async (text) => {
    const h = await reconnecting();
    const peer = pair(h.sockets[1]);
    h.sockets[1].bin(peer.seal(encodeMessage("login_response", fStr(1, text))));   // 沒有 Hash
    h.sockets[1].text({ t: "close", reason: "peer_closed" });                        // 後端轉告受控端關了
    h.sockets[1].drop();
    expect(h.decisions).toEqual(["wait", "stop"]);                                   // 關閉不會再算一次
    expect(h.infos[1]).toEqual({ code: "rd_login_error", detail: text, params: { reason: text } });
    expect(h.sockets[1].sentBin).toHaveLength(1);                                    // 只有 PublicKey，沒有送登入
    expect(h.rc.auth).toBeNull();
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(h.sockets).toHaveLength(2);
  });

  it.each(REFUSED_BEFORE_HASH)("受控端改用 close_reason 送「%s」：同樣停止，帶原文", async (text) => {
    const h = await reconnecting();
    const peer = pair(h.sockets[1]);
    h.sockets[1].bin(peer.seal(encodeCloseReason(text)));
    h.sockets[1].drop();
    expect(h.decisions).toEqual(["wait", "stop"]);
    expect(h.infos[1]).toMatchObject({ code: "rd_peer_closed", detail: text, peerReason: text });
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(h.sockets).toHaveLength(2);
  });
});
