/**
 * 相容 RustDesk 的網頁連線：Windows 免安裝受控端的系統管理員視窗、UAC 與請求提權（規格附錄 K.3 的單元測試）。
 *
 * - K.1 的編解碼：Misc.elevation_request（18）兩種、Misc.uac（15）／foreground_window_elevated（16）／
 *   elevation_response（19）／portable_service_running（20）、PeerInfo.platform_additions 的 is_installed
 * - K.2 的規則（elevation.ts）：標籤、提示的顯示與移除、工具列選單的條件、送出後的回覆（已送出／成功／錯誤／逾時）、
 *   稽核訊息（送出時與得到結果時各一則）、新連線一切重新判斷
 * - 連線流程（session.ts）：連線中把這幾個 Misc 交給畫面；提權請求加密送給受控端；送給後端的稽核只有四個欄位，
 *   帳號密碼不出現在任何文字訊息裡
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { concat, fBool, fMsg, fStr, fStrAlways, fVarint, fVarintAlways, getBool, getStr, parse } from "../pb";
import { decodeMessage, encodeElevationRequest, encodeMessage, parseMisc, Permission, type PeerInfo } from "../messages";
import {
  classifyElevationError, ELEVATION_DETAIL_MAX, ELEVATION_TIMEOUT_MS, ElevationTracker, elevationUi, parseIsInstalled,
  type ElevationMethod, type ElevationResult, type ElevationState,
} from "../elevation";
import { RdSession, type SessionEvents } from "../session";
import { encodeFileLoginRequest } from "../files";
import { FakePeer, FakeWs, PEER } from "./fakeRustDesk";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new Uint8Array(new TextEncoder().encode(s));

afterEach(() => {
  vi.useRealTimers();
});

// ── 受控端送的 Misc（K.1：都在 Message.misc (19) 的 oneof 裡；false／空字串也會寫出欄位） ──

const miscBool = (field: number, v: boolean) => encodeMessage("misc", fVarintAlways(field, v ? 1 : 0));
const uacMsg = (v: boolean) => miscBool(15, v);
const foregroundMsg = (v: boolean) => miscBool(16, v);
const responseMsg = (text: string) => encodeMessage("misc", fStrAlways(19, text));
const serviceMsg = (v: boolean) => miscBool(20, v);

describe("K.1：Misc.elevation_request 的編碼", () => {
  it("direct：Misc 欄位 18 → ElevationRequest { direct (1) = true }", () => {
    const out = encodeElevationRequest({ method: "direct" });
    // Message { misc (19) { elevation_request (18) { direct (1): true } } }
    expect(hex(out)).toBe("9a01" + "05" + "9201" + "02" + "0801");
    const m = decodeMessage(out);
    expect(m.kind).toBe("misc");
    const req = parse(parse(m.body).get(18)![0] as Uint8Array);
    expect([...req.keys()]).toEqual([1]);
    expect(getBool(req, 1)).toBe(true);
  });

  it("logon：ElevationRequest { logon (2) = ElevationRequestWithLogon { username (1), password (2) } }", () => {
    const out = encodeElevationRequest({ method: "logon", username: "CORP\\admin", password: "S3cret-Pa55" });
    const m = decodeMessage(out);
    expect(m.kind).toBe("misc");
    const misc = parse(m.body);
    expect([...misc.keys()]).toEqual([18]);
    const req = parse(misc.get(18)![0] as Uint8Array);
    expect([...req.keys()]).toEqual([2]);
    const logon = parse(req.get(2)![0] as Uint8Array);
    expect(getStr(logon, 1)).toBe("CORP\\admin");
    expect(getStr(logon, 2)).toBe("S3cret-Pa55");
    // 位元組：12 len (0a 0a "CORP\admin" 12 0b "S3cret-Pa55")
    const inner = concat(Uint8Array.of(0x0a, 10), utf8("CORP\\admin"), Uint8Array.of(0x12, 11), utf8("S3cret-Pa55"));
    expect(hex(req.get(2)![0] as Uint8Array)).toBe(hex(inner));
  });

  it("logon 的子訊息即使帳號密碼都空也要寫出（oneof）", () => {
    const req = parse(parse(decodeMessage(encodeElevationRequest({ method: "logon", username: "", password: "" })).body)
      .get(18)![0] as Uint8Array);
    expect(req.has(2)).toBe(true);
  });
});

describe("K.1：uac／foreground_window_elevated／elevation_response／portable_service_running 的解碼", () => {
  const misc = (msg: Uint8Array) => parseMisc(decodeMessage(msg).body);

  it("uac（15）", () => {
    expect(misc(uacMsg(true))).toEqual({ type: "uac", value: true });
    expect(misc(uacMsg(false))).toEqual({ type: "uac", value: false });
  });

  it("foreground_window_elevated（16）", () => {
    expect(misc(foregroundMsg(true))).toEqual({ type: "foreground_window_elevated", value: true });
    expect(misc(foregroundMsg(false))).toEqual({ type: "foreground_window_elevated", value: false });
  });

  it("elevation_response（19）：空字串＝已發出啟動；非空＝錯誤原文", () => {
    expect(misc(responseMsg(""))).toEqual({ type: "elevation_response", text: "" });
    expect(misc(responseMsg("No permission"))).toEqual({ type: "elevation_response", text: "No permission" });
  });

  it("portable_service_running（20）", () => {
    expect(misc(serviceMsg(true))).toEqual({ type: "portable_service_running", value: true });
    expect(misc(serviceMsg(false))).toEqual({ type: "portable_service_running", value: false });
  });

  it("其他 Misc 照舊", () => {
    expect(misc(encodeMessage("misc", fStr(9, "bye"))).type).toBe("close_reason");
    expect(misc(encodeMessage("misc", fBool(13, true))).type).toBe("other");
  });
});

describe("K.1：PeerInfo.platform_additions 的 is_installed", () => {
  it("true／false", () => {
    expect(parseIsInstalled('{"is_installed": true}')).toBe(true);
    expect(parseIsInstalled('{"is_installed":false,"is_wayland":false}')).toBe(false);
  });

  it("沒有這個鍵（非 Windows、舊版）：不適用（null）", () => {
    expect(parseIsInstalled('{"is_wayland": true}')).toBeNull();
    expect(parseIsInstalled("")).toBeNull();
    expect(parseIsInstalled("{}")).toBeNull();
  });

  it("JSON 壞掉、不是物件、值不是布林：不適用（null），不丟例外", () => {
    expect(parseIsInstalled('{"is_installed": fals')).toBeNull();
    expect(parseIsInstalled("not json")).toBeNull();
    expect(parseIsInstalled("[true]")).toBeNull();
    expect(parseIsInstalled("null")).toBeNull();
    expect(parseIsInstalled("true")).toBeNull();
    expect(parseIsInstalled('{"is_installed": "false"}')).toBeNull();
    expect(parseIsInstalled('{"is_installed": 0}')).toBeNull();
  });
});

describe("K.2：錯誤原文的分類（三種常見的翻譯成說明，其他顯示原文）", () => {
  it("No permission／No need to elevate／Failed to run portable service process 開頭", () => {
    expect(classifyElevationError("No permission")).toBe("no_permission");
    expect(classifyElevationError("No need to elevate")).toBe("no_need");
    expect(classifyElevationError("Failed to run portable service process")).toBe("failed");
    expect(classifyElevationError("Failed to run portable service process: The operation was canceled by the user."))
      .toBe("failed");
  });

  it("其他原文（含 already running）不分類，照原文顯示", () => {
    expect(classifyElevationError("already running")).toBeNull();
    expect(classifyElevationError("something else")).toBeNull();
    expect(classifyElevationError("constructor")).toBeNull();
    expect(classifyElevationError("no permission")).toBeNull();
  });
});

// ── 規則（elevation.ts）──

function peerInfo(platform: string, additions = ""): PeerInfo {
  return {
    username: "", hostname: "pc", platform, displays: [], currentDisplay: 0, version: "1.5.0",
    platformAdditions: additions, resolutions: [], encoding: null,
  };
}
const WIN_PORTABLE = peerInfo("Windows", '{"is_installed":false}');
const WIN_INSTALLED = peerInfo("Windows", '{"is_installed":true}');
const LINUX = peerInfo("Linux", '{"is_wayland":false}');
const CONTROL = { connected: true, viewOnly: false, keyboardBlocked: false };

interface AuditCall { method: ElevationMethod; result: ElevationResult; detail: string }

function tracker(opts: { send?: boolean } = {}) {
  const sent: unknown[] = [];
  const audits: AuditCall[] = [];
  const states: ElevationState[] = [];
  const t = new ElevationTracker({
    send: (req) => { sent.push(req); return opts.send ?? true; },
    audit: (method, result, detail) => { audits.push({ method, result, detail }); },
    change: (s) => { states.push(s); },
  });
  return { t, sent, audits, states, ui: (c = CONTROL) => elevationUi(t.state, c) };
}

describe("K.2：狀態列標籤與工具列「請求提權」的條件", () => {
  it("Windows 免安裝：標籤「免安裝版」、有選單；收到 portable_service_running = true 後改成已提權、選單不顯示", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    expect(ui()).toMatchObject({ tag: "portable", menu: true, foregroundAlert: false, uacAlert: false, busy: false });
    t.service(false);                       // 登入後第一次檢查一定送一次目前的值
    expect(ui()).toMatchObject({ tag: "portable", menu: true });
    t.service(true);
    expect(ui()).toMatchObject({ tag: "elevated", menu: false });
  });

  it("唯讀檢視、對方關閉控制權、不在連線中：沒有選單（標籤照常）", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    expect(ui({ ...CONTROL, viewOnly: true })).toMatchObject({ tag: "portable", menu: false });
    expect(ui({ ...CONTROL, keyboardBlocked: true })).toMatchObject({ tag: "portable", menu: false });
    expect(ui({ ...CONTROL, connected: false })).toMatchObject({ menu: false });
  });

  it("已安裝的 Windows、Linux、沒有 is_installed、JSON 壞掉：沒有標籤也沒有選單", () => {
    for (const info of [WIN_INSTALLED, LINUX, peerInfo("Windows", ""), peerInfo("Windows", "{bad"),
                        peerInfo("Linux", '{"is_installed":false}')]) {
      const { t, ui } = tracker();
      t.login(info);
      expect(ui(), info.platform + info.platformAdditions).toMatchObject({ tag: null, menu: false });
    }
  });

  it("連線中的 peer_info：帶了 is_installed 才更新；沒帶（只有螢幕資訊）就沿用登入時的", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.peerInfo(peerInfo("Windows", '{"is_wayland":false}'));
    expect(ui().tag).toBe("portable");
    t.peerInfo(peerInfo("Windows", '{"is_installed":true}'));
    expect(ui().tag).toBeNull();
  });
});

describe("K.2：前景是系統管理員視窗、UAC 確認畫面的提示", () => {
  it("收到 true 顯示、收到 false 移除", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.foreground(true);
    expect(ui().foregroundAlert).toBe(true);
    t.uac(true);
    expect(ui()).toMatchObject({ foregroundAlert: true, uacAlert: true });
    t.foreground(false);
    expect(ui()).toMatchObject({ foregroundAlert: false, uacAlert: true });
    t.uac(false);
    expect(ui()).toMatchObject({ foregroundAlert: false, uacAlert: false });
  });

  it("沒有控制權、唯讀檢視時不顯示", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.foreground(true);
    t.uac(true);
    expect(ui({ ...CONTROL, viewOnly: true })).toMatchObject({ foregroundAlert: false, uacAlert: false });
    expect(ui({ ...CONTROL, keyboardBlocked: true })).toMatchObject({ foregroundAlert: false, uacAlert: false });
  });

  it("輔助服務在跑（提權成功）時移除提示；之後服務停了也不會冒出舊的提示", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.foreground(true);
    t.uac(true);
    t.service(true);
    expect(ui()).toMatchObject({ foregroundAlert: false, uacAlert: false });
    t.service(false);
    expect(ui()).toMatchObject({ foregroundAlert: false, uacAlert: false, tag: "portable", menu: true });
    t.foreground(true);                      // 受控端重新判斷後再送
    expect(ui().foregroundAlert).toBe(true);
  });
});

describe("K.2：請求提權與回覆", () => {
  it("direct：送出請求並記稽核 requested；空字串回覆＝已送出；portable_service_running = true＝成功，記稽核 ok", () => {
    const { t, sent, audits, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.foreground(true);
    expect(t.request({ method: "direct" })).toBe(true);
    expect(sent).toEqual([{ method: "direct" }]);
    expect(audits).toEqual([{ method: "direct", result: "requested", detail: "" }]);
    expect(t.state.notice).toEqual({ kind: "requesting", method: "direct" });
    expect(ui().busy).toBe(true);
    t.response("");
    expect(t.state.notice).toEqual({ kind: "sent", method: "direct" });
    expect(audits).toHaveLength(1);           // 已送出還不是結果
    t.service(true);
    expect(t.state.notice).toEqual({ kind: "ok", method: "direct" });
    expect(audits).toEqual([{ method: "direct", result: "requested", detail: "" },
                            { method: "direct", result: "ok", detail: "" }]);
    expect(ui()).toMatchObject({ tag: "elevated", foregroundAlert: false, busy: false, menu: false });
  });

  it("請求進行中不能再送第二次", () => {
    const { t, sent } = tracker();
    t.login(WIN_PORTABLE);
    expect(t.request({ method: "direct" })).toBe(true);
    expect(t.request({ method: "logon", username: "a", password: "b" })).toBe(false);
    expect(sent).toHaveLength(1);
  });

  it("沒有送出（session 拒絕：唯讀、沒有控制權）：不記稽核、沒有進行中", () => {
    const { t, audits } = tracker({ send: false });
    t.login(WIN_PORTABLE);
    expect(t.request({ method: "direct" })).toBe(false);
    expect(audits).toEqual([]);
    expect(t.state.notice).toBeNull();
  });

  it("非空回覆＝錯誤：三種常見的分類，其他照原文；稽核 error 帶原文（最多 200 字）", () => {
    for (const [text, reason] of [["No permission", "no_permission"], ["No need to elevate", "no_need"],
                                  ["Failed to run portable service process", "failed"],
                                  ["already running", null], ["系統找不到指定的檔案。", null]] as const) {
      const { t, audits, ui } = tracker();
      t.login(WIN_PORTABLE);
      t.request({ method: "logon", username: "admin", password: "pw" });
      t.response(text);
      expect(t.state.notice).toEqual({ kind: "error", method: "logon", text, reason });
      expect(audits[1]).toEqual({ method: "logon", result: "error", detail: text });
      expect(ui()).toMatchObject({ busy: false, menu: true });       // 可以再試
    }
    const { t, audits } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "direct" });
    t.response("錯".repeat(500));
    expect(Array.from(audits[1].detail)).toHaveLength(ELEVATION_DETAIL_MAX);
  });

  it("送出後 60 秒還沒收到 portable_service_running = true：逾時，記稽核 timeout；可以再試", () => {
    vi.useFakeTimers();
    const { t, audits, sent } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "direct" });
    t.response("");
    vi.advanceTimersByTime(ELEVATION_TIMEOUT_MS - 1);
    expect(t.state.notice?.kind).toBe("sent");
    vi.advanceTimersByTime(1);
    expect(t.state.notice).toEqual({ kind: "timeout", method: "direct" });
    expect(audits.map((a) => a.result)).toEqual(["requested", "timeout"]);
    // 可以再試：第二次照樣送出、照樣計時
    expect(t.request({ method: "direct" })).toBe(true);
    expect(sent).toHaveLength(2);
    t.service(true);
    expect(audits.map((a) => a.result)).toEqual(["requested", "timeout", "requested", "ok"]);
    expect(ELEVATION_TIMEOUT_MS).toBe(60_000);
  });

  it("逾時之後才來的 portable_service_running = true：改成已提權、顯示成功，並補記結果 ok（提權確實發生了，稽核不可以漏）", () => {
    vi.useFakeTimers();
    const { t, audits, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "direct" });
    vi.advanceTimersByTime(ELEVATION_TIMEOUT_MS);
    t.dismiss();                              // 使用者關掉逾時的提示也一樣
    t.service(true);
    expect(ui().tag).toBe("elevated");
    expect(t.state.notice).toEqual({ kind: "ok", method: "direct" });
    expect(audits.map((a) => a.result)).toEqual(["requested", "timeout", "ok"]);
    t.service(false);
    t.service(true);                          // 同一個請求只記一次結果
    expect(audits.map((a) => a.result)).toEqual(["requested", "timeout", "ok"]);
  });

  it("逾時之後才來的錯誤回覆：顯示錯誤並記結果；之後的空字串回覆不理", () => {
    vi.useFakeTimers();
    const { t, audits } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "direct" });
    vi.advanceTimersByTime(ELEVATION_TIMEOUT_MS);
    t.response("");
    expect(t.state.notice?.kind).toBe("timeout");
    t.response("Failed to run portable service process");
    expect(t.state.notice).toMatchObject({ kind: "error", reason: "failed" });
    expect(audits.map((a) => a.result)).toEqual(["requested", "timeout", "error"]);
  });

  it("成功之後計時器停掉，不會再記逾時", () => {
    vi.useFakeTimers();
    const { t, audits } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "direct" });
    t.service(true);                          // 沒等到空字串回覆就成功也算
    vi.advanceTimersByTime(ELEVATION_TIMEOUT_MS * 2);
    expect(audits.map((a) => a.result)).toEqual(["requested", "ok"]);
  });

  it("沒有在等的時候收到回覆：不顯示、不記稽核", () => {
    const { t, audits } = tracker();
    t.login(WIN_PORTABLE);
    t.response("No need to elevate");
    t.response("");
    expect(t.state.notice).toBeNull();
    expect(audits).toEqual([]);
  });

  it("logon 的帳號密碼只交給 send：不進稽核、不留在狀態裡", () => {
    const { t, sent, audits, states } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "logon", username: "CORP\\administrator", password: "S3cret-Pa55" });
    t.response("Failed to run portable service process");
    expect(sent).toEqual([{ method: "logon", username: "CORP\\administrator", password: "S3cret-Pa55" }]);
    const dumped = JSON.stringify({ audits, states, now: t.state });
    expect(dumped).not.toContain("administrator");
    expect(dumped).not.toContain("S3cret-Pa55");
  });

  it("關掉結果提示（dismiss）：只清結果，不影響進行中的請求", () => {
    const { t } = tracker();
    t.login(WIN_PORTABLE);
    t.request({ method: "direct" });
    t.dismiss();
    expect(t.state.notice?.kind).toBe("requesting");
    t.response("No permission");
    t.dismiss();
    expect(t.state.notice).toBeNull();
  });
});

describe("K.2：自動重連（新連線）一切重新判斷", () => {
  it("reset：狀態、提示、進行中的請求與計時器都清掉，之後不會再記逾時", () => {
    vi.useFakeTimers();
    const { t, audits, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.foreground(true);
    t.service(true);
    t.service(false);
    t.request({ method: "direct" });
    t.reset();
    expect(t.state).toEqual({ platform: "", installed: null, serviceRunning: false, uac: false,
                              foregroundElevated: false, notice: null });
    expect(ui()).toMatchObject({ tag: null, menu: false, foregroundAlert: false, uacAlert: false, busy: false });
    vi.advanceTimersByTime(ELEVATION_TIMEOUT_MS * 2);
    expect(audits.map((a) => a.result)).toEqual(["requested"]);
  });

  it("上一條連線已提權：新連線以新連線收到的 portable_service_running 為準", () => {
    const { t, ui } = tracker();
    t.login(WIN_PORTABLE);
    t.service(true);
    t.reset();
    t.login(WIN_PORTABLE);
    expect(ui().tag).toBe("portable");
  });
});

// ── 連線流程（session.ts）──

function connectedSession(opts: { viewOnly?: boolean; file?: boolean } = {}, events: SessionEvents = {}) {
  const ws = new FakeWs();
  const peer = new FakePeer(ws);
  const s = new RdSession({
    url: "wss://x", peerId: PEER, myName: "alice (jt-ipam)", password: "",
    decoding: { vp9: true, h264: false, vp8: false, av1: false }, viewOnly: opts.viewOnly,
    encodeLogin: opts.file ? (o) => encodeFileLoginRequest({ ...o, dir: "", showHidden: false }) : undefined,
    events, wsFactory: () => ws,
  });
  peer.handshake();
  return { ws, peer, s };
}

async function loggedIn(opts: { viewOnly?: boolean; file?: boolean } = {}, events: SessionEvents = {}) {
  const env = connectedSession(opts, events);
  env.peer.hash();
  await vi.waitFor(() => expect(env.ws.sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
  env.peer.drain();
  const disp = concat(fVarint(3, 1280), fVarint(4, 800));
  env.peer.send(encodeMessage("login_response", fMsg(2, concat(fStr(3, "Windows"), fMsg(4, disp),
                                                               fStr(12, '{"is_installed":false}')))));
  expect(env.s.phase).toBe("connected");
  return env;
}

describe("session：連線中把 K.1 的 Misc 交給畫面", () => {
  it("uac、foreground_window_elevated、elevation_response、portable_service_running", async () => {
    const got: unknown[] = [];
    const { peer } = await loggedIn({}, {
      uac: (v) => got.push(["uac", v]),
      foregroundElevated: (v) => got.push(["fg", v]),
      elevationResponse: (t) => got.push(["resp", t]),
      portableService: (v) => got.push(["svc", v]),
    });
    peer.send(serviceMsg(false));
    peer.send(foregroundMsg(true));
    peer.send(uacMsg(true));
    peer.send(responseMsg(""));
    peer.send(responseMsg("No permission"));
    peer.send(serviceMsg(true));
    peer.send(uacMsg(false));
    expect(got).toEqual([["svc", false], ["fg", true], ["uac", true], ["resp", ""], ["resp", "No permission"],
                         ["svc", true], ["uac", false]]);
  });

  it("登入前收到的不交給畫面", () => {
    const got: unknown[] = [];
    const { peer } = connectedSession({}, { uac: (v) => got.push(v), portableService: (v) => got.push(v) });
    peer.send(uacMsg(true));
    peer.send(serviceMsg(false));
    expect(got).toEqual([]);
  });
});

describe("session：requestElevation（K.1）", () => {
  it("加密送出 Misc.elevation_request；帳號密碼不出現在任何文字訊息裡", async () => {
    const { s, ws, peer } = await loggedIn();
    expect(s.requestElevation({ method: "direct" })).toBe(true);
    expect(s.requestElevation({ method: "logon", username: "CORP\\administrator", password: "S3cret-Pa55" })).toBe(true);
    const [direct, logon] = peer.drain().map((p) => decodeMessage(p));
    expect(direct.kind).toBe("misc");
    expect(getBool(parse(parse(direct.body).get(18)![0] as Uint8Array), 1)).toBe(true);
    const lr = parse(parse(parse(logon.body).get(18)![0] as Uint8Array).get(2)![0] as Uint8Array);
    expect(getStr(lr, 1)).toBe("CORP\\administrator");
    expect(getStr(lr, 2)).toBe("S3cret-Pa55");
    const texts = JSON.stringify(ws.sentText);
    expect(texts).not.toContain("administrator");
    expect(texts).not.toContain("S3cret-Pa55");
    // 送到後端的 binary 是密文：明文的密碼不會出現在位元組裡
    const pw = hex(utf8("S3cret-Pa55"));
    expect(ws.sentBin.some((b) => hex(b).includes(pw))).toBe(false);
  });

  it("唯讀檢視、對方關閉控制權、登入前、檔案傳輸的連線：不送", async () => {
    const ro = await loggedIn({ viewOnly: true });
    expect(ro.s.requestElevation({ method: "direct" })).toBe(false);
    expect(ro.peer.drain()).toEqual([]);

    const kb = await loggedIn();
    kb.peer.permission(Permission.Keyboard, false);
    expect(kb.s.requestElevation({ method: "direct" })).toBe(false);
    expect(kb.peer.drain()).toEqual([]);

    const early = connectedSession();
    expect(early.s.requestElevation({ method: "direct" })).toBe(false);

    const file = connectedSession({ file: true });
    file.peer.hash();
    await vi.waitFor(() => expect(file.ws.sentBin.length).toBe(2), { timeout: 2000, interval: 5 });
    file.peer.drain();
    file.peer.loginOk("Windows");
    expect(file.s.phase).toBe("connected");
    expect(file.s.requestElevation({ method: "direct" })).toBe(false);
    expect(file.peer.drain()).toEqual([]);
  });
});

describe("session：reportElevation（K.2 的稽核訊息）", () => {
  it("送 {t, method, result, detail} 四個欄位；detail 截到 200 字", async () => {
    const { s, ws } = await loggedIn();
    ws.sentText.length = 0;
    s.reportElevation("direct", "requested");
    s.reportElevation("logon", "error", "x".repeat(300));
    expect(ws.sentText[0]).toEqual({ t: "elevation_audit", method: "direct", result: "requested", detail: "" });
    expect(Object.keys(ws.sentText[1]).sort()).toEqual(["detail", "method", "result", "t"]);
    expect(ws.sentText[1].detail).toBe("x".repeat(ELEVATION_DETAIL_MAX));
  });

  it("不在清單內的 method／result 不送；檔案傳輸的連線不送", async () => {
    const { s, ws } = await loggedIn();
    ws.sentText.length = 0;
    s.reportElevation("runas" as ElevationMethod, "ok");
    s.reportElevation("direct", "cancelled" as ElevationResult);
    expect(ws.sentText).toEqual([]);

    const file = connectedSession({ file: true });
    file.ws.sentText.length = 0;
    file.s.reportElevation("direct", "requested");
    expect(file.ws.sentText).toEqual([]);
  });

  it("整個流程（tracker 接 session）：送給後端的文字訊息只有登入結果與兩則提權稽核，沒有帳號密碼", async () => {
    const { s, ws, peer } = await loggedIn();
    const t = new ElevationTracker({
      send: (req) => s.requestElevation(req),
      audit: (m, r, d) => s.reportElevation(m, r, d),
      change: () => undefined,
    });
    t.login(s.peerInfo!);
    expect(elevationUi(t.state, CONTROL).menu).toBe(true);
    t.request({ method: "logon", username: "CORP\\administrator", password: "S3cret-Pa55" });
    peer.send(responseMsg(""));
    t.response("");
    t.service(true);
    const kinds = ws.sentText.map((x) => x.t);
    expect(kinds).toEqual(["login_result", "elevation_audit", "elevation_audit"]);
    expect(ws.sentText.slice(1)).toEqual([
      { t: "elevation_audit", method: "logon", result: "requested", detail: "" },
      { t: "elevation_audit", method: "logon", result: "ok", detail: "" },
    ]);
    const texts = JSON.stringify(ws.sentText);
    expect(texts).not.toContain("administrator");
    expect(texts).not.toContain("S3cret-Pa55");
  });
});
