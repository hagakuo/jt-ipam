/**
 * 多螢幕與解析度（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 H，H.6 的單元測試清單）：
 * - 座標換算（原點非 0、負原點、macOS scale、5 像素以內貼齊、更遠的不送、左鍵放開例外）
 * - VideoFrame.display 過濾
 * - 執行中的 peer_info 更新清單與拔除處理
 * - 單一螢幕大小改變不當成切換
 * - 切換時送出的三則訊息與順序（switch_display → capture_displays set → refresh_video_display）
 * 模擬受控端的作法與 session.test.ts 相同（各自一份，互不相依）。
 */
import { describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fSint, fStr, fVarint, getRepeatedInts, parse } from "../pb";
import { SecretBoxStream } from "../crypto";
import {
  decodeMessage, encodeCaptureDisplays, encodeChangeResolution, encodeMessage, encodeSwitchDisplay, parseMisc,
  parsePeerInfo, type Decoded,
} from "../messages";
import { RdSession, type CloseInfo, type SessionEvents, type SessionOptions, type WebSocketLike } from "../session";
import { DisplayTracker, viewFromPeerInfo, type DisplayEventKind, type DisplayView } from "../displays";
import { mapPointer, unmapPointer } from "../input";

const PEER = "123456789";
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const last = <T,>(a: T[]): T => a[a.length - 1];
/** double（wire type 1，8 bytes little-endian）：DisplayInfo.scale */
function fDouble(field: number, v: number): Uint8Array {
  const b = new Uint8Array(9);
  b[0] = (field << 3) | 1;
  new DataView(b.buffer).setFloat64(1, v, true);
  return b;
}

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

/** DisplayInfo：x、y 是 sint32（H.1） */
function disp(x: number, y: number, w: number, h: number, extra: Uint8Array = new Uint8Array(0)): Uint8Array {
  return concat(fSint(1, x), fSint(2, y), fVarint(3, w), fVarint(4, h), extra);
}
const resolution = (w: number, h: number) => concat(fVarint(1, w), fVarint(2, h));

/** PeerInfo 本體（登入回應與執行中的 peer_info 共用） */
function peerInfoBody(displays: Uint8Array[], current = 0, extra: Uint8Array = new Uint8Array(0)): Uint8Array {
  return concat(fStr(2, "pc"), fStr(3, "Linux"), ...displays.map((d) => fMsg(4, d)), fVarint(5, current),
                fStr(7, "1.4.1"), extra);
}

/** SwitchDisplay { display (1), x (2), y (3), width (4), height (5), cursor_embedded (6), resolutions (7), original_resolution (8) } */
function switchDisplayMsg(display: number, x: number, y: number, w: number, h: number,
                          extra: Uint8Array = new Uint8Array(0)): Uint8Array {
  return encodeMessage("misc", fMsg(5, concat(fVarint(1, display), fSint(2, x), fSint(3, y), fVarint(4, w),
                                               fVarint(5, h), extra)));
}

function videoFrame(display: number, key = true): Uint8Array {
  const ef = concat(fBytes(1, new Uint8Array([7])), fVarint(2, key ? 1 : 0), fVarint(3, 1));
  return encodeMessage("video_frame", concat(fMsg(6, fMsg(1, ef)), fVarint(14, display)));
}

const TWO = [disp(0, 0, 1920, 1080), disp(1920, 0, 2560, 1440)];

interface Env {
  ws: FakeWs; s: RdSession; seal(m: Uint8Array): Uint8Array; closes: CloseInfo[];
  /** 控制端送出的每一則（索引同 ws.sentBin；密文只能依序解一次，所以集中在這裡解） */
  sent(): Decoded[];
  events: { kind: DisplayEventKind; view: DisplayView; removed?: number }[];
}

/** 走完握手、登入，收到登入回應（PeerInfo 本體由呼叫端給） */
async function connect(body: Uint8Array = peerInfoBody(TWO), opts: Partial<SessionOptions> = {},
                       events: SessionEvents = {}): Promise<Env> {
  const server = nacl.sign.keyPair();
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  const ws = new FakeWs();
  const closes: CloseInfo[] = [];
  const evs: Env["events"] = [];
  const s = new RdSession({
    url: "wss://x", peerId: PEER, myName: "alice (jt-ipam)", decoding: { vp9: true, h264: false, vp8: false, av1: false },
    password: "Pa55-word", ...opts,
    events: {
      ...events,
      displays: (view, kind, removed) => { evs.push({ kind, view, removed }); events.displays?.(view, kind, removed); },
      closed: (i) => { closes.push(i); events.closed?.(i); },
    },
    wsFactory: () => ws,
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
  const msgs: Decoded[] = [decodeMessage(ws.sentBin[0])];          // PublicKey 是明文
  const sent = () => {
    while (msgs.length < ws.sentBin.length) msgs.push(decodeMessage(rx.open(ws.sentBin[msgs.length])!));
    return msgs;
  };
  ws.bin(seal(encodeMessage("hash", concat(fStr(1, "aB3dE9"), fStr(2, "x7Kq2Z")))));
  await vi.waitFor(() => expect(ws.sentBin.length).toBeGreaterThanOrEqual(2), { timeout: 2000, interval: 5 });
  expect(sent()[1].kind).toBe("login_request");
  ws.bin(seal(encodeMessage("login_response", fMsg(2, body))));
  return { ws, s, seal, sent, closes, events: evs };
}

/** 從第 from 則開始，控制端送出的 Misc 的 oneof 欄位編號與內容 */
function sentMisc(env: Env, from: number): { field: number; body: Uint8Array | bigint }[] {
  return env.sent().slice(from).filter((m) => m.kind === "misc").map((m) => {
    const f = parse(m.body);
    const field = [...f.keys()][0];
    return { field, body: f.get(field)![0] };
  });
}

describe("H.3：滑鼠座標是整個虛擬桌面的絕對座標", () => {
  it("第二個螢幕（原點 x = 1920）要加上原點，否則點到的是主螢幕", () => {
    const d = { x: 1920, y: 0, width: 2560, height: 1440 };
    expect(mapPointer(0, 0, 1280, 720, d)).toEqual({ x: 1920, y: 0 });
    expect(mapPointer(640, 360, 1280, 720, d)).toEqual({ x: 1920 + 1280, y: 720 });
  });

  it("負原點（主螢幕左邊的螢幕）", () => {
    const d = { x: -1920, y: -200, width: 1920, height: 1080 };
    expect(mapPointer(0, 0, 960, 540, d)).toEqual({ x: -1920, y: -200 });
    expect(mapPointer(480, 270, 960, 540, d)).toEqual({ x: -960, y: 340 });
  });

  it("最大值是 x + width − 1、y + height − 1（每個平台都一樣：右邊緣再過去就是隔壁的螢幕）", () => {
    const d = { x: 0, y: 0, width: 1920, height: 1080 };
    expect(mapPointer(960, 540, 960, 540, d)).toEqual({ x: 1919, y: 1079 });
  });

  it("超出螢幕 5 像素以內貼齊邊緣，更遠的不送；左鍵放開例外（照送，貼齊邊緣）", () => {
    const d = { x: 100, y: 50, width: 1000, height: 500 };
    // 顯示成同樣大小，畫面上的 1 像素＝受控端 1 像素
    expect(mapPointer(-5, 0, 1000, 500, d)).toEqual({ x: 100, y: 50 });         // 左邊超出 5：貼齊
    expect(mapPointer(-6, 0, 1000, 500, d)).toBeNull();                         // 超出 6：不送
    expect(mapPointer(1004, 499, 1000, 500, d)).toEqual({ x: 1099, y: 549 });   // 最大值 1099，超出 5：貼齊
    expect(mapPointer(1005, 0, 1000, 500, d)).toBeNull();
    expect(mapPointer(10, 506, 1000, 500, d)).toBeNull();                       // 下面超出 7
    expect(mapPointer(-60, 900, 1000, 500, d, true)).toEqual({ x: 100, y: 549 });   // 左鍵放開：照送
  });

  it("macOS（scale > 1）：送螢幕的 x 加上像素位移，不自己除以 scale（受控端會除）", () => {
    // x、y 是邏輯點、寬高是像素：第二個 Retina 螢幕在邏輯座標 1440，2880×1800 像素
    const d = { x: 1440, y: 0, width: 2880, height: 1800 };
    expect(mapPointer(720, 450, 1440, 900, d)).toEqual({ x: 1440 + 1440, y: 900 });
  });

  it("遠端游標（附錄 E）也在同一個絕對空間：疊加層先減掉目前螢幕的原點；落在別的螢幕不畫", () => {
    const d = { x: 1920, y: 0, width: 2560, height: 1440 };
    expect(unmapPointer(1920 + 1280, 720, 1280, 720, d)).toEqual({ px: 640, py: 360 });
    expect(unmapPointer(1919, 720, 1280, 720, d)).toBeNull();            // 在主螢幕上
    expect(unmapPointer(1920 + 2560, 0, 1280, 720, d)).toBeNull();       // 右邊緣再過去
    const neg = { x: -1920, y: 0, width: 1920, height: 1080 };
    expect(unmapPointer(-960, 540, 960, 540, neg)).toEqual({ px: 480, py: 270 });
  });
});

describe("H.1：螢幕清單（訊息解析）", () => {
  it("DisplayInfo 的 online、original_resolution、scale；PeerInfo.resolutions", () => {
    const d = disp(-1920, 0, 1920, 1080, concat(fStr(5, "HDMI-1"), fVarint(6, 1), fMsg(8, resolution(3840, 2160)),
                                               fDouble(9, 2)));
    const info = parsePeerInfo(peerInfoBody([d], 0, fMsg(11, concat(fMsg(1, resolution(1920, 1080)),
                                                                    fMsg(1, resolution(1280, 720))))));
    expect(info.displays[0]).toMatchObject({ x: -1920, width: 1920, name: "HDMI-1", online: true, scale: 2,
                                             originalResolution: { width: 3840, height: 2160 } });
    expect(info.resolutions).toEqual([{ width: 1920, height: 1080 }, { width: 1280, height: 720 }]);
  });

  it("受控端回的 switch_display 帶新螢幕的位置、大小、解析度清單與原始解析度", () => {
    const m = decodeMessage(switchDisplayMsg(1, 1920, -10, 2560, 1440, concat(
      fMsg(7, concat(fMsg(1, resolution(2560, 1440)), fMsg(1, resolution(1920, 1080)))),
      fMsg(8, resolution(2560, 1440)))));
    expect(parseMisc(m.body)).toEqual({
      type: "switch_display", display: 1, x: 1920, y: -10, width: 2560, height: 1440, cursorEmbedded: false,
      resolutions: [{ width: 2560, height: 1440 }, { width: 1920, height: 1080 }],
      originalResolution: { width: 2560, height: 1440 },
    });
  });

  it("SwitchDisplay.resolutions 是 SupportedResolutions 包一層（規格 H.2 已確認）：只照這個讀，0×0 的項目不列", () => {
    const wrapped = decodeMessage(switchDisplayMsg(0, 0, 0, 1920, 1080, fMsg(7, concat(
      fMsg(1, resolution(1280, 720)), fMsg(1, resolution(0, 0))))));
    expect(parseMisc(wrapped.body)).toMatchObject({ resolutions: [{ width: 1280, height: 720 }] });
    // 直接放 repeated Resolution 不是規格的格式：不當成解析度清單
    const bare = decodeMessage(switchDisplayMsg(0, 0, 0, 1920, 1080, concat(
      fMsg(7, resolution(1280, 720)), fMsg(7, resolution(800, 600)))));
    expect(parseMisc(bare.body)).toMatchObject({ resolutions: [] });
  });

  it("current_display 超出清單範圍當成 0", () => {
    const v = viewFromPeerInfo(parsePeerInfo(peerInfoBody(TWO, 5)));
    expect(v?.primary).toBe(0);
    expect(v?.current).toBe(0);
    expect(viewFromPeerInfo(parsePeerInfo(peerInfoBody([], 0)))).toBeNull();
  });
});

describe("H.2：切換螢幕", () => {
  it("送出的三則訊息與順序：switch_display（只填 display）→ capture_displays set=[n] → refresh_video_display(n)", async () => {
    const env = await connect();
    const n = env.ws.sentBin.length;
    expect(env.s.switchDisplay(1)).toBe(true);
    const sent = sentMisc(env, n);
    expect(sent.map((m) => m.field)).toEqual([5, 30, 31]);
    const sd = parse(sent[0].body as Uint8Array);
    expect([...sd.keys()]).toEqual([1]);                 // width／height 填 0（不寫出），只有 display
    expect(sd.get(1)![0]).toBe(1n);
    const cap = parse(sent[1].body as Uint8Array);
    expect(getRepeatedInts(cap, 3)).toEqual([1]);       // set
    expect(cap.has(1) || cap.has(2)).toBe(false);       // 不用 add／sub
    expect(sent[2].body).toBe(1n);
    expect(last(env.events)).toMatchObject({ kind: "select", view: { current: 1, geometry: { x: 1920, width: 2560 } } });
  });

  it("切回 0 時三則都照樣寫出（0 在 oneof 裡也要有欄位）", () => {
    expect(decodeMessage(encodeSwitchDisplay(0)).body).toEqual(fMsg(5, new Uint8Array(0)));
    expect(getRepeatedInts(parse(parse(decodeMessage(encodeCaptureDisplays([0])).body).get(30)![0] as Uint8Array), 3))
      .toEqual([0]);
  });

  it("目標就是目前那個螢幕、或不存在：什麼都不送", async () => {
    const env = await connect();
    const n = env.ws.sentBin.length;
    expect(env.s.switchDisplay(0)).toBe(false);
    expect(env.s.switchDisplay(2)).toBe(false);
    expect(env.s.switchDisplay(-1)).toBe(false);
    expect(env.ws.sentBin.length).toBe(n);
  });

  it("8.3 要求關鍵影格改用 refresh_video_display，帶目前的螢幕編號", async () => {
    const env = await connect();
    env.s.switchDisplay(1);
    const n = env.ws.sentBin.length;
    env.s.requestKeyframe();
    expect(sentMisc(env, n)).toEqual([{ field: 31, body: 1n }]);
  });

  it("VideoFrame.display 不是目前螢幕的影格丟掉（切換的空檔還會有舊螢幕的幾張）", async () => {
    const video = vi.fn();
    const env = await connect(undefined, {}, { video });
    env.ws.bin(env.seal(videoFrame(0)));
    env.ws.bin(env.seal(videoFrame(1)));
    expect(video.mock.calls.map((c) => c[2])).toEqual([0]);
    env.s.switchDisplay(1);
    env.ws.bin(env.seal(videoFrame(0, false)));         // 舊螢幕還在路上的
    env.ws.bin(env.seal(switchDisplayMsg(1, 1920, 0, 2560, 1440)));
    env.ws.bin(env.seal(videoFrame(1)));
    expect(video.mock.calls.map((c) => c[2])).toEqual([0, 1]);
  });

  it("受控端回同一個編號的 switch_display＝切換完成：以回覆的位置、大小、解析度為準", async () => {
    const env = await connect();
    env.s.switchDisplay(1);
    env.ws.bin(env.seal(switchDisplayMsg(1, 1920, 0, 2560, 1440, fMsg(7, fMsg(1, resolution(1920, 1080))))));
    expect(last(env.events)).toMatchObject({
      kind: "switch", view: { current: 1, geometry: { x: 1920, y: 0, width: 2560, height: 1440 },
                              resolutions: [{ width: 1920, height: 1080 }] },
    });
  });

  it("單一螢幕的大小改變（同一個編號、新的大小）不當成切換：只更新大小與座標換算，不送任何東西", async () => {
    const env = await connect();
    const n = env.ws.sentBin.length;
    env.ws.bin(env.seal(switchDisplayMsg(0, 0, 0, 1280, 720)));
    expect(last(env.events)).toMatchObject({ kind: "resize", view: { current: 0, geometry: { width: 1280, height: 720 } } });
    expect(env.events.some((e) => e.kind === "switch" || e.kind === "select")).toBe(false);
    expect(env.ws.sentBin.length).toBe(n);
    expect(env.s.displayView?.list[0].width).toBe(1280);   // 選單上的大小也跟著改
  });

  it("受控端要求跟著切（follow_current_display，Misc 38）：不理會", async () => {
    const env = await connect();
    const n = env.events.length;
    env.ws.bin(env.seal(encodeMessage("misc", fVarint(38, 1))));
    expect(env.events).toHaveLength(n);
    expect(env.s.displayView?.current).toBe(0);
    expect(env.closes).toHaveLength(0);
  });
});

describe("H.1：連線中的 peer_info", () => {
  it("只更新螢幕清單；它的 current_display 一律是 0，不拿來當目前螢幕", async () => {
    const env = await connect();
    env.s.switchDisplay(1);
    env.ws.bin(env.seal(switchDisplayMsg(1, 1920, 0, 2560, 1440)));
    const three = [...TWO, disp(4480, 0, 1280, 1024)];
    env.ws.bin(env.seal(encodeMessage("peer_info", concat(...three.map((d) => fMsg(4, d)), fVarint(5, 0)))));
    expect(last(env.events)).toMatchObject({ kind: "update", view: { current: 1, primary: 0 } });
    expect(last(env.events).view.list).toHaveLength(3);
    expect(env.s.peerInfo?.platform).toBe("Linux");     // 平台以登入回應為準（附錄 C-4）
  });

  it("目前選的螢幕被拔除：切到主螢幕（登入時的 current_display），照 H.2 送三則，事件帶被拔除的編號", async () => {
    const three = [...TWO, disp(4480, 0, 1280, 1024)];
    const env = await connect(peerInfoBody(three, 1));           // 主螢幕是 1
    env.s.switchDisplay(2);
    env.ws.bin(env.seal(switchDisplayMsg(2, 4480, 0, 1280, 1024)));
    const n = env.ws.sentBin.length;
    env.ws.bin(env.seal(encodeMessage("peer_info", concat(...TWO.map((d) => fMsg(4, d))))));
    expect(sentMisc(env, n).map((m) => [m.field, typeof m.body === "bigint" ? m.body : null]))
      .toEqual([[5, null], [30, null], [31, 1n]]);
    expect(last(env.events)).toMatchObject({ kind: "removed", removed: 2, view: { current: 1 } });
  });

  it("主螢幕也不在了：切到 0", async () => {
    const env = await connect(peerInfoBody(TWO, 1));
    const n = env.ws.sentBin.length;
    env.ws.bin(env.seal(encodeMessage("peer_info", fMsg(4, disp(0, 0, 1920, 1080)))));
    expect(sentMisc(env, n).map((m) => m.field)).toEqual([5, 30, 31]);
    expect(last(env.events)).toMatchObject({ kind: "removed", removed: 1, view: { current: 0 } });
  });

  it("空的螢幕清單不採用", async () => {
    const env = await connect();
    const n = env.events.length;
    env.ws.bin(env.seal(encodeMessage("peer_info", fStr(12, "{}"))));
    expect(env.events).toHaveLength(n);
    expect(env.s.displayView?.list).toHaveLength(2);
  });
});

describe("H.1：登入", () => {
  it("清單是空的：顯示「沒有螢幕」並結束（不當成已連線）", async () => {
    const connected = vi.fn();
    const env = await connect(peerInfoBody([]), {}, { connected });
    expect(connected).not.toHaveBeenCalled();
    expect(env.closes[0]).toMatchObject({ code: "rd_no_display" });
    expect(sentMisc(env, 2).map((m) => m.field)).toContain(9);    // 結束前送 close_reason
  });

  it("登入成功後送一次 login 事件，主螢幕＝current_display", async () => {
    const env = await connect(peerInfoBody(TWO, 1));
    expect(env.events[0]).toMatchObject({ kind: "login", view: { primary: 1, current: 1, geometry: { x: 1920 } } });
  });
});

describe("H.5：自動重連回到使用者原本選的螢幕", () => {
  it("SessionOptions.display 存在而且不是主螢幕：登入後照 H.2 切過去", async () => {
    const env = await connect(undefined, { display: 1 });
    expect(sentMisc(env, 2).map((m) => m.field)).toEqual([5, 30, 31]);
    expect(env.s.displayView?.current).toBe(1);
  });

  it("那個螢幕已經不在、或就是主螢幕：不送", async () => {
    for (const display of [5, 0]) {
      const env = await connect(undefined, { display });
      expect(sentMisc(env, 2)).toEqual([]);
    }
  });

  it("要先選 Windows 工作階段時（G.6），選好之後才切", async () => {
    const ws = fMsg(13, concat(fMsg(1, concat(fVarint(1, 1), fStr(2, "Console"))),
                               fMsg(1, concat(fVarint(1, 2), fStr(2, "RDP"))), fVarint(2, 1)));
    const env = await connect(peerInfoBody(TWO, 0, ws), { display: 1 });
    expect(sentMisc(env, 2)).toEqual([]);
    env.s.selectWindowsSession(1);
    expect(sentMisc(env, 2).map((m) => m.field)).toEqual([35, 5, 30, 31]);
  });
});

describe("H.4：改受控端解析度", () => {
  it("Misc.change_display_resolution { display, resolution { width, height } }", async () => {
    const env = await connect();
    env.s.switchDisplay(1);
    const n = env.ws.sentBin.length;
    expect(env.s.changeResolution({ width: 1920, height: 1080 })).toBe(true);
    const [m] = sentMisc(env, n);
    expect(m.field).toBe(36);
    const f = parse(m.body as Uint8Array);
    expect(f.get(1)![0]).toBe(1n);
    const r = parse(f.get(2)![0] as Uint8Array);
    expect([r.get(1)![0], r.get(2)![0]]).toEqual([1920n, 1080n]);
    expect(decodeMessage(encodeChangeResolution(1, { width: 1920, height: 1080 })).body).toEqual(env.sent()[n].body);
  });

  it("唯讀檢視、對方關閉控制權、尺寸不合理時不送", async () => {
    const ro = await connect(undefined, { viewOnly: true });
    const n = ro.ws.sentBin.length;
    expect(ro.s.changeResolution({ width: 1920, height: 1080 })).toBe(false);
    expect(ro.ws.sentBin.length).toBe(n);
    const env = await connect();
    expect(env.s.changeResolution({ width: 0, height: 1080 })).toBe(false);
    env.ws.bin(env.seal(encodeMessage("misc", fMsg(6, fVarint(2, 0)))));     // Keyboard 權限關閉
    expect(env.s.changeResolution({ width: 1920, height: 1080 })).toBe(false);
  });
});

describe("DisplayTracker（純邏輯）", () => {
  const info = (displays: Uint8Array[], current = 0) => parsePeerInfo(peerInfoBody(displays, current));
  const sw = (display: number, w: number, h: number) => ({
    display, x: 0, y: 0, width: w, height: h, cursorEmbedded: false, resolutions: [],
    originalResolution: { width: 0, height: 0 },
  });

  it("連續切換時前一次的回覆（不是目前的螢幕）不採用", () => {
    const t = new DisplayTracker();
    t.login(info([...TWO, disp(4480, 0, 800, 600)]));
    t.select(1);
    t.select(2);
    expect(t.onSwitch({ ...sw(1, 2560, 1440), x: 1920 })).toBe("stale");
    expect(t.view().geometry.x).toBe(4480);
    expect(t.onSwitch({ ...sw(2, 800, 600), x: 4480 })).toBe("switch");
  });

  it("切出去又在回覆前切回原本的螢幕：回覆仍算切換完成，不是大小改變", () => {
    const t = new DisplayTracker();
    t.login(info(TWO));
    t.select(1);
    t.select(0);
    expect(t.onSwitch(sw(0, 1920, 1080))).toBe("switch");
    expect(t.onSwitch(sw(0, 1280, 720))).toBe("resize");
  });

  it("回覆沒帶原始解析度：沿用清單裡的（不要因此變成「虛擬螢幕」）", () => {
    const t = new DisplayTracker();
    t.login(info([disp(0, 0, 1920, 1080, fMsg(8, resolution(3840, 2160)))]));
    t.onSwitch(sw(0, 1280, 720));
    expect(t.view().originalResolution).toEqual({ width: 3840, height: 2160 });
  });
});
