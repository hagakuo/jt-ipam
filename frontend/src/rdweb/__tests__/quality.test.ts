/**
 * 畫質、更新率與編碼（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 I，I.3 的單元測試清單）：
 * - custom_image_quality 的位元編碼
 * - 各選項送出的 Misc.option 內容（執行中只帶改變的欄位）
 * - 登入時帶入目前設定
 * - 編碼選單只列兩邊都支援的；supported_decoding 的能力照實填
 * - 換編碼時重建解碼器
 * 另外：localStorage 只存三個選項、讀寫失敗不丟例外；TestDelay 的延遲與位元率；每秒解出的張數。
 * 模擬受控端的作法與 session.test.ts 相同（各自一份，互不相依）。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { concat, fBytes, fMsg, fStr, fVarint, parse, type Fields } from "../pb";
import { SecretBoxStream } from "../crypto";
import {
  decodeMessage, encodeLoginRequest, encodeMessage, ImageQuality, parseMisc, parsePeerInfo, PreferCodec,
  type Decoded, type Decoding,
} from "../messages";
import { RdSession, type CloseInfo, type SessionEvents, type SessionOptions, type WebSocketLike } from "../session";
import {
  codecChoices, codecLabel, customImageQualityValue, DEFAULT_QUALITY, FpsMeter, loadQuality, loadShowStats,
  QUALITY_STORAGE_KEY, saveQuality, saveShowStats, SHOW_STATS_STORAGE_KEY, toQualityOption, type QualitySettings,
} from "../quality";
import { VideoPipeline, type VideoSink } from "../video";

const PEER = "123456789";
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const ALL: Decoding = { vp9: true, h264: true, vp8: true, av1: true };
const VP9_ONLY: Decoding = { vp9: true, h264: false, vp8: false, av1: false };
const q = (over: Partial<QualitySettings> = {}): QualitySettings => ({ ...DEFAULT_QUALITY, ...over });

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

interface Env {
  ws: FakeWs; s: RdSession; seal(m: Uint8Array): Uint8Array; open(c: Uint8Array): Decoded; closes: CloseInfo[];
  /** 第一個 LoginRequest 的 option（OptionMessage） */
  loginOption: Fields;
}

/** 走完握手並送出 LoginRequest；connected=true 時再收到登入回應（peerInfoExtra 加在 PeerInfo 裡） */
async function start(opts: Partial<SessionOptions> = {}, events: SessionEvents = {}, connected = true,
                     peerInfoExtra: Uint8Array = new Uint8Array(0)): Promise<Env> {
  const server = nacl.sign.keyPair();
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  const ws = new FakeWs();
  const closes: CloseInfo[] = [];
  const s = new RdSession({
    url: "wss://x", peerId: PEER, myName: "alice (jt-ipam)", decoding: VP9_ONLY, password: "Pa55-word", ...opts,
    events: { ...events, closed: (i) => { closes.push(i); events.closed?.(i); } }, wsFactory: () => ws,
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
  await vi.waitFor(() => expect(ws.sentBin.length).toBeGreaterThanOrEqual(2), { timeout: 2000, interval: 5 });
  const login = open(ws.sentBin[1]);
  expect(login.kind).toBe("login_request");
  const loginOption = parse(parse(login.body).get(6)![0] as Uint8Array);
  if (connected) {
    const disp = concat(fVarint(3, 1280), fVarint(4, 800));
    ws.bin(seal(encodeMessage("login_response", fMsg(2, concat(fStr(3, "Linux"), fMsg(4, disp), fStr(7, "1.4.1"),
                                                               peerInfoExtra)))));
  }
  return { ws, s, seal, open, closes, loginOption };
}

/** 控制端最後送出的 Misc.option（OptionMessage 的欄位） */
function lastOption(env: Env): Fields | null {
  const m = env.open(env.ws.sentBin[env.ws.sentBin.length - 1]);
  if (m.kind !== "misc") return null;
  const f = parse(m.body);
  return f.has(7) ? parse(f.get(7)![0] as Uint8Array) : null;
}

const fieldsOf = (f: Fields | null) => (f ? [...f.keys()].sort((a, b) => a - b) : []);

describe("I.1：custom_image_quality 的位元編碼", () => {
  it("數值左移 8 位元（50 → 50 << 8）；範圍 10～100", () => {
    expect(customImageQualityValue(50)).toBe(50 << 8);
    expect(customImageQualityValue(50)).toBe(12800);
    expect(customImageQualityValue(10)).toBe(2560);
    expect(customImageQualityValue(100)).toBe(25600);
    expect(customImageQualityValue(3)).toBe(10 << 8);        // 夾在 10～100
    expect(customImageQualityValue(500)).toBe(100 << 8);
    expect(customImageQualityValue(49.6)).toBe(50 << 8);
  });

  it("自訂時 image_quality 填 NotSet、custom_image_quality 填左移後的值；其他畫質不帶自訂", () => {
    expect(toQualityOption(q({ level: "custom", custom: 70 }), ALL)).toMatchObject(
      { imageQuality: ImageQuality.NotSet, customImageQuality: 70 << 8 });
    expect(toQualityOption(q({ level: "low", custom: 70 }), ALL)).toMatchObject(
      { imageQuality: ImageQuality.Low, customImageQuality: 0 });
    expect(toQualityOption(q({ level: "best" }), ALL).imageQuality).toBe(4);
    expect(toQualityOption(q(), ALL).imageQuality).toBe(3);
  });
});

describe("I.1：各選項送出的 Misc.option（執行中只帶改變的欄位）", () => {
  it("畫質：低 → image_quality 2、最佳 → 4、平衡 → 3", async () => {
    const env = await start({ quality: toQualityOption(q(), VP9_ONLY) });
    for (const [level, v] of [["low", 2n], ["best", 4n], ["balanced", 3n]] as const) {
      expect(env.s.setQuality(toQualityOption(q({ level }), VP9_ONLY))).toBe(true);
      const o = lastOption(env)!;
      expect(fieldsOf(o)).toEqual([1]);
      expect(o.get(1)![0]).toBe(v);
    }
  });

  it("自訂：只送 custom_image_quality（左移後的值），image_quality 是 NotSet（不寫出）；改數值再送一次", async () => {
    const env = await start({ quality: toQualityOption(q({ level: "low" }), VP9_ONLY) });
    env.s.setQuality(toQualityOption(q({ level: "custom", custom: 50 }), VP9_ONLY));
    let o = lastOption(env)!;
    expect(fieldsOf(o)).toEqual([6]);
    expect(o.get(6)![0]).toBe(BigInt(50 << 8));
    env.s.setQuality(toQualityOption(q({ level: "custom", custom: 80 }), VP9_ONLY));
    o = lastOption(env)!;
    expect(o.get(6)![0]).toBe(BigInt(80 << 8));
  });

  it("更新率上限：只送 custom_fps", async () => {
    const env = await start({ quality: toQualityOption(q(), VP9_ONLY) });
    env.s.setQuality(toQualityOption(q({ fps: 60 }), VP9_ONLY));
    const o = lastOption(env)!;
    expect(fieldsOf(o)).toEqual([11]);
    expect(o.get(11)![0]).toBe(60n);
  });

  it("編碼偏好：只送新的 supported_decoding（改 prefer，能力欄位照實填）", async () => {
    const dec: Decoding = { vp9: true, h264: true, vp8: false, av1: true };
    const env = await start({ decoding: dec, quality: toQualityOption(q(), dec) });
    env.s.setQuality(toQualityOption(q({ codec: "av1" }), dec));
    const o = lastOption(env)!;
    expect(fieldsOf(o)).toEqual([10]);
    const sd = parse(o.get(10)![0] as Uint8Array);
    expect(sd.get(4)![0]).toBe(BigInt(PreferCodec.AV1));
    expect(sd.get(1)![0]).toBe(1n);          // ability_vp9
    expect(sd.get(2)![0]).toBe(1n);          // ability_h264：解得了
    expect(sd.has(3)).toBe(false);           // ability_h265：解不了，填 0
    expect(sd.has(5)).toBe(false);           // ability_vp8：解不了，填 0
    expect(sd.get(6)![0]).toBe(1n);          // ability_av1
  });

  it("沒有改變就不送；登入前改只記下來（登入時帶入）", async () => {
    const env = await start({ quality: toQualityOption(q({ level: "low", fps: 60 }), VP9_ONLY) });
    const n = env.ws.sentBin.length;
    expect(env.s.setQuality(toQualityOption(q({ level: "low", fps: 60 }), VP9_ONLY))).toBe(false);
    expect(env.ws.sentBin.length).toBe(n);
    const pre = await start({ quality: toQualityOption(q(), VP9_ONLY) }, {}, false);
    expect(pre.s.setQuality(toQualityOption(q({ level: "best" }), VP9_ONLY))).toBe(false);
  });

  it("使用者再選一次目前的畫質（例如登入時沒送的平衡）：照樣送出（受控端目前可能是別人設的畫質）", async () => {
    const env = await start({ quality: toQualityOption(q(), VP9_ONLY) });
    expect(env.s.setQuality(toQualityOption(q(), VP9_ONLY), ["imageQuality"])).toBe(true);
    const o = lastOption(env)!;
    expect(fieldsOf(o)).toEqual([1]);
    expect(o.get(1)![0]).toBe(3n);
    // 改的是別的選項：畫質不跟著送（不去蓋掉別人設的畫質）
    env.s.setQuality(toQualityOption(q({ fps: 15 }), VP9_ONLY), ["customFps"]);
    expect(fieldsOf(lastOption(env))).toEqual([11]);
  });
});

describe("I.2：登入時帶入目前的設定（LoginRequest.option）", () => {
  it("低畫質、60 fps、偏好 H.264", async () => {
    const dec: Decoding = { vp9: true, h264: true, vp8: false, av1: false };
    const env = await start({ decoding: dec, quality: toQualityOption(q({ level: "low", fps: 60, codec: "h264" }), dec) },
                            {}, false);
    expect(env.loginOption.get(1)![0]).toBe(2n);
    expect(env.loginOption.get(11)![0]).toBe(60n);
    expect(env.loginOption.has(6)).toBe(false);
    expect(parse(env.loginOption.get(10)![0] as Uint8Array).get(4)![0]).toBe(BigInt(PreferCodec.H264));
    expect(env.loginOption.get(3)![0]).toBe(2n);         // 其他選項照舊（show_remote_cursor）
  });

  it("自訂畫質：custom_image_quality，image_quality 不寫出", async () => {
    const env = await start({ quality: toQualityOption(q({ level: "custom", custom: 30 }), VP9_ONLY) }, {}, false);
    expect(env.loginOption.has(1)).toBe(false);
    expect(env.loginOption.get(6)![0]).toBe(BigInt(30 << 8));
  });

  it("平衡（預設）登入時不送 image_quality（官方客戶端也不送）；更新率照送；偏好「自動」", async () => {
    const env = await start({ quality: toQualityOption(q(), VP9_ONLY) }, {}, false);
    expect(env.loginOption.has(1)).toBe(false);
    expect(env.loginOption.get(11)![0]).toBe(30n);
    const sd = parse(env.loginOption.get(10)![0] as Uint8Array);
    expect(sd.has(4)).toBe(false);                        // prefer = Auto（0）
    expect(sd.get(1)![0]).toBe(1n);
  });

  it("偏好的編碼瀏覽器解不了：改成自動", () => {
    expect(toQualityOption(q({ codec: "h264" }), VP9_ONLY).prefer).toBe(PreferCodec.Auto);
    expect(toQualityOption(q({ codec: "vp9" }), VP9_ONLY).prefer).toBe(PreferCodec.VP9);
  });

  it("沒給設定：第一階段的行為（偏好 VP9，不帶畫質欄位）", () => {
    const m = decodeMessage(encodeLoginRequest({
      peerId: PEER, password: new Uint8Array(0), myId: "jt-ipam", myName: "a", sessionId: 1n, version: "1.4.1",
      decoding: VP9_ONLY,
    }));
    const opt = parse(parse(m.body).get(6)![0] as Uint8Array);
    expect(opt.has(1) || opt.has(6) || opt.has(11)).toBe(false);
    expect(parse(opt.get(10)![0] as Uint8Array).get(4)![0]).toBe(1n);
  });
});

describe("I.2：編碼選單只列兩邊都支援的", () => {
  it("瀏覽器解得了、受控端也編得出來才列；自動與 VP9 一定在", () => {
    const enc = { h264: true, h265: true, vp8: true, av1: false };
    expect(codecChoices({ vp9: true, h264: true, vp8: true, av1: true }, enc)).toEqual(["auto", "vp9", "h264"]);
    expect(codecChoices({ vp9: true, h264: false, vp8: true, av1: true }, enc)).toEqual(["auto", "vp9"]);
    expect(codecChoices(ALL, { h264: false, h265: false, vp8: false, av1: true })).toEqual(["auto", "vp9", "av1"]);
    expect(codecChoices(ALL, null)).toEqual(["auto", "vp9"]);         // 沒帶 encoding：只有 VP9
  });

  it("受控端編不出來時偏好改成自動", () => {
    expect(toQualityOption(q({ codec: "av1" }), ALL, { h264: true, h265: false, vp8: false, av1: false }).prefer)
      .toBe(PreferCodec.Auto);
  });

  it("PeerInfo.encoding 與 Misc.supported_encoding 的解析", async () => {
    const info = parsePeerInfo(concat(fStr(3, "Linux"), fMsg(10, concat(fVarint(1, 1), fVarint(4, 1)))));
    expect(info.encoding).toEqual({ h264: true, h265: false, vp8: false, av1: true });
    expect(parsePeerInfo(fStr(3, "Linux")).encoding).toBeNull();
    const misc = parseMisc(fMsg(34, fVarint(3, 1)));
    expect(misc).toEqual({ type: "supported_encoding", encoding: { h264: false, h265: false, vp8: true, av1: false } });
    const encoding = vi.fn();
    const env = await start({}, { encoding });
    env.ws.bin(env.seal(encodeMessage("misc", fMsg(34, fVarint(1, 1)))));
    expect(encoding).toHaveBeenCalledWith({ h264: true, h265: false, vp8: false, av1: false });
  });
});

describe("I.1：TestDelay 的延遲與位元率", () => {
  it("受控端送的 TestDelay 照舊原封不動送回，並把 last_delay、target_bitrate 交給畫面", async () => {
    const delay = vi.fn();
    const env = await start({}, { delay });
    const td = encodeMessage("test_delay", concat(fVarint(1, 1759000000000), fVarint(3, 23), fVarint(4, 2073)));
    const n = env.ws.sentBin.length;
    env.ws.bin(env.seal(td));
    expect(delay).toHaveBeenCalledWith({ lastDelay: 23, targetBitrate: 2073 });
    expect(env.ws.sentBin.length).toBe(n + 1);
  });
});

describe("I.2：設定記在 localStorage（只存三個選項）", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  it("只寫一個鍵，內容只有畫質（含自訂數值）、更新率、編碼偏好；讀回來一樣", () => {
    expect(saveQuality(q({ level: "custom", custom: 70, fps: 60, codec: "av1" }))).toBe(true);
    expect(localStorage.length).toBe(1);
    expect(Object.keys(JSON.parse(localStorage.getItem(QUALITY_STORAGE_KEY)!)).sort())
      .toEqual(["codec", "custom", "fps", "level"]);
    expect(loadQuality()).toEqual({ level: "custom", custom: 70, fps: 60, codec: "av1" });
  });

  it("沒有、壞掉、值不合法：用預設值", () => {
    expect(loadQuality()).toEqual(DEFAULT_QUALITY);
    localStorage.setItem(QUALITY_STORAGE_KEY, "{not json");
    expect(loadQuality()).toEqual(DEFAULT_QUALITY);
    localStorage.setItem(QUALITY_STORAGE_KEY, JSON.stringify({ level: "ultra", custom: 999, fps: 25, codec: "h265" }));
    expect(loadQuality()).toEqual({ ...DEFAULT_QUALITY, custom: 100 });
  });

  it("儲存空間不能用（私密視窗、封鎖網站資料）：不丟例外，不影響連線", () => {
    const broken = {
      getItem: () => { throw new Error("SecurityError"); },
      setItem: () => { throw new Error("QuotaExceededError"); },
    } as unknown as Storage;
    expect(loadQuality(broken)).toEqual(DEFAULT_QUALITY);
    expect(saveQuality(q(), broken)).toBe(false);
    expect(loadQuality(null)).toEqual(DEFAULT_QUALITY);
    expect(saveQuality(q(), null)).toBe(false);
  });
});

describe("效能列（延遲、位元率…）預設不顯示，畫質選單勾了才顯示（使用者 2026-10-06）", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  it("沒設定過：不顯示", () => {
    expect(loadShowStats()).toBe(false);
  });

  it("勾了記住、取消也記住；跟畫質選項分開存，不動畫質那個鍵", () => {
    expect(saveShowStats(true)).toBe(true);
    expect(loadShowStats()).toBe(true);
    expect(localStorage.getItem(QUALITY_STORAGE_KEY)).toBeNull();
    expect(saveShowStats(false)).toBe(true);
    expect(loadShowStats()).toBe(false);
    expect(localStorage.getItem(SHOW_STATS_STORAGE_KEY)).toBe("0");
  });

  it("壞掉的值與不能用的儲存空間：當作不顯示，不丟例外", () => {
    localStorage.setItem(SHOW_STATS_STORAGE_KEY, "yes please");
    expect(loadShowStats()).toBe(false);
    const broken = {
      getItem: () => { throw new Error("SecurityError"); },
      setItem: () => { throw new Error("QuotaExceededError"); },
    } as unknown as Storage;
    expect(loadShowStats(broken)).toBe(false);
    expect(saveShowStats(true, broken)).toBe(false);
    expect(loadShowStats(null)).toBe(false);
  });
});

describe("I.2：狀態列", () => {
  it("每秒解出的張數：第一次只記起點，之後是這段期間的每秒張數", () => {
    const m = new FpsMeter();
    expect(m.sample(0, 0)).toBeNull();
    expect(m.sample(30, 1000)).toBe(30);
    expect(m.sample(45, 2000)).toBe(15);
    expect(m.sample(5, 3000)).toBeNull();        // 換了一條新的解碼管線（累計數變小）
    expect(m.sample(65, 5000)).toBe(30);
  });

  it("編碼名稱", () => {
    expect([codecLabel("vp9"), codecLabel("h264"), codecLabel("av1"), codecLabel(null)]).toEqual(["VP9", "H.264", "AV1", ""]);
  });
});

describe("I.1：換編碼時重建解碼器", () => {
  class FakeDecoder {
    static instances: FakeDecoder[] = [];
    state = "unconfigured";
    decodeQueueSize = 0;
    config: { codec: string } | null = null;
    chunks: { type: string }[] = [];
    constructor(public init: { output: (f: unknown) => void; error: (e: unknown) => void }) {
      FakeDecoder.instances.push(this);
    }
    configure(c: { codec: string }) { this.config = c; this.state = "configured"; }
    decode(chunk: { type: string }) { this.chunks.push(chunk); }
    close() { this.state = "closed"; }
  }
  class FakeChunk {
    type: string;
    constructor(init: { type: string }) { this.type = init.type; }
  }
  beforeEach(() => {
    FakeDecoder.instances = [];
    vi.stubGlobal("VideoDecoder", FakeDecoder);
    vi.stubGlobal("EncodedVideoChunk", FakeChunk);
  });
  afterEach(() => vi.unstubAllGlobals());
  const f = (key: boolean) => ({ data: new Uint8Array([1]), key, pts: 1n });

  it("影格的編碼跟目前的解碼器不同：關掉舊的、照新編碼 configure，從新編碼的關鍵影格開始解", () => {
    const sink = { frame: vi.fn(), requestKeyframe: vi.fn(), unsupported: vi.fn() };
    const p = new VideoPipeline(sink as unknown as VideoSink, () => 0);
    p.push("vp9", [f(true), f(false)]);
    expect(p.currentCodec).toBe("vp9");
    p.push("h264", [f(true), f(false)]);                // 受控端重新協商，下一張是新編碼的關鍵影格
    expect(FakeDecoder.instances).toHaveLength(2);
    expect(FakeDecoder.instances[0].state).toBe("closed");
    expect(FakeDecoder.instances[1].config?.codec).toBe("avc1.42E01E");
    expect(FakeDecoder.instances[1].chunks.map((c) => c.type)).toEqual(["key", "delta"]);
    expect(p.currentCodec).toBe("h264");
    expect(sink.unsupported).not.toHaveBeenCalled();
  });

  it("等關鍵影格但不再要求一次（切換螢幕時已經送過 refresh_video_display）", () => {
    const sink = { frame: vi.fn(), requestKeyframe: vi.fn(), unsupported: vi.fn() };
    const p = new VideoPipeline(sink as unknown as VideoSink, () => 0);
    p.push("vp9", [f(true)]);
    sink.requestKeyframe.mockClear();
    p.waitForKeyframe(false);
    expect(sink.requestKeyframe).not.toHaveBeenCalled();
    p.push("vp9", [f(true)]);
    expect(FakeDecoder.instances[0].chunks).toHaveLength(2);
  });
});
