/**
 * 相容 RustDesk 的網頁連線：protobuf、加密、密碼雜湊、輸入、按鍵代碼。
 * 測試向量全部取自 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md（附錄 B 與內文）。
 */
import { describe, expect, it } from "vitest";
import nacl from "tweetnacl";
import {
  concat, fBytes, fMsg, fPacked, fSint, fStr, fVarint, getRepeatedInts, getSint, getStr, parse, varint, zigzag,
} from "../pb";
import { nonceFor, openSigned, passwordHash, passwordHash1, SecretBoxStream, keyExchangeV0 } from "../crypto";
import {
  decodeMessage, encodeCloseReason, encodeCtrlAltDel, encodeKeyMap, encodeLoginRequest, encodeMouseEvent,
  encodeRefreshVideo, parseMisc, parsePeerInfo, parseVideoFrame, versionAtLeast,
} from "../messages";
import { mapPointer, mouseMask, MouseButton, MouseKind, WheelAccumulator, domButton } from "../input";
import { keyCodeFor, lockModifiers } from "../keymap";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("protobuf（第 3 節）", () => {
  it("zigzag：−1 → 1、100 → 200、−1920 → 3839", () => {
    expect(zigzag(-1)).toBe(1);
    expect(zigzag(100)).toBe(200);
    expect(zigzag(-1920)).toBe(3839);
  });

  it("sint32 欄位用 zigzag 編，解得回來", () => {
    const f = parse(concat(fSint(2, -1920), fSint(3, 100)));
    expect(getSint(f, 2)).toBe(-1920);
    expect(getSint(f, 3)).toBe(100);
  });

  it("int32 的負值是 10 bytes 的 varint", () => {
    expect(varint(-1).length).toBe(10);
  });

  it("repeated 數值送出用 packed，解碼 packed 與逐個都收", () => {
    const packed = fPacked(4, [1, 4]);
    expect(packed[0]).toBe((4 << 3) | 2);
    expect(getRepeatedInts(parse(packed), 4)).toEqual([1, 4]);
    const unpacked = concat(fVarint(4, 1), fVarint(4, 4));
    expect(getRepeatedInts(parse(unpacked), 4)).toEqual([1, 4]);
  });

  it("值全是預設值的 Message 是 0 bytes；oneof 的空子訊息算有這個欄位", () => {
    expect(fVarint(1, 0).length).toBe(0);
    expect(fStr(1, "").length).toBe(0);
    const m = decodeMessage(fMsg(25, new Uint8Array(0)));   // peer_info = {}
    expect(m.kind).toBe("peer_info");
    expect(m.body.length).toBe(0);
  });

  it("未知欄位忽略", () => {
    const f = parse(concat(fStr(1, "a"), fStr(99, "future"), fVarint(77, 5)));
    expect(getStr(f, 1)).toBe("a");
  });
});

describe("secretbox 的 nonce 與計數器（6.4）", () => {
  it("計數 1 與 258 的 nonce", () => {
    expect(hex(nonceFor(1n))).toBe("010000000000000000000000000000000000000000000000");
    expect(hex(nonceFor(258n))).toBe("020100000000000000000000000000000000000000000000");
  });

  it("兩邊的第一則密文都用計數 1；密文長度是明文加 16", () => {
    const key = nacl.randomBytes(32);
    const a = new SecretBoxStream(key);
    const b = new SecretBoxStream(key);
    const c1 = a.seal(new Uint8Array([1, 2, 3]));
    expect(c1.length).toBe(19);
    expect(nacl.secretbox.open(c1, nonceFor(1n), key)).toEqual(new Uint8Array([1, 2, 3]));
    expect(b.open(c1)).toEqual(new Uint8Array([1, 2, 3]));
    const c2 = a.seal(new Uint8Array([4]));
    expect(b.open(c2)).toEqual(new Uint8Array([4]));
  });

  it("MAC 不符解不開", () => {
    const key = nacl.randomBytes(32);
    const c = new SecretBoxStream(key).seal(new Uint8Array([9, 9]));
    c[c.length - 1] ^= 1;
    expect(new SecretBoxStream(key).open(c)).toBeNull();
  });
});

describe("金鑰交換 v0（6.3）", () => {
  it("box 的輸出 48 bytes，受控端用自己的私鑰打得開", () => {
    const peer = nacl.box.keyPair();
    const kx = keyExchangeV0(peer.publicKey);
    expect(kx.sealed.length).toBe(48);
    const opened = nacl.box.open(kx.sealed, new Uint8Array(24), kx.ourPk, peer.secretKey);
    expect(opened).toEqual(kx.key);
  });

  it("簽章附訊息：驗得過才拿得到訊息", () => {
    const kp = nacl.sign.keyPair();
    const signed = nacl.sign(new Uint8Array([1, 2, 3]), kp.secretKey);
    expect(openSigned(signed, kp.publicKey)).toEqual(new Uint8Array([1, 2, 3]));
    expect(openSigned(signed, nacl.sign.keyPair().publicKey)).toBeNull();
  });
});

describe("密碼雜湊（7.2）", () => {
  it("Pa55-word / aB3dE9 / x7Kq2Z", async () => {
    expect(hex(await passwordHash1("Pa55-word", "aB3dE9")))
      .toBe("785d9695403b00957cd9fa07b849b520b62d407a8a4acce6d34220aa04af4c32");
    expect(hex(await passwordHash("Pa55-word", "aB3dE9", "x7Kq2Z")))
      .toBe("78b83fce809b76e7359978565022d729350f6e725f68f65e85448190884bb03f");
  });

  it("中文密碼（UTF-8）", async () => {
    expect(hex(await passwordHash("密碼123", "aB3dE9", "x7Kq2Z")))
      .toBe("a000b7305dbdbd8e350228a7c62ee7e1d65c56efe365cb60bad82ec7f56b2925");
  });
});

describe("LoginRequest（7.3、7.4）", () => {
  it("欄位照規格，password 是 32 個原始位元組", () => {
    const pw = new Uint8Array(32).fill(7);
    const m = decodeMessage(encodeLoginRequest({
      peerId: "123456789", password: pw, myId: "jt-ipam", myName: "alice (jt-ipam)", sessionId: 42n,
      version: "1.4.1", decoding: { vp9: true, h264: true, vp8: false, av1: false },
    }));
    expect(m.kind).toBe("login_request");
    const f = parse(m.body);
    expect(getStr(f, 1)).toBe("123456789");
    expect(f.get(2)![0]).toEqual(pw);
    expect(getStr(f, 4)).toBe("jt-ipam");
    expect(getStr(f, 5)).toBe("alice (jt-ipam)");
    expect(getStr(f, 11)).toBe("1.4.1");
    expect(getStr(f, 13)).toBe("Web");
    expect(f.get(10)![0]).toBe(42n);
    expect(f.has(9)).toBe(false);                 // video_ack_required = false
    for (const n of [7, 8, 15, 16]) expect(f.has(n)).toBe(false);    // union 欄位不填
    const opt = parse(f.get(6)![0] as Uint8Array);
    expect(opt.get(7)![0]).toBe(2n);              // disable_audio = Yes
    expect(opt.get(8)![0]).toBe(2n);              // disable_clipboard = Yes
    expect(opt.get(3)![0]).toBe(2n);              // show_remote_cursor = Yes（附錄 E 更正）
    const sd = parse(opt.get(10)![0] as Uint8Array);
    expect(sd.get(1)![0]).toBe(1n);               // ability_vp9
    expect(sd.get(2)![0]).toBe(1n);               // ability_h264
    expect(sd.get(4)![0]).toBe(1n);               // prefer = VP9
    expect(sd.has(3)).toBe(false);                // h265 = 0
  });

  it("show_remote_cursor = Yes：受控端才會送它自己游標移動的 cursor_position（附錄 E 更正）；唯讀檢視也要", () => {
    for (const viewOnly of [false, true]) {
      const m = decodeMessage(encodeLoginRequest({
        peerId: "123456789", password: new Uint8Array(0), myId: "jt-ipam", myName: "a", sessionId: 1n,
        version: "1.4.1", decoding: { vp9: true, h264: false, vp8: false, av1: false }, viewOnly,
      }));
      const opt = parse(parse(m.body).get(6)![0] as Uint8Array);
      expect(opt.get(3)).toEqual([2n]);
      expect(opt.get(12)?.[0] ?? 0n).toBe(viewOnly ? 2n : 0n);     // disable_keyboard 不受影響
    }
  });
});

describe("輸入（9）", () => {
  it("mask：左鍵按下 9、放開 10、右鍵按下 17、中鍵按下 33、移動 0、滾輪 3", () => {
    expect(mouseMask(MouseKind.Down, MouseButton.Left)).toBe(9);
    expect(mouseMask(MouseKind.Up, MouseButton.Left)).toBe(10);
    expect(mouseMask(MouseKind.Down, MouseButton.Right)).toBe(17);
    expect(mouseMask(MouseKind.Down, MouseButton.Middle)).toBe(33);
    expect(mouseMask(MouseKind.Move)).toBe(0);
    expect(mouseMask(MouseKind.Wheel)).toBe(3);
  });

  it("DOM 的按鍵編號對應", () => {
    expect([0, 1, 2, 3, 4, 9].map(domButton)).toEqual([0x01, 0x04, 0x02, 0x08, 0x10, 0]);
  });

  it("MouseEvent：座標是 sint32、modifiers 是 packed", () => {
    const m = decodeMessage(encodeMouseEvent(9, -1920, 100, [1, 4]));
    expect(m.kind).toBe("mouse_event");
    const f = parse(m.body);
    expect(f.get(1)![0]).toBe(9n);
    expect(f.get(2)![0]).toBe(3839n);
    expect(f.get(3)![0]).toBe(200n);
    expect(getRepeatedInts(f, 4)).toEqual([1, 4]);
  });

  it("座標換算：四個角落；最大值一律是寬 − 1、高 − 1（附錄 H.3 取代 9.1 的「Windows 到右緣」）", () => {
    const d = { x: -1920, y: 0, width: 1920, height: 1080 };
    expect(mapPointer(0, 0, 960, 540, d)).toEqual({ x: -1920, y: 0 });
    expect(mapPointer(960, 540, 960, 540, d)).toEqual({ x: -1, y: 1079 });
    expect(mapPointer(480, 270, 960, 540, d)).toEqual({ x: -960, y: 540 });
    expect(mapPointer(-5, 9999, 960, 540, d)).toBeNull();             // 超出 5 像素以上不送（H.3）
    expect(mapPointer(-5, 9999, 960, 540, d, true)).toEqual({ x: -1920, y: 1079 });   // 左鍵放開照送
  });

  it("滾輪：往下捲送 y = −1，每 100 像素一格，一次最多 5 格", () => {
    const w = new WheelAccumulator();
    expect(w.push(0, 100)).toEqual([[0, -1]]);
    expect(w.push(0, -200)).toEqual([[0, 1], [0, 1]]);
    expect(w.push(100, 0)).toEqual([[-1, 0]]);
    expect(w.push(0, 5000)).toHaveLength(5);
    // 觸控板的小 delta 累積
    const t = new WheelAccumulator();
    expect(t.push(0, 10)).toEqual([]);
    for (let i = 0; i < 8; i++) t.push(0, 10);
    expect(t.push(0, 10)).toEqual([[0, -1]]);
    // 滑鼠一格只有 53 像素也要動
    expect(new WheelAccumulator().push(0, 53)).toEqual([[0, -1]]);
  });
});

describe("鍵盤（9.2、附錄 A）", () => {
  it("依平台選欄位", () => {
    expect(keyCodeFor("KeyA", "Windows")).toBe(0x1e);
    expect(keyCodeFor("KeyA", "Linux")).toBe(38);
    expect(keyCodeFor("KeyA", "Mac OS")).toBe(0x00);
    expect(keyCodeFor("ControlRight", "Windows")).toBe(0xe01d);
    expect(keyCodeFor("Delete", "Windows")).toBe(0xe053);
    expect(keyCodeFor("PrintScreen", "Mac OS")).toBeNull();      // 「—」不送
    expect(keyCodeFor("F13", "Windows")).toBeNull();             // 第一階段沒有
    expect(keyCodeFor("KeyA", "Android")).toBeNull();
    expect(keyCodeFor("constructor", "Windows")).toBeNull();
  });

  it("鎖定鍵：字母帶 CapsLock、數字鍵盤帶 NumLock，其他不帶", () => {
    expect(lockModifiers("KeyQ", true, true)).toEqual([3]);
    expect(lockModifiers("KeyQ", false, true)).toEqual([]);
    expect(lockModifiers("Numpad5", true, true)).toEqual([63]);
    expect(lockModifiers("Digit5", true, true)).toEqual([]);
  });

  it("map 模式的 KeyEvent：chr 為 0 也要寫出", () => {
    const m = decodeMessage(encodeKeyMap(true, 0x00, [3]));
    const f = parse(m.body);
    expect(m.kind).toBe("key_event");
    expect(f.get(1)![0]).toBe(1n);
    expect(f.get(4)![0]).toBe(0n);
    expect(getRepeatedInts(f, 8)).toEqual([3]);
    expect(f.get(9)![0]).toBe(1n);                // Map
    const up = parse(decodeMessage(encodeKeyMap(false, 38, [])).body);
    expect(up.has(1)).toBe(false);                // down = false
    expect(up.get(4)![0]).toBe(38n);
  });

  it("Ctrl+Alt+Del：Windows 與其他平台（9.3）", () => {
    const w = parse(decodeMessage(encodeCtrlAltDel("Windows")).body);
    expect(w.get(1)![0]).toBe(1n);
    expect(w.get(3)![0]).toBe(100n);
    expect(w.has(9)).toBe(false);                 // Legacy = 0
    const l = parse(decodeMessage(encodeCtrlAltDel("Linux")).body);
    expect(l.get(2)![0]).toBe(1n);                // press
    expect(l.get(3)![0]).toBe(5n);                // Delete
    expect(getRepeatedInts(l, 8)).toEqual([1, 4]);
  });
});

describe("其他訊息", () => {
  it("close_reason 空字串也要寫出欄位（10）", () => {
    const m = decodeMessage(encodeCloseReason(""));
    expect(m.kind).toBe("misc");
    expect(parseMisc(m.body)).toEqual({ type: "close_reason", reason: "" });
  });

  it("要求關鍵影格：一律 refresh_video_display 帶螢幕編號（含 0）；不用 refresh_video（附錄 H.2：它會讓所有螢幕、所有觀看者重新開始）", () => {
    const n = parse(decodeMessage(encodeRefreshVideo(0)).body);
    expect(n.get(31)![0]).toBe(0n);
    const o = parse(decodeMessage(encodeRefreshVideo(2)).body);
    expect([...o.keys()]).toEqual([31]);
    expect(o.get(31)![0]).toBe(2n);
    expect(versionAtLeast("1.2.4", [1, 2, 4])).toBe(true);
    expect(versionAtLeast("1.10.0", [1, 2, 4])).toBe(true);
    expect(versionAtLeast("", [1, 2, 4])).toBe(false);
  });

  it("PeerInfo 與 DisplayInfo（x、y 是 sint32）", () => {
    const disp = concat(fSint(1, -1920), fSint(2, 0), fVarint(3, 1920), fVarint(4, 1080), fStr(5, "DP-1"));
    const pi = parsePeerInfo(concat(fStr(1, "bob"), fStr(2, "pc"), fStr(3, "Linux"), fMsg(4, disp),
                                    fVarint(5, 0), fStr(7, "1.4.1")));
    expect(pi.platform).toBe("Linux");
    expect(pi.displays[0]).toMatchObject({ x: -1920, y: 0, width: 1920, height: 1080, name: "DP-1" });
    expect(pi.version).toBe("1.4.1");
  });

  it("VideoFrame：格式、影格、螢幕索引", () => {
    const ef = concat(fBytes(1, new Uint8Array([1, 2, 3])), fVarint(2, 1), fVarint(3, 1234));
    const vf = parseVideoFrame(concat(fMsg(13, fMsg(1, ef)), fVarint(14, 1)));
    expect(vf.codec).toBe("av1");
    expect(vf.display).toBe(1);
    expect(vf.frames).toEqual([{ data: new Uint8Array([1, 2, 3]), key: true, pts: 1234n }]);
  });
});
