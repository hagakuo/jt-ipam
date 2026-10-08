/**
 * 相容 RustDesk 的網頁連線：雙向剪貼簿（規格附錄 F.3 的單元測試）與有上限的 zstd 解壓。
 * 壓縮過的測試資料是用 zstd 官方 CLI（v1.5.5）產生的標準 frame，不是自己編的。
 */
import { describe, expect, it, vi } from "vitest";
import { concat, fBool, fBytes, fMsg, fVarint, getBool, getBytes, getInt, getMsgs, parse } from "../pb";
import { decodeMessage, encodeMessage } from "../messages";
import {
  ClipboardSync, COMPRESS_THRESHOLD, encodeClipboardBytes, encodeClipboardOption, htmlToText, isPasteKey,
  MAX_CLIPBOARD_BYTES, parseMultiClipboards, pasteKeys, readIncoming, waitForPaste, type ClipboardTransport,
} from "../clipboard";
import { zstdDecompress } from "../zstd";

const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
// jsdom 的 TextEncoder 回傳的是另一個 realm 的 Uint8Array，toEqual 會判成不同：複製一份成這裡的
const utf8 = (s: string) => new Uint8Array(new TextEncoder().encode(s));

// printf 'hello, 剪貼簿 clipboard' | zstd -c（串流：沒有宣告內容大小、有 checksum）
const Z_HELLO = b64("KLUv/QRY0QAAaGVsbG8sIOWJquiyvOewvyBjbGlwYm9hcmRzrSUv");
// 200,000 個 a（zstd -c 檔案：有宣告內容大小）；F.1 第 3 點的那種「20 萬字壓成幾十 bytes」
const Z_A200K = b64("KLUv/aRADQMAVAAAEGFhAQD7/znAAgNqCGGDVryY");
// 2 MiB 的 b：檔案（宣告內容大小 2 MiB）與串流（沒有宣告，只能邊解邊數）
const Z_B2M_FCS = b64("KLUv/aQAACAAVAAAEGJiAQD7/znAAgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAwAQYtdNACM=");
const Z_B2M_STREAM = b64("KLUv/QRYVAAAEGJiAQD7/znAAgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAwAQYtdNACM=");
// 剛好 1 MiB 與 1 MiB＋1 的 c（串流）
const Z_C1M = b64("KLUv/QRYVAAAEGNjAQD7/znAAgIAEGMCABBjAgAQYwIAEGMCABBjAgAQYwMAEGO/6m7C");
const Z_C1M_PLUS1 = b64("KLUv/QRYVAAAEGNjAQD7/znAAgIAEGMCABBjAgAQYwIAEGMCABBjAgAQYwIAEGMJAABjqP+gNw==");

/** 測試用的 zstd frame（RFC 8878）：Single_Segment、4 bytes 內容大小、只用 raw block。格式合法但不會變小。 */
function zstdRawFrame(raw: Uint8Array): Uint8Array {
  const n = raw.length;
  const parts = [Uint8Array.of(0x28, 0xb5, 0x2f, 0xfd, 0xa0, n & 255, (n >> 8) & 255, (n >> 16) & 255, n >>> 24)];
  for (let off = 0; off < n || off === 0; off += 131072) {
    const size = Math.min(131072, n - off);
    const last = off + size >= n ? 1 : 0;
    const h = last | (size << 3);
    parts.push(Uint8Array.of(h & 255, (h >> 8) & 255, (h >> 16) & 255), raw.subarray(off, off + size));
    if (last) break;
  }
  return concat(...parts);
}

/** Clipboard 項目（format 0 是預設值，不寫） */
function item(content: Uint8Array, format = 0, compress = false): Uint8Array {
  return concat(fBool(1, compress), fBytes(2, content), fVarint(5, format));
}
const multi = (...items: Uint8Array[]) => concat(...items.map((i) => fMsg(1, i)));

describe("有上限的 zstd 解壓", () => {
  it("官方 CLI 產生的 frame 解得開（有無宣告內容大小、有 checksum 都可以）", () => {
    const a = zstdDecompress(Z_HELLO, MAX_CLIPBOARD_BYTES);
    expect(a.ok && new TextDecoder().decode(a.data)).toBe("hello, 剪貼簿 clipboard");
    const b = zstdDecompress(Z_A200K, MAX_CLIPBOARD_BYTES);
    expect(b.ok && b.data.length).toBe(200_000);
    expect(b.ok && b.data.every((x) => x === 0x61)).toBe(true);
  });

  it("宣告的內容大小超過上限：不解就拒絕", () => {
    expect(zstdDecompress(Z_B2M_FCS, MAX_CLIPBOARD_BYTES)).toEqual({ ok: false, reason: "too_large" });
  });

  it("沒有宣告大小的串流：邊解邊數，超過就中止", () => {
    expect(zstdDecompress(Z_B2M_STREAM, MAX_CLIPBOARD_BYTES)).toEqual({ ok: false, reason: "too_large" });
    const ok = zstdDecompress(Z_C1M, MAX_CLIPBOARD_BYTES);          // 剛好 1 MiB 可以
    expect(ok.ok && ok.data.length).toBe(MAX_CLIPBOARD_BYTES);
    expect(zstdDecompress(Z_C1M_PLUS1, MAX_CLIPBOARD_BYTES)).toEqual({ ok: false, reason: "too_large" });
  });

  it("宣告的視窗大到不合理（會讓函式庫配置大量記憶體）：拒絕", () => {
    // 不是 single segment、視窗描述 0x88 = 2^27（128 MiB）、一個空的 raw block
    const f = Uint8Array.of(0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x88, 0x01, 0x00, 0x00);
    expect(zstdDecompress(f, MAX_CLIPBOARD_BYTES)).toEqual({ ok: false, reason: "too_large" });
  });

  it("格式不對、截斷、要字典的：invalid，不丟例外", () => {
    expect(zstdDecompress(utf8("not zstd at all"), 100)).toEqual({ ok: false, reason: "invalid" });
    expect(zstdDecompress(new Uint8Array(0), 100)).toEqual({ ok: false, reason: "invalid" });
    expect(zstdDecompress(Z_HELLO.subarray(0, Z_HELLO.length - 6), 100)).toEqual({ ok: false, reason: "invalid" });
    const withDict = Uint8Array.of(0x28, 0xb5, 0x2f, 0xfd, 0x21, 0x07, 0x00, 0x01, 0x00, 0x00);  // dict id = 7
    expect(zstdDecompress(withDict, 100)).toEqual({ ok: false, reason: "invalid" });
  });

  it("測試用的 raw block frame 自己解得回來（跨 128 KB 的多個 block）", () => {
    const raw = utf8("剪".repeat(100_000));
    const r = zstdDecompress(zstdRawFrame(raw), MAX_CLIPBOARD_BYTES);
    expect(r.ok && r.data).toEqual(raw);
  });
});

describe("受控端 → 瀏覽器（F.1、F.2）", () => {
  it("multi_clipboards：未壓縮的純文字", () => {
    const items = parseMultiClipboards(multi(item(utf8("hello 中文"))));
    expect(items).toEqual([{ compress: false, content: utf8("hello 中文"), format: 0 }]);
    expect(readIncoming(items)).toEqual({ kind: "text", text: "hello 中文" });
  });

  it("multi_clipboards：壓縮的純文字（compress = true，content 是 zstd）", () => {
    expect(readIncoming(parseMultiClipboards(multi(item(Z_HELLO, 0, true)))))
      .toEqual({ kind: "text", text: "hello, 剪貼簿 clipboard" });
    const big = readIncoming(parseMultiClipboards(multi(item(Z_A200K, 0, true))));
    expect(big.kind === "text" && big.text.length).toBe(200_000);
  });

  it("多個項目：取第一個 Text，不管 Html 排在前面", () => {
    const body = multi(item(utf8("<b>粗體</b>"), 2), item(utf8("第一個")), item(utf8("第二個")));
    expect(readIncoming(parseMultiClipboards(body))).toEqual({ kind: "text", text: "第一個" });
  });

  it("只有 Html：轉成純文字，HTML 本身也交出去", () => {
    const html = "<p>Hello <b>世界</b></p><script>alert(1)</script><style>p{}</style>";
    const r = readIncoming(parseMultiClipboards(multi(item(utf8(html), 2))));
    expect(r).toEqual({ kind: "text", text: "Hello 世界", html });
  });

  it("其他格式（圖片等）忽略", () => {
    expect(readIncoming(parseMultiClipboards(multi(item(new Uint8Array([1, 2, 3]), 7))))).toEqual({ kind: "none" });
    expect(readIncoming([])).toEqual({ kind: "none" });
  });

  it("超過 1 MB：未壓縮與解壓後都丟掉", () => {
    const tooBig = new Uint8Array(MAX_CLIPBOARD_BYTES + 1).fill(0x41);
    expect(readIncoming(parseMultiClipboards(multi(item(tooBig))))).toEqual({ kind: "too_large" });
    expect(readIncoming(parseMultiClipboards(multi(item(Z_B2M_STREAM, 0, true))))).toEqual({ kind: "too_large" });
    expect(readIncoming(parseMultiClipboards(multi(item(Z_B2M_FCS, 0, true))))).toEqual({ kind: "too_large" });
  });

  it("壓縮的內容解不開：當成沒有內容", () => {
    expect(readIncoming(parseMultiClipboards(multi(item(utf8("garbage"), 0, true))))).toEqual({ kind: "none" });
  });

  it("也接受舊式的 clipboard (16)", () => {
    const sync = new ClipboardSync({ enabled: () => true, send: () => true });
    expect(sync.receive("clipboard", item(Z_HELLO, 0, true))).toEqual({ kind: "text", text: "hello, 剪貼簿 clipboard" });
  });

  it("htmlToText 不執行指令碼、不留 style 的內容", () => {
    expect(htmlToText("<div>a<br>b</div><style>.x{color:red}</style>")).toBe("ab");
  });
});

describe("瀏覽器 → 受控端（F.2）", () => {
  const firstItem = (msg: Uint8Array) => {
    const m = decodeMessage(msg);
    expect(m.kind).toBe("multi_clipboards");
    const items = getMsgs(parse(m.body), 1);
    expect(items).toHaveLength(1);
    return items[0];
  };

  it("未壓縮：一個 Text 項目，compress 與 format 都是預設值", () => {
    const it0 = firstItem(encodeClipboardBytes(utf8("貼上這段")));
    expect(getBool(it0, 1)).toBe(false);
    expect(new TextDecoder().decode(getBytes(it0, 2))).toBe("貼上這段");
    expect(getInt(it0, 5)).toBe(0);
    expect(it0.has(3) || it0.has(4) || it0.has(6)).toBe(false);
  });

  it("超過 64 KB、有壓縮器：compress = true，content 是 zstd，解得回原文", () => {
    const raw = utf8("x".repeat(COMPRESS_THRESHOLD + 1));
    const compress = vi.fn(zstdRawFrame);
    const it0 = firstItem(encodeClipboardBytes(raw, compress));
    expect(compress).toHaveBeenCalledTimes(1);
    expect(getBool(it0, 1)).toBe(true);
    const back = zstdDecompress(getBytes(it0, 2), MAX_CLIPBOARD_BYTES);
    expect(back.ok && back.data).toEqual(raw);
  });

  it("64 KB 以內不壓縮；沒有壓縮器時大的也照樣不壓縮送出（F.1 第 5 點）", () => {
    const compress = vi.fn(zstdRawFrame);
    expect(getBool(firstItem(encodeClipboardBytes(utf8("y".repeat(COMPRESS_THRESHOLD)), compress)), 1)).toBe(false);
    expect(compress).not.toHaveBeenCalled();
    const big = firstItem(encodeClipboardBytes(utf8("z".repeat(200_000))));
    expect(getBool(big, 1)).toBe(false);
    expect(getBytes(big, 2).length).toBe(200_000);
  });

  it("執行中切換：Misc.option 只帶 disable_clipboard（開＝No、關＝Yes）", () => {
    for (const [on, v] of [[true, 1n], [false, 2n]] as const) {
      const m = decodeMessage(encodeClipboardOption(on));
      expect(m.kind).toBe("misc");
      const opt = parse(parse(m.body).get(7)![0] as Uint8Array);
      expect([...opt.keys()]).toEqual([8]);
      expect(opt.get(8)![0]).toBe(v);
    }
  });
});

describe("ClipboardSync", () => {
  function setup(on = true) {
    const sent: Uint8Array[] = [];
    const state = { on };
    const t: ClipboardTransport = { enabled: () => state.on, send: (m) => { sent.push(m); return true; } };
    return { sync: new ClipboardSync(t), sent, state };
  }
  const textOf = (msg: Uint8Array) =>
    new TextDecoder().decode(getBytes(getMsgs(parse(decodeMessage(msg).body), 1)[0], 2));

  it("相同內容連續送出時略過；明確要求（傳送文字）時照送", () => {
    const { sync, sent } = setup();
    expect(sync.send("abc")).toBe("sent");
    expect(sync.send("abc")).toBe("duplicate");
    expect(sent).toHaveLength(1);
    expect(sync.send("abc", true)).toBe("sent");
    expect(sync.send("def")).toBe("sent");
    expect(sent.map(textOf)).toEqual(["abc", "abc", "def"]);
  });

  it("對方的剪貼簿變了之後，同樣的內容要再送一次", () => {
    const { sync, sent } = setup();
    sync.send("abc");
    sync.receive("multi_clipboards", multi(item(utf8("對方複製的"))));
    expect(sync.send("abc")).toBe("sent");
    // 對方送來的就是本機現在的內容：不必再送回去
    sync.receive("multi_clipboards", multi(item(utf8("同一段"))));
    expect(sync.send("同一段")).toBe("duplicate");
    // 對方換成我們不處理的格式（圖片）：不知道對方剪貼簿是什麼了，照送
    sync.receive("multi_clipboards", multi(item(new Uint8Array([9]), 7)));
    expect(sync.send("同一段")).toBe("sent");
    expect(sent.map(textOf)).toEqual(["abc", "abc", "同一段"]);
  });

  it("關閉時不送（也不編碼、不記錄）", () => {
    const { sync, sent, state } = setup(false);
    expect(sync.send("abc")).toBe("disabled");
    expect(sent).toHaveLength(0);
    state.on = true;
    expect(sync.send("abc")).toBe("sent");    // 關著時沒記下來，打開後照送
    expect(sent).toHaveLength(1);
  });

  it("重新打開剪貼簿後不再假設對方的內容", () => {
    const { sync, sent } = setup();
    sync.send("abc");
    sync.reset();
    expect(sync.send("abc")).toBe("sent");
    expect(sent).toHaveLength(2);
  });

  it("空字串與超過 1 MB 的不送", () => {
    const { sync, sent } = setup();
    expect(sync.send("")).toBe("empty");
    expect(sync.send("中".repeat(MAX_CLIPBOARD_BYTES / 3 + 1))).toBe("too_large");   // 上限算的是 UTF-8 bytes
    expect(sent).toHaveLength(0);
  });

  it("transport 沒送出（例如還沒登入）時回 disabled，也不記成對方的內容", () => {
    const sent: Uint8Array[] = [];
    let ok = false;
    const sync = new ClipboardSync({ enabled: () => true, send: (m) => { if (ok) sent.push(m); return ok; } });
    expect(sync.send("abc")).toBe("disabled");
    ok = true;
    expect(sync.send("abc")).toBe("sent");
    expect(sent).toHaveLength(1);
  });

  it("有壓縮器時大的內容走壓縮", () => {
    const sent: Uint8Array[] = [];
    const sync = new ClipboardSync({ enabled: () => true, send: (m) => { sent.push(m); return true; } },
                                   { compress: zstdRawFrame });
    sync.send("q".repeat(COMPRESS_THRESHOLD + 10));
    expect(getBool(getMsgs(parse(decodeMessage(sent[0]).body), 1)[0], 1)).toBe(true);
  });
});

describe("Ctrl+V 的按鍵（F.2 第 1 點）", () => {
  const k = (o: Partial<{ code: string; ctrlKey: boolean; metaKey: boolean; altKey: boolean }>) =>
    ({ code: "KeyV", ctrlKey: false, metaKey: false, altKey: false, ...o });

  it("Ctrl+V、Ctrl+Shift+V 算；macOS 也接受 Cmd+V；其他平台的 Meta+V、Alt 組合、別的鍵不算", () => {
    expect(isPasteKey(k({ ctrlKey: true }), false)).toBe(true);
    expect(isPasteKey(k({ metaKey: true }), true)).toBe(true);
    expect(isPasteKey(k({ metaKey: true }), false)).toBe(false);
    expect(isPasteKey(k({ ctrlKey: true, altKey: true }), false)).toBe(false);
    expect(isPasteKey(k({ code: "KeyC", ctrlKey: true }), false)).toBe(false);
    expect(isPasteKey(k({}), false)).toBe(false);
  });

  it("Ctrl+V：只補 V 的按下", () => {
    expect(pasteKeys(false, ["ControlLeft"])).toEqual([{ code: "KeyV", down: true }]);
  });

  it("Cmd+V → 對方收到 Ctrl+V，Meta 先放開再按回去", () => {
    expect(pasteKeys(true, ["MetaLeft", "ShiftLeft"])).toEqual([
      { code: "MetaLeft", down: false },
      { code: "ControlLeft", down: true }, { code: "KeyV", down: true },
      { code: "KeyV", down: false }, { code: "ControlLeft", down: false },
      { code: "MetaLeft", down: true },
    ]);
  });
});

describe("取得本機剪貼簿", () => {
  function pasteEvent(text: string): Event {
    const e = new Event("paste", { bubbles: true, cancelable: true });
    Object.defineProperty(e, "clipboardData", { value: { getData: (t: string) => (t === "text/plain" ? text : "") } });
    return e;
  }

  it("優先用 paste 事件，不讀剪貼簿 API；事件的預設動作被取消（不會真的貼進輸入框）", async () => {
    const target = new EventTarget();
    const readText = vi.fn(async () => "from api");
    const p = waitForPaste(target, { readText });
    const e = pasteEvent("from paste");
    target.dispatchEvent(e);
    expect(await p).toBe("from paste");
    expect(e.defaultPrevented).toBe(true);
    expect(readText).not.toHaveBeenCalled();
  });

  it("等不到 paste 事件：改用 readText", async () => {
    const readText = vi.fn(async () => "from api");
    expect(await waitForPaste(new EventTarget(), { waitMs: 5, readText })).toBe("from api");
  });

  it("readText 被拒絕或等太久：null", async () => {
    expect(await waitForPaste(new EventTarget(), { waitMs: 5, readText: () => Promise.reject(new Error("denied")) }))
      .toBeNull();
    expect(await waitForPaste(new EventTarget(), { waitMs: 5, readTimeoutMs: 10, readText: () => new Promise(() => {}) }))
      .toBeNull();
  });
});

describe("Message 的種類", () => {
  it("clipboard (16)、multi_clipboards (28) 認得", () => {
    expect(decodeMessage(encodeMessage("clipboard", item(utf8("a")))).kind).toBe("clipboard");
    expect(decodeMessage(fMsg(28, multi(item(utf8("a"))))).kind).toBe("multi_clipboards");
  });
});
