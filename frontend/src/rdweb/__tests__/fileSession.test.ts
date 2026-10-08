/**
 * 相容 RustDesk 的網頁連線：檔案傳輸的流程（規格附錄 J.7 的單元測試）。
 *
 * 用假的受控端走完 §6 的握手與 §7 的登入（union file_transfer），再照 J.2～J.5 回應：列目錄、下載（digest／confirm、
 * 略過、壓縮塊、多檔的 file_num、錯誤、取消）、上傳（同名時的詢問）、建立／改名／刪除、Windows 磁碟機，以及
 * J.6 送給後端的 file_audit 內容。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { concat, fBool, fBytes, fMsg, fSint, fStr, fVarint, parse } from "../pb";
import {
  decodeFileMessage, encodeDone, encodeFileError, FileType, MSG_FILE_ACTION, MSG_FILE_RESPONSE, type FileAction,
  type FileResponse,
} from "../files";
import {
  checkUploadLimits, fileTiming, RdFileSession, type ConflictAnswer, type ConflictInfo, type DownloadSink, type FileSessionEvents,
  type UploadSource,
} from "../fileSession";
import type { CloseInfo } from "../session";
import { FakePeer, FakeWs, PEER } from "./fakeRustDesk";

const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
// printf 'hello, 剪貼簿 clipboard' | zstd -c（zstd 官方 CLI 產生的標準 frame；與 clipboard.test.ts 同一份）
const Z_HELLO = b64("KLUv/QRY0QAAaGVsbG8sIOWJquiyvOewvyBjbGlwYm9hcmRzrSUv");
const HELLO = "hello, 剪貼簿 clipboard";
// 2 MiB 的 b（宣告內容大小 2 MiB）：解壓後超過單塊上限，要拒絕
const Z_B2M_FCS = b64("KLUv/aQAACAAVAAAEGJiAQD7/znAAgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAgAQYgIAEGICABBiAwAQYtdNACM=");
const utf8 = (s: string) => new Uint8Array(new TextEncoder().encode(s));
const MB = 1024 * 1024;
const LIMITS = { maxFileBytes: 2048 * MB, maxTotalBytes: 10240 * MB };

const sessions: RdFileSession[] = [];
fileTiming.doneGraceMs = 20;          // 上傳送完 done 之後等受控端回錯誤的時間（測試不必等滿）
afterEach(() => {
  for (const s of sessions.splice(0)) s.close();
  vi.useRealTimers();
});

// ── 受控端送的訊息 ──

function entry(type: number, name: string, size = 0, mtime = 0, hidden = false): Uint8Array {
  return fMsg(3, concat(fVarint(1, type), fStr(2, name), fBool(3, hidden), fVarint(4, size), fVarint(5, mtime)));
}
const dirMsg = (id: number, path: string, ...entries: Uint8Array[]) =>
  fMsg(MSG_FILE_RESPONSE, fMsg(1, concat(fVarint(1, id), fStr(2, path), ...entries)));
const digestMsg = (id: number, fileNum: number, size: number, opts: { upload?: boolean; identical?: boolean } = {}) =>
  fMsg(MSG_FILE_RESPONSE, fMsg(5, concat(fVarint(1, id), fSint(2, fileNum), fVarint(3, 1_700_000_000),
                                         fVarint(4, size), fBool(5, !!opts.upload), fBool(6, !!opts.identical))));
const blockMsg = (id: number, fileNum: number, data: Uint8Array, compressed = false) =>
  fMsg(MSG_FILE_RESPONSE, fMsg(2, concat(fVarint(1, id), fSint(2, fileNum), fBytes(3, data), fBool(4, compressed))));
/** 上傳時受控端回的 FileAction.send_confirm（offset_blk = 0 在 oneof 裡要寫出） */
const peerConfirm = (id: number, fileNum: number) =>
  fMsg(MSG_FILE_ACTION, fMsg(9, concat(fVarint(1, id), fSint(2, fileNum), Uint8Array.of(0x20, 0x00))));

// ── 控制端送出的檔案訊息 ──

type Sent = { side: "action"; action: FileAction } | { side: "response"; response: FileResponse };
function fileSent(peer: FakePeer): Sent[] {
  return peer.drain().map((p) => decodeFileMessage(p)).filter((m): m is Sent => m !== null);
}
function actions(peer: FakePeer): FileAction[] {
  return fileSent(peer).flatMap((m) => (m.side === "action" ? [m.action] : []));
}

/** 等到控制端送出符合條件的檔案訊息（之前的照順序收集起來） */
async function nextSent(peer: FakePeer, acc: Sent[], pred: (m: Sent) => boolean): Promise<Sent> {
  let found: Sent | undefined;
  await vi.waitFor(() => {
    acc.push(...fileSent(peer));
    found = acc.find(pred);
    expect(found).toBeDefined();
  }, { timeout: 3000, interval: 5 });
  acc.splice(acc.indexOf(found!), 1);
  return found!;
}

class MemSink implements DownloadSink {
  chunks: Uint8Array[] = [];
  closed = false;
  aborted = false;
  write(c: Uint8Array): void { this.chunks.push(c.slice()); }
  async close(): Promise<void> { this.closed = true; }
  abort(): void { this.aborted = true; }
  text(): string { return new TextDecoder().decode(concat(...this.chunks)); }
  get size(): number { return this.chunks.reduce((n, c) => n + c.length, 0); }
}

function source(name: string, data: Uint8Array, lastModified = 1_700_000_000_000): UploadSource {
  return { name, size: data.length, lastModified, read: async (off, len) => data.slice(off, off + len) };
}

interface Env { ws: FakeWs; peer: FakePeer; s: RdFileSession; closes: CloseInfo[]; listings: string[] }

/** 握手 → Hash → 空密碼（等對方同意，不必算雜湊）→ 受控端回 peer_info＝已登入 */
function connect(events: FileSessionEvents = {},
                 opts: { platform?: string; showHidden?: boolean; limits?: typeof LIMITS } = {}): Env {
  const ws = new FakeWs();
  const peer = new FakePeer(ws);
  const closes: CloseInfo[] = [];
  const listings: string[] = [];
  const s = new RdFileSession({
    url: "wss://x/api/v1/addresses/1/rustdesk/ws?ticket=t", peerId: PEER, myName: "alice (jt-ipam)",
    password: "", showHidden: opts.showHidden, limits: opts.limits ?? LIMITS, wsFactory: () => ws,
    events: {
      ...events,
      listing: (l) => { listings.push(l.path); events.listing?.(l); },
      closed: (i) => { closes.push(i); events.closed?.(i); },
    },
  });
  sessions.push(s);
  peer.handshake();
  peer.hash();
  peer.loginOk(opts.platform);
  return { ws, peer, s, closes, listings };
}

describe("登入（J.1）", () => {
  it("LoginRequest 填 union file_transfer（7）{ dir, show_hidden }，不填遠端桌面的 option（6）", () => {
    const ws = new FakeWs();
    const peer = new FakePeer(ws);
    const s = new RdFileSession({ url: "wss://x", peerId: PEER, myName: "alice (jt-ipam)", password: "",
                                  showHidden: true, limits: LIMITS, wsFactory: () => ws, events: {} });
    sessions.push(s);
    peer.handshake();
    peer.hash();
    const login = peer.drain().map((p) => parse(p)).find((f) => f.has(7))!;
    const lr = parse(login.get(7)![0] as Uint8Array);
    expect(lr.has(6)).toBe(false);
    const ft = parse(lr.get(7)![0] as Uint8Array);
    expect(new TextDecoder().decode(ft.get(1)?.[0] as Uint8Array ?? new Uint8Array(0))).toBe("");
    expect(ft.get(2)![0]).toBe(1n);
  });

  it("受控端沒開「允許檔案傳輸」：登入回 No permission of file transfer 的原文、連線結束", () => {
    const ws = new FakeWs();
    const peer = new FakePeer(ws);
    const closes: CloseInfo[] = [];
    const s = new RdFileSession({ url: "wss://x", peerId: PEER, myName: "a", password: "", limits: LIMITS,
                                  wsFactory: () => ws, events: { closed: (i) => closes.push(i) } });
    sessions.push(s);
    peer.handshake();
    peer.hash();
    peer.loginError("No permission of file transfer");
    expect(closes[0]).toMatchObject({ code: "rd_login_error", detail: "No permission of file transfer" });
    expect(ws.sentText).toContainEqual({ t: "login_result", ok: false, error: "No permission of file transfer" });
  });

  it("連線中受控端關掉檔案傳輸權限（Misc.permission_info File = false）：結束檔案傳輸連線", () => {
    const { peer, closes } = connect();
    peer.permission(4, false);
    expect(closes[0].code).toBe("rd_file_permission_off");
  });

  it("其他權限的變化（鍵盤）不影響檔案傳輸", () => {
    const { peer, closes, s } = connect();
    peer.permission(0, false);
    expect(closes).toHaveLength(0);
    expect(s.phase).toBe("connected");
  });

  it("登入回覆的 peer_info 沒有螢幕清單：檔案傳輸的連線照常進行（附錄 H 的「沒有螢幕就結束」只適用遠端桌面）", async () => {
    // FakePeer.loginOk 送的 PeerInfo 不帶 displays（檔案傳輸的登入回覆可能就是這樣）
    const { peer, s, closes, ws } = connect();
    expect(closes).toHaveLength(0);
    expect(s.phase).toBe("connected");
    expect(ws.closed).toBe(false);
    expect(ws.sentText.some((x) => x.t === "close")).toBe(false);
    const p = s.list("/tmp");
    peer.send(dirMsg(0, "/tmp", entry(FileType.File, "a", 1)));
    expect((await p).entries.map((e) => e.name)).toEqual(["a"]);
  });
});

describe("列目錄（J.2）", () => {
  it("登入後受控端自己先送一次列表（家目錄）；之後 read_dir 照順序配對", async () => {
    const seen: string[][] = [];
    const { peer, s, listings } = connect({ listing: (l) => seen.push(l.entries.map((e) => e.name)) });
    peer.send(dirMsg(0, "/home/alice", entry(FileType.Dir, "docs"), entry(FileType.File, "a.txt", 10)));
    expect(listings).toEqual(["/home/alice"]);
    expect(s.cwd).toBe("/home/alice");
    expect(s.windows).toBe(false);
    const p = s.list("/home/alice/docs");
    const sent = actions(peer);
    expect(sent).toContainEqual({ type: "read_dir", path: "/home/alice/docs", includeHidden: false });
    peer.send(dirMsg(0, "/home/alice/docs", entry(FileType.File, "b.txt", 3)));
    const l = await p;
    expect(l.path).toBe("/home/alice/docs");
    expect(l.entries.map((e) => e.name)).toEqual(["b.txt"]);
    expect(seen).toHaveLength(2);
  });

  it("沒勾顯示隱藏檔：受控端萬一送了隱藏項目也不列；勾了才要求 include_hidden", async () => {
    const { peer, s } = connect();
    const p = s.list("/x");
    peer.send(dirMsg(0, "/x", entry(FileType.File, ".hidden", 1, 0, true), entry(FileType.File, "shown", 1)));
    expect((await p).entries.map((e) => e.name)).toEqual(["shown"]);
    actions(peer);
    const p2 = s.setShowHidden(true);
    expect(actions(peer)).toContainEqual({ type: "read_dir", path: "/x", includeHidden: true });
    peer.send(dirMsg(0, "/x", entry(FileType.File, ".hidden", 1, 0, true), entry(FileType.File, "shown", 1)));
    expect((await p2)!.entries.map((e) => e.name)).toEqual([".hidden", "shown"]);
  });

  it("Windows 受控端：/ 列出磁碟機（DirDrive），上一層從 C:\\ 回到磁碟機清單", async () => {
    const { peer, s } = connect({}, { platform: "Windows" });
    peer.send(dirMsg(0, "C:\\Users\\alice", entry(FileType.Dir, "Desktop")));
    expect(s.windows).toBe(true);
    expect(s.parent("C:\\Users\\alice")).toBe("C:\\Users");
    expect(s.parent("C:\\")).toBe("/");
    expect(s.child("/", { type: FileType.DirDrive, name: "D:", hidden: false, size: 0, mtime: 0 })).toBe("D:\\");
    const p = s.list("/");
    expect(actions(peer)).toContainEqual({ type: "read_dir", path: "/", includeHidden: false });
    peer.send(dirMsg(0, "/", entry(FileType.DirDrive, "C:"), entry(FileType.DirDrive, "D:")));
    const l = await p;
    expect(l.drives).toBe(true);
    expect(l.entries.map((e) => e.name)).toEqual(["C:", "D:"]);
  });

  it("沒有 platform 也看得出是 Windows（家目錄是 C:\\ 開頭）", () => {
    const { peer, s } = connect({}, { platform: "" });
    peer.send(dirMsg(0, "C:\\Users\\bob"));
    expect(s.windows).toBe(true);
  });

  it("列目錄失敗（受控端回 error）：那一次的請求收到錯誤原文", async () => {
    const { peer, s } = connect();
    const p = s.list("/root");
    peer.send(encodeFileError(0, "Permission denied (os error 13)", 0));
    await expect(p).rejects.toMatchObject({ peerError: "Permission denied (os error 13)" });
  });
});

describe("下載（J.3）", () => {
  it("send → dir → digest → send_confirm(offset_blk 0) → block（含壓縮塊）→ done；稽核 ok", async () => {
    const { peer, s, ws } = connect();
    const sink = new MemSink();
    const job = s.download("/home/a/hello.txt", { name: "hello.txt", size: 30, sink: () => sink });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    expect(send).toMatchObject({ action: { type: "send", path: "/home/a/hello.txt", includeHidden: false, fileNum: 0,
                                           fileType: 0 } });
    const id = (send as { action: { id: number } }).action.id;
    expect(id).toBeGreaterThan(0);
    peer.send(dirMsg(id, "/home/a/hello.txt", entry(FileType.File, "", 30)));
    peer.send(digestMsg(id, 0, utf8("abc").length + utf8(HELLO).length));
    const confirm = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(confirm).toEqual({ side: "action", action: { type: "send_confirm", id, fileNum: 0, offsetBlk: 0 } });
    peer.send(blockMsg(id, 0, utf8("abc")));
    peer.send(blockMsg(id, 0, Z_HELLO, true));                 // compressed：zstd 解壓後才是檔案內容
    peer.send(encodeDone(id, 0));
    const v = await job.done;
    expect(v.status).toBe("done");
    expect(sink.closed).toBe(true);
    expect(sink.text()).toBe("abc" + HELLO);
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "download", path: "/home/a/hello.txt",
                                         size: sink.size, result: "ok" });
  });

  it("多個檔案：file_num 是清單的索引，每個檔案都有自己的 digest／confirm", async () => {
    const { peer, s } = connect();
    const sinks: MemSink[] = [];
    const names: string[] = [];
    const job = s.download("/d", { name: "d", size: 0, sink: (e) => { names.push(e.name); const k = new MemSink(); sinks.push(k); return k; } });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    const id = (send as { action: { id: number } }).action.id;
    peer.send(dirMsg(id, "/d", entry(FileType.File, "one.txt", 3), entry(FileType.File, "sub/two.txt", 3)));
    peer.send(digestMsg(id, 0, 3));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm" && m.action.fileNum === 0);
    peer.send(blockMsg(id, 0, utf8("111")));
    peer.send(digestMsg(id, 1, 3));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm" && m.action.fileNum === 1);
    peer.send(blockMsg(id, 1, utf8("222")));
    peer.send(encodeDone(id, 1));
    await job.done;
    expect(names).toEqual(["one.txt", "sub/two.txt"]);
    expect(sinks.map((k) => k.text())).toEqual(["111", "222"]);
    expect(sinks.every((k) => k.closed)).toBe(true);
  });

  it("略過：沒有存檔的地方（sink 回 null）就回 skip = true，不收那個檔案", async () => {
    const { peer, s } = connect();
    const job = s.download("/d", { name: "d", size: 0, sink: () => null });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    const id = (send as { action: { id: number } }).action.id;
    peer.send(dirMsg(id, "/d", entry(FileType.File, "x", 3)));
    peer.send(digestMsg(id, 0, 3));
    const c = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(c).toEqual({ side: "action", action: { type: "send_confirm", id, fileNum: 0, skip: true } });
    peer.send(encodeDone(id, 0));
    expect((await job.done).skipped).toBe(1);
  });

  it("受控端回錯誤：丟掉寫到一半的檔案，工作失敗，稽核 error", async () => {
    const { peer, s, ws } = connect();
    const sink = new MemSink();
    const job = s.download("/gone", { name: "gone", size: 5, sink: () => sink });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    const id = (send as { action: { id: number } }).action.id;
    peer.send(encodeFileError(id, "Not exists", 0));
    const v = await job.done;
    expect(v.status).toBe("error");
    expect(v.error).toBe("Not exists");
    expect(sink.closed).toBe(false);
    // size 是檔案的大小（受控端還沒給 digest 時用清單上的大小），不是收到的位元組數
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "download", path: "/gone", size: 5, result: "error" });
  });

  it("壓縮塊解壓後超過單塊上限：拒絕（不讓惡意資料吃光記憶體）", async () => {
    const { peer, s } = connect();
    const sink = new MemSink();
    const job = s.download("/z", { name: "z", size: 2 * MB, sink: () => sink });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    const id = (send as { action: { id: number } }).action.id;
    peer.send(dirMsg(id, "/z", entry(FileType.File, "z", 2 * MB)));
    peer.send(digestMsg(id, 0, 2 * MB));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    peer.send(blockMsg(id, 0, Z_B2M_FCS, true));
    const v = await job.done;
    expect(v.status).toBe("error");
    expect(sink.aborted).toBe(true);
    // 停下來時要告訴受控端（J.5 的 cancel），不然它會一直送
    expect(acc.concat(fileSent(peer))).toContainEqual({ side: "action", action: { type: "cancel", id } });
  });

  it("取消：送 FileAction.cancel、丟掉寫到一半的檔案，之後才到的資料塊不理；稽核 cancelled", async () => {
    const { peer, s, ws } = connect();
    const sink = new MemSink();
    const job = s.download("/big", { name: "big", size: 10, sink: () => sink });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    const id = (send as { action: { id: number } }).action.id;
    peer.send(dirMsg(id, "/big", entry(FileType.File, "big", 10)));
    peer.send(digestMsg(id, 0, 10));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    peer.send(blockMsg(id, 0, utf8("12345")));
    await vi.waitFor(() => expect(sink.size).toBe(5), { timeout: 2000, interval: 5 });
    s.cancel(job.key);
    expect(await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "cancel"))
      .toEqual({ side: "action", action: { type: "cancel", id } });
    peer.send(blockMsg(id, 0, utf8("67890")));               // 已經在路上的
    const v = await job.done;
    expect(v.status).toBe("cancelled");
    expect(sink.aborted).toBe(true);
    expect(sink.size).toBe(5);
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "download", path: "/big", size: 10, result: "cancelled" });
  });

  it("一次一個傳輸工作：第二個排隊，第一個結束才送出它的請求", async () => {
    const { peer, s } = connect();
    const j1 = s.download("/a", { name: "a", size: 1, sink: () => new MemSink() });
    const j2 = s.download("/b", { name: "b", size: 1, sink: () => new MemSink() });
    const acc: Sent[] = [];
    const send1 = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    expect(s.jobs.map((j) => j.status)).toEqual(["running", "queued"]);
    acc.push(...fileSent(peer));
    expect(acc.some((m) => m.side === "action" && m.action.type === "send")).toBe(false);
    const id1 = (send1 as { action: { id: number } }).action.id;
    peer.send(encodeFileError(id1, "Not exists", 0));
    await j1.done;
    const send2 = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    expect(send2).toMatchObject({ action: { path: "/b" } });
    const id2 = (send2 as { action: { id: number } }).action.id;
    expect(id2).not.toBe(id1);
    peer.send(encodeFileError(id2, "Not exists", 0));
    await j2.done;
  });

  it("連線斷掉：進行中的工作失敗、檔案丟掉", async () => {
    const { peer, s, ws } = connect();
    const sink = new MemSink();
    const job = s.download("/a", { name: "a", size: 3, sink: () => sink });
    const acc: Sent[] = [];
    const send = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send");
    const id = (send as { action: { id: number } }).action.id;
    peer.send(dirMsg(id, "/a", entry(FileType.File, "a", 3)));
    peer.send(digestMsg(id, 0, 3));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    ws.drop();
    expect((await job.done).status).toBe("error");
    expect(sink.aborted).toBe(true);
  });
});

describe("上傳（J.4）", () => {
  it("receive → digest(is_upload) → 受控端 send_confirm → 128 KiB 一塊 → done；稽核 ok", async () => {
    const { peer, s, ws } = connect();
    const data = new Uint8Array(300 * 1024).map((_, i) => i & 255);
    const job = s.upload("/home/a", [source("big.bin", data)]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const r = (recv as { action: Extract<FileAction, { type: "receive" }> }).action;
    expect(r.path).toBe("/home/a");
    expect(r.totalSize).toBe(data.length);
    expect(r.files).toEqual([{ type: FileType.File, name: "big.bin", hidden: false, size: data.length,
                               mtime: 1_700_000_000 }]);
    const d = await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest");
    expect(d).toEqual({ side: "response", response: { type: "digest", id: r.id, fileNum: 0,
                        lastModified: 1_700_000_000, fileSize: data.length, isUpload: true, isIdentical: false } });
    // 受控端還沒回之前不送資料
    acc.push(...fileSent(peer));
    expect(acc.some((m) => m.side === "response" && m.response.type === "block")).toBe(false);
    peer.send(peerConfirm(r.id, 0));
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "done");
    const blocks = acc.filter((m) => m.side === "response" && m.response.type === "block")
      .map((m) => (m as { response: Extract<FileResponse, { type: "block" }> }).response);
    expect(blocks.map((b) => b.data.length)).toEqual([131072, 131072, 300 * 1024 - 262144]);
    expect(blocks.every((b) => b.fileNum === 0 && !b.compressed && b.id === r.id)).toBe(true);
    expect(concat(...blocks.map((b) => b.data))).toEqual(data);
    const v = await job.done;
    expect(v.status).toBe("done");
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "upload", path: "/home/a/big.bin", size: data.length,
                                         result: "ok" });
  });

  it("同名：受控端回 digest（is_identical）→ 問使用者；覆蓋送 offset_blk 0、略過送 skip，選了「全部」就不再問", async () => {
    const asked: ConflictInfo[] = [];
    const answers: ConflictAnswer[] = [{ action: "overwrite", all: false }, { action: "skip", all: true }];
    const { peer, s, ws } = connect({ conflict: async (c) => { asked.push(c); return answers.shift()!; } });
    const job = s.upload("/up", [source("a", utf8("A")), source("b", utf8("BB")), source("c", utf8("CCC"))]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const id = (recv as { action: { id: number } }).action.id;
    // a：同名而且一樣 → 覆蓋
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest" && m.response.fileNum === 0);
    peer.send(digestMsg(id, 0, 1, { upload: true, identical: true }));
    const c0 = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(c0).toEqual({ side: "action", action: { type: "send_confirm", id, fileNum: 0, offsetBlk: 0 } });
    expect(asked[0]).toMatchObject({ name: "a", identical: true, remaining: 2 });
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "block" && m.response.fileNum === 0);
    // b：同名 → 略過（全部略過）
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest" && m.response.fileNum === 1);
    peer.send(digestMsg(id, 1, 5, { upload: true }));
    const c1 = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(c1).toEqual({ side: "action", action: { type: "send_confirm", id, fileNum: 1, skip: true } });
    // c：同名 → 不再問，照「全部略過」
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest" && m.response.fileNum === 2);
    peer.send(digestMsg(id, 2, 9, { upload: true }));
    const c2 = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(c2).toEqual({ side: "action", action: { type: "send_confirm", id, fileNum: 2, skip: true } });
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "done");
    expect(acc.some((m) => m.side === "response" && m.response.type === "block" && m.response.fileNum !== 0)).toBe(false);
    expect(asked).toHaveLength(2);
    const v = await job.done;
    expect(v.skipped).toBe(2);
    const audits = ws.sentText.filter((x) => x.t === "file_audit");
    expect(audits).toEqual([{ t: "file_audit", op: "upload", path: "/up/a", size: 1, result: "ok" }]);
  });

  it("同名時受控端回的 digest 沒有大小與時間（實機 1.4.1）：詢問用這次上傳的檔名與大小，不拿受控端的 0 當大小", async () => {
    const asked: ConflictInfo[] = [];
    const { peer, s } = connect({ conflict: async (c) => { asked.push(c); return { action: "skip", all: false }; } });
    const job = s.upload("/root", [source("jt-up.txt", utf8("x".repeat(26)))]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const id = (recv as { action: { id: number } }).action.id;
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest");
    // 只有 id、file_num 與 is_identical：file_size、last_modified 都是 0
    peer.send(fMsg(MSG_FILE_RESPONSE, fMsg(5, concat(fVarint(1, id), fBool(5, true), fBool(6, true)))));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(asked).toEqual([{ name: "jt-up.txt", size: 26, identical: true, remaining: 0 }]);
    expect((await job.done).skipped).toBe(1);
  });

  it("受控端的 digest 帶了大小與修改時間：另外附上（peerSize、peerModified），檔名與大小仍以這次上傳的為準", async () => {
    const asked: ConflictInfo[] = [];
    const { peer, s } = connect({ conflict: async (c) => { asked.push(c); return { action: "skip", all: false }; } });
    const job = s.upload("/root", [source("a.txt", utf8("abc"))]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const id = (recv as { action: { id: number } }).action.id;
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest");
    peer.send(digestMsg(id, 0, 999, { upload: true }));
    await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(asked).toEqual([{ name: "a.txt", size: 3, identical: false, remaining: 0, peerSize: 999,
                             peerModified: 1_700_000_000 }]);
    await job.done;
  });

  it("只有一個檔案時，受控端 digest 的 file_num 對不上也照樣問（用這個工作唯一的檔案）", async () => {
    const asked: ConflictInfo[] = [];
    const { peer, s } = connect({ conflict: async (c) => { asked.push(c); return { action: "overwrite", all: false }; } });
    const job = s.upload("/root", [source("one.bin", utf8("12345"))]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const id = (recv as { action: { id: number } }).action.id;
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest");
    peer.send(digestMsg(id, 7, 0, { upload: true }));
    const c = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "send_confirm");
    expect(c).toEqual({ side: "action", action: { type: "send_confirm", id, fileNum: 0, offsetBlk: 0 } });
    expect(asked[0]).toMatchObject({ name: "one.bin", size: 5 });
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "done");
    expect((await job.done).status).toBe("done");
  });

  it("寫入失敗（受控端回 error）：停止送出，工作失敗", async () => {
    const { peer, s, ws } = connect();
    const job = s.upload("/ro", [source("x", utf8("data"))]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const id = (recv as { action: { id: number } }).action.id;
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest");
    peer.send(encodeFileError(id, "one-way-file-transfer-tip", 0));
    const v = await job.done;
    expect(v.status).toBe("error");
    expect(v.error).toBe("one-way-file-transfer-tip");
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "upload", path: "/ro/x", size: 4, result: "error" });
  });

  it("取消上傳：送 cancel、停止送資料；稽核 cancelled", async () => {
    const { peer, s, ws } = connect();
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => { release = r; });
    const data = new Uint8Array(400 * 1024);
    const slow: UploadSource = { name: "slow", size: data.length, lastModified: 0,
                                 read: async (off, len) => { if (off > 0) await gate; return data.slice(off, off + len); } };
    const job = s.upload("/u", [slow]);
    const acc: Sent[] = [];
    const recv = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "receive");
    const id = (recv as { action: { id: number } }).action.id;
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "digest");
    peer.send(peerConfirm(id, 0));
    await nextSent(peer, acc, (m) => m.side === "response" && m.response.type === "block");
    s.cancel(job.key);
    release();
    expect(await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "cancel"))
      .toEqual({ side: "action", action: { type: "cancel", id } });
    const v = await job.done;
    expect(v.status).toBe("cancelled");
    acc.push(...fileSent(peer));
    expect(acc.some((m) => m.side === "response" && m.response.type === "done")).toBe(false);
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "upload", path: "/u/slow", size: data.length,
                                         result: "cancelled" });
  });

  it("超過伺服器設定的上限就不送（單檔、單次總量）", () => {
    const limits = { maxFileBytes: 10, maxTotalBytes: 15 };
    const a = source("a", new Uint8Array(8));
    const b = source("b", new Uint8Array(11));
    const c = source("c", new Uint8Array(8));
    expect(checkUploadLimits([a, b], limits)).toEqual({ ok: [a], tooLarge: ["b"], totalTooLarge: false });
    expect(checkUploadLimits([a, c], limits)).toEqual({ ok: [a, c], tooLarge: [], totalTooLarge: true });
    // 畫面會先用 checkUploadLimits 篩過；連線本身也再檢查一次（不送超過上限的）
    const { s } = connect({}, { limits });
    expect(() => s.upload("/x", [b])).toThrow();
    expect(() => s.upload("/x", [a, c])).toThrow();
  });
});

describe("建立、改名、刪除（J.5）", () => {
  it("建立目錄、改名、刪除檔案：成功回 done；稽核 mkdir／rename／delete", async () => {
    const { peer, s, ws } = connect();
    const acc: Sent[] = [];
    const p1 = s.mkdir("/home/a/new");
    const create = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "create");
    const cid = (create as { action: { id: number } }).action.id;
    expect(create).toEqual({ side: "action", action: { type: "create", id: cid, path: "/home/a/new" } });
    peer.send(encodeDone(cid, 0));
    await p1;
    const p2 = s.rename("/home/a/old.txt", "new.txt");
    const rn = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "rename");
    const rid = (rn as { action: { id: number } }).action.id;
    expect(rn).toEqual({ side: "action", action: { type: "rename", id: rid, path: "/home/a/old.txt", newName: "new.txt" } });
    peer.send(encodeDone(rid, 0));
    await p2;
    const p3 = s.remove({ path: "/home/a/f.bin", dir: false, size: 42 });
    const rf = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "remove_file");
    const fid = (rf as { action: { id: number } }).action.id;
    expect(rf).toEqual({ side: "action", action: { type: "remove_file", id: fid, path: "/home/a/f.bin", fileNum: 0 } });
    peer.send(encodeDone(fid, 0));
    await p3;
    const audits = ws.sentText.filter((x) => x.t === "file_audit");
    expect(audits).toEqual([
      { t: "file_audit", op: "mkdir", path: "/home/a/new", result: "ok" },
      { t: "file_audit", op: "rename", path: "/home/a/old.txt", to: "/home/a/new.txt", result: "ok" },
      { t: "file_audit", op: "delete", path: "/home/a/f.bin", size: 42, result: "ok" },
    ]);
  });

  it("改名失敗（來源不存在）：錯誤原文給畫面，稽核 error", async () => {
    const { peer, s, ws } = connect();
    const acc: Sent[] = [];
    const p = s.rename("/x/nope", "y");
    const rn = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "rename");
    peer.send(encodeFileError((rn as { action: { id: number } }).action.id, "/x/nope not exists", 0));
    await expect(p).rejects.toMatchObject({ peerError: "/x/nope not exists" });
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "rename", path: "/x/nope", to: "/x/y", result: "error" });
  });

  it("刪除整個資料夾：all_files 取得整棵 → 逐一 remove_file → remove_dir（recursive）", async () => {
    const { peer, s, ws } = connect();
    const acc: Sent[] = [];
    const p = s.remove({ path: "/data/old", dir: true, size: 0 });
    const all = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "all_files");
    const aid = (all as { action: { id: number } }).action.id;
    expect(all).toEqual({ side: "action", action: { type: "all_files", id: aid, path: "/data/old", includeHidden: true } });
    peer.send(dirMsg(aid, "/data/old", entry(FileType.File, "a.txt", 5), entry(FileType.File, "sub/.b", 7, 0, true)));
    for (const [i, path] of ["/data/old/a.txt", "/data/old/sub/.b"].entries()) {
      const rf = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "remove_file");
      expect(rf).toMatchObject({ action: { type: "remove_file", path, fileNum: i } });
      peer.send(encodeDone((rf as { action: { id: number } }).action.id, i));
    }
    const rd = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "remove_dir");
    expect(rd).toMatchObject({ action: { type: "remove_dir", path: "/data/old", recursive: true } });
    peer.send(encodeDone((rd as { action: { id: number } }).action.id, 0));
    await p;
    expect(ws.sentText).toContainEqual({ t: "file_audit", op: "delete", path: "/data/old", size: 12, result: "ok" });
  });
});

describe("稽核訊息（J.6）", () => {
  it("路徑截到 512 個字元；不帶檔案內容", async () => {
    const { peer, s, ws } = connect();
    const long = "/" + "長".repeat(700);
    const acc: Sent[] = [];
    const p = s.mkdir(long);
    const c = await nextSent(peer, acc, (m) => m.side === "action" && m.action.type === "create");
    peer.send(encodeDone((c as { action: { id: number } }).action.id, 0));
    await p;
    const a = ws.sentText.find((x) => x.t === "file_audit")!;
    expect(Array.from(String(a.path)).length).toBe(512);
    expect(Object.keys(a).sort()).toEqual(["op", "path", "result", "t"]);
  });
});

describe("保活（J.1）", () => {
  it("受控端沒送 TestDelay 時，10 秒沒送東西就主動送一則（from_client = true）", () => {
    vi.useFakeTimers();
    const { peer } = connect();
    peer.send(dirMsg(0, "/home/a"));
    peer.drain();
    vi.advanceTimersByTime(11_000);
    const sent = peer.drain().map((p) => parse(p));
    const td = sent.find((f) => f.has(5));
    expect(td).toBeDefined();
    expect(parse(td!.get(5)![0] as Uint8Array).get(2)![0]).toBe(1n);
  });

  it("受控端 20 秒沒有任何訊息：用 read_dir 探一下；到 30 秒還沒有就結束（rd_file_timeout）", () => {
    vi.useFakeTimers();
    const { peer, closes } = connect();
    peer.send(dirMsg(0, "/home/a"));
    peer.drain();
    vi.advanceTimersByTime(21_000);
    expect(actions(peer)).toContainEqual({ type: "read_dir", path: "/home/a", includeHidden: false });
    vi.advanceTimersByTime(10_000);
    expect(closes[0]?.code).toBe("rd_file_timeout");
  });

  it("有回應就不會逾時", () => {
    vi.useFakeTimers();
    const { peer, closes } = connect();
    peer.send(dirMsg(0, "/home/a"));
    for (let i = 0; i < 6; i++) {
      vi.advanceTimersByTime(15_000);
      peer.send(fMsg(5, concat(fVarint(1, 1), fVarint(3, 5))));      // 受控端的 TestDelay
    }
    expect(closes).toHaveLength(0);
  });
});
