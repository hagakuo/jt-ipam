/**
 * 相容 RustDesk 的網頁連線：檔案傳輸的訊息編解碼與路徑處理（規格附錄 J.1～J.5、J.7 的單元測試）。
 * 欄位編號與型別照規格：file_num 在 digest／send_confirm／block 是 sint32（zigzag），send 的 file_num 是 int32；
 * send_confirm 的 offset_blk 在 oneof 裡，0 也要寫出。
 */
import { describe, expect, it } from "vitest";
import { concat, fBool, fBytes, fMsg, fStr, fVarint, getBool, getStr, parse } from "../pb";
import {
  baseName, decodeFileMessage, encodeAllFiles, encodeBlock, encodeCancel, encodeCreate, encodeDigest, encodeDone,
  encodeFileError, encodeFileLoginRequest, encodeReadDir, encodeReceive, encodeRemoveDir, encodeRemoveFile,
  encodeRename, encodeSend, encodeSendConfirm, FileType, isWindowsPath, joinPath, parentPath, parseFileAction,
  parseFileResponse, safeDownloadName, MSG_FILE_ACTION, MSG_FILE_RESPONSE,
} from "../files";

const bytes = (...b: number[]) => Uint8Array.from(b);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Message → (欄位, 子訊息)：檔案訊息一律包在 Message.file_action (17) 或 file_response (18) 底下 */
function unwrap(msg: Uint8Array): { field: number; body: Uint8Array } {
  const f = parse(msg);
  const field = [...f.keys()][0];
  return { field, body: f.get(field)![0] as Uint8Array };
}

describe("FileAction 的編碼（控制端 → 受控端）", () => {
  it("read_dir（1）：ReadDir { path, include_hidden }；家目錄填空字串，子訊息也要寫出", () => {
    const m = unwrap(encodeReadDir("/home/a", true));
    expect(m.field).toBe(MSG_FILE_ACTION);
    expect(parseFileAction(m.body)).toEqual({ type: "read_dir", path: "/home/a", includeHidden: true });
    // 家目錄：path 是空字串、沒有勾隱藏檔，ReadDir 本身是空的，但 FileAction.read_dir 欄位還是要在
    const home = encodeReadDir("", false);
    expect(hex(home)).toBe("8a01020a00");
    expect(parseFileAction(unwrap(home).body)).toEqual({ type: "read_dir", path: "", includeHidden: false });
  });

  it("send（2）：id、path、include_hidden、file_num（int32）、file_type（Generic = 0）", () => {
    const m = unwrap(encodeSend({ id: 7, path: "C:\\a.txt", includeHidden: false, fileNum: 0 }));
    expect(m.field).toBe(MSG_FILE_ACTION);
    expect(parseFileAction(m.body)).toEqual({
      type: "send", id: 7, path: "C:\\a.txt", includeHidden: false, fileNum: 0, fileType: 0 });
  });

  it("receive（3）：目的目錄、檔案清單（相對路徑、大小、修改時間）、total_size", () => {
    const m = unwrap(encodeReceive({
      id: 3, path: "/tmp/up", fileNum: 0, totalSize: 300_000,
      files: [{ type: FileType.File, name: "a.bin", hidden: false, size: 100_000, mtime: 1_700_000_000 },
              { type: FileType.File, name: "b.bin", hidden: false, size: 200_000, mtime: 1_700_000_001 }],
    }));
    const a = parseFileAction(m.body);
    expect(a).toEqual({
      type: "receive", id: 3, path: "/tmp/up", fileNum: 0, totalSize: 300_000,
      files: [{ type: FileType.File, name: "a.bin", hidden: false, size: 100_000, mtime: 1_700_000_000 },
              { type: FileType.File, name: "b.bin", hidden: false, size: 200_000, mtime: 1_700_000_001 }],
    });
  });

  it("create（4）、remove_dir（5）、remove_file（6）、all_files（7）、cancel（8）、rename（10）", () => {
    expect(parseFileAction(unwrap(encodeCreate(4, "/x/y/z")).body)).toEqual({ type: "create", id: 4, path: "/x/y/z" });
    expect(parseFileAction(unwrap(encodeRemoveDir(5, "/x", true)).body))
      .toEqual({ type: "remove_dir", id: 5, path: "/x", recursive: true });
    expect(parseFileAction(unwrap(encodeRemoveFile(6, "/x/f", 2)).body))
      .toEqual({ type: "remove_file", id: 6, path: "/x/f", fileNum: 2 });
    expect(parseFileAction(unwrap(encodeAllFiles(8, "/x", true)).body))
      .toEqual({ type: "all_files", id: 8, path: "/x", includeHidden: true });
    expect(parseFileAction(unwrap(encodeCancel(9)).body)).toEqual({ type: "cancel", id: 9 });
    expect(parseFileAction(unwrap(encodeRename(10, "/x/old", "new")).body))
      .toEqual({ type: "rename", id: 10, path: "/x/old", newName: "new" });
  });

  it("send_confirm（9）：file_num 是 sint32；offset_blk = 0 在 oneof 裡也要寫出；略過是 skip = true", () => {
    const go = unwrap(encodeSendConfirm(1, 1, { offsetBlk: 0 }));
    expect(go.field).toBe(MSG_FILE_ACTION);
    // FileAction.send_confirm (9) { id=1 (08 01), file_num=1 → zigzag 2 (10 02), offset_blk=0 (20 00) }
    expect(hex(go.body)).toBe("4a06080110022000");
    expect(parseFileAction(go.body)).toEqual({ type: "send_confirm", id: 1, fileNum: 1, offsetBlk: 0 });
    const skip = unwrap(encodeSendConfirm(1, 0, { skip: true }));
    expect(parseFileAction(skip.body)).toEqual({ type: "send_confirm", id: 1, fileNum: 0, skip: true });
  });

  it("認不得的 FileAction 不丟例外", () => {
    expect(parseFileAction(fMsg(99, bytes()))).toEqual({ type: "other" });
  });
});

describe("FileResponse 的編解碼", () => {
  it("dir（1）：FileDirectory { id, path, entries }；FileEntry 的型別、隱藏、大小與修改時間", () => {
    const entry = (t: number, name: string, size = 0, mtime = 0, hidden = false) =>
      fMsg(3, concat(fVarint(1, t), fStr(2, name), fBool(3, hidden), fVarint(4, size), fVarint(5, mtime)));
    const body = fMsg(1, concat(fVarint(1, 12), fStr(2, "/home/u"),
                                entry(FileType.Dir, "docs"), entry(FileType.File, "a.txt", 5_000_000_000, 1_700_000_000),
                                entry(FileType.FileLink, ".rc", 10, 5, true), entry(FileType.DirDrive, "C:")));
    const r = parseFileResponse(body);
    expect(r).toEqual({
      type: "dir", dir: { id: 12, path: "/home/u", entries: [
        { type: FileType.Dir, name: "docs", hidden: false, size: 0, mtime: 0 },
        { type: FileType.File, name: "a.txt", hidden: false, size: 5_000_000_000, mtime: 1_700_000_000 },
        { type: FileType.FileLink, name: ".rc", hidden: true, size: 10, mtime: 5 },
        { type: FileType.DirDrive, name: "C:", hidden: false, size: 0, mtime: 0 },
      ] },
    });
  });

  it("digest（5）：上傳時由控制端送（is_upload = true）；file_num 是 sint32", () => {
    const m = unwrap(encodeDigest({ id: 2, fileNum: 3, lastModified: 1_700_000_000, fileSize: 1234,
                                    isUpload: true, isIdentical: false }));
    expect(m.field).toBe(MSG_FILE_RESPONSE);
    const inner = parse(parse(m.body).get(5)![0] as Uint8Array);
    expect(inner.get(2)![0]).toBe(6n);                 // zigzag(3)
    expect(parseFileResponse(m.body)).toEqual({ type: "digest", id: 2, fileNum: 3, lastModified: 1_700_000_000,
                                                fileSize: 1234, isUpload: true, isIdentical: false });
  });

  it("block（2）：data、compressed；blk_id 一律不寫", () => {
    const data = bytes(1, 2, 3, 4);
    const m = unwrap(encodeBlock({ id: 2, fileNum: 1, data, compressed: false }));
    expect(m.field).toBe(MSG_FILE_RESPONSE);
    const inner = parse(parse(m.body).get(2)![0] as Uint8Array);
    expect(inner.has(5)).toBe(false);
    expect(inner.get(2)![0]).toBe(2n);                 // zigzag(1)
    const r = parseFileResponse(m.body);
    expect(r).toMatchObject({ type: "block", id: 2, fileNum: 1, compressed: false });
    if (r.type === "block") expect(Array.from(r.data)).toEqual([1, 2, 3, 4]);
    const z = parseFileResponse(fMsg(2, concat(fVarint(1, 2), fBytes(3, data), fBool(4, true))));
    expect(z).toMatchObject({ type: "block", id: 2, fileNum: 0, compressed: true });
  });

  it("done（4）與 error（3）", () => {
    expect(parseFileResponse(unwrap(encodeDone(5, 1)).body)).toEqual({ type: "done", id: 5, fileNum: 1 });
    expect(parseFileResponse(unwrap(encodeFileError(5, "Not exists", 0)).body))
      .toEqual({ type: "error", id: 5, error: "Not exists", fileNum: 0 });
  });

  it("decodeFileMessage 只認 Message 的 17 與 18，其他回 null", () => {
    expect(decodeFileMessage(encodeCancel(1))).toEqual({ side: "action", action: { type: "cancel", id: 1 } });
    expect(decodeFileMessage(encodeDone(2, 0))).toEqual({ side: "response", response: { type: "done", id: 2, fileNum: 0 } });
    expect(decodeFileMessage(fMsg(5, bytes()))).toBeNull();          // TestDelay
    expect(decodeFileMessage(bytes(0xff))).toBeNull();               // 壞掉的不丟例外
  });
});

describe("LoginRequest：union file_transfer（7）", () => {
  it("填 FileTransfer { dir, show_hidden }，不填遠端桌面的 option（6）", () => {
    const m = encodeFileLoginRequest({ peerId: "123456789", password: new Uint8Array(32).fill(1), myId: "jt-ipam",
                                       myName: "alice (jt-ipam)", sessionId: 42n, version: "1.4.1",
                                       dir: "/home/a", showHidden: true });
    const f = parse(parse(m).get(7)![0] as Uint8Array);
    expect(getStr(f, 1)).toBe("123456789");
    expect((f.get(2)![0] as Uint8Array).length).toBe(32);
    expect(getStr(f, 4)).toBe("jt-ipam");
    expect(getStr(f, 5)).toBe("alice (jt-ipam)");
    expect(f.get(10)![0]).toBe(42n);
    expect(getStr(f, 11)).toBe("1.4.1");
    expect(getStr(f, 13)).toBe("Web");
    expect(f.has(6)).toBe(false);
    const ft = parse(f.get(7)![0] as Uint8Array);
    expect(getStr(ft, 1)).toBe("/home/a");
    expect(getBool(ft, 2)).toBe(true);
  });

  it("家目錄、不顯示隱藏檔時 FileTransfer 是空的，但欄位 7 還是要在（不然就是遠端桌面）", () => {
    const m = encodeFileLoginRequest({ peerId: "1", password: new Uint8Array(0), myId: "jt-ipam", myName: "a",
                                       sessionId: 1n, version: "1.4.1", dir: "", showHidden: false });
    const f = parse(parse(m).get(7)![0] as Uint8Array);
    expect(f.has(7)).toBe(true);
    expect((f.get(7)![0] as Uint8Array).length).toBe(0);
    expect(f.has(2)).toBe(false);                   // 沒有密碼（等對方同意）
  });
});

describe("路徑", () => {
  it("Windows：最上層 / 是磁碟機清單，C: 進去是 C:\\", () => {
    expect(isWindowsPath("C:\\Users\\a")).toBe(true);
    expect(isWindowsPath("C:")).toBe(true);
    expect(isWindowsPath("/home/a")).toBe(false);
    expect(joinPath("/", "C:", true)).toBe("C:\\");
    expect(joinPath("C:\\", "Users", true)).toBe("C:\\Users");
    expect(joinPath("C:\\Users", "a b.txt", true)).toBe("C:\\Users\\a b.txt");
    expect(parentPath("C:\\Users\\a", true)).toBe("C:\\Users");
    expect(parentPath("C:\\Users", true)).toBe("C:\\");
    expect(parentPath("C:\\", true)).toBe("/");
    expect(parentPath("D:", true)).toBe("/");
    expect(parentPath("/", true)).toBeNull();
  });

  it("Linux／macOS：/ 就是根目錄", () => {
    expect(joinPath("/", "etc", false)).toBe("/etc");
    expect(joinPath("/etc/", "hosts", false)).toBe("/etc/hosts");
    expect(parentPath("/etc/ssh", false)).toBe("/etc");
    expect(parentPath("/etc", false)).toBe("/");
    expect(parentPath("/", false)).toBeNull();
    expect(baseName("/etc/ssh/sshd_config")).toBe("sshd_config");
    expect(baseName("C:\\a\\b.txt")).toBe("b.txt");
  });

  it("下載的檔名只留最後一段，去掉路徑分隔與控制字元（含雙向文字覆寫）", () => {
    expect(safeDownloadName("report.pdf")).toBe("report.pdf");
    expect(safeDownloadName("../../etc/passwd")).toBe("passwd");
    expect(safeDownloadName("C:\\Windows\\win.ini")).toBe("win.ini");
    expect(safeDownloadName("a\u0000b\u001fc\u007f.txt")).toBe("abc.txt");
    expect(safeDownloadName("evil\u202Etxt.exe")).toBe("eviltxt.exe");
    expect(safeDownloadName("..")).toBe("download");
    expect(safeDownloadName("")).toBe("download");
    expect(safeDownloadName("/")).toBe("download");
    expect(safeDownloadName("a:b*c?.txt")).toBe("a_b_c_.txt");
    expect(safeDownloadName("x".repeat(400)).length).toBeLessThanOrEqual(200);
  });
});
