/**
 * 相容 RustDesk 的網頁連線：檔案傳輸的訊息（規格附錄 J.1～J.5）與路徑處理。
 *
 * 唯一依據是 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 J。欄位編號與型別照規格，名稱自取：
 * - 所有檔案訊息在 Message.file_action（17）與 Message.file_response（18）之下（J.1）。上傳時方向相反的那幾則
 *   （控制端送 digest／block／done，受控端回 send_confirm）用的也是同樣的欄位（J.4）
 * - file_num 在 digest、send_confirm、block 是 sint32（zigzag）；send 的 file_num 是 int32。規格沒寫型別的
 *   （receive、remove_file、done、error 的 file_num）照一般數值（int32）處理
 * - send_confirm 的 skip／offset_blk 在 oneof 裡：offset_blk = 0 也要寫出，對方才知道是「要傳」
 * - 檔案傳輸的 LoginRequest 填 union file_transfer（7），不填遠端桌面的 option（J.1）
 *
 * 受控端送來的檔名與路徑只拿來顯示與當下載的檔名（下載檔名先經過 safeDownloadName）。
 */
import {
  concat, fBool, fBytes, fMsg, fSint, fStr, fVarint, fVarintAlways, getBig, getBool, getBytes, getInt, getMsgs,
  getSint, getStr, has, oneof, parse, PbError, type Fields,
} from "./pb";

/** Message 的欄位（J.1） */
export const MSG_FILE_ACTION = 17;
export const MSG_FILE_RESPONSE = 18;

/** J.3：每塊最多 128 KiB（上傳時我們也照這個大小切） */
export const BLOCK_SIZE = 128 * 1024;

/** FileType（J.2；沒有 1） */
export const FileType = { Dir: 0, DirLink: 2, DirDrive: 3, File: 4, FileLink: 5 } as const;

export function isDirType(t: number): boolean {
  return t === FileType.Dir || t === FileType.DirLink || t === FileType.DirDrive;
}

/** FileEntry { entry_type (1), name (2), is_hidden (3), size (4) uint64, modified_time (5) uint64（Unix 秒） } */
export interface FileEntry {
  type: number;
  name: string;
  hidden: boolean;
  size: number;
  mtime: number;
}

/** FileDirectory { id (1) int32, path (2), entries (3) } */
export interface FileDirectory {
  id: number;
  path: string;
  entries: FileEntry[];
}

const FA = { read_dir: 1, send: 2, receive: 3, create: 4, remove_dir: 5, remove_file: 6, all_files: 7, cancel: 8,
             send_confirm: 9, rename: 10 } as const;
const FR = { dir: 1, block: 2, error: 3, done: 4, digest: 5 } as const;

/** uint64 → number（檔案大小、秒數都遠小於 2^53） */
function getU64(f: Fields, field: number): number {
  return Number(BigInt.asUintN(64, getBig(f, field)));
}

function action(field: number, body: Uint8Array): Uint8Array {
  return fMsg(MSG_FILE_ACTION, fMsg(field, body));
}

function response(field: number, body: Uint8Array): Uint8Array {
  return fMsg(MSG_FILE_RESPONSE, fMsg(field, body));
}

function encodeEntry(e: FileEntry): Uint8Array {
  return concat(fVarint(1, e.type), fStr(2, e.name), fBool(3, e.hidden), fVarint(4, e.size), fVarint(5, e.mtime));
}

function parseEntry(f: Fields): FileEntry {
  return { type: getInt(f, 1), name: getStr(f, 2), hidden: getBool(f, 3), size: getU64(f, 4), mtime: getU64(f, 5) };
}

function parseDirectory(body: Uint8Array): FileDirectory {
  const f = parse(body);
  return { id: getInt(f, 1), path: getStr(f, 2), entries: getMsgs(f, 3).map(parseEntry) };
}

// ── FileAction（控制端 → 受控端；send_confirm 在上傳時由受控端送來）──

/** J.2：ReadDir { path (1), include_hidden (2) }。家目錄填空字串；Windows 的磁碟機清單填 "/"。 */
export function encodeReadDir(path: string, includeHidden: boolean): Uint8Array {
  return action(FA.read_dir, concat(fStr(1, path), fBool(2, includeHidden)));
}

/** J.3：FileTransferSendRequest { id, path, include_hidden, file_num (int32), file_type（Generic = 0） } */
export function encodeSend(o: { id: number; path: string; includeHidden: boolean; fileNum: number }): Uint8Array {
  return action(FA.send, concat(fVarint(1, o.id), fStr(2, o.path), fBool(3, o.includeHidden), fVarint(4, o.fileNum),
                                fVarint(5, 0)));
}

/** J.4：FileTransferReceiveRequest { id, path（受控端的目的目錄）, files, file_num, total_size } */
export function encodeReceive(o: { id: number; path: string; files: FileEntry[]; fileNum: number;
                                   totalSize: number }): Uint8Array {
  return action(FA.receive, concat(fVarint(1, o.id), fStr(2, o.path), ...o.files.map((e) => fMsg(3, encodeEntry(e))),
                                   fVarint(4, o.fileNum), fVarint(5, o.totalSize)));
}

/** J.5：FileDirCreate { id, path }（會建立中間的目錄） */
export function encodeCreate(id: number, path: string): Uint8Array {
  return action(FA.create, concat(fVarint(1, id), fStr(2, path)));
}

/** J.5：FileRemoveDir { id, path, recursive } */
export function encodeRemoveDir(id: number, path: string, recursive: boolean): Uint8Array {
  return action(FA.remove_dir, concat(fVarint(1, id), fStr(2, path), fBool(3, recursive)));
}

/** J.5：FileRemoveFile { id, path, file_num } */
export function encodeRemoveFile(id: number, path: string, fileNum: number): Uint8Array {
  return action(FA.remove_file, concat(fVarint(1, id), fStr(2, path), fVarint(3, fileNum)));
}

/** J.5：ReadAllFiles { id, path, include_hidden }（回 FileResponse.dir：整棵的檔案清單） */
export function encodeAllFiles(id: number, path: string, includeHidden: boolean): Uint8Array {
  return action(FA.all_files, concat(fVarint(1, id), fStr(2, path), fBool(3, includeHidden)));
}

/** J.5：FileTransferCancel { id }（沒有回覆） */
export function encodeCancel(id: number): Uint8Array {
  return action(FA.cancel, fVarint(1, id));
}

/** J.3／J.4：FileTransferSendConfirmRequest { id, file_num (sint32), oneof { skip (3), offset_blk (4) } } */
export function encodeSendConfirm(id: number, fileNum: number, how: { skip: true } | { offsetBlk: number }): Uint8Array {
  const tail = "skip" in how ? fBool(3, true) : fVarintAlways(4, how.offsetBlk);
  return action(FA.send_confirm, concat(fVarint(1, id), fSint(2, fileNum), tail));
}

/** J.5：FileRename { id, path, new_name }（同一個目錄內） */
export function encodeRename(id: number, path: string, newName: string): Uint8Array {
  return action(FA.rename, concat(fVarint(1, id), fStr(2, path), fStr(3, newName)));
}

export type FileAction =
  | { type: "read_dir"; path: string; includeHidden: boolean }
  | { type: "send"; id: number; path: string; includeHidden: boolean; fileNum: number; fileType: number }
  | { type: "receive"; id: number; path: string; files: FileEntry[]; fileNum: number; totalSize: number }
  | { type: "create"; id: number; path: string }
  | { type: "remove_dir"; id: number; path: string; recursive: boolean }
  | { type: "remove_file"; id: number; path: string; fileNum: number }
  | { type: "all_files"; id: number; path: string; includeHidden: boolean }
  | { type: "cancel"; id: number }
  | { type: "send_confirm"; id: number; fileNum: number; skip?: boolean; offsetBlk?: number }
  | { type: "rename"; id: number; path: string; newName: string }
  | { type: "other" };

/** FileAction 的 oneof 內容（不含 Message 外層）。 */
export function parseFileAction(body: Uint8Array): FileAction {
  const f = parse(body);
  const which = oneof(f, Object.values(FA));
  if (which === null) return { type: "other" };
  const s = parse(getBytes(f, which));
  switch (which) {
    case FA.read_dir:
      return { type: "read_dir", path: getStr(s, 1), includeHidden: getBool(s, 2) };
    case FA.send:
      return { type: "send", id: getInt(s, 1), path: getStr(s, 2), includeHidden: getBool(s, 3),
               fileNum: getInt(s, 4), fileType: getInt(s, 5) };
    case FA.receive:
      return { type: "receive", id: getInt(s, 1), path: getStr(s, 2), files: getMsgs(s, 3).map(parseEntry),
               fileNum: getInt(s, 4), totalSize: getU64(s, 5) };
    case FA.create:
      return { type: "create", id: getInt(s, 1), path: getStr(s, 2) };
    case FA.remove_dir:
      return { type: "remove_dir", id: getInt(s, 1), path: getStr(s, 2), recursive: getBool(s, 3) };
    case FA.remove_file:
      return { type: "remove_file", id: getInt(s, 1), path: getStr(s, 2), fileNum: getInt(s, 3) };
    case FA.all_files:
      return { type: "all_files", id: getInt(s, 1), path: getStr(s, 2), includeHidden: getBool(s, 3) };
    case FA.cancel:
      return { type: "cancel", id: getInt(s, 1) };
    case FA.send_confirm: {
      const out: FileAction = { type: "send_confirm", id: getInt(s, 1), fileNum: getSint(s, 2) };
      const how = oneof(s, [3, 4]);
      if (how === 3) out.skip = getBool(s, 3);
      else if (how === 4) out.offsetBlk = Number(getBig(s, 4));
      return out;
    }
    case FA.rename:
      return { type: "rename", id: getInt(s, 1), path: getStr(s, 2), newName: getStr(s, 3) };
    default:
      return { type: "other" };
  }
}

// ── FileResponse（受控端 → 控制端；上傳時 digest／block／done 由控制端送）──

export interface Digest {
  id: number; fileNum: number; lastModified: number; fileSize: number; isUpload: boolean; isIdentical: boolean;
}

/** J.3／J.4：FileTransferDigest { id, file_num (sint32), last_modified, file_size, is_upload, is_identical } */
export function encodeDigest(d: Digest): Uint8Array {
  return response(FR.digest, concat(fVarint(1, d.id), fSint(2, d.fileNum), fVarint(3, d.lastModified),
                                    fVarint(4, d.fileSize), fBool(5, d.isUpload), fBool(6, d.isIdentical)));
}

/** J.3／J.4：FileTransferBlock { id, file_num (sint32), data, compressed, blk_id（不用，不寫） } */
export function encodeBlock(b: { id: number; fileNum: number; data: Uint8Array; compressed: boolean }): Uint8Array {
  return response(FR.block, concat(fVarint(1, b.id), fSint(2, b.fileNum), fBytes(3, b.data), fBool(4, b.compressed)));
}

/** J.3／J.4：FileTransferDone { id, file_num } */
export function encodeDone(id: number, fileNum: number): Uint8Array {
  return response(FR.done, concat(fVarint(1, id), fVarint(2, fileNum)));
}

/** J.3：FileTransferError { id, error, file_num }（測試用；我們不送錯誤給受控端） */
export function encodeFileError(id: number, error: string, fileNum: number): Uint8Array {
  return response(FR.error, concat(fVarint(1, id), fStr(2, error), fVarint(3, fileNum)));
}

export type FileResponse =
  | { type: "dir"; dir: FileDirectory }
  | { type: "block"; id: number; fileNum: number; data: Uint8Array; compressed: boolean }
  | { type: "error"; id: number; error: string; fileNum: number }
  | { type: "done"; id: number; fileNum: number }
  | ({ type: "digest" } & Digest)
  | { type: "other" };

/** FileResponse 的 oneof 內容（不含 Message 外層）。 */
export function parseFileResponse(body: Uint8Array): FileResponse {
  const f = parse(body);
  const which = oneof(f, Object.values(FR));
  if (which === null) return { type: "other" };
  const raw = getBytes(f, which);
  if (which === FR.dir) return { type: "dir", dir: parseDirectory(raw) };
  const s = parse(raw);
  switch (which) {
    case FR.block:
      return { type: "block", id: getInt(s, 1), fileNum: getSint(s, 2), data: getBytes(s, 3),
               compressed: getBool(s, 4) };
    case FR.error:
      return { type: "error", id: getInt(s, 1), error: getStr(s, 2), fileNum: getInt(s, 3) };
    case FR.done:
      return { type: "done", id: getInt(s, 1), fileNum: getInt(s, 2) };
    case FR.digest:
      return { type: "digest", id: getInt(s, 1), fileNum: getSint(s, 2), lastModified: getU64(s, 3),
               fileSize: getU64(s, 4), isUpload: getBool(s, 5), isIdentical: getBool(s, 6) };
    default:
      return { type: "other" };
  }
}

export type FileMessage =
  | { side: "action"; action: FileAction }
  | { side: "response"; response: FileResponse };

/** 解密後的 Message：是檔案訊息（17／18）就解開，其他（或格式壞掉的）回 null。 */
export function decodeFileMessage(plain: Uint8Array): FileMessage | null {
  try {
    const f = parse(plain);
    const which = oneof(f, [MSG_FILE_ACTION, MSG_FILE_RESPONSE]);
    if (which === null || !has(f, which)) return null;
    const body = getBytes(f, which);
    return which === MSG_FILE_ACTION
      ? { side: "action", action: parseFileAction(body) }
      : { side: "response", response: parseFileResponse(body) };
  } catch (e) {
    if (e instanceof PbError) return null;
    throw e;
  }
}

// ── 登入（J.1）──

export interface FileLoginOptions {
  peerId: string;
  password: Uint8Array;          // 7.2 的 h2（32 bytes）；沒有密碼時是空的（等對方同意）
  myId: string;
  myName: string;
  sessionId: bigint;
  version: string;
  /** FileTransfer.dir：登入後受控端先列這個目錄（不存在就列家目錄）；空字串＝家目錄 */
  dir: string;
  showHidden: boolean;
}

/**
 * J.1：檔案傳輸的 LoginRequest。流程與 §7.3 相同，差別在 union 填 file_transfer (7) FileTransfer { dir (1),
 * show_hidden (2) }，不填遠端桌面的 option (6) 與 video_ack_required (9)。union 的子訊息即使是空的也要寫出。
 */
export function encodeFileLoginRequest(o: FileLoginOptions): Uint8Array {
  const body = concat(
    fStr(1, o.peerId),
    fBytes(2, o.password),
    fStr(4, o.myId),
    fStr(5, o.myName),
    fMsg(7, concat(fStr(1, o.dir), fBool(2, o.showHidden))),
    fVarint(10, o.sessionId),
    fStr(11, o.version),
    fStr(13, "Web"),
  );
  return fMsg(7, body);               // Message.login_request (7)
}

/** 8.6 的 TestDelay，由控制端主動送（from_client = true）：受控端沒有送 TestDelay 時的保活（見 fileSession.ts） */
export function encodeClientTestDelay(timeMs: number): Uint8Array {
  return fMsg(5, concat(fVarint(1, Math.max(0, Math.floor(timeMs))), fBool(2, true)));
}

// ── 路徑（J.2：Windows 的 / 是磁碟機清單；兩邊作業系統不同時分隔字元要自己處理）──

/** C:、C:\、C:\Users… */
export function isWindowsPath(p: string): boolean {
  return /^[A-Za-z]:(?:[\\/]|$)/.test(p);
}

export function joinPath(dir: string, name: string, windows: boolean): string {
  if (windows) {
    if (dir === "/" || dir === "") return /^[A-Za-z]:$/.test(name) ? `${name}\\` : name;
    return dir.replace(/[\\/]+$/, "") + "\\" + name;
  }
  return (dir.replace(/\/+$/, "") || "") + "/" + name;
}

/** 上一層；已經在最上層回 null。Windows 的磁碟機根目錄（C:\）上一層是磁碟機清單（/）。 */
export function parentPath(path: string, windows: boolean): string | null {
  if (path === "/" || path === "") return null;
  if (windows && isWindowsPath(path)) {
    const p = path.replace(/[\\/]+$/, "");
    if (/^[A-Za-z]:$/.test(p)) return "/";
    const cut = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
    const up = p.slice(0, cut);
    return /^[A-Za-z]:$/.test(up) ? `${up}\\` : up;
  }
  const p = path.replace(/\/+$/, "");
  if (!p) return null;
  const up = p.slice(0, p.lastIndexOf("/"));
  return up || "/";
}

/** 路徑的最後一段（/ 與 \ 都當分隔）。 */
export function baseName(path: string): string {
  const p = path.replace(/[\\/]+$/, "");
  return p.slice(Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\")) + 1);
}

// 控制字元（C0、DEL、C1）與雙向文字的覆寫／隔離字元（把副檔名顛倒顯示的那一類）
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/**
 * 受控端給的檔名 → 瀏覽器存檔用的檔名：只留最後一段（去掉 / 與 \）、拿掉控制字元與雙向覆寫字元、
 * Windows 不允許的字元換成底線，頭尾的空白與結尾的點去掉，最長 200 個字元。剩下空的（或 . ..）就叫 download。
 */
export function safeDownloadName(name: string): string {
  let n = baseName(name || "").replace(UNSAFE_CHARS, "").replace(/[<>:"|?*]/g, "_");
  n = n.replace(/^\s+|[\s.]+$/g, "");            // 開頭的點保留（.bashrc），結尾的點與空白 Windows 存不了
  if (/^\.+$/.test(n)) n = "";
  if (Array.from(n).length > 200) n = Array.from(n).slice(0, 200).join("");
  return n || "download";
}
