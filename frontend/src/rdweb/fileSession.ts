/**
 * 相容 RustDesk 的網頁連線：檔案傳輸的連線（規格附錄 J）。
 *
 * 檔案傳輸是**另外一條連線**（J.1）：會合、中繼、安全握手、Hash 與密碼雜湊都照 §4～§7，沿用 session.ts 的 RdSession，
 * 差別只在 LoginRequest 填 union file_transfer（files.ts 的 encodeFileLoginRequest）。登入之後的檔案訊息
 * （Message.file_action／file_response）由這裡處理：
 *
 * - 列目錄（J.2）：read_dir 沒有 id，回覆照送出的順序配對（id 不是我們發出的工作的，就是列目錄的回覆）
 * - 下載（J.3）：send → dir（清單）→ 每個檔案 digest → 我們回 send_confirm（offset_blk 0，或 skip）→ block … → done
 * - 上傳（J.4）：receive → 每個檔案我們送 digest → 受控端回 send_confirm（沒有同名）或 digest（有同名，問使用者）
 *   → block（128 KiB 一塊，不壓縮）… → 全部送完送 done
 * - 取消（J.5）：送 cancel，沒有回覆，兩邊各自停止
 * - 建立目錄、刪除、改名（J.5）：每個動作一個 id，回 done 或 error
 * - **一次一個傳輸工作**（J.6），其他的排隊；不做續傳
 *
 * 稽核（J.6）：後端只看得到密文，所以每個動作做完由瀏覽器另外送一則摘要給後端（文字訊息 `file_audit`：
 * op、path（截到 512 字元）、size、result）。這是瀏覽器自報的，不含任何檔案內容。
 *
 * 保活（J.1：兩邊都是 30 秒沒收到東西就放棄）：
 * - 受控端送 TestDelay 時 RdSession 照 §8.6 原封不動送回，這樣就夠了。萬一它不送（規格待黑箱確認），
 *   10 秒沒送任何東西就主動送一則 from_client = true 的 TestDelay，讓受控端知道我們還在
 * - 受控端 20 秒沒有任何訊息：用 read_dir（目前的目錄）探一下，一定有回覆；到 30 秒還是沒有就結束連線。
 *   上傳中不算（上傳時受控端本來就不回東西，J.4 沒有逐塊確認）
 */
import { RdSession, type CloseInfo, type PasswordReason, type Phase, type WebSocketLike } from "./session";
import type { LoginOptions, MessageBox, PeerInfo } from "./messages";
import {
  baseName, BLOCK_SIZE, decodeFileMessage, encodeAllFiles, encodeBlock, encodeCancel, encodeClientTestDelay,
  encodeCreate, encodeDigest, encodeDone, encodeFileLoginRequest, encodeReadDir, encodeReceive, encodeRemoveDir,
  encodeRemoveFile, encodeRename, encodeSend, encodeSendConfirm, FileType, isDirType, isWindowsPath, joinPath,
  parentPath, type FileDirectory, type FileEntry, type FileMessage,
} from "./files";
import { zstdDecompress } from "./zstd";

/** 時限（毫秒）。測試可以改小。 */
export const fileTiming = {
  /** 列目錄等回覆 */
  listTimeoutMs: 15_000,
  /** 建立／改名／刪除等回覆 */
  opTimeoutMs: 30_000,
  /** 上傳時送出 digest 後等受控端回 send_confirm 或 digest */
  peerAnswerTimeoutMs: 30_000,
  /** 這麼久沒送任何東西給受控端就送一則 TestDelay（J.1：受控端 30 秒沒收到東西會關閉連線） */
  keepaliveMs: 10_000,
  /** 受控端這麼久沒有任何訊息：用 read_dir 探一下 */
  probeMs: 20_000,
  /** 受控端這麼久沒有任何訊息就結束連線（J.1） */
  silenceMs: 30_000,
  /** 登入後受控端應該會自己先送一次列表；這麼久還沒有就自己要 */
  initialListMs: 3_000,
  /** 上傳送完 done 之後，等一下受控端可能回的寫入錯誤（J.4 第 4 步沒有成功的回覆） */
  doneGraceMs: 800,
  /** 上傳的送出緩衝上限：超過就等瀏覽器把資料送出去（受控端沒有流量控制） */
  highWater: 4 * 1024 * 1024,
};

/** 壓縮塊解壓後的上限：規格說每塊最多 128 KiB（J.3），留一點餘裕，但不讓惡意的壓縮資料吃光記憶體 */
export const MAX_BLOCK_BYTES = 1024 * 1024;
/** J.6：稽核的路徑截到 512 個字元 */
export const AUDIT_PATH_MAX = 512;

export interface FileLimits {
  /** 單檔上限（位元組，伺服器設定） */
  maxFileBytes: number;
  /** 單次上傳總量上限（位元組，伺服器設定） */
  maxTotalBytes: number;
}

/** 要上傳的檔案（畫面把瀏覽器的 File 包成這個；測試用記憶體裡的資料） */
export interface UploadSource {
  /** 相對於目的目錄的名稱 */
  name: string;
  size: number;
  /** 毫秒（File.lastModified） */
  lastModified: number;
  read(offset: number, length: number): Promise<Uint8Array>;
}

/** 下載的存檔目的地（記憶體、瀏覽器的串流存檔…，見 fileSave.ts） */
export interface DownloadSink {
  write(chunk: Uint8Array): void | Promise<void>;
  /** 全部收完：存檔 */
  close(): Promise<void>;
  /** 中斷：丟掉寫到一半的 */
  abort(): void | Promise<void>;
}

/**
 * 上傳遇到同名時給畫面的資料。檔名與大小一律是這次上傳的那個檔案（用 digest 的 file_num 對到工作自己的清單）：
 * 實機（官方 1.4.1）同名時回的 digest 只有 id、file_num 與 is_identical，大小與修改時間是 0，畫面不可以依賴它。
 */
export interface ConflictInfo {
  /** 這次要上傳的檔名（受控端那邊同名） */
  name: string;
  /** 這次要上傳的檔案大小 */
  size: number;
  /** 受控端說兩個一樣（is_identical，J.4） */
  identical: boolean;
  /** 這一批後面還有幾個檔案 */
  remaining: number;
  /** 受控端那個同名檔案的大小：digest 有帶（大於 0）才有 */
  peerSize?: number;
  /** 受控端那個同名檔案的修改時間（Unix 秒）：digest 有帶（大於 0）才有 */
  peerModified?: number;
}

export interface ConflictAnswer {
  action: "overwrite" | "skip";
  /** 其餘同名的也這樣處理 */
  all: boolean;
}

export interface Listing {
  path: string;
  entries: FileEntry[];
  windows: boolean;
  /** Windows 的最上層（磁碟機清單） */
  drives: boolean;
}

export type JobStatus = "queued" | "running" | "done" | "error" | "cancelled";

export interface FileJobView {
  key: number;
  kind: "download" | "upload";
  /** 畫面顯示的名稱（受控端給的名稱只當文字顯示） */
  name: string;
  /** 下載：受控端的路徑；上傳：受控端的目的目錄 */
  path: string;
  total: number;
  done: number;
  status: JobStatus;
  /** 失敗的原因（受控端的錯誤原文，或 errors 的代碼 code） */
  error?: string;
  code?: string;
  files: number;
  fileIndex: number;
  skipped: number;
  current: string;
}

export type AuditOp = "download" | "upload" | "delete" | "rename" | "mkdir";
export type AuditResult = "ok" | "error" | "cancelled";

/**
 * 檔案動作失敗。code：
 * - peer：受控端回 FileResponse.error，原文在 peerError（例如 Not exists、one-way-file-transfer-tip）
 * - timeout、closed、cancelled、too_large、read（讀不到本機檔案）、write（存檔失敗）、bad_block、protocol、short
 */
export class FileOpError extends Error {
  constructor(readonly code: string, readonly peerError = "") {
    super(peerError || code);
  }
}

export interface FileSessionEvents {
  phase?(p: Phase): void;
  needPassword?(reason: PasswordReason, code?: string): void;
  need2fa?(wrong: boolean): void;
  waitingApproval?(): void;
  connected?(info: PeerInfo): void;
  listing?(l: Listing): void;
  /** 傳輸佇列有變化（進度最多每 200 毫秒一次） */
  jobs?(jobs: FileJobView[]): void;
  /** 上傳遇到同名（J.4 第 2 步）：問使用者。沒給就略過 */
  conflict?(c: ConflictInfo): Promise<ConflictAnswer>;
  messageBox?(mb: MessageBox): void;
  closed?(info: CloseInfo): void;
}

export interface FileSessionOptions {
  url: string;
  peerId: string;
  myName: string;
  /** 一開始就給的密碼（空字串＝請對方按同意）；undefined＝收到 Hash 時再問 */
  password?: string;
  /** 附錄 D：用連線帳密金庫裡的這一筆登入 */
  savedCredentialId?: string;
  /** FileTransfer.dir（登入後先列的目錄）；空字串＝家目錄 */
  dir?: string;
  showHidden?: boolean;
  limits: FileLimits;
  events: FileSessionEvents;
  wsFactory?: (url: string) => WebSocketLike;
}

/** 畫面先用這個篩過；超過上限的不送（J.6）。totalTooLarge 是篩過之後的總量仍超過單次上限。 */
export function checkUploadLimits(sources: UploadSource[], limits: FileLimits):
    { ok: UploadSource[]; tooLarge: string[]; totalTooLarge: boolean } {
  const ok = sources.filter((s) => s.size <= limits.maxFileBytes);
  const tooLarge = sources.filter((s) => s.size > limits.maxFileBytes).map((s) => s.name);
  const total = ok.reduce((n, s) => n + s.size, 0);
  return { ok, tooLarge, totalTooLarge: total > limits.maxTotalBytes };
}

const OPEN = 1;
const CANCELLED = (): FileOpError => new FileOpError("cancelled");

interface Route {
  handle(m: FileMessage): void;
  fail(e: FileOpError): void;
}

interface Job {
  view: FileJobView;
  id: number;
  cancelled: boolean;
  run: (job: Job) => Promise<void>;
  /** 連線結束或取消：讓進行中的等待立刻結束 */
  abort?: (e: FileOpError) => void;
  resolve: (v: FileJobView) => void;
  done: Promise<FileJobView>;
}

interface PendingList {
  path: string;
  resolve: (l: Listing) => void;
  reject: (e: FileOpError) => void;
  timer: ReturnType<typeof setTimeout>;
}

function clip(path: string): string {
  const cps = Array.from(path);
  return cps.length > AUDIT_PATH_MAX ? cps.slice(0, AUDIT_PATH_MAX).join("") : path;
}

function asFileError(e: unknown, fallback = "protocol"): FileOpError {
  return e instanceof FileOpError ? e : new FileOpError(fallback, e instanceof Error ? e.message : String(e));
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class RdFileSession {
  readonly rd: RdSession;
  /** 目前列出的目錄 */
  cwd = "";
  /** 受控端是 Windows（PeerInfo.platform，或路徑長得像 C:\） */
  windows = false;
  showHidden: boolean;
  peerInfo: PeerInfo | null = null;

  private readonly ws: WebSocketLike;
  private readonly limits: FileLimits;
  private readonly startDir: string;
  private lastSent = Date.now();
  private lastRecv = Date.now();
  private seqId = 0;
  private routes = new Map<number, Route>();
  private lists: PendingList[] = [];
  private history: Job[] = [];
  private active: Job | null = null;
  private nextKey = 1;
  private ended = false;
  private closeInfo: CloseInfo | null = null;
  private tick: ReturnType<typeof setInterval> | null = null;
  private initialTimer: ReturnType<typeof setTimeout> | null = null;
  private emitTimer: ReturnType<typeof setTimeout> | null = null;
  private lastEmit = 0;
  private gotListing = false;
  private probing = false;
  /** 登入回覆之前就到的檔案訊息（照理不會有）：連上之後再處理 */
  private early: Uint8Array[] = [];

  constructor(private readonly opts: FileSessionOptions) {
    this.showHidden = !!opts.showHidden;
    this.limits = opts.limits;
    this.startDir = opts.dir ?? "";
    const factory = opts.wsFactory ?? ((u: string) => new WebSocket(u) as unknown as WebSocketLike);
    const holder: { ws?: WebSocketLike } = {};
    this.rd = new RdSession({
      url: opts.url,
      peerId: opts.peerId,
      myName: opts.myName,
      decoding: { vp9: true, h264: false, vp8: false, av1: false },     // 檔案傳輸不收畫面，登入時也不帶
      password: opts.password,
      savedCredentialId: opts.savedCredentialId,
      encodeLogin: (o) => this.encodeLogin(o),
      wsFactory: (u) => {
        const ws = factory(u);
        holder.ws = ws;
        // 記下最後一次送出 binary 的時間（保活用）。文字訊息是給後端的，受控端收不到，不算
        const send = ws.send.bind(ws);
        ws.send = (d) => {
          if (typeof d !== "string") this.lastSent = Date.now();
          send(d);
        };
        return ws;
      },
      events: {
        phase: (p) => opts.events.phase?.(p),
        needPassword: (r, c) => opts.events.needPassword?.(r, c),
        need2fa: (w) => opts.events.need2fa?.(w),
        waitingApproval: () => opts.events.waitingApproval?.(),
        connected: (info) => this.onConnected(info),
        messageBox: (mb) => opts.events.messageBox?.(mb),
        unhandled: (plain) => this.onPlain(plain),
        filePermission: (enabled) => { if (!enabled) this.closeWith({ code: "rd_file_permission_off" }); },
        closed: (info) => this.onClosed(info),
      },
    });
    this.ws = holder.ws!;
    // 記下最後一次收到受控端訊息的時間（J.1 的 30 秒）
    const onmessage = this.ws.onmessage;
    this.ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") this.lastRecv = Date.now();
      onmessage?.(ev);
    };
  }

  get phase(): Phase {
    return this.rd.phase;
  }

  get jobs(): FileJobView[] {
    return this.history.map((j) => ({ ...j.view }));
  }

  login(password: string): Promise<void> {
    return this.rd.login(password);
  }

  submit2fa(code: string): void {
    this.rd.submit2fa(code);
  }

  /** 使用者結束（送 close_reason，§10）。 */
  close(): void {
    this.rd.close();
  }

  // ── 路徑 ──

  parent(path: string): string | null {
    return parentPath(path, this.windows);
  }

  child(dir: string, e: FileEntry): string {
    return joinPath(dir, e.name, this.windows);
  }

  // ── 列目錄（J.2）──

  /** 列一個目錄。空字串＝家目錄；Windows 的 "/" 是磁碟機清單。回覆照送出的順序配對。 */
  list(path: string): Promise<Listing> {
    return new Promise((resolve, reject) => {
      if (this.ended || this.rd.phase !== "connected") {
        reject(new FileOpError("closed"));
        return;
      }
      const item: PendingList = {
        path, resolve, reject,
        timer: setTimeout(() => {
          const i = this.lists.indexOf(item);
          if (i >= 0) this.lists.splice(i, 1);
          reject(new FileOpError("timeout"));
        }, fileTiming.listTimeoutMs),
      };
      this.lists.push(item);
      if (!this.send(encodeReadDir(path, this.showHidden))) {
        clearTimeout(item.timer);
        this.lists.splice(this.lists.indexOf(item), 1);
        reject(new FileOpError("closed"));
      }
    });
  }

  refresh(): Promise<Listing> {
    return this.list(this.cwd);
  }

  /** 切換「顯示隱藏檔」並重新列出目前的目錄。 */
  setShowHidden(v: boolean): Promise<Listing> | null {
    this.showHidden = v;
    return this.rd.phase === "connected" ? this.refresh() : null;
  }

  // ── 建立、改名、刪除（J.5）──

  async mkdir(path: string): Promise<void> {
    try {
      await this.op((id) => encodeCreate(id, path), "done");
      this.audit("mkdir", path, "ok");
    } catch (e) {
      this.audit("mkdir", path, "error");
      throw e;
    }
  }

  /** 同一個目錄內改名（newName 不可以含路徑分隔字元，畫面先擋）。 */
  async rename(path: string, newName: string): Promise<void> {
    const to = joinPath(this.parent(path) ?? "", newName, this.windows);
    try {
      await this.op((id) => encodeRename(id, path, newName), "done");
      this.audit("rename", path, "ok", { to });
    } catch (e) {
      this.audit("rename", path, "error", { to });
      throw e;
    }
  }

  /**
   * 刪除檔案（remove_file），或整個資料夾：all_files 取得整棵的檔案清單（含隱藏檔）→ 逐一 remove_file →
   * remove_dir（recursive）。連結只刪連結本身，不跟進去。
   */
  async remove(t: { path: string; dir: boolean; size: number }): Promise<void> {
    let size = t.size;
    try {
      if (!t.dir) {
        await this.op((id) => encodeRemoveFile(id, t.path, 0), "done");
      } else {
        const tree = (await this.op((id) => encodeAllFiles(id, t.path, true), "dir")) as FileDirectory;
        const base = tree.path || t.path;
        const files = tree.entries.filter((e) => e.type === FileType.File || e.type === FileType.FileLink
                                                 || e.type === FileType.DirLink);
        size = files.reduce((n, e) => n + e.size, 0);
        for (const [i, e] of files.entries()) {
          const p = isWindowsPath(e.name) || e.name.startsWith("/") ? e.name : joinPath(base, e.name, this.windows);
          await this.op((id) => encodeRemoveFile(id, p, i), "done");
        }
        await this.op((id) => encodeRemoveDir(id, t.path, true), "done");
      }
      this.audit("delete", t.path, "ok", { size });
    } catch (e) {
      this.audit("delete", t.path, "error", { size });
      throw e;
    }
  }

  // ── 傳輸工作（J.3、J.4；一次一個）──

  /**
   * 下載。sink(entry, index) 回存檔的目的地；回 null＝略過那個檔案（skip）。
   * 畫面只下載單一檔案（資料夾下載之後另議，J.6），但協定上一個工作可以有好幾個檔案（file_num）。
   */
  download(path: string, o: { name: string; size: number;
                              sink: (e: FileEntry, index: number) => DownloadSink | null }):
      { key: number; done: Promise<FileJobView> } {
    return this.enqueue("download", o.name, path, o.size, (job) => this.runDownload(job, path, o.size, o.sink));
  }

  /** 上傳到受控端的 dest 目錄。超過伺服器設定的上限就不送（丟出 FileOpError("too_large")）。 */
  upload(dest: string, sources: UploadSource[]): { key: number; done: Promise<FileJobView> } {
    const chk = checkUploadLimits(sources, this.limits);
    if (chk.tooLarge.length || chk.totalTooLarge) throw new FileOpError("too_large");
    const total = sources.reduce((n, s) => n + s.size, 0);
    const r = this.enqueue("upload", sources[0]?.name ?? "", dest, total, (job) => this.runUpload(job, dest, sources));
    const job = this.history.find((j) => j.view.key === r.key);
    if (job) job.view.files = sources.length;
    return r;
  }

  /** 取消：排隊中的直接拿掉；進行中的送 FileAction.cancel（沒有回覆，兩邊各自停止，J.5）。 */
  cancel(key: number): void {
    const job = this.history.find((j) => j.view.key === key);
    if (!job || job.cancelled) return;
    if (job.view.status === "queued") {
      job.cancelled = true;
      job.view.status = "cancelled";
      job.resolve({ ...job.view });
      this.emitJobs(true);
      return;
    }
    if (job.view.status !== "running") return;
    job.cancelled = true;
    if (job.id) this.send(encodeCancel(job.id));
    job.abort?.(CANCELLED());
  }

  /** 從佇列拿掉已經結束的工作。 */
  clearFinished(): void {
    this.history = this.history.filter((j) => j.view.status === "queued" || j.view.status === "running");
    this.emitJobs(true);
  }

  // ── 內部：連線 ──

  private encodeLogin(o: LoginOptions): Uint8Array {
    return encodeFileLoginRequest({
      peerId: o.peerId, password: o.password, myId: o.myId, myName: o.myName, sessionId: o.sessionId,
      version: o.version, dir: this.startDir, showHidden: this.showHidden,
    });
  }

  private onConnected(info: PeerInfo): void {
    this.peerInfo = info;
    this.windows = info.platform === "Windows";
    this.lastRecv = Date.now();
    this.tick = setInterval(() => this.onTick(), 1000);
    this.initialTimer = setTimeout(() => {
      if (!this.gotListing && !this.ended) this.list(this.startDir).catch(() => undefined);
    }, fileTiming.initialListMs);
    this.opts.events.connected?.(info);
    const early = this.early.splice(0);
    for (const p of early) this.onPlain(p);
  }

  private onClosed(info: CloseInfo): void {
    if (this.ended) return;
    this.ended = true;
    if (this.tick) clearInterval(this.tick);
    if (this.initialTimer) clearTimeout(this.initialTimer);
    if (this.emitTimer) clearTimeout(this.emitTimer);
    const err = new FileOpError("closed");
    for (const r of [...this.routes.values()]) r.fail(err);
    this.routes.clear();
    for (const l of this.lists.splice(0)) {
      clearTimeout(l.timer);
      l.reject(err);
    }
    this.active?.abort?.(err);
    for (const j of this.history) {
      if (j.view.status === "queued") {
        j.view.status = "error";
        j.view.code = "closed";
        j.resolve({ ...j.view });
      }
    }
    this.emitJobs(true);
    const out: CloseInfo = this.closeInfo ? { ...info, ...this.closeInfo, byUser: false } : info;
    this.opts.events.closed?.(out);
  }

  /** 我們自己決定結束（權限被關、逾時）：照 §10 結束，畫面看到的是這個原因。 */
  private closeWith(info: CloseInfo): void {
    if (this.ended) return;
    this.closeInfo = info;
    this.rd.close();
  }

  private onTick(): void {
    if (this.ended || this.rd.phase !== "connected") return;
    const now = Date.now();
    if (now - this.lastSent >= fileTiming.keepaliveMs) this.send(encodeClientTestDelay(now));
    // 上傳中受控端本來就不回東西（J.4 沒有逐塊確認）：不算沉默
    if (this.active?.view.kind === "upload") this.lastRecv = now;
    const silent = now - this.lastRecv;
    if (silent >= fileTiming.silenceMs) {
      this.closeWith({ code: "rd_file_timeout" });
      return;
    }
    if (silent >= fileTiming.probeMs && !this.probing) {
      this.probing = true;
      this.list(this.cwd).catch(() => undefined).finally(() => { this.probing = false; });
    }
  }

  private send(plain: Uint8Array): boolean {
    if (this.ended) return false;
    return this.rd.sendMessage(plain);
  }

  private sendText(obj: Record<string, unknown>): void {
    if (this.ws.readyState === OPEN) this.ws.send(JSON.stringify(obj));
  }

  /** J.6：每個動作的摘要給後端寫稽核（瀏覽器自報；不含檔案內容）。 */
  private audit(op: AuditOp, path: string, result: AuditResult, extra: { size?: number; to?: string } = {}): void {
    const msg: Record<string, unknown> = { t: "file_audit", op, path: clip(path) };
    if (extra.size !== undefined) msg.size = Math.max(0, Math.floor(extra.size));
    if (extra.to !== undefined) msg.to = clip(extra.to);
    msg.result = result;
    this.sendText(msg);
  }

  private nextId(): number {
    this.seqId = this.seqId >= 0x7ffffffe ? 1 : this.seqId + 1;
    return this.seqId;
  }

  /** 解密後、session.ts 不處理的訊息。 */
  private onPlain(plain: Uint8Array): void {
    if (this.ended) return;
    if (this.rd.phase !== "connected") {
      if (this.early.length < 8) this.early.push(plain);
      return;
    }
    const m = decodeFileMessage(plain);
    if (!m) return;
    const id = m.side === "response"
      ? (m.response.type === "dir" ? m.response.dir.id : "id" in m.response ? m.response.id : 0)
      : ("id" in m.action ? m.action.id : 0);
    const route = id ? this.routes.get(id) : undefined;
    if (route) {
      route.handle(m);
      return;
    }
    if (m.side !== "response") return;
    if (m.response.type === "dir") this.onListing(m.response.dir);
    else if (m.response.type === "error") this.onListingError(m.response.error);
  }

  private onListing(dir: FileDirectory): void {
    const item = this.lists.shift();
    if (item) clearTimeout(item.timer);
    const path = dir.path || item?.path || "";
    if (isWindowsPath(path) || (dir.entries.length > 0 && dir.entries.every((e) => e.type === FileType.DirDrive))) {
      this.windows = true;
    }
    const listing: Listing = {
      path,
      entries: dir.entries.filter((e) => this.showHidden || !e.hidden),
      windows: this.windows,
      drives: this.windows && (path === "/" || dir.entries.some((e) => e.type === FileType.DirDrive)),
    };
    this.cwd = path;
    this.gotListing = true;
    this.opts.events.listing?.(listing);
    item?.resolve(listing);
  }

  private onListingError(error: string): void {
    const item = this.lists.shift();
    if (!item) return;
    clearTimeout(item.timer);
    item.reject(new FileOpError("peer", error));
  }

  /** 單一動作：送出、等同一個 id 的 done（或 dir）或 error。 */
  private op(build: (id: number) => Uint8Array, expect: "done" | "dir"): Promise<FileDirectory | void> {
    return new Promise((resolve, reject) => {
      if (this.ended) {
        reject(new FileOpError("closed"));
        return;
      }
      const id = this.nextId();
      const finish = () => {
        clearTimeout(timer);
        this.routes.delete(id);
      };
      const timer = setTimeout(() => { finish(); reject(new FileOpError("timeout")); }, fileTiming.opTimeoutMs);
      this.routes.set(id, {
        handle: (m) => {
          if (m.side !== "response") return;
          const r = m.response;
          if (r.type === "error") { finish(); reject(new FileOpError("peer", r.error)); }
          else if (expect === "done" && r.type === "done") { finish(); resolve(); }
          else if (expect === "dir" && r.type === "dir") { finish(); resolve(r.dir); }
        },
        fail: (e) => { finish(); reject(e); },
      });
      if (!this.send(build(id))) {
        finish();
        reject(new FileOpError("closed"));
      }
    });
  }

  // ── 內部：佇列 ──

  private enqueue(kind: "download" | "upload", name: string, path: string, total: number,
                  run: (job: Job) => Promise<void>): { key: number; done: Promise<FileJobView> } {
    let resolve!: (v: FileJobView) => void;
    const done = new Promise<FileJobView>((r) => { resolve = r; });
    const view: FileJobView = { key: this.nextKey++, kind, name, path, total, done: 0, status: "queued", files: 1,
                                fileIndex: 0, skipped: 0, current: name };
    const job: Job = { view, id: 0, cancelled: false, run, resolve, done };
    if (this.ended) {
      view.status = "error";
      view.code = "closed";
      resolve({ ...view });
      return { key: view.key, done };
    }
    this.history.push(job);
    // 留最近的 100 筆（已結束的先丟）
    while (this.history.length > 100) {
      const i = this.history.findIndex((j) => j.view.status !== "queued" && j.view.status !== "running");
      if (i < 0) break;
      this.history.splice(i, 1);
    }
    this.emitJobs(true);
    void this.pump();
    return { key: view.key, done };
  }

  private async pump(): Promise<void> {
    if (this.active || this.ended) return;
    const job = this.history.find((j) => j.view.status === "queued");
    if (!job) return;
    this.active = job;
    job.view.status = "running";
    this.emitJobs(true);
    try {
      await job.run(job);
      job.view.status = job.cancelled ? "cancelled" : "done";
    } catch (e) {
      const err = asFileError(e);
      if (job.cancelled) {
        job.view.status = "cancelled";
      } else {
        job.view.status = "error";
        job.view.code = err.code;
        job.view.error = err.peerError || undefined;
      }
    }
    this.active = null;
    this.emitJobs(true);
    job.resolve({ ...job.view });
    void this.pump();
  }

  private emitJobs(force = false): void {
    const cb = this.opts.events.jobs;
    if (!cb) return;
    const now = Date.now();
    if (force || now - this.lastEmit >= 200) {
      if (this.emitTimer) { clearTimeout(this.emitTimer); this.emitTimer = null; }
      this.lastEmit = now;
      cb(this.jobs);
      return;
    }
    if (!this.emitTimer) {
      this.emitTimer = setTimeout(() => {
        this.emitTimer = null;
        this.lastEmit = Date.now();
        cb(this.jobs);
      }, 200);
    }
  }

  // ── 內部：下載（J.3）──

  private runDownload(job: Job, path: string, sizeHint: number,
                      sinkFor: (e: FileEntry, index: number) => DownloadSink | null): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const id = this.nextId();
      job.id = id;
      let files: FileEntry[] = [];
      let size = sizeHint;          // 稽核記的是檔案大小（單一檔案時以受控端的 digest 為準）
      let cur: { num: number; sink: DownloadSink; got: number; expect: number; chain: Promise<void>;
                 writeError: unknown } | null = null;
      let seq: Promise<void> = Promise.resolve();
      let ended = false;

      const end = (err: FileOpError | null, tellPeer = false) => {
        if (ended) return;
        ended = true;
        this.routes.delete(id);
        if (err) {
          const c = cur;
          cur = null;
          if (c) void Promise.resolve().then(() => c.sink.abort()).catch(() => undefined);
          if (tellPeer) this.send(encodeCancel(id));          // 我們自己停下來的：受控端還在送（J.5）
          this.audit("download", path, job.cancelled ? "cancelled" : "error", { size });
          reject(err);
        } else {
          this.audit("download", path, "ok", { size });
          resolve();
        }
      };
      job.abort = (e) => end(e);

      const finishCurrent = async () => {
        const c = cur;
        if (!c) return;
        await c.chain;
        if (c.writeError) throw new FileOpError("write", String(c.writeError));
        if (c.got < c.expect) throw new FileOpError("short");
        cur = null;
        await c.sink.close();
      };

      const handle = async (m: FileMessage) => {
        if (m.side !== "response") return;
        const r = m.response;
        switch (r.type) {
          case "dir":
            files = r.dir.entries;
            job.view.files = Math.max(1, files.length);
            job.view.total = files.reduce((n, e) => n + e.size, 0);
            if (files.length > 1) size = job.view.total;
            else if (files.length === 1) size = files[0].size;
            this.emitJobs(true);
            return;
          case "digest": {
            await finishCurrent();
            const e: FileEntry = files[r.fileNum]
              ?? { type: FileType.File, name: baseName(path), hidden: false, size: r.fileSize, mtime: r.lastModified };
            if (files.length <= 1) {
              size = r.fileSize;
              job.view.total = r.fileSize;
            }
            job.view.fileIndex = r.fileNum;
            job.view.current = e.name || baseName(path);
            let sink: DownloadSink | null;
            try { sink = sinkFor(e, r.fileNum); } catch (err) { throw new FileOpError("write", String(err)); }
            if (!sink) {
              job.view.skipped += 1;
              this.send(encodeSendConfirm(id, r.fileNum, { skip: true }));
              return;
            }
            cur = { num: r.fileNum, sink, got: 0, expect: r.fileSize, chain: Promise.resolve(), writeError: null };
            this.send(encodeSendConfirm(id, r.fileNum, { offsetBlk: 0 }));
            this.emitJobs(true);
            return;
          }
          case "block": {
            const c = cur;
            if (!c || c.num !== r.fileNum) throw new FileOpError("protocol");
            if (c.writeError) throw new FileOpError("write", String(c.writeError));
            let data = r.data;
            if (r.compressed) {
              const z = zstdDecompress(data, MAX_BLOCK_BYTES);
              if (!z.ok) throw new FileOpError("bad_block");
              data = z.data;
            }
            c.got += data.length;
            job.view.done += data.length;
            c.chain = c.chain.then(() => c.sink.write(data)).catch((err) => { c.writeError = err ?? "write"; });
            this.emitJobs();
            return;
          }
          case "done":
            await finishCurrent();
            end(null);
            return;
          case "error":
            end(new FileOpError("peer", r.error));
            return;
          default:
            return;
        }
      };

      this.routes.set(id, {
        handle: (m) => {
          if (ended) return;
          seq = seq.then(() => (ended ? undefined : handle(m))).catch((e) => {
            const err = asFileError(e);
            end(err, err.code !== "peer");
          });
        },
        fail: (e) => end(e),
      });
      if (!this.send(encodeSend({ id, path, includeHidden: this.showHidden, fileNum: 0 }))) {
        end(new FileOpError("closed"));
      }
    });
  }

  // ── 內部：上傳（J.4）──

  private async runUpload(job: Job, dest: string, sources: UploadSource[]): Promise<void> {
    const id = this.nextId();
    job.id = id;
    const entries: FileEntry[] = sources.map((s) => ({
      type: FileType.File, name: this.remoteRel(s.name), hidden: false, size: s.size,
      mtime: Math.max(0, Math.floor(s.lastModified / 1000)),
    }));
    let failure: FileOpError | null = null;
    let waiter: { fileNum: number; resolve: (a: PeerAnswer) => void; reject: (e: FileOpError) => void } | null = null;
    let abortReject: ((e: FileOpError) => void) | null = null;
    const aborted = new Promise<never>((_, rej) => { abortReject = rej; });
    aborted.catch(() => undefined);
    const fail = (e: FileOpError) => {
      if (!failure) failure = e;
      waiter?.reject(e);
      waiter = null;
      abortReject?.(e);
    };
    job.abort = fail;
    const check = () => {
      if (job.cancelled) throw CANCELLED();
      if (failure) throw failure;
    };
    this.routes.set(id, {
      handle: (m) => {
        if (m.side === "action" && m.action.type === "send_confirm") {
          const a = m.action;
          // file_num 對得上才算；這個工作只有一個檔案時不必對（只可能是那一個）
          if (waiter && (waiter.fileNum === a.fileNum || sources.length === 1)) {
            const w = waiter;
            waiter = null;
            w.resolve({ kind: a.skip ? "skip" : "go" });
          }
        } else if (m.side === "response" && m.response.type === "digest") {
          const d = m.response;
          if (waiter && (waiter.fileNum === d.fileNum || sources.length === 1)) {
            const w = waiter;
            waiter = null;
            w.resolve({ kind: "conflict", fileNum: d.fileNum, size: d.fileSize, modified: d.lastModified,
                        identical: d.isIdentical });
          }
        } else if (m.side === "response" && m.response.type === "error") {
          fail(new FileOpError("peer", m.response.error));
        }
      },
      fail,
    });
    const waitAnswer = (fileNum: number) => new Promise<PeerAnswer>((resolve, reject) => {
      const timer = setTimeout(() => { waiter = null; reject(new FileOpError("timeout")); },
                               fileTiming.peerAnswerTimeoutMs);
      waiter = {
        fileNum,
        resolve: (a) => { clearTimeout(timer); resolve(a); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
    });

    const sent: { path: string; size: number }[] = [];
    let current: { path: string; size: number } | null = null;
    let conflictAll: "overwrite" | "skip" | null = null;
    try {
      const total = sources.reduce((n, s) => n + s.size, 0);
      if (!this.send(encodeReceive({ id, path: dest, files: entries, fileNum: 0, totalSize: total }))) {
        throw new FileOpError("closed");
      }
      for (const [i, src] of sources.entries()) {
        check();
        current = { path: joinPath(dest, entries[i].name, this.windows), size: src.size };
        job.view.fileIndex = i;
        job.view.current = src.name;
        this.emitJobs(true);
        const answer = waitAnswer(i);
        this.send(encodeDigest({ id, fileNum: i, lastModified: entries[i].mtime, fileSize: src.size, isUpload: true,
                                 isIdentical: false }));
        const ans = await answer;
        let go = ans.kind === "go";
        if (ans.kind === "conflict") {
          let action = conflictAll;
          if (!action) {
            const ask = this.opts.events.conflict;
            // 檔名與大小用工作自己的清單（digest 的 file_num；只有一個檔案時就是它），受控端的值有意義才附上
            const mine = sources[ans.fileNum] ?? (sources.length === 1 ? sources[0] : src);
            const info: ConflictInfo = { name: mine.name, size: mine.size, identical: ans.identical,
                                         remaining: sources.length - i - 1 };
            if (ans.size > 0) info.peerSize = ans.size;
            if (ans.size > 0 && ans.modified > 0) info.peerModified = ans.modified;
            const a: ConflictAnswer = ask
              ? await Promise.race([ask(info), aborted])
              : { action: "skip", all: false };
            check();
            action = a.action;
            if (a.all) conflictAll = a.action;
          }
          go = action === "overwrite";
          this.send(encodeSendConfirm(id, i, go ? { offsetBlk: 0 } : { skip: true }));
        }
        if (!go) {
          job.view.skipped += 1;
          job.view.done += src.size;
          current = null;
          continue;
        }
        await this.sendBlocks(job, id, i, src, check);
        sent.push(current);
        current = null;
      }
      check();
      this.send(encodeDone(id, Math.max(0, sources.length - 1)));
      await this.waitDrained(check);
      await Promise.race([sleep(fileTiming.doneGraceMs), aborted]);
      check();
      for (const f of sent) this.audit("upload", f.path, "ok", { size: f.size });
    } catch (e) {
      const err = asFileError(e);
      for (const f of sent) this.audit("upload", f.path, "ok", { size: f.size });
      if (current) this.audit("upload", current.path, job.cancelled ? "cancelled" : "error", { size: current.size });
      throw err;
    } finally {
      this.routes.delete(id);
      waiter = null;
    }
  }

  /** 送一個檔案的資料塊：128 KiB 一塊、不壓縮；瀏覽器的送出緩衝超過上限就等（受控端沒有流量控制）。 */
  private async sendBlocks(job: Job, id: number, fileNum: number, src: UploadSource, check: () => void): Promise<void> {
    for (let off = 0; off < src.size; off += BLOCK_SIZE) {
      const len = Math.min(BLOCK_SIZE, src.size - off);
      let data: Uint8Array;
      try {
        data = await src.read(off, len);
      } catch (e) {
        throw new FileOpError("read", e instanceof Error ? e.message : String(e));
      }
      check();
      if (data.length !== len) throw new FileOpError("read");
      while ((this.ws.bufferedAmount ?? 0) > fileTiming.highWater) {
        if (this.ws.readyState !== OPEN) throw new FileOpError("closed");
        await sleep(20);
        check();
      }
      if (!this.send(encodeBlock({ id, fileNum, data, compressed: false }))) throw new FileOpError("closed");
      job.view.done += len;
      this.emitJobs();
    }
  }

  /** 等瀏覽器把送出緩衝都送出去（最多 2 分鐘）。 */
  private async waitDrained(check: () => void): Promise<void> {
    const until = Date.now() + 120_000;
    while ((this.ws.bufferedAmount ?? 0) > 0 && Date.now() < until) {
      if (this.ws.readyState !== OPEN) throw new FileOpError("closed");
      await sleep(20);
      check();
    }
  }

  /** 上傳清單的相對路徑用受控端的分隔字元 */
  private remoteRel(name: string): string {
    return this.windows ? name.replace(/\//g, "\\") : name.replace(/\\/g, "/");
  }
}

type PeerAnswer = { kind: "go" } | { kind: "skip" }
  | { kind: "conflict"; fileNum: number; size: number; modified: number; identical: boolean };

/** 畫面用：這一列是不是資料夾（含連結到資料夾、磁碟機） */
export function entryIsDir(e: FileEntry): boolean {
  return isDirType(e.type);
}
