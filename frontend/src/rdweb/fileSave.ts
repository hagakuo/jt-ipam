/**
 * 相容 RustDesk 的網頁連線：下載的檔案交給瀏覽器存檔（規格附錄 J.6）。
 *
 * - 小檔（MEMORY_SAVE_MAX 以下）在記憶體組好再存
 * - 大檔：瀏覽器支援串流存檔（File System Access API，Chrome／Edge）時邊收邊寫進磁碟，要在按下「下載」的
 *   當下問存到哪裡（瀏覽器要求使用者手勢）；不支援的瀏覽器改成分段寫入：每 SEGMENT_BYTES 合成一個 Blob 片段，
 *   JavaScript 記憶體裡只留一段（瀏覽器會把大的 Blob 放到磁碟），不會把整個檔案放在記憶體裡
 * - 檔名來自受控端：只用來當下載的檔名，先經過 safeDownloadName（去掉路徑分隔與控制字元）
 */
import type { DownloadSink } from "./fileSession";
import { safeDownloadName } from "./files";

/** J.6：這個大小以下在記憶體組好再存 */
export const MEMORY_SAVE_MAX = 200 * 1024 * 1024;
/** 分段寫入：每 8 MB 合成一個 Blob 片段 */
export const SEGMENT_BYTES = 8 * 1024 * 1024;

export type Saver = (blob: Blob, name: string) => void;

/** 以 <a download> 存檔（檔名再過一次 safeDownloadName）。 */
export function anchorSave(blob: Blob, name: string): void {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = safeDownloadName(name);
  a.rel = "noopener";
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 60_000);
}

/** 收進 Blob 片段，收完再存檔。片段大小以下的資料才留在 JavaScript 記憶體。 */
export class BlobSink implements DownloadSink {
  private parts: Blob[] = [];
  private pending: Uint8Array[] = [];
  private pendingBytes = 0;
  private done = false;

  constructor(private readonly name: string, private readonly save: Saver = anchorSave,
              private readonly segment = SEGMENT_BYTES) {}

  write(chunk: Uint8Array): void {
    if (this.done) return;
    this.pending.push(chunk);
    this.pendingBytes += chunk.length;
    if (this.pendingBytes >= this.segment) this.flush();
  }

  async close(): Promise<void> {
    if (this.done) return;
    this.flush();
    this.done = true;
    const blob = new Blob(this.parts, { type: "application/octet-stream" });
    this.parts = [];
    this.save(blob, this.name);
  }

  abort(): void {
    this.done = true;
    this.parts = [];
    this.pending = [];
    this.pendingBytes = 0;
  }

  /** 已經合成的片段數（測試用） */
  get segments(): number {
    return this.parts.length;
  }

  private flush(): void {
    if (!this.pending.length) return;
    this.parts.push(new Blob(this.pending as BlobPart[]));
    this.pending = [];
    this.pendingBytes = 0;
  }
}

/** File System Access API 的可寫串流（只用到這幾個方法） */
export interface WritableLike {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort?(): Promise<void>;
}

/** 邊收邊寫進磁碟。中斷時 abort：瀏覽器丟掉暫存檔，不會留下半截的檔案。 */
export class StreamSink implements DownloadSink {
  constructor(private readonly writable: WritableLike) {}

  write(chunk: Uint8Array): Promise<void> {
    return this.writable.write(chunk);
  }

  close(): Promise<void> {
    return this.writable.close();
  }

  async abort(): Promise<void> {
    try { await this.writable.abort?.(); } catch { /* 已經關了 */ }
  }
}

type SavePicker = (o: { suggestedName: string }) => Promise<{ createWritable(): Promise<WritableLike> }>;

/**
 * 按下「下載」時呼叫（要在點擊的當下、任何 await 之前）：大檔而且瀏覽器支援串流存檔就先問存到哪裡；
 * 其他情況收進 Blob 片段。使用者取消存檔對話框回 null。
 */
export async function pickDownloadSink(name: string, size: number,
                                       win: { showSaveFilePicker?: unknown } = window as never): Promise<DownloadSink | null> {
  const pick = win.showSaveFilePicker as SavePicker | undefined;
  if (size > MEMORY_SAVE_MAX && typeof pick === "function") {
    try {
      const handle = await pick.call(win, { suggestedName: safeDownloadName(name) });
      return new StreamSink(await handle.createWritable());
    } catch (e) {
      if ((e as { name?: string } | null)?.name === "AbortError") return null;
      throw e;
    }
  }
  return new BlobSink(name);
}
