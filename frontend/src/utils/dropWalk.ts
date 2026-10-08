/**
 * 把拖進來的項目展開成「要上傳的檔案 + 它在目的地的相對路徑」。
 *
 * 拖資料夾時瀏覽器只給一個 `DataTransferItem`，裡面的內容要自己用
 * `FileSystemDirectoryEntry.createReader()` 一層一層讀出來 —— 而且 `readEntries()`
 * **一次不保證回傳全部**，要一直讀到回空陣列為止；只讀一次的話大資料夾會安靜地少檔案。
 *
 * 拿不到 entry API 時退回「只收檔案、資料夾略過」，行為與先前一致。
 *
 * ⚠️ **絕對不可以用 `File.size` 判斷是不是資料夾** —— macOS 交出來的資料夾 size 是 256，
 * 用 `size > 0` 篩會把資料夾當成檔案，一路送到上傳流程才在讀內容時失敗，
 * 而且會把整條連線的協定弄錯位（實際踩過，症狀是「連線已中斷」）。型別只看 entry。
 */

export interface EntryLike {
  isFile: boolean;
  isDirectory?: boolean;
  name?: string;
  file?: (ok: (f: File) => void, err?: (e: unknown) => void) => void;
  createReader?: () => { readEntries: (ok: (es: EntryLike[]) => void, err?: (e: unknown) => void) => void };
}

/** 一個要上傳的檔案：`path` 是相對於「放置的那個目錄」的路徑（含子目錄）。 */
export interface PickedFile {
  file: File;
  path: string;
}

export interface WalkResult {
  files: PickedFile[];
  /** 拿不到 entry 而被略過的資料夾數（舊行為的退路）。 */
  skippedDirs: number;
  /** 因為超過上限而沒有收進來的項目數 —— **一定要說出來**，不能安靜截斷。 */
  droppedOverLimit: number;
}

/** 一次拖曳最多展開幾個檔案。純粹是防呆：誤拖家目錄不該讓瀏覽器與遠端一起陪葬。 */
export const MAX_FILES_PER_DROP = 500;
/** 最多往下幾層 —— 避免符號連結繞成環時無止盡地走下去。 */
export const MAX_DEPTH = 16;

function entryFile(e: EntryLike): Promise<File | null> {
  return new Promise((resolve) => {
    if (!e.file) { resolve(null); return; }
    try { e.file((f) => resolve(f), () => resolve(null)); } catch { resolve(null); }
  });
}

/** 讀完一個目錄的所有項目（`readEntries` 要一直呼叫到回空陣列）。 */
function readAll(e: EntryLike): Promise<EntryLike[]> {
  return new Promise((resolve) => {
    const reader = e.createReader?.();
    if (!reader) { resolve([]); return; }
    const acc: EntryLike[] = [];
    const step = () => {
      reader.readEntries((batch) => {
        if (!batch.length) { resolve(acc); return; }
        acc.push(...batch);
        step();
      }, () => resolve(acc));
    };
    step();
  });
}

/** 檔名／資料夾名的安全檢查：路徑分隔字元與 `..` 一律不收。 */
function safeName(name: string | undefined): string | null {
  const n = (name ?? "").trim();
  if (!n || n === "." || n === ".." || n.includes("/") || n.includes("\\")) return null;
  return n;
}

async function walk(
  entry: EntryLike, prefix: string, out: PickedFile[], depth: number, state: { over: number },
): Promise<void> {
  if (out.length >= MAX_FILES_PER_DROP) { state.over += 1; return; }
  const name = safeName(entry.name);
  if (name === null) { state.over += 1; return; }
  const path = prefix ? `${prefix}/${name}` : name;

  if (entry.isFile) {
    const f = await entryFile(entry);
    // 讀不到就跳過：那是使用者機器上的問題，不該讓整批停下來
    if (f) out.push({ file: f, path });
    return;
  }
  if (!entry.isDirectory || depth >= MAX_DEPTH) { state.over += 1; return; }
  for (const child of await readAll(entry)) {
    await walk(child, path, out, depth + 1, state);
    if (out.length >= MAX_FILES_PER_DROP) { state.over += 1; return; }
  }
}

/**
 * `files` 與 `entries` 在拖放時索引是對齊的。有 entry 就照 entry 展開（資料夾會遞迴進去），
 * 拿不到 entry 的項目就當一般檔案收下 —— 上傳前還有一道可讀性檢查。
 */
export async function collectDroppedFiles(
  files: File[], entries: (EntryLike | null | undefined)[],
): Promise<WalkResult> {
  const out: PickedFile[] = [];
  const state = { over: 0 };
  let skippedDirs = 0;

  for (let i = 0; i < files.length; i += 1) {
    const e = entries[i];
    if (!e) {
      // 沒有 entry：只能當檔案處理。資料夾在這條路徑上分辨不出來，
      // 但上傳前的可讀性檢查會擋下它。
      out.push({ file: files[i], path: files[i].name });
      continue;
    }
    if (e.isDirectory && !e.createReader) { skippedDirs += 1; continue; }
    await walk(e, "", out, 0, state);
  }
  return { files: out, skippedDirs, droppedOverLimit: state.over };
}

/** 一批檔案要先建立的目錄，由淺到深排序（父目錄一定排在子目錄前面）。 */
export function dirsToCreate(files: PickedFile[]): string[] {
  const dirs = new Set<string>();
  for (const f of files) {
    const parts = f.path.split("/");
    parts.pop();
    let acc = "";
    for (const p of parts) {
      acc = acc ? `${acc}/${p}` : p;
      dirs.add(acc);
    }
  }
  return [...dirs].sort((a, b) => a.split("/").length - b.split("/").length || a.localeCompare(b));
}
