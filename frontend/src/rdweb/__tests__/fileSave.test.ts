/**
 * 相容 RustDesk 的網頁連線：下載的存檔（規格附錄 J.6）。小檔在記憶體組好再存；大檔用串流存檔（支援時）或分段寫入。
 */
import { describe, expect, it } from "vitest";
import { BlobSink, MEMORY_SAVE_MAX, pickDownloadSink, StreamSink, type WritableLike } from "../fileSave";

describe("Blob 片段", () => {
  it("每滿一段就合成一個 Blob，JavaScript 記憶體只留一段；收完用安全的檔名存檔", async () => {
    const saved: { blob: Blob; name: string }[] = [];
    const sink = new BlobSink("../evil‮fdp.exe", (blob, name) => saved.push({ blob, name }), 10);
    sink.write(new Uint8Array(6));
    expect(sink.segments).toBe(0);
    sink.write(new Uint8Array(6));
    expect(sink.segments).toBe(1);
    sink.write(new Uint8Array(3));
    await sink.close();
    expect(saved).toHaveLength(1);
    expect(saved[0].blob.size).toBe(15);
    // 檔名要等存檔時才過濾（anchorSave 裡）；這裡交給 Saver 的是原本的名稱
    expect(saved[0].name).toBe("../evil‮fdp.exe");
  });

  it("中斷就不存檔", async () => {
    const saved: Blob[] = [];
    const sink = new BlobSink("a", (b) => saved.push(b));
    sink.write(new Uint8Array(3));
    sink.abort();
    await sink.close();
    expect(saved).toHaveLength(0);
  });
});

describe("選擇存檔方式", () => {
  class FakeWritable implements WritableLike {
    written = 0;
    closed = false;
    aborted = false;
    async write(d: Uint8Array) { this.written += d.length; }
    async close() { this.closed = true; }
    async abort() { this.aborted = true; }
  }

  it("小檔：記憶體（不問存到哪裡）", async () => {
    let asked = false;
    const sink = await pickDownloadSink("a.txt", 100, { showSaveFilePicker: async () => { asked = true; } });
    expect(sink).toBeInstanceOf(BlobSink);
    expect(asked).toBe(false);
  });

  it("大檔而且支援串流存檔：先問存到哪裡（建議檔名已過濾），邊收邊寫", async () => {
    const w = new FakeWritable();
    let suggested = "";
    const sink = await pickDownloadSink("dir/big\u0007.iso", MEMORY_SAVE_MAX + 1, {
      showSaveFilePicker: async (o: { suggestedName: string }) => {
        suggested = o.suggestedName;
        return { createWritable: async () => w };
      },
    });
    expect(sink).toBeInstanceOf(StreamSink);
    expect(suggested).toBe("big.iso");
    await sink!.write(new Uint8Array(5));
    await sink!.close();
    expect(w.written).toBe(5);
    expect(w.closed).toBe(true);
  });

  it("使用者取消存檔對話框：回 null（不下載）", async () => {
    const sink = await pickDownloadSink("x", MEMORY_SAVE_MAX + 1, {
      showSaveFilePicker: async () => { throw Object.assign(new Error("cancel"), { name: "AbortError" }); },
    });
    expect(sink).toBeNull();
  });

  it("大檔但不支援串流存檔：分段寫入（Blob 片段）", async () => {
    const sink = await pickDownloadSink("x", MEMORY_SAVE_MAX * 3, {});
    expect(sink).toBeInstanceOf(BlobSink);
  });
});
