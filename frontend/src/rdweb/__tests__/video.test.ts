/**
 * 相容 RustDesk 的網頁連線：畫面解碼的規則（8.2、8.3）。jsdom 沒有 WebCodecs，用假的 VideoDecoder。
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { VideoPipeline, type VideoSink } from "../video";
import type { EncodedFrame } from "../messages";

class FakeDecoder {
  static instances: FakeDecoder[] = [];
  state = "unconfigured";
  decodeQueueSize = 0;
  config: { codec: string } | null = null;
  chunks: { type: string; timestamp: number }[] = [];
  constructor(public init: { output: (f: unknown) => void; error: (e: unknown) => void }) {
    FakeDecoder.instances.push(this);
  }
  configure(c: { codec: string }) { this.config = c; this.state = "configured"; }
  decode(chunk: { type: string; timestamp: number }) { this.chunks.push(chunk); }
  close() { this.state = "closed"; }
}

class FakeChunk {
  type: string;
  timestamp: number;
  constructor(init: { type: string; timestamp: number }) {
    this.type = init.type;
    this.timestamp = init.timestamp;
  }
}

const f = (key: boolean, pts = 1): EncodedFrame => ({ data: new Uint8Array([1]), key, pts: BigInt(pts) });

describe("VideoPipeline", () => {
  let sink: { frame: Mock; requestKeyframe: Mock; unsupported: Mock };
  let t = 0;
  beforeEach(() => {
    FakeDecoder.instances = [];
    vi.stubGlobal("VideoDecoder", FakeDecoder);
    vi.stubGlobal("EncodedVideoChunk", FakeChunk);
    sink = { frame: vi.fn(), requestKeyframe: vi.fn(), unsupported: vi.fn() };
    t = 0;
  });
  afterEach(() => vi.unstubAllGlobals());

  it("一開始丟掉非關鍵影格，等到關鍵影格才開始解", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("vp9", [f(false), f(false)]);
    const d = FakeDecoder.instances[0];
    expect(d.config?.codec).toBe("vp09.00.10.08");
    expect(d.chunks).toHaveLength(0);
    expect(sink.requestKeyframe).toHaveBeenCalledTimes(1);     // 一秒內只要求一次
    p.push("vp9", [f(true, 5), f(false, 6)]);
    expect(d.chunks.map((c) => c.type)).toEqual(["key", "delta"]);
    expect(d.chunks[0].timestamp).toBe(5000);                   // pts（毫秒）× 1000
  });

  it("格式變了就重新 configure，並等新的關鍵影格", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("vp9", [f(true)]);
    p.push("av1", [f(false)]);
    expect(FakeDecoder.instances).toHaveLength(2);
    expect(FakeDecoder.instances[0].state).toBe("closed");
    expect(FakeDecoder.instances[1].config?.codec).toBe("av01.0.04M.08");
    expect(FakeDecoder.instances[1].chunks).toHaveLength(0);
    p.push("av1", [f(true)]);
    expect(FakeDecoder.instances[1].chunks).toHaveLength(1);
  });

  it("落後超過 5 個影格：丟非關鍵影格、要求關鍵影格", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("vp9", [f(true)]);
    const d = FakeDecoder.instances[0];
    d.decodeQueueSize = 6;
    sink.requestKeyframe.mockClear();
    p.push("vp9", [f(false), f(false)]);
    expect(d.chunks).toHaveLength(1);
    expect(sink.requestKeyframe).toHaveBeenCalledTimes(1);
    d.decodeQueueSize = 0;
    p.push("vp9", [f(false)]);                 // 還在等關鍵影格
    expect(d.chunks).toHaveLength(1);
    p.push("vp9", [f(true)]);
    expect(d.chunks).toHaveLength(2);
  });

  it("解碼錯誤後重建解碼器並要求關鍵影格", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("vp9", [f(true)]);
    sink.requestKeyframe.mockClear();
    FakeDecoder.instances[0].init.error(new Error("boom"));
    expect(sink.requestKeyframe).toHaveBeenCalledTimes(1);
    p.push("vp9", [f(false)]);
    expect(FakeDecoder.instances).toHaveLength(2);
    expect(FakeDecoder.instances[1].chunks).toHaveLength(0);
  });

  it("換螢幕後等新的關鍵影格", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("vp9", [f(true)]);
    p.waitForKeyframe();
    p.push("vp9", [f(false)]);
    expect(FakeDecoder.instances[0].chunks).toHaveLength(1);
  });

  it("H.265 第一階段不支援", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("h265", [f(true)]);
    expect(sink.unsupported).toHaveBeenCalledWith("h265");
  });

  it("H.264 用 avc1.42E01E、不給 description（Annex B）", () => {
    const p = new VideoPipeline(sink as unknown as VideoSink, () => t);
    p.push("h264", [f(true)]);
    expect(FakeDecoder.instances[0].config).toEqual({ codec: "avc1.42E01E", optimizeForLatency: true });
  });
});
