/**
 * 相容 RustDesk 的網頁連線：畫面解碼（規格第 8.2、8.3 節），用瀏覽器的 WebCodecs。
 *
 * - 一開始、換格式後、換螢幕後、解碼錯誤後：丟掉非關鍵影格，等到 key = true 才開始送進解碼器
 * - 格式變了就重新 configure（同一台同時有別人連著時，受控端選的格式可能不是我們偏好的）
 * - 落後：decodeQueueSize 超過大約 5 個影格，丟掉非關鍵影格並要求關鍵影格
 * - 解出來的 VideoFrame 畫到 canvas，畫完一定要 close()
 */
import type { Codec, Decoding, EncodedFrame } from "./messages";

/** 8.2 的 codec 字串。H.265 第一階段不宣告，收到就是不支援。 */
export const CODEC_STRINGS: Partial<Record<Codec, string>> = {
  vp9: "vp09.00.10.08",
  vp8: "vp8",
  av1: "av01.0.04M.08",
  h264: "avc1.42E01E",          // 不給 description：資料是 Annex B
};

const BACKLOG_LIMIT = 5;
const KEYFRAME_REQUEST_GAP_MS = 1000;

/** 先用 isConfigSupported 測瀏覽器能解哪些（7.4：依實際能解的宣告）。 */
export async function probeDecoding(): Promise<Decoding & { webcodecs: boolean }> {
  const out = { vp9: false, h264: false, vp8: false, av1: false, webcodecs: false };
  const VD = (globalThis as { VideoDecoder?: typeof VideoDecoder }).VideoDecoder;
  if (!VD || typeof VD.isConfigSupported !== "function") return out;
  out.webcodecs = true;
  for (const c of ["vp9", "h264", "vp8", "av1"] as const) {
    try {
      const r = await VD.isConfigSupported({ codec: CODEC_STRINGS[c]!, optimizeForLatency: true });
      out[c] = !!r.supported;
    } catch {
      out[c] = false;
    }
  }
  return out;
}

export interface VideoSink {
  /** 新的一張畫面（呼叫端畫完要 close）。 */
  frame(frame: VideoFrame): void;
  /** 要求受控端送關鍵影格（8.3）。 */
  requestKeyframe(): void;
  /** 瀏覽器解不了受控端選的格式。 */
  unsupported(codec: Codec): void;
}

export class VideoPipeline {
  private decoder: VideoDecoder | null = null;
  private codec: Codec | null = null;
  private needKey = true;
  private lastKeyRequest = Number.NEGATIVE_INFINITY;
  private closed = false;
  decoded = 0;
  dropped = 0;

  constructor(private readonly sink: VideoSink, private readonly now: () => number = () => performance.now()) {}

  /** 一則 VideoFrame 訊息裡的影格，依序處理。 */
  push(codec: Codec, frames: EncodedFrame[]): void {
    if (this.closed) return;
    if (codec !== this.codec || !this.decoder || this.decoder.state === "closed") {
      if (!this.configure(codec)) return;
    }
    const dec = this.decoder!;
    for (const f of frames) {
      if (this.needKey && !f.key) {
        this.dropped++;
        this.askForKeyframe();
        continue;
      }
      if (!f.key && dec.decodeQueueSize > BACKLOG_LIMIT) {
        // 落後（例如分頁暫停過）：丟到下一個關鍵影格
        this.dropped++;
        this.needKey = true;
        this.askForKeyframe();
        continue;
      }
      if (f.key) this.needKey = false;
      try {
        dec.decode(new EncodedVideoChunk({
          type: f.key ? "key" : "delta",
          timestamp: Number(f.pts) * 1000,
          data: f.data,
        }));
      } catch {
        this.recover();
        return;
      }
    }
  }

  /** 這條管線目前在解的格式（狀態列顯示用，附錄 I.2） */
  get currentCodec(): Codec | null {
    return this.codec;
  }

  /**
   * 換螢幕或解析度（8.5 switch_display）：等新的關鍵影格。
   * request = false：不再要求一次（附錄 H.2 的切換已經送過 refresh_video_display；大小改變後受控端會自己送）。
   */
  waitForKeyframe(request = true): void {
    this.needKey = true;
    if (request) this.askForKeyframe(true);
  }

  close(): void {
    this.closed = true;
    try {
      if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    } catch { /* 已經關了 */ }
    this.decoder = null;
  }

  private configure(codec: Codec): boolean {
    const codecString = CODEC_STRINGS[codec];
    if (!codecString || typeof VideoDecoder === "undefined") {
      this.sink.unsupported(codec);
      return false;
    }
    try {
      if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    } catch { /* 忽略 */ }
    const dec = new VideoDecoder({
      output: (frame) => {
        this.decoded++;
        if (this.closed) {
          frame.close();
          return;
        }
        this.sink.frame(frame);
      },
      error: () => {
        // 解碼器出錯後就不能用了：重建、丟到下一個關鍵影格
        if (!this.closed) this.recover();
      },
    });
    try {
      dec.configure({ codec: codecString, optimizeForLatency: true });
    } catch {
      this.sink.unsupported(codec);
      return false;
    }
    this.decoder = dec;
    this.codec = codec;
    this.needKey = true;
    return true;
  }

  private recover(): void {
    const codec = this.codec;
    this.codec = null;
    try {
      if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    } catch { /* 忽略 */ }
    this.decoder = null;
    this.needKey = true;
    if (codec) this.askForKeyframe(true);
  }

  private askForKeyframe(force = false): void {
    const t = this.now();
    if (!force && t - this.lastKeyRequest < KEYFRAME_REQUEST_GAP_MS) return;
    this.lastKeyRequest = t;
    this.sink.requestKeyframe();
  }
}
