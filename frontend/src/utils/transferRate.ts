/**
 * 傳輸速率（SFTP 上傳／下載）：最近幾秒的平均，而不是從頭算起的平均。
 *
 * 用「現在」當終點算：資料停了，速率就會往 0 掉，不會一直停在最後一次的數字 ——
 * 停住正是使用者最需要看出來的狀態（曾經的上傳卡住問題，畫面上的數字一動也不動才查得到）。
 */
export class RateMeter {
  private samples: { t: number; b: number }[] = [];

  constructor(private readonly windowMs = 5000) {}

  reset(): void {
    this.samples = [];
  }

  /** 記一筆「到目前為止共傳了多少位元組」。位元組變少（換了檔案）就從頭算 */
  add(bytes: number, now: number = Date.now()): void {
    const last = this.samples[this.samples.length - 1];
    if (last && bytes < last.b) this.samples = [];
    this.samples.push({ t: now, b: bytes });
    this.prune(now);
  }

  /** 每秒位元組；資料不夠（剛開始不到 1 秒）回 null */
  rate(now: number = Date.now()): number | null {
    this.prune(now);
    if (!this.samples.length) return null;
    const first = this.samples[0];
    const last = this.samples[this.samples.length - 1];
    const dt = (now - first.t) / 1000;
    if (dt < 1) return null;
    return Math.max(0, (last.b - first.b) / dt);
  }

  /** 剩餘秒數；算不出來（沒有速率或停住）回 null */
  eta(total: number, now: number = Date.now()): number | null {
    const r = this.rate(now);
    if (!r) return null;
    const last = this.samples[this.samples.length - 1];
    return Math.max(0, (total - last.b) / r);
  }

  private prune(now: number): void {
    // 留一筆窗外的當起點，才算得出整個窗的平均；更舊的丟掉
    while (this.samples.length > 1 && now - this.samples[1].t >= this.windowMs) this.samples.shift();
  }
}
