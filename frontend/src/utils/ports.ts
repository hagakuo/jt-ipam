/**
 * 連接埠清單解析：支援單一埠與 `起-迄` 範圍（`22-23`）。
 *
 * 用 `-` 而不是 `:`：nmap、ufw、iptables 都是這個寫法，網管一看就懂；
 * `:` 在 Docker 等工具裡是「對映」的意思，容易誤解。
 *
 * **不合法的部分要回報，不能默默丟掉** —— 原本 `Number("22-23")` 得到 NaN 後被過濾掉，
 * 使用者輸入了範圍卻只看到單一埠的結果，畫面上沒有任何說明。
 */
export interface PortParse {
  ports: number[];
  /** 看不懂而被略過的片段（要顯示給使用者，不能吞掉） */
  invalid: string[];
  /** 因為超過上限而沒被納入 */
  overflow: boolean;
}

export const MAX_PORTS = 16;

export function parsePorts(raw: string, max = MAX_PORTS): PortParse {
  const out: number[] = [];
  const invalid: string[] = [];
  let overflow = false;
  const seen = new Set<number>();

  const push = (n: number) => {
    if (seen.has(n)) return;
    if (out.length >= max) { overflow = true; return; }
    seen.add(n);
    out.push(n);
  };
  const valid = (n: number) => Number.isInteger(n) && n >= 1 && n <= 65535;

  for (const part of raw.split(/[\s,;]+/).filter(Boolean)) {
    const m = /^(\d+)-(\d+)$/.exec(part);
    if (m) {
      const a = Number(m[1]);
      const b = Number(m[2]);
      // 反向範圍（23-22）視為輸入錯誤而不是自動交換：使用者多半是打錯，
      // 默默調換會讓錯誤永遠不被發現
      if (!valid(a) || !valid(b) || a > b) { invalid.push(part); continue; }
      for (let p = a; p <= b; p += 1) push(p);
      continue;
    }
    const n = Number(part);
    if (!valid(n)) { invalid.push(part); continue; }
    push(n);
  }
  return { ports: out, invalid, overflow };
}
