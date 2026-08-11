export interface TraceHopEvent {
  type: "hop" | "done" | "error";
  hop?: number;
  host?: string | null;
  rtt_ms?: number | null;
  note?: string | null;
  tool?: string;
  path_mtu?: number | null;
  truncated?: boolean;
  detail?: string;
}

/**
 * 路徑追蹤（SSE）：一跳一個事件，最後一個是 done。
 *
 * 用 fetch 而不是 EventSource —— EventSource 不支援 POST，也帶不了 Authorization。
 * 與 chat 串流同一套解析。
 */
export async function traceStream(
  target: string,
  maxHops: number,
  onEvent: (ev: TraceHopEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  // 與 chat 串流同一套取法（apiClient 的 baseURL 是 "/"，這裡要自己組）
  const base = import.meta.env.VITE_API_BASE_URL || "";
  const token = localStorage.getItem("access_token");
  const resp = await fetch(`${base}/api/v1/tools/net/traceroute/stream`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ target, max_hops: maxHops }),
    signal,
  });
  if (!resp.ok || !resp.body) {
    let detail = `HTTP ${resp.status}`;
    try { detail = (await resp.json())?.detail ?? detail; } catch { /* 非 JSON */ }
    throw new Error(detail);
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let sep: number;
    while ((sep = buf.indexOf("\n\n")) !== -1) {
      const raw = buf.slice(0, sep);
      buf = buf.slice(sep + 2);
      const line = raw.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      const s = line.slice(5).trim();
      if (!s) continue;
      try { onEvent(JSON.parse(s) as TraceHopEvent); } catch { /* 跳過壞掉的 chunk */ }
    }
  }
}
