import { apiClient } from "./client";

/**
 * 調查模式：一個位址的完整線索。
 *
 * baseURL 是 "/"，所以路徑要自己帶 /api/v1 首碼（漏掉會打到 SPA 路徑，GET 拿回 index.html）。
 */
export async function investigate(ip: string, narrative = false, lang = "zh-TW") {
  const { data } = await apiClient.get("/api/v1/investigate", {
    params: { ip, narrative, lang },
  });
  return data as {
    dossier: any;
    narrative: string | null;
    narrative_error: string | null;
  };
}

export interface NarrativeEvent {
  type: "thinking" | "content" | "done" | "error";
  text?: string;
  elapsed?: number;
  detail?: string;
}

/**
 * 判讀的串流版：邊寫邊收，畫面才有進度。
 *
 * 一次等到好的話，使用者面對的是一顆按下去毫無動靜的按鈕 —— 分不出模型是在想、
 * 卡住、還是壞了。用 fetch 而非 EventSource（後者不支援 POST，也帶不了 Authorization）。
 */
export async function narrativeStream(
  ip: string,
  lang: string,
  onEvent: (ev: NarrativeEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const base = import.meta.env.VITE_API_BASE_URL || "";
  const token = localStorage.getItem("access_token");
  const url = `${base}/api/v1/investigate/narrative/stream`
    + `?ip=${encodeURIComponent(ip)}&lang=${encodeURIComponent(lang)}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
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
      const t = line.slice(5).trim();
      if (!t) continue;
      try { onEvent(JSON.parse(t) as NarrativeEvent); } catch { /* 壞掉的 chunk 跳過 */ }
    }
  }
}
