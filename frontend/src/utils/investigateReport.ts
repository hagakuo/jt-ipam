/**
 * 把「調查」的內容匯出成報告檔（.md / .txt / .html / .csv）。
 *
 * **零相依、純瀏覽器端**：只用 Blob + URL.createObjectURL，所以安裝與升級不必追加
 * 任何套件（這點有先確認過再做）。
 *
 * 中文編碼：
 * - `.txt` / `.csv` 前置 UTF-8 BOM。少了它，Excel 會以系統預設編碼開啟 CSV，
 *   中文變成亂碼 —— 這是實務上最常見的「匯出壞掉」。
 * - `.md` 不加 BOM：多數 Markdown 工具會把 BOM 當成內容的一部分，第一個標題會壞掉。
 * - `.html` 用 `<meta charset="utf-8">` 宣告，不靠 BOM。
 */

export type ReportFormat = "md" | "txt" | "html" | "csv";

const BOM = "﻿";

function download(text: string, filename: string, mime: string, bom: boolean): void {
  const blob = new Blob([bom ? BOM + text : text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  // 立刻 revoke 在部分瀏覽器會讓下載中斷，延後釋放
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/** 報告的一個區塊：標題 + 若干行。行留空的區塊不輸出，免得報告一半是空標題。 */
export interface ReportSection {
  title: string;
  lines: string[];
}

export interface ReportInput {
  ip: string;
  generatedAt: string;      // 呼叫端傳入（本地時間字串）
  summary: [string, string][];   // 名稱 / 值
  conflicts: string[];
  sections: ReportSection[];
  narrative?: string;       // AI 判讀（可能沒有）
  narrativeNote?: string;   // 「這是推測不是查核過的結論」那句
  /** 已渲染好的判讀 HTML（僅 .html 用）。純文字格式仍用 narrative 的原文。 */
  narrativeHtml?: string;
}

function esc(s: string): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** CSV 欄位跳脫：逗號、引號、換行都要包起來，否則欄位會錯位。 */
function csvCell(s: string): string {
  const v = String(s ?? "");
  return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function buildReport(input: ReportInput, fmt: ReportFormat): string {
  const secs = input.sections.filter((s) => s.lines.length > 0);
  if (fmt === "csv") {
    const rows: string[][] = [["區塊", "內容"]];
    for (const [k, v] of input.summary) rows.push([k, v]);
    for (const c of input.conflicts) rows.push(["矛盾", c]);
    for (const s of secs) for (const l of s.lines) rows.push([s.title, l]);
    if (input.narrative) rows.push(["AI 判讀", input.narrative]);
    // CRLF：Excel 對 LF-only 的多行欄位處理不一致
    return rows.map((r) => r.map(csvCell).join(",")).join("\r\n");
  }
  if (fmt === "html") {
    const part = (s: ReportSection) =>
      `<h2>${esc(s.title)}</h2>\n<ul>\n${s.lines.map((l) => `  <li>${esc(l)}</li>`).join("\n")}\n</ul>`;
    return `<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<title>${esc(input.ip)} 調查報告</title>
<style>
 body { font-family: system-ui, "Noto Sans TC", sans-serif; line-height: 1.7;
        max-width: 900px; margin: 32px auto; padding: 0 16px; color: #222; }
 h1 { font-size: 22px; } h2 { font-size: 16px; margin-top: 26px; }
 table { border-collapse: collapse; } td { padding: 2px 12px 2px 0; vertical-align: top; }
 .k { color: #666; } .warn { background: #fff6e5; padding: 10px 14px; border-radius: 8px; }
 .note { color: #666; font-size: 13px; }
 ul { padding-left: 20px; } li { margin: 2px 0; }
 .md code { background: #f2f2f2; padding: 1px 5px; border-radius: 4px; font-size: 13px; }
 .md p { margin: 8px 0; }
</style>
</head>
<body>
<h1>${esc(input.ip)} 調查報告</h1>
<p class="note">產生時間：${esc(input.generatedAt)}</p>
<table>
${input.summary.map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td>${esc(v)}</td></tr>`).join("\n")}
</table>
${input.conflicts.length ? `<div class="warn"><b>矛盾</b><ul>${input.conflicts.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></div>` : ""}
${secs.map(part).join("\n")}
${input.narrative ? `<h2>AI 判讀</h2>\n<p class="note">${esc(input.narrativeNote ?? "")}</p>\n<div class="md">${input.narrativeHtml ?? `<pre style="white-space:pre-wrap">${esc(input.narrative)}</pre>`}</div>` : ""}
</body>
</html>`;
  }
  // md 與 txt 共用結構，差別只在標記符號
  const md = fmt === "md";
  const h1 = md ? `# ${input.ip} 調查報告` : `${input.ip} 調查報告`;
  const bullet = md ? "- " : "  · ";
  const out: string[] = [h1, "", `產生時間：${input.generatedAt}`, ""];
  for (const [k, v] of input.summary) out.push(`${bullet}${k}：${v}`);
  if (input.conflicts.length) {
    out.push("", md ? "## 矛盾" : "【矛盾】");
    for (const c of input.conflicts) out.push(`${bullet}${c}`);
  }
  for (const s of secs) {
    out.push("", md ? `## ${s.title}` : `【${s.title}】`);
    for (const l of s.lines) out.push(`${bullet}${l}`);
  }
  if (input.narrative) {
    out.push("", md ? "## AI 判讀" : "【AI 判讀】");
    if (input.narrativeNote) out.push(input.narrativeNote, "");
    out.push(input.narrative);
  }
  return out.join("\n");
}

const MIME: Record<ReportFormat, string> = {
  md: "text/markdown", txt: "text/plain", html: "text/html", csv: "text/csv",
};

export function downloadReport(input: ReportInput, fmt: ReportFormat): void {
  const name = `investigate-${input.ip.replace(/[^0-9a-zA-Z.:_-]/g, "_")}.${fmt}`;
  // txt / csv 加 BOM（Excel 與 Windows 記事本靠它認出 UTF-8）；md / html 不加
  download(buildReport(input, fmt), name, MIME[fmt], fmt === "txt" || fmt === "csv");
}
