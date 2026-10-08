/**
 * 登入後要回去的頁面（`?next=`）只接受本站路徑（CodeQL 標出的開放式轉址，2026-09-29）。
 *
 * 原本只檢查「以 / 開頭」—— 但 `//evil.example/` 與 `/\evil.example/` 也以 / 開頭，
 * 瀏覽器會把它們當成**另一個網站**（protocol-relative URL；反斜線被當成斜線）。
 * 攻擊者寄一個真的 jt-ipam 登入連結，使用者登入後就被帶到長得一樣的假網站。
 * 做法：用目前網址當基準解析，來源（origin）必須相同，只取路徑＋查詢＋錨點。
 */
export function safeNextPath(next: unknown, origin: string = window.location.origin): string {
  if (typeof next !== "string" || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) {
    return "/";
  }
  try {
    const u = new URL(next, origin);
    if (u.origin !== origin) return "/";
    // 登入頁自己不當目的地（登入完又回登入頁會像沒登入成功）
    if (u.pathname === "/login") return "/";
    return u.pathname + u.search + u.hash;
  } catch {
    return "/";
  }
}
