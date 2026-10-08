/**
 * RustDesk 客戶端回報的作業系統字串：「windows / Windows 11 Pro - 11 (26200)」「ubuntu / Linux 24.04 Ubuntu」。
 * 畫面只要「Windows 11 Pro」「Ubuntu 24.04」：前面的平台名稱重複、後面的版本與組建號不需要（使用者 2026-10-05）。
 * Linux 的原文是「Linux <版本> <發行版>」、平台寫發行版名稱 —— 重排成「<發行版> <版本>」、平台一律寫 linux
 * （使用者 2026-10-07）。後端 services/rustdesk.py 的 os_display 是同一套規則。
 * 回傳 [主要文字, 平台]；沒有「 / 」時平台是空字串。
 */
const LINUX_DETAIL = /^linux\s+(\d[\w.-]*)\s+(.+)$/i;
const LINUX_NO_VERSION = /^linux\s+(\D.*)$/i;

export function rustdeskOs(raw: string | null | undefined): [string, string] {
  if (!raw) return ["", ""];
  const [plat, ...rest] = String(raw).split(" / ");
  let detail = (rest.join(" / ") || plat).replace(/\s+-\s+[\d.]+\s*\(\d+\)\s*$/, "").trim();
  let platform = rest.length ? plat : "";
  const m = LINUX_DETAIL.exec(detail);
  const n = m ? null : LINUX_NO_VERSION.exec(detail);
  if (m) {
    detail = `${m[2].trim()} ${m[1]}`;
    platform = "linux";
  } else if (n) {
    detail = n[1].trim();
    platform = "linux";
  }
  return [detail, platform];
}
