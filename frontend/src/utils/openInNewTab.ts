/**
 * 開新分頁（主控台等站內頁面）。一律 noopener：
 * 留著 window.opener 會讓 Chrome 把兩個分頁放在同一個渲染程序、共用主執行緒，
 * 使用者回報從 IP 頁開 SSH 分頁後切回來整頁變黑。主控台頁不需要 opener。
 *
 * 彈出視窗（有指定視窗名稱與尺寸）不走這裡：同名視窗要能被重複使用，那需要 opener 關係。
 */
export function openInNewTab(href: string): void {
  window.open(href, "_blank", "noopener");
}
