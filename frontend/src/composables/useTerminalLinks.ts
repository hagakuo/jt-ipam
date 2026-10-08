/**
 * 把「網址變成可以點的連結」接到任何一個 xterm 終端機上（SSH / BMC / noVNC 序列畫面共用）。
 *
 * 三件事一起做，因為它們是同一個抱怨的三個面向（TUI 裡的網址很難拿出來用）：
 *   1. 可點：自訂連結供應器，軟折行與 TUI 自己硬斷行的網址都接得回來（見 utils/terminalLinks）
 *   2. 看得到要去哪裡：滑過去時把**完整**網址回報給呼叫端顯示 —— 終端機文字是遠端主機控制的，
 *      點下去之前應該看得到實際目標，不能只看畫面上被切成好幾段的樣子
 *   3. 還是要複製時不會壞：選取跨列的網址複製時，把換行接回去（僅限毫無歧義的情況）
 *
 * 另外開 Unicode 11 寬度表：TUI 的框線與 emoji 寬度算錯就會整片錯位，
 * 而錯位會讓「使用者看到的」與「緩衝區實際的欄位」對不起來，選取自然也跟著歪掉。
 */

import { ref } from "vue";
import type { Terminal } from "@xterm/xterm";
import { createLinkProvider, joinIfBrokenUrl, openUrlSafely } from "@/utils/terminalLinks";

export function useTerminalLinks() {
  /** 滑鼠目前停在哪條連結上（完整網址）；null＝沒有 */
  const hoveredUrl = ref<string | null>(null);

  /** 回傳 dispose；元件卸載時呼叫 */
  function attachTerminalLinks(term: Terminal, container: HTMLElement | null): () => void {
    const disposables: (() => void)[] = [];

    const provider = term.registerLinkProvider(
      createLinkProvider(term, { onHover: (u) => { hoveredUrl.value = u; } }),
    );
    disposables.push(() => provider.dispose());

    // OSC 8 超連結：有些程式會用跳脫序列標記連結，xterm 認得但要我們決定怎麼開
    term.options.linkHandler = {
      activate: (event: MouseEvent, uri: string) => { event.preventDefault(); openUrlSafely(uri); },
      hover: (_e: MouseEvent, uri: string) => { hoveredUrl.value = uri; },
      leave: () => { hoveredUrl.value = null; },
    };

    // Unicode 11 寬度表（需要 allowProposedApi，建立 Terminal 時要一起開）
    void (async () => {
      try {
        const { Unicode11Addon } = await import("@xterm/addon-unicode11");
        term.loadAddon(new Unicode11Addon());
        term.unicode.activeVersion = "11";
      } catch {
        /* 載不到就用內建寬度表，功能不受影響 */
      }
    })();

    if (container) {
      const onCopy = (ev: ClipboardEvent) => {
        const sel = term.getSelection();
        const joined = joinIfBrokenUrl(sel);
        if (!joined || !ev.clipboardData) return;
        ev.clipboardData.setData("text/plain", joined);
        ev.preventDefault();
        // xterm 自己也掛了 copy 處理器（在內部的 textarea 上），它會無條件把原始選取寫回剪貼簿。
        // 這裡在捕獲階段就把事件擋下來，否則我們接好的網址會立刻被覆蓋掉。
        ev.stopPropagation();
      };
      container.addEventListener("copy", onCopy, true);
      disposables.push(() => container.removeEventListener("copy", onCopy, true));
    }

    return () => {
      hoveredUrl.value = null;
      for (const d of disposables) {
        try { d(); } catch { /* 卸載時的例外不需處理 */ }
      }
    };
  }

  return { hoveredUrl, attachTerminalLinks };
}
