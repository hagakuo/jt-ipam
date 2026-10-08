/**
 * 手寫 <table>（沒有走 NDataTable 的那幾張）的欄寬拖拉：`<table v-col-resize>`。
 *
 * NDataTable 已在元件層統一可拖拉（utils/resizableColumns）；這裡補上少數直接寫 HTML 表格、
 * 但有欄位標頭的地方，行為一致：拖標頭右緣改該欄寬度，其他欄不動（表格跟著變寬／變窄）。
 * 第一次拖的時候才把目前的欄寬固定下來，拖之前的排版與原本完全一樣。
 */
import type { Directive } from "vue";

const MIN_W = 48;
const HANDLE_CLASS = "jt-col-resize";

function headerCells(table: HTMLTableElement): HTMLTableCellElement[] {
  const row = table.tHead?.rows[0];
  return row ? Array.from(row.cells) : [];
}

/** 第一次拖之前：把每欄目前的寬度寫死、改成固定排版，之後只動被拖的那一欄 */
function freeze(table: HTMLTableElement, cells: HTMLTableCellElement[]) {
  if (table.dataset.colFrozen) return;
  const widths = cells.map((c) => c.getBoundingClientRect().width);
  // border-box：量到的寬度含內距與框線，寫回去時也要照同一個算法，不然每格都會多出內距那麼寬
  cells.forEach((c, i) => { c.style.boxSizing = "border-box"; c.style.width = `${widths[i]}px`; });
  table.style.width = `${table.getBoundingClientRect().width}px`;
  table.style.tableLayout = "fixed";
  table.dataset.colFrozen = "1";
}

function attach(table: HTMLTableElement) {
  for (const th of headerCells(table)) {
    if (th.querySelector(`:scope > .${HANDLE_CLASS}`)) continue;
    if (getComputedStyle(th).position === "static") th.style.position = "relative";
    const handle = document.createElement("span");
    handle.className = HANDLE_CLASS;
    handle.setAttribute("aria-hidden", "true");
    handle.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      freeze(table, headerCells(table));
      const startX = ev.clientX;
      const startW = th.getBoundingClientRect().width;
      const startTable = table.getBoundingClientRect().width;
      handle.setPointerCapture(ev.pointerId);
      const move = (e: PointerEvent) => {
        const w = Math.max(MIN_W, startW + e.clientX - startX);
        th.style.width = `${w}px`;
        table.style.width = `${startTable + (w - startW)}px`;
      };
      const up = (e: PointerEvent) => {
        handle.releasePointerCapture(e.pointerId);
        handle.removeEventListener("pointermove", move);
        handle.removeEventListener("pointerup", up);
        handle.removeEventListener("pointercancel", up);
      };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", up);
      handle.addEventListener("pointercancel", up);
    });
    // 點把手不要觸發標頭上的排序／點擊
    handle.addEventListener("click", (e) => e.stopPropagation());
    th.appendChild(handle);
  }
}

function tableOf(el: HTMLElement): HTMLTableElement | null {
  return el instanceof HTMLTableElement ? el : el.querySelector("table");
}

export const vColResize: Directive<HTMLElement> = {
  mounted(el) { const t = tableOf(el); if (t) attach(t); },
  // 標頭會隨語言／資料重繪：新長出來的 th 補上把手
  updated(el) { const t = tableOf(el); if (t) attach(t); },
};

let styled = false;
/**
 * 把手的樣式（全站一份）：標頭右緣內側一條 8px 的感應區，滑過時顯示細線。
 * 不可以跨出格子：標頭設了透明度（opacity）時每格自成一層，跨到隔壁的那一半會被蓋住、點不到。
 */
export function installColResizeStyle(): void {
  if (styled || typeof document === "undefined") return;
  styled = true;
  const s = document.createElement("style");
  s.textContent = `
.${HANDLE_CLASS}{position:absolute;top:0;right:0;width:8px;height:100%;cursor:col-resize;z-index:1;touch-action:none}
.${HANDLE_CLASS}::after{content:"";position:absolute;top:20%;bottom:20%;right:0;width:2px;border-radius:1px;background:transparent;transition:background .15s}
th:hover>.${HANDLE_CLASS}::after,.${HANDLE_CLASS}:active::after{background:rgba(128,128,128,.45)}
`;
  document.head.appendChild(s);
}

// 全域指令的型別（模板裡的 v-col-resize）
declare module "vue" {
  interface GlobalDirectives {
    vColResize: typeof vColResize;
  }
}
