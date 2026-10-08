/**
 * 頁籤列的左右捲動按鈕（2026-09-29 使用者回饋：異常偵測的頁籤超出畫面只能用滾輪捲，
 * 沒有滾輪的滑鼠到不了最左、最右）。
 *
 * 做在元件這一層、全站的 NTabs 一次套上（頁籤多到超出的不只異常偵測，之後新頁面也一樣）：
 * 頁籤列放不下時，兩端才出現箭頭；還有東西在那一側才顯示那一側的箭頭。按一下捲大約八成的可見寬度，
 * 按兩下直接到底。按鈕蓋在捲動區兩端（不改變原本的排版），元件卸載時一起清掉。
 */
import { getCurrentInstance, onBeforeUnmount, onMounted, onUpdated, type SetupContext } from "vue";
import { i18n } from "@/i18n";

const BTN_CLASS = "jt-tab-arrow";
const CHEVRON = {
  left: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M15 6l-6 6 6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  right: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};

interface Arrows {
  scroller: HTMLElement;
  left: HTMLButtonElement;
  right: HTMLButtonElement;
  update: () => void;
  destroy: () => void;
}

function makeButton(side: "left" | "right", scroller: HTMLElement, onChange: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = `${BTN_CLASS} ${BTN_CLASS}--${side}`;
  b.innerHTML = CHEVRON[side];
  b.setAttribute("aria-label", String(i18n.global.t(side === "left" ? "common.scroll_left" : "common.scroll_right")));
  b.dataset.testid = `tabs-scroll-${side}`;
  const dir = side === "left" ? -1 : 1;
  b.addEventListener("click", (e) => {
    e.stopPropagation();
    scroller.scrollBy({ left: dir * Math.max(80, scroller.clientWidth * 0.8), behavior: "smooth" });
    window.setTimeout(onChange, 350);
  });
  b.addEventListener("dblclick", (e) => {
    e.stopPropagation();
    scroller.scrollTo({ left: dir < 0 ? 0 : scroller.scrollWidth, behavior: "smooth" });
    window.setTimeout(onChange, 350);
  });
  return b;
}

/** 在一個 NTabs 根元素上掛上箭頭；不是會捲動的頁籤列（分段式、直向）就不掛 */
export function attachTabArrows(root: Element | null | undefined): Arrows | null {
  if (!(root instanceof HTMLElement)) return null;
  const wrapper = root.querySelector<HTMLElement>(":scope > .n-tabs-nav > .n-tabs-nav-scroll-wrapper");
  const scroller = wrapper?.firstElementChild as HTMLElement | null | undefined;
  if (!wrapper || !scroller) return null;
  const update = () => {
    const max = scroller.scrollWidth - scroller.clientWidth;
    const overflow = max > 1;
    left.hidden = !overflow || scroller.scrollLeft <= 1;
    right.hidden = !overflow || scroller.scrollLeft >= max - 1;
  };
  const left = makeButton("left", scroller, () => update());
  const right = makeButton("right", scroller, () => update());
  if (getComputedStyle(wrapper).position === "static") wrapper.style.position = "relative";
  wrapper.append(left, right);
  scroller.addEventListener("scroll", update, { passive: true });
  const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(update) : null;
  ro?.observe(scroller);
  if (scroller.firstElementChild) ro?.observe(scroller.firstElementChild);
  update();
  return {
    scroller, left, right, update,
    destroy() {
      scroller.removeEventListener("scroll", update);
      ro?.disconnect();
      left.remove();
      right.remove();
    },
  };
}

interface SetupComponent {
  setup?: (props: Record<string, unknown>, ctx: SetupContext) => unknown;
  __jtTabArrows?: boolean;
}

/** 包住 NTabs 的 setup：掛載後加箭頭、更新時重算要不要顯示、卸載時清掉 */
export function installTabScrollArrows(component: unknown): void {
  const comp = component as SetupComponent;
  if (!comp || comp.__jtTabArrows || typeof comp.setup !== "function") return;
  const original = comp.setup;
  comp.setup = function (this: unknown, props, ctx) {
    const result = original.call(this, props, ctx);
    const inst = getCurrentInstance();
    let arrows: Arrows | null = null;
    const ensure = () => {
      const el = inst?.proxy?.$el as Element | undefined;
      // 根元素換掉了（很少見）就重掛
      if (arrows && !el?.contains(arrows.scroller)) { arrows.destroy(); arrows = null; }
      if (!arrows) arrows = attachTabArrows(el);
      arrows?.update();
    };
    onMounted(ensure);
    onUpdated(ensure);
    onBeforeUnmount(() => { arrows?.destroy(); arrows = null; });
    return result;
  };
  comp.__jtTabArrows = true;
}

let styled = false;
export function installTabArrowStyle(): void {
  if (styled || typeof document === "undefined") return;
  styled = true;
  const s = document.createElement("style");
  s.textContent = `
.${BTN_CLASS}{position:absolute;top:50%;transform:translateY(-50%);z-index:3;width:26px;height:26px;padding:0;
  display:inline-flex;align-items:center;justify-content:center;border-radius:50%;cursor:pointer;
  border:1px solid rgba(128,128,128,.28);background:rgba(255,255,255,.96);color:inherit;
  box-shadow:0 1px 4px rgba(15,23,42,.14)}
.${BTN_CLASS}[hidden]{display:none}
.${BTN_CLASS}--left{left:2px}
.${BTN_CLASS}--right{right:2px}
.${BTN_CLASS}:hover{border-color:rgba(24,160,88,.6);color:#18a058}
.${BTN_CLASS}:focus-visible{outline:2px solid #18a058;outline-offset:1px}
html[data-theme="dark"] .${BTN_CLASS}{background:rgba(40,40,46,.96);border-color:rgba(148,163,184,.3)}
`;
  document.head.appendChild(s);
}
