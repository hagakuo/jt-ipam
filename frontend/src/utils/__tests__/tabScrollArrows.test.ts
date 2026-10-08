import { describe, expect, it } from "vitest";
import { attachTabArrows } from "@/utils/tabScrollArrows";

// 使用者回饋：頁籤超出畫面時只能靠滾輪，沒有滾輪的滑鼠到不了最左、最右 → 兩端要有按鈕
function fakeTabs(scrollWidth: number, clientWidth: number) {
  const root = document.createElement("div");
  root.innerHTML = `<div class="n-tabs-nav"><div class="n-tabs-nav-scroll-wrapper"><div class="v-x-scroll"><div class="n-tabs-nav-scroll-content"></div></div></div></div>`;
  const scroller = root.querySelector(".v-x-scroll") as HTMLElement;
  Object.defineProperty(scroller, "scrollWidth", { value: scrollWidth, configurable: true });
  Object.defineProperty(scroller, "clientWidth", { value: clientWidth, configurable: true });
  document.body.appendChild(root);
  return { root, scroller };
}

describe("attachTabArrows", () => {
  it("放得下就不出現箭頭", () => {
    const { root } = fakeTabs(500, 800);
    const a = attachTabArrows(root)!;
    expect(a.left.hidden).toBe(true);
    expect(a.right.hidden).toBe(true);
  });

  it("放不下：在最左時只有右箭頭，捲到中間兩邊都有，捲到底只剩左箭頭", () => {
    const { root, scroller } = fakeTabs(2000, 800);
    const a = attachTabArrows(root)!;
    expect([a.left.hidden, a.right.hidden]).toEqual([true, false]);
    scroller.scrollLeft = 600;
    a.update();
    expect([a.left.hidden, a.right.hidden]).toEqual([false, false]);
    scroller.scrollLeft = 1200;
    a.update();
    expect([a.left.hidden, a.right.hidden]).toEqual([false, true]);
  });

  it("按右箭頭往右捲大約八成的可見寬度", () => {
    const { root, scroller } = fakeTabs(2000, 800);
    let asked: ScrollToOptions | undefined;
    scroller.scrollBy = ((o: ScrollToOptions) => { asked = o; }) as typeof scroller.scrollBy;
    const a = attachTabArrows(root)!;
    a.right.click();
    expect(asked?.left).toBe(640);
  });

  it("不是會捲動的頁籤列（分段式）就不掛", () => {
    const root = document.createElement("div");
    root.innerHTML = `<div class="n-tabs-nav"><div class="n-tabs-rail"></div></div>`;
    expect(attachTabArrows(root)).toBeNull();
  });

  it("卸載時把按鈕清掉", () => {
    const { root } = fakeTabs(2000, 800);
    const a = attachTabArrows(root)!;
    a.destroy();
    expect(root.querySelectorAll(".jt-tab-arrow").length).toBe(0);
  });
});
