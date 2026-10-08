/**
 * 欄位選單的拖拉排序（使用者 2026-10-05：「所有頁面可以挑欄位的，也要可以拖拉改變欄位順序」）。
 *
 * 拖拉用 pointer events 做；jsdom 沒有版面，列的位置用 getBoundingClientRect 假造。
 */
import { afterEach, describe, expect, it } from "vitest";
import { nextTick } from "vue";
import { mount, type VueWrapper } from "@vue/test-utils";
import { createI18n } from "vue-i18n";
import ColumnPicker from "../ColumnPicker.vue";
import zhTW from "@/i18n/zh-TW.json";

const ALL = [
  { key: "ip", label: "IP" },
  { key: "hostname", label: "主機名稱" },
  { key: "mac", label: "MAC" },
];

let wrapper: VueWrapper | null = null;
afterEach(() => { wrapper?.unmount(); wrapper = null; document.body.innerHTML = ""; });

async function open(props: Record<string, unknown>) {
  const i18n = createI18n({ legacy: false, locale: "zh-TW", messages: { "zh-TW": zhTW } });
  wrapper = mount(ColumnPicker, {
    props: { all: ALL, visible: ["ip", "hostname", "mac"], ...props },
    global: { plugins: [i18n] },
    attachTo: document.body,
  });
  await wrapper.find("button").trigger("click");   // 打開選單
  await nextTick();
  await nextTick();
  return wrapper;
}

function rows(): HTMLElement[] {
  return Array.from(document.body.querySelectorAll<HTMLElement>("[data-picker-key]"));
}
function rowKeys(): string[] {
  return rows().map((r) => r.dataset.pickerKey!);
}
function handle(key: string): HTMLElement {
  return rows().find((r) => r.dataset.pickerKey === key)!.querySelector<HTMLElement>(".col-drag")!;
}
// 每列高 20px，由上往下排
function fakeLayout() {
  rows().forEach((r, i) => {
    r.getBoundingClientRect = () => ({
      top: i * 20, bottom: i * 20 + 20, left: 0, right: 200, height: 20, width: 200, x: 0, y: i * 20,
      toJSON: () => ({}),
    }) as DOMRect;
  });
}
function pointer(el: HTMLElement, type: string, clientY: number) {
  // jsdom 沒有 PointerEvent；用同名的 MouseEvent，元件只讀 clientY / button / pointerType
  el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, clientY, button: 0 }));
}

describe("ColumnPicker 拖拉排序", () => {
  it("照 order 顯示；沒有 order（null）就照 all", async () => {
    await open({ order: ["mac", "ip", "hostname"] });
    expect(rowKeys()).toEqual(["mac", "ip", "hostname"]);
    wrapper!.unmount(); wrapper = null; document.body.innerHTML = "";
    await open({ order: null });
    expect(rowKeys()).toEqual(["ip", "hostname", "mac"]);
  });

  it("把第一列拖到最後一列放開 → 送出新順序", async () => {
    const w = await open({ order: null });
    fakeLayout();
    const h = handle("ip");
    pointer(h, "pointerdown", 10);
    await nextTick();
    pointer(h, "pointermove", 55);     // 第三列（40～60）
    await nextTick();
    expect(rowKeys()).toEqual(["hostname", "mac", "ip"]);   // 拖拉中就看得到暫定順序
    expect(w.emitted("update:order")).toBeUndefined();      // 放開前不存
    pointer(h, "pointerup", 55);
    await nextTick();
    expect(w.emitted("update:order")).toEqual([[["hostname", "mac", "ip"]]]);
  });

  it("拖了又拖回原位、或被取消 → 不送出", async () => {
    const w = await open({ order: null });
    fakeLayout();
    const h = handle("ip");
    pointer(h, "pointerdown", 10);
    pointer(h, "pointermove", 30);
    await nextTick();
    fakeLayout();
    pointer(h, "pointermove", 5);
    pointer(h, "pointerup", 5);
    await nextTick();
    pointer(h, "pointerdown", 10);
    pointer(h, "pointermove", 55);
    pointer(h, "pointercancel", 55);
    await nextTick();
    expect(w.emitted("update:order")).toBeUndefined();
    expect(rowKeys()).toEqual(["ip", "hostname", "mac"]);
  });

  it("鍵盤：把手上按上／下方向鍵移動一格；頭尾再按不動", async () => {
    const w = await open({ order: null });
    handle("hostname").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
    handle("ip").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
    expect(w.emitted("update:order")).toEqual([[["hostname", "ip", "mac"]]]);
  });

  it("勾選照舊送出 update:visible", async () => {
    const w = await open({ order: null });
    const box = rows().find((r) => r.dataset.pickerKey === "mac")!.querySelector<HTMLElement>(".n-checkbox")!;
    box.click();
    await nextTick();
    expect(w.emitted("update:visible")).toEqual([[["ip", "hostname"]]]);
  });

  it("沒有接 order 的用法不顯示把手（拖了也存不起來）", async () => {
    await open({});
    expect(rows()).toHaveLength(3);
    expect(document.body.querySelectorAll(".col-drag")).toHaveLength(0);
  });
});
