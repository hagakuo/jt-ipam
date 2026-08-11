/**
 * 偵測「已部署新版前端」→ 提示使用者重新整理。
 *
 * 解決長壽 SPA 分頁跑舊 bundle 的老問題：build 時 vite 會輸出 dist/version.json，
 * 這裡每隔幾分鐘（及視窗重新取得焦點時）以 no-store 取回，不同就跳一次持久提醒，
 * 點「重新整理」即整頁重載拿新 bundle。
 *
 * 比對兩件事：
 * 1. `version` 對上編譯進來的 __APP_VERSION__ —— 版本號有變就是新版。
 * 2. `build`（index.html 的雜湊）跟**這個分頁第一次看到的值**比 —— 同一個版本號重新
 *    build 時版本號不變，只有這個會變。少了它，改完 bug 重新部署，開著的分頁不會收到
 *    任何提示，會繼續跑舊 bundle 去呼叫已經不存在的端點（實際踩過）。
 *    刻意用「第一次看到的值」而不是編譯期常數：雜湊要等 bundle 產完才算得出來，
 *    沒辦法在 build 時塞進 bundle 自己。
 */
import { h, onMounted, onUnmounted } from "vue";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import { RefreshIcon } from "@/icons";

let prompted = false;         // 全分頁只提醒一次，避免洗版
let seenBuild: string | null = null;   // 這個分頁第一次看到的 build 識別碼

export function useVersionCheck() {
  const message = useMessage();
  const { t } = useI18n();
  let timer: number | null = null;

  async function check() {
    if (prompted) return;
    try {
      const res = await fetch(`/version.json?t=${Date.now()}`, { cache: "no-store" });
      if (!res.ok) return;
      const data = (await res.json()) as { version?: string; build?: string };
      const deployed = data?.version;
      const running = __APP_VERSION__;
      const build = data?.build;
      if (build && seenBuild === null) seenBuild = build;
      const changed = (!!deployed && !!running && deployed !== running)
        || (!!build && !!seenBuild && build !== seenBuild);
      if (changed) {
        prompted = true;
        message.warning("", {
          duration: 0,
          closable: true,
          render: () =>
            h(
              "div",
              {
                title: t("update.new_version_v", { v: deployed }),
                style:
                  "display:inline-flex;align-items:center;gap:8px;cursor:pointer;line-height:1;"
                  + "border:1px solid var(--primary-color,#18a058);border-radius:10px;"
                  + "padding:8px 16px;background:rgba(24,160,88,.1);"
                  + "box-shadow:0 4px 14px rgba(0,0,0,.15);"
                  + "font-weight:600;color:var(--primary-color,#18a058);white-space:nowrap",
                onClick: () => window.location.reload(),
              },
              [
                h("span", {
                  style: "display:inline-flex;align-items:center;justify-content:center;"
                    + "width:16px;height:16px;flex:0 0 auto",
                }, h(RefreshIcon, { width: 16, height: 16, style: "display:block" })),
                h("span", { style: "line-height:1" }, t("update.banner")),
              ],
            ),
        });
      }
    } catch { /* 離線 / 尚未部署 version.json → 略過 */ }
  }

  function onFocus() { void check(); }

  onMounted(() => {
    void check();
    timer = window.setInterval(check, 180_000); // 每 3 分鐘
    window.addEventListener("focus", onFocus);
  });
  onUnmounted(() => {
    if (timer !== null) window.clearInterval(timer);
    window.removeEventListener("focus", onFocus);
  });
}
