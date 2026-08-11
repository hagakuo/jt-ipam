import { defineConfig, loadEnv, type Plugin } from "vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";
import { readFileSync, writeFileSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";

// 從 package.json 讀版本號，build 時注入 __APP_VERSION__
const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf-8"));

// build 後輸出 dist/version.json，給前端輪詢偵測「已部署新版」→ 提示重新整理（解長壽分頁跑舊 bundle）
function emitVersionJson(): Plugin {
  return {
    name: "emit-version-json",
    apply: "build",
    closeBundle() {
      // 只寫版本號不夠：同一個版本號重新 build（修 bug、改 UI）時檔案內容不變，
      // 開著的舊分頁永遠不會被提示重載，於是繼續呼叫已經被移除的端點（實際踩過：
      // 舊 bundle 一直打 /ai-audit/run/stream 拿 404，畫面顯示「連線失敗」）。
      // 拿 index.html 的雜湊當 build 識別碼 —— 內容一樣就一樣，不會沒事跳提醒。
      const indexHtml = readFileSync(
        fileURLToPath(new URL("./dist/index.html", import.meta.url)), "utf-8");
      const build = createHash("sha256").update(indexHtml).digest("hex").slice(0, 12);
      writeFileSync(
        fileURLToPath(new URL("./dist/version.json", import.meta.url)),
        JSON.stringify({ version: pkg.version, build }),
      );
    },
  };
}

// 部署保留舊 hash 資產（搭配 emptyOutDir:false）：剛部署完，開著的舊分頁換頁時仍能抓到
// 自己那版的舊 chunk（不會 404 → 不被迫整頁重載 → 換頁秒開）。只清掉 7 天前的舊資產，
// 避免 dist 無限長大；這麼舊的分頁早就被版本偵測提示重載過了，刪掉也不影響任何活躍分頁。
function pruneOldAssets(days = 7): Plugin {
  return {
    name: "prune-old-assets",
    apply: "build",
    closeBundle() {
      try {
        const dir = fileURLToPath(new URL("./dist/assets", import.meta.url));
        const cutoff = Date.now() - days * 86_400_000;
        for (const f of readdirSync(dir)) {
          const p = `${dir}/${f}`;
          if (statSync(p).mtimeMs < cutoff) unlinkSync(p);
        }
      } catch { /* dist/assets 不存在（首次 build）就略過 */ }
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");

  return {
    plugins: [vue(), emitVersionJson(), pruneOldAssets()],
    define: {
      __APP_VERSION__: JSON.stringify(pkg.version),
    },
    resolve: {
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
    server: {
      host: "0.0.0.0",
      port: 5173,
      strictPort: true,
      proxy: {
        // Dev 模式下，代理 /api 到後端，避免 CORS（OWASP A05 — prod 走 nginx）
        "/api": {
          target: env.VITE_API_BASE_URL ?? "http://localhost:8000",
          changeOrigin: true,
          secure: false,
          // WebSocket（SSH／SFTP／AI 串流）也要代理，否則本機驗證時連不上 ——
          // 正式環境是 nginx 同源反代，本機沒有這一段就與正式行為不一致
          ws: true,
        },
      },
    },
    // `vite preview` 服務的是正式 build。本機用瀏覽器驗證時走這條路，
    // 所以它也要有同一份代理，否則前端打的 /api 會落到 preview 自己身上。
    preview: {
      proxy: {
        "/api": {
          target: env.VITE_API_BASE_URL ?? "http://localhost:8000",
          changeOrigin: true,
          secure: false,
          ws: true,
        },
      },
    },
    build: {
      target: "es2022",
      sourcemap: false, // prod 不出 sourcemap（避免洩漏內部資訊）
      // 不清空 dist：保留前幾版的 hash 資產，讓剛部署時開著的舊分頁換頁仍抓得到舊 chunk
      // （配合 pruneOldAssets 清 7 天前的舊檔）。index.html / version.json 每次 build 都會覆寫。
      emptyOutDir: false,
      rollupOptions: {
        output: {
          // 更佳的 chunk 切割
          manualChunks: {
            "naive-ui": ["naive-ui"],
            "vue-ecosystem": ["vue", "vue-router", "pinia"],
          },
        },
      },
    },
  };
});
