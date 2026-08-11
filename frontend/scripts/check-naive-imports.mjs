#!/usr/bin/env node
/**
 * 檢查每個 .vue 的 template 裡用到的 <n-xxx> 都有在同一個檔案 import。
 *
 * 這個專案沒有自動註冊 naive-ui，元件要逐檔 `import { NFoo } from "naive-ui"`。
 * 漏掉不會有任何錯誤：vue-tsc / eslint / build 全都會過，因為那是執行期解析的事。
 * 畫面上的症狀是「元件消失，它的預設插槽內容原地變成純文字」——
 * v0.5.140 的 <n-popconfirm> 就是這樣，確認文字直接印在頁首按鈕列上。
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("../src", import.meta.url).pathname;

/** 由 App.vue 的 n-config-provider 等提供、或 naive 自己內部渲染的，不必逐檔 import。 */
const GLOBAL_OK = new Set([
  "n-config-provider", "n-message-provider", "n-dialog-provider",
  "n-notification-provider", "n-loading-bar-provider", "n-modal-provider",
]);

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".vue") ? [p] : [];
  });
}

/** kebab <n-radio-button> → PascalCase NRadioButton */
const toPascal = (tag) =>
  tag.split("-").map((w) => w[0].toUpperCase() + w.slice(1)).join("");

let bad = 0;
let files = 0;
for (const file of walk(ROOT)) {
  const src = readFileSync(file, "utf8");
  files += 1;
  const used = new Set();
  for (const m of src.matchAll(/<(n-[a-z0-9-]+)[\s/>]/g)) used.add(m[1]);
  if (!used.size) continue;
  // 同一個檔案可能有多段 naive-ui import（常見是 `import type { ... }` 另外一段），
  // 只取第一段會誤判整份檔案沒 import。全部取出來合併。
  const imported = new Set();
  // 群組內不允許出現大括號 —— 否則非貪婪比對會從檔案更前面的 import 一路吃過來，
  // 把 `NCard` 黏在 `ref } from "vue";\nimport {\n  NCard` 這種字串裡，逗號一切就認不得了。
  for (const m of src.matchAll(/import\s+(?:type\s+)?\{([^{}]*)\}\s*from\s*["']naive-ui["']/g)) {
    for (const part of m[1].split(",")) {
      const name = part.replace(/\btype\b/, "").split(/\bas\b/)[0].trim();
      if (name) imported.add(name);
    }
  }
  const missing = [...used]
    .filter((tag) => !GLOBAL_OK.has(tag))
    .filter((tag) => !imported.has(toPascal(tag)));
  if (missing.length) {
    bad += 1;
    console.error(`[check-naive] ${file.replace(ROOT, "src")} 用了但沒 import：${missing.join(", ")}`);
  }
}

console.log(`[check-naive] checked ${files} .vue files — ${bad} with missing imports`);
process.exit(bad ? 1 : 0);
