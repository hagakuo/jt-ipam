#!/usr/bin/env node
// =============================================================================
// i18n compile gate — scan every message in each locale file with the
// vue-i18n message compiler. A literal @ (linked-message), { } (interpolation)
// or | (plural) in a message compiles fine in dev (warning only) but THROWS a
// SyntaxError in the production build, blanking the surrounding render.
// Escape literals with vue-i18n literal interpolation: {'@'} {'{'} {'}'} {'|'}.
//
// Exit 1 if any message fails to compile. See project_vue_i18n_special_chars.
// =============================================================================
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), ".."); // frontend/

function pick(m) { return m && (m.compile || m.baseCompile) || null; }
function loadCompiler() {
  try { const c = pick(require("@intlify/message-compiler")); if (c) return c; } catch { /* not hoisted */ }
  try {
    const pnpm = join(root, "node_modules/.pnpm");
    const d = readdirSync(pnpm).find((x) => x.startsWith("@intlify+message-compiler@"));
    if (d) {
      const p = join(pnpm, d, "node_modules/@intlify/message-compiler/dist/message-compiler.prod.cjs");
      return pick(require(p));
    }
  } catch { /* ignore */ }
  return null;
}

const compile = loadCompiler();
if (!compile) {
  console.warn("[check-i18n] @intlify/message-compiler not found — skipping i18n scan");
  process.exit(0);
}

const LOCALES = ["zh-TW", "en-US", "ja-JP"];

let total = 0;
let bad = 0;
for (const loc of LOCALES) {
  const obj = JSON.parse(readFileSync(join(root, `src/i18n/${loc}.json`), "utf-8"));
  const walk = (o, prefix) => {
    for (const [k, v] of Object.entries(o)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (typeof v === "string") {
        total++;
        let err = null;
        try { compile(v, { onError: (e) => { err = e; } }); } catch (e) { err = e; }
        if (err) {
          bad++;
          console.error(`  ${loc}  ${key}\n    ${String(err.message).split("\n")[0]}\n    ${JSON.stringify(v).slice(0, 90)}`);
        }
      } else if (v && typeof v === "object") {
        walk(v, key);
      }
    }
  };
  walk(obj, "");
}

console.log(`[check-i18n] scanned ${total} messages — ${bad} broken`);
if (bad) {
  console.error("[check-i18n] FAILED: escape literal @ { } | with {'@'} {'{'} {'}'} {'|'}");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Missing-key gate — a t("x.y") whose key does not exist renders the key ITSELF
// on screen (no error, no warning). Shipped that once: the IP hover card showed
// a literal "addresses.state" where the label should have been.
// Only literal keys are checked; t(`a.${b}`) and t("a." + b) are skipped.
// ---------------------------------------------------------------------------
const dicts = {};
for (const loc of LOCALES) {
  dicts[loc] = JSON.parse(readFileSync(join(root, `src/i18n/${loc}.json`), "utf-8"));
}
const hasKey = (d, key) => {
  let cur = d;
  for (const part of key.split(".")) {
    if (!cur || typeof cur !== "object" || !(part in cur)) return false;
    cur = cur[part];
  }
  return typeof cur === "string";
};

const srcFiles = [];
const walkDir = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) walkDir(full);
    else if (/\.(vue|ts)$/.test(e.name)) srcFiles.push(full);
  }
};
walkDir(join(root, "src"));

let missing = 0;
for (const file of srcFiles) {
  const src = readFileSync(file, "utf-8");
  // 後面接 + 的是字串拼接（t("a.b_" + kind)）→ 略過，那不是完整的 key
  // 單引號與雙引號都要掃：只掃雙引號的話，`t('a.b')` 這種寫法整條被跳過 ——
  // v0.5.146 的調查視窗就是這樣漏掉一個不存在的鍵，畫面直接顯示 "addresses.os"。
  for (const m of src.matchAll(/\bt\(\s*["']([a-zA-Z0-9_.]+)["']\s*(.?)/g)) {
    const [, key, next] = m;
    if (next === "+" || key.endsWith(".") || key.endsWith("_")) continue;
    for (const loc of Object.keys(dicts)) {
      if (!hasKey(dicts[loc], key)) {
        missing++;
        console.error(`  ${file.replace(root + "/", "")}: ${key} missing in ${loc}`);
      }
    }
  }
}
console.log(`[check-i18n] checked ${srcFiles.length} source files — ${missing} missing keys`);
if (missing) {
  console.error("[check-i18n] FAILED: a missing key renders as the key itself on screen");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Locale parity gate — a key missing from one locale does not error: vue-i18n
// falls back to en-US, so the page renders half-translated and nobody notices.
// Every locale must carry exactly the same key set.
// ---------------------------------------------------------------------------
const keysOf = (o, prefix = "") => {
  const out = new Set();
  for (const [k, v] of Object.entries(o)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object") for (const x of keysOf(v, key)) out.add(x);
    else out.add(key);
  }
  return out;
};
const base = keysOf(dicts[LOCALES[0]]);
let parity = 0;
for (const loc of LOCALES.slice(1)) {
  const here = keysOf(dicts[loc]);
  for (const k of base) if (!here.has(k)) { parity++; console.error(`  ${loc}: missing ${k}`); }
  for (const k of here) if (!base.has(k)) { parity++; console.error(`  ${loc}: extra ${k}`); }
}
if (parity) {
  console.error(`[check-i18n] FAILED: ${parity} key(s) out of sync between locales`);
  process.exit(1);
}
console.log(`[check-i18n] ${LOCALES.length} locales, ${base.size} keys each — in sync`);
