#!/usr/bin/env node
// =============================================================================
// i18n compile gate — scan every message in zh-TW.json / en-US.json with the
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

let total = 0;
let bad = 0;
for (const loc of ["zh-TW", "en-US"]) {
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
