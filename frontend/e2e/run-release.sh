#!/usr/bin/env bash
# 發版用的完整 e2e：一般的 spec 用 E2E_WORKERS（預設 2）個 worker 平行跑，
# 會改全站設定的 spec（e2e/global-state-specs.txt）之後再單一 worker 依序跑 —— 兩者混在一起平行跑會互相干擾。
# 需要的環境變數與單獨跑 playwright 時相同（E2E_BASE_URL、E2E_ADMIN_PASS…）。
set -uo pipefail
cd "$(dirname "$0")/.."
GLOBAL=$(grep -vE '^[[:space:]]*(#|$)' e2e/global-state-specs.txt | sed 's/\.spec\.ts$//' | paste -sd'|')
echo "== 平行（${E2E_WORKERS:-2} workers），排除：$GLOBAL"
pnpm exec playwright test --reporter=line --workers="${E2E_WORKERS:-2}" --grep-invert "(${GLOBAL})\.spec"
a=$?
echo "== 依序（1 worker）：$GLOBAL"
pnpm exec playwright test --reporter=line --workers=1 --grep "(${GLOBAL})\.spec"
b=$?
echo "parallel exit=$a serial exit=$b"
exit $(( a != 0 || b != 0 ))
