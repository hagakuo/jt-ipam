#!/usr/bin/env bash
# =============================================================================
# jt-ipam local CI — pre-release gate (mirrors TEST_CHECKLIST.md static checks + optional integration tests)
#
# Default (fast, no DB):
#   - backend imports
#   - backend ruff (lint + security "S" bandit rules)
#   - backend pytest collection (DB tests are skipped)
#   - frontend vue-tsc
#   - frontend eslint
#   - frontend i18n compile scan (catches literal @ { } | that blank the prod render)
#   - frontend build
#
# With --db: also run backend integration tests (requires JTIPAM_TEST_DATABASE_URL
#            pointing at a disposable test DB that has been alembic upgrade head'd).
#
# Usage:
#   scripts/ci.sh                # static checks
#   JTIPAM_TEST_DATABASE_URL=... scripts/ci.sh --db    # including integration tests
# Exits non-zero if any step fails.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0
step() { echo -e "\n\033[1;36m== $* ==\033[0m"; }
ok()   { echo -e "\033[1;32mPASS\033[0m $*"; }
bad()  { echo -e "\033[1;31mFAIL\033[0m $*"; FAIL=1; }

# ── backend ──
if [[ -x "$ROOT/backend/.venv/bin/python" ]]; then
  cd "$ROOT/backend"
  step "backend import"
  if .venv/bin/python -c "import app.main" 2>/dev/null; then ok "import app.main"; else bad "import app.main (check for missing env: set -a; source <env>; set +a)"; fi

  step "backend ruff (lint + security S-rules)"
  if [[ -x .venv/bin/ruff ]]; then
    if .venv/bin/ruff check app/ >/dev/null 2>&1; then ok "ruff"; else .venv/bin/ruff check app/ 2>&1 | tail -40; bad "ruff"; fi
  else
    echo "ruff not installed in .venv — skipping"
  fi

  step "backend pytest collect"
  if .venv/bin/pytest -q --collect-only >/dev/null 2>&1; then ok "pytest collect"; else bad "pytest collect"; fi

  if [[ "${1:-}" == "--db" ]]; then
    step "backend pytest (integration, needs JTIPAM_TEST_DATABASE_URL)"
    if [[ -n "${JTIPAM_TEST_DATABASE_URL:-}" ]]; then
      if .venv/bin/pytest -q; then ok "pytest"; else bad "pytest"; fi
    else
      bad "JTIPAM_TEST_DATABASE_URL not set, skipping integration tests"
    fi
  fi
else
  bad "backend/.venv not found -- skipping backend checks"
fi

# ── frontend ──
if [[ -d "$ROOT/frontend/node_modules" ]]; then
  cd "$ROOT/frontend"
  step "frontend vue-tsc"
  if npx vue-tsc --noEmit; then ok "vue-tsc"; else bad "vue-tsc"; fi
  step "frontend eslint"
  if npx eslint src --ext .ts,.vue >/dev/null 2>&1; then ok "eslint"; else npx eslint src --ext .ts,.vue 2>&1 | tail -40; bad "eslint"; fi
  step "frontend i18n compile scan"
  if node scripts/check-i18n.mjs; then ok "i18n"; else bad "i18n — escape literal @ { } | in the messages above"; fi
  step "frontend build"
  if npm run build >/dev/null 2>&1; then ok "build"; else bad "build"; fi
else
  bad "frontend/node_modules not found -- skipping frontend checks"
fi

echo
if [[ $FAIL -eq 0 ]]; then echo -e "\033[1;32mCI OK — safe to release\033[0m"; else echo -e "\033[1;31mCI FAILED — fix the red items before releasing\033[0m"; fi
exit $FAIL
