#!/usr/bin/env bash
# =============================================================================
# 升級時「歷史對不上」的自動復原（不做任何真實安裝；不需 root；不碰系統）
#
# 守的是這件事：升級用 `git pull --ff-only`，而腳本跑在 `set -e` 底下 ——
# pull 一失敗，整個升級就停在那裡（沒有備份、沒有 migration、沒有建置、沒有重啟），
# 而操作者只看到 git 自己的錯誤訊息。更糟的是它不是偶發：之後每一次升級都會
# 用同樣的方式失敗，因為儲存庫的狀態沒有變。解法是 `git reset --hard origin/<branch>`，
# 而那是沒有人猜得到的。
#
# 這裡用兩個暫時的本機儲存庫模擬「上游改寫過歷史」，只呼叫 recover_diverged_repo()。
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../jt-ipam.sh"

PASS=0; FAIL=0
ok()  { echo "  ok: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*" >&2; FAIL=$((FAIL+1)); }

echo "== upgrade: divergent-history recovery =="

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git -c init.defaultBranch=main init -q "$TMP/upstream"
(
  cd "$TMP/upstream"
  git config user.email t@example.com; git config user.name t
  echo one > f.txt; git add f.txt; git commit -qm one
  echo two >> f.txt; git commit -qam two
)
git clone -q "$TMP/upstream" "$TMP/clone"
(cd "$TMP/clone" && git config user.email t@example.com && git config user.name t)

# 上游改寫最後一筆 → clone 的歷史從此對不上（等於公開歷史被 force push 過）
(
  cd "$TMP/upstream"
  git reset -q --hard HEAD~1
  echo two-rewritten >> f.txt; git commit -qam "two (rewritten)"
)

# 先確認前提成立：--ff-only 真的會失敗（否則這條測試等於沒測）
(cd "$TMP/clone" && git fetch -q origin && ! git merge --ff-only origin/main >/dev/null 2>&1) \
  && ok "前提：--ff-only 在歷史分歧時確實失敗" \
  || bad "前提不成立：--ff-only 竟然成功，這條測試沒有守到東西"

# 載入腳本裡的函式（source 不該啟動任何升級流程）
# shellcheck disable=SC1090
as_user() { "$@"; }          # 測試環境不切換使用者
log()  { :; }
warn() { :; }
die()  { echo "die: $*" >&2; exit 1; }
export -f as_user 2>/dev/null || true
source "$SCRIPT" >/dev/null 2>&1 || true

if declare -F recover_diverged_repo >/dev/null; then
  ok "source 腳本不會啟動升級，且函式取得到"
else
  bad "recover_diverged_repo 取不到 —— source 可能執行了 main 或函式改名了"
  echo "  $PASS passed, $FAIL failed"; exit 1
fi

# 復原
OUT="$(cd "$TMP/clone" && recover_diverged_repo "$TMP/clone" 2>&1 || true)"

if (cd "$TMP/clone" && [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ]); then
  ok "復原後與上游同一個 commit"
else
  bad "復原後仍與上游不同：$OUT"
fi

if (cd "$TMP/clone" && git branch --list 'upgrade-recovery/*' | grep -q .); then
  ok "只存在於本機的 commit 有留在備份分支上（沒有靜靜丟掉）"
else
  bad "沒有建立備份分支 —— 本機獨有的 commit 被直接丟棄了"
fi

if (cd "$TMP/clone" && grep -q two-rewritten f.txt); then
  ok "工作目錄內容確實換成上游的版本"
else
  bad "檔案內容沒有跟著換"
fi

echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
