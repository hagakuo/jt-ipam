#!/usr/bin/env bash
# =============================================================================
# 前端建置用的 Node.js：安裝／升級時怎麼決定（不做任何真實安裝；不需 root；不碰系統）
#
# 守的是這幾件事：
#
# 1. 升級時，既有站台的 Node 20（NodeSource）要自己換成 22，不需要任何手動步驟。
# 2. 升級時裝不起來 22：沿用既有的 >= 20 並大聲警告，升級照常完成；而且**不可以**為了
#    重試去 purge 既有的 nodejs：重試也失敗的話，站台就連一個 node 都沒有了。
# 3. 全新安裝裝不起來 22：停下來並講清楚怎麼手動裝。
# 4. sudo 呼叫者的 nvm：有 >= 22 就用；只有舊版就不沿用，改替 root 裝 NodeSource 22。
#    （nvm 那段原本用 -maxdepth 2 找 ~/.nvm/versions/node/vX/bin/node，永遠找不到。）
# 5. 先前連到 nvm 舊版的 /usr/local/bin/node，裝好 22 之後不可以繼續蓋住它。
#
# 做法：source 腳本、只呼叫 ensure_node()；apt-get／curl／getent 換成記錄呼叫的假函式，
# node 是印版本號的假執行檔。PATH 只放測試要用的系統工具，開發機或 CI 上真的
# /usr/bin/node 不可以混進來，否則結果取決於跑測試的機器。
# 呼叫 ensure_node 時保留腳本本身的 `set -euo pipefail`：這個函式出過「set -e 讓
# 整個安裝無聲結束」的事故，關掉 errexit 測就測不到那種錯。
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../jt-ipam.sh"

PASS=0; FAIL=0
ok()  { echo "  ok: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*" >&2; FAIL=$((FAIL+1)); }

echo "== ensure_node: Node.js for the frontend build =="
unset SUDO_USER   # 只在指定的情境裡模擬 sudo 呼叫者

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SYS="$TMP/sys"; mkdir -p "$SYS"
for t in bash sh env sed find sort head tail cut dirname readlink ln rm cat grep mkdir chmod tr basename printf seq; do
    p="$(command -v "$t" 2>/dev/null || true)"
    [[ "$p" == /* ]] && ln -s "$p" "$SYS/$t"
done

fake_node() {   # fake_node <path> <version>
    mkdir -p "$(dirname "$1")"
    printf '#!/bin/sh\necho %s\n' "$2" > "$1"
    chmod +x "$1"
}

# new_case <name>：每個情境一個乾淨目錄
#   $C/usrbin    = NodeSource 安裝 node 的地方（/usr/bin）
#   $C/localbin  = /usr/local/bin（先前執行留下的連結會在這裡）
#   $C/home      = sudo 呼叫者的家目錄
#   $C/apt       = 假 apt-get 裝 nodejs 的結果：ok | fail
new_case() {
    C="$TMP/$1"
    mkdir -p "$C/usrbin" "$C/localbin" "$C/home"
    echo ok > "$C/apt"
    : > "$C/calls"
}

# run_ensure <mode> [times]：在子 shell 裡 source 腳本後呼叫 ensure_node，輸出寫到 $C/out
run_ensure() {
    local mode="$1" times="${2:-1}"
    set +e
    (
        export PATH="$C/localbin:$C/usrbin:$SYS"
        export JT_IPAM_NODE_LINK_DIR="$C/localbin" JT_IPAM_NODE_SYSTEM_BIN="$C/usrbin/node"
        # shellcheck disable=SC1090
        source "$SCRIPT" >/dev/null 2>&1
        trap - EXIT
        log()  { echo "log: $*"; }
        warn() { echo "warn: $*"; }
        die()  { echo "die: $*"; exit 1; }
        getent() { [[ "$1" == passwd ]] && echo "$2:x:1000:1000::$C/home:/bin/bash"; }
        curl() { echo "curl $*" >> "$C/calls"; echo true; }
        apt-get() {
            echo "apt-get $*" >> "$C/calls"
            case "$*" in
                *"install -y nodejs"*)
                    if [[ "$(cat "$C/apt")" == ok ]]; then fake_node "$C/usrbin/node" v22.23.3; return 0; fi
                    return 100 ;;
                *purge*) rm -f "$C/usrbin/node" ;;
            esac
            return 0
        }
        set -euo pipefail
        for _ in $(seq "$times"); do ensure_node "$mode"; done
        echo "DONE node=$(node -v 2>/dev/null || echo none) at=$(command -v node || echo none)"
    ) > "$C/out" 2>&1
    RC=$?
    set -e
}

out_has()   { grep -qF -- "$1" "$C/out"; }
calls_has() { grep -qF -- "$1" "$C/calls"; }
show()      { sed 's/^/      | /' "$C/out" >&2; }

# ── 1. 已經是 22：什麼都不裝 ──
new_case already22; fake_node "$C/usrbin/node" v22.23.3
run_ensure upgrade
if [[ $RC -eq 0 ]] && out_has "DONE node=v22.23.3" && ! calls_has apt-get; then
    ok "node 22 on PATH is used as is (no apt)"
else bad "node 22 on PATH: rc=$RC"; show; fi

# ── 2. 升級：NodeSource 20 → 22 ──
new_case up20; fake_node "$C/usrbin/node" v20.20.2
run_ensure upgrade
if [[ $RC -eq 0 ]] && out_has "DONE node=v22.23.3" && calls_has "setup_22.x"; then
    ok "upgrade moves an existing Node 20 to NodeSource 22"
else bad "upgrade from Node 20: rc=$RC"; show; fi
calls_has "setup_20.x" && { bad "upgrade still fetches setup_20.x"; show; } || ok "setup_20.x is not used any more"

# ── 3. 升級：裝不起來 22 → 沿用 20、警告、不 purge ──
new_case up20fail; fake_node "$C/usrbin/node" v20.20.2; echo fail > "$C/apt"
run_ensure upgrade
if [[ $RC -eq 0 ]] && out_has "DONE node=v20.20.2"; then
    ok "upgrade falls back to the existing Node 20 when 22 cannot be installed"
else bad "upgrade fallback: rc=$RC"; show; fi
out_has "warn: ===" && ok "the fallback is announced with a banner" || { bad "no banner on fallback"; show; }
calls_has purge && { bad "upgrade purged the node it was going to fall back on"; cat "$C/calls" >&2; } \
                || ok "upgrade does not purge the fallback node"

# ── 3b. 第二次呼叫不再重裝（升級會先檢查一次、建置前再呼叫一次）──
new_case twice; fake_node "$C/usrbin/node" v20.20.2; echo fail > "$C/apt"
run_ensure upgrade 2
n="$(grep -c 'install -y nodejs' "$C/calls" || true)"
[[ $RC -eq 0 && "$n" == 1 ]] && ok "a second call in the same run does not retry the install" \
                             || { bad "second call retried (installs=$n rc=$RC)"; show; }

# ── 4. 升級：比 20 還舊、又裝不起來 → 停下來 ──
new_case up18fail; fake_node "$C/usrbin/node" v18.19.1; echo fail > "$C/apt"
run_ensure upgrade
if [[ $RC -ne 0 ]] && out_has "die:" && out_has "setup_22.x"; then
    ok "upgrade stops when only Node 18 is left (below the fallback floor)"
else bad "upgrade with Node 18 and no 22: rc=$RC"; show; fi

# ── 5. 全新安裝：沒有 node → 22 ──
new_case fresh
run_ensure install
if [[ $RC -eq 0 ]] && out_has "DONE node=v22.23.3" && calls_has "setup_22.x"; then
    ok "fresh install gets NodeSource 22"
else bad "fresh install: rc=$RC"; show; fi

# ── 6. 全新安裝：裝不起來 → 停下來，訊息指向 22 ──
new_case freshfail; echo fail > "$C/apt"
run_ensure install
if [[ $RC -ne 0 ]] && out_has "die:" && out_has "Node 22" && out_has "setup_22.x"; then
    ok "fresh install stops with a Node 22 message when it cannot install"
else bad "fresh install failure: rc=$RC"; show; fi

# ── 6b. 全新安裝：既有 20、裝不起來 22 → 一樣停下來（只有升級才沿用）──
new_case fresh20fail; fake_node "$C/usrbin/node" v20.20.2; echo fail > "$C/apt"
run_ensure install
[[ $RC -ne 0 ]] && out_has "die:" && ok "fresh install does not fall back to Node 20" \
                || { bad "fresh install fell back: rc=$RC"; show; }

# ── 7. sudo 呼叫者有 nvm 22 → 連過去用，不碰 apt ──
new_case nvm22; fake_node "$C/usrbin/node" v20.20.2
fake_node "$C/home/.nvm/versions/node/v20.20.2/bin/node" v20.20.2
fake_node "$C/home/.nvm/versions/node/v22.23.3/bin/node" v22.23.3
fake_node "$C/home/.nvm/versions/node/v22.23.3/bin/npm" 10.9.9
SUDO_USER=dev run_ensure upgrade
if [[ $RC -eq 0 ]] && out_has "DONE node=v22.23.3 at=$C/localbin/node" && ! calls_has apt-get; then
    ok "sudo caller's nvm Node 22 is linked for root"
else bad "nvm 22: rc=$RC"; show; fi

# ── 8. sudo 呼叫者只有 nvm 20 → 不沿用，改裝 NodeSource 22 ──
new_case nvm20
fake_node "$C/home/.nvm/versions/node/v20.20.2/bin/node" v20.20.2
SUDO_USER=dev run_ensure install
if [[ $RC -eq 0 ]] && out_has "DONE node=v22.23.3 at=$C/usrbin/node" && [[ ! -e "$C/localbin/node" ]]; then
    ok "an nvm Node 20 is not reused; NodeSource 22 is installed instead"
else bad "nvm 20 only: rc=$RC"; show; fi

# ── 9. 舊連結 /usr/local/bin/node → nvm 20，裝好 22 後不可以繼續蓋住 ──
new_case stalelink; fake_node "$C/usrbin/node" v20.20.2
fake_node "$C/home/.nvm/versions/node/v20.20.2/bin/node" v20.20.2
ln -s "$C/home/.nvm/versions/node/v20.20.2/bin/node" "$C/localbin/node"
run_ensure upgrade
if [[ $RC -eq 0 ]] && out_has "DONE node=v22.23.3 at=$C/usrbin/node"; then
    ok "a stale link to an old nvm node no longer shadows NodeSource 22"
else bad "stale link: rc=$RC"; show; fi

# ── 10. 失敗的 node 不可以在 migration 之後才被發現 ──
# 升級裡的 ensure_node 要在 alembic 之前；放在建置那裡，就是資料庫已經升級完才停下來。
body="$(sed -n '/^cmd_upgrade() {/,/^}/p' "$SCRIPT")"
l_node="$(grep -n 'ensure_node upgrade' <<<"$body" | head -1 | cut -d: -f1 || true)"
l_mig="$(grep -n 'alembic upgrade head"' <<<"$body" | head -1 | cut -d: -f1 || true)"
if [[ -n "$l_node" && -n "$l_mig" ]] && (( l_node < l_mig )); then
    ok "upgrade settles Node.js before the database migration"
else
    bad "upgrade does not call 'ensure_node upgrade' before the migration (node line ${l_node:-none}, migration line ${l_mig:-none})"
fi

echo
echo "通過：$PASS　失敗：$FAIL"
[[ $FAIL -eq 0 ]] && { echo "ALL OK"; exit 0; } || exit 1
