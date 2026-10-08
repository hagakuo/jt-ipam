#!/usr/bin/env bash
# =============================================================================
# 失敗時給出的疑難排解網址（不做任何真實安裝；不需 root；不碰系統）
#
# 守的是兩件事：
#
# 1. **每條失敗路徑都要印出網址。** 這是唯一一個把安裝／升級失敗接回文件的地方；
#    它是從單一個 EXIT trap 印出來的，而不是散在二十個 die 呼叫點上 —— 散著寫，
#    第二十一個一定會漏掉，尤其是那些沒有人寫過訊息、`set -e` 直接停住的失敗。
#
# 2. **語言跟著作業系統走。** 終端機已經是日文的人，不該先落在英文頁再自己找切換。
#    這條規則寫死在 case 分支裡，很容易在之後改動時被無聲改掉，所以用測試釘住。
#
# 這裡只 source 腳本並呼叫函式 —— jt-ipam.sh 結尾有 BASH_SOURCE 守衛，
# source 不會啟動任何子命令。
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../jt-ipam.sh"
BOOTSTRAP="$HERE/../bootstrap.sh"

PASS=0; FAIL=0
ok()  { echo "  ok: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*" >&2; FAIL=$((FAIL+1)); }

echo "== troubleshooting URL =="

# ── 1. 語系 → 語言參數 ──
url_for() {
    # 在子 shell 裡 source，避免 trap / 變數污染這個測試自己的環境
    ( set +e; unset LC_ALL LC_MESSAGES LANG
      export LANG="$1"
      # shellcheck disable=SC1090
      source "$SCRIPT" >/dev/null 2>&1
      troubleshooting_url )
}

check() {
    local locale="$1" want="$2" got
    got="$(url_for "$locale")"
    if [[ "$got" == *"lang=${want}" ]]; then
        ok "LANG=$locale -> lang=$want"
    else
        bad "LANG=$locale -> expected lang=$want, got '$got'"
    fi
}

check zh_TW.UTF-8 zh-TW
check zh_CN.UTF-8 zh-TW      # 只有一份中文頁；中文語系一律連中文
check ja_JP.UTF-8 ja
check en_US.UTF-8 en
check de_DE.UTF-8 en         # 非中日一律英文
check C            en
check ""           en        # 沒有語系設定（sudo 清掉環境）也要有網址

# ── 2. 失敗時真的會印出來 ──
# upgrade 在非 root／找不到設定檔時就會 die，這是最容易觸發的失敗路徑。
out="$(LANG=ja_JP.UTF-8 JT_IPAM_DOCS_BASE=https://example.invalid \
        bash "$SCRIPT" upgrade 2>&1 || true)"
if [[ "$out" == *"https://example.invalid/troubleshooting.html?lang=ja"* ]]; then
    ok "a failing run prints the URL in the OS language"
else
    bad "a failing run did not print the URL; output was: $out"
fi

# ── 3. 用法說明不該被當成失敗 ──
out="$(bash "$SCRIPT" help 2>&1 || true)"
if [[ "$out" != *"troubleshooting.html"* ]]; then
    ok "help output does not print the troubleshooting URL"
else
    bad "help output printed the troubleshooting URL"
fi

out="$(bash "$SCRIPT" 2>&1 || true)"
if [[ "$out" != *"troubleshooting.html"* ]]; then
    ok "usage (no arguments) does not print the troubleshooting URL"
else
    bad "usage printed the troubleshooting URL"
fi

# ── 4. bootstrap.sh 也要有同一份對照 ──
# 這支腳本沒有 BASH_SOURCE 守衛（它就是入口），source 會真的去 clone 並安裝，
# 所以只取出函式本身來評估。
fn="$(sed -n '/^troubleshooting_url() {/,/^}/p' "$BOOTSTRAP")"
if [[ -z "$fn" ]]; then
    bad "bootstrap.sh has no troubleshooting_url()"
else
    for pair in "ja_JP.UTF-8 lang=ja" "zh_TW.UTF-8 lang=zh-TW" "en_US.UTF-8 lang=en"; do
        set -- $pair
        got="$( unset LC_ALL LC_MESSAGES; LANG="$1" bash -c "
            DOCS_BASE=https://example.invalid
            $fn
            troubleshooting_url" )"
        if [[ "$got" == *"$2" ]]; then
            ok "bootstrap.sh: LANG=$1 -> $2"
        else
            bad "bootstrap.sh: LANG=$1 -> expected $2, got '$got'"
        fi
    done
fi

echo
echo "  passed: $PASS   failed: $FAIL"
[[ $FAIL -eq 0 ]]
