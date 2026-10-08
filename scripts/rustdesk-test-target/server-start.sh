#!/bin/sh
# hbbs 用它自己工作目錄裡的金鑰對（第一次啟動時產生），hbbr 用 -k 帶同一把公鑰（只接受同一把公鑰的連線）。
#
# ⚠️ hbbs 不要用 `-k <公鑰字串>` 啟動：黑箱實測（2026-10-04）那樣啟動時 relay_response 的 pk 是空的
# （hbbs 不簽受控端身分），相容 RustDesk 的網頁連線依規格 6.1.3 會拒絕連線（rd_insecure_refused）。
# 不帶 -k 時 hbbs 仍然會檢查 licence_key（錯的公鑰回 LICENSE_MISMATCH），而且會簽。
set -eu
cd /data
if [ ! -s id_ed25519.pub ]; then
    hbbs >/dev/null 2>&1 &
    pid=$!
    i=0
    while [ ! -s id_ed25519.pub ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
fi
KEY="$(cat id_ed25519.pub)"
echo "public key: $KEY"
hbbr -k "$KEY" &
# 受控端照 -r 去連中繼；jt-ipam 後端自己用設定的中繼位址連同一個 hbbr
exec hbbs -r "${RELAY:-rdtest-server:21117}"
