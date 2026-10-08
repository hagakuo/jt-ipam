#!/bin/sh
# 受控端：Xvfb 桌面＋大字級 xterm＋RustDesk（只連同一個 docker 內部網路上的測試 hbbs／hbbr）。
# ID_SERVER、KEY 由 run.sh 帶進來；密碼是固定的永久密碼（PASSWORD）。
set -eu
ID_SERVER="${ID_SERVER:-rdtest-server}"
KEY="${KEY:?KEY（測試 hbbs 的公鑰）沒有給}"
PASSWORD="${PASSWORD:-Rd-Test-2026}"
export DISPLAY=:0

mkdir -p /root/.config/rustdesk
cat > /root/.config/rustdesk/RustDesk2.toml <<CFG
[options]
custom-rendezvous-server = '${ID_SERVER}'
relay-server = '${ID_SERVER}'
key = '${KEY}'
CFG

# 容器重新啟動（docker restart）時 /tmp 會留著上一次的 X 鎖定檔：不清掉 Xvfb 起不來，受控端每次登入都回
# connection refused（2026-10-05 驗自動重連時踩到）
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0
# 連線管理程式以 sudo -E XDG_RUNTIME_DIR=/run/user/0 啟動：目錄要在
mkdir -p /run/user/0 && chmod 700 /run/user/0
Xvfb :0 -screen 0 1280x800x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
i=0; while ! xdpyinfo >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
openbox >/tmp/openbox.log 2>&1 &
# 大字級終端機：打什麼字畫面上就看得到（鍵盤、滑鼠肉眼可驗）
xterm -geometry 70x16+40+40 -fa 'DejaVu Sans Mono' -fs 20 -bg black -fg '#7CFC00' -T rdtest-xterm >/dev/null 2>&1 &

rustdesk --server >/tmp/rd-server.log 2>&1 &
# 永久密碼要等 --server 起來之後才設得進去（之前會回 No such file or directory）
i=0
until rustdesk --password "${PASSWORD}" 2>/dev/null | grep -q Done; do
    i=$((i + 1)); [ $i -gt 30 ] && echo "password not set" && break; sleep 1
done
echo "rustdesk id: $(rustdesk --get-id 2>/dev/null | tail -1)"
wait
