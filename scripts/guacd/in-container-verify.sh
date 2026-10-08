#!/bin/bash
# 在「乾淨」的目標作業系統容器裡驗一份預編檔：只裝 .deps 列的執行期套件（不裝編譯工具），
# 解開、跑 guacd、確認 rdp／vnc 外掛載得起來；有給 RDP_TARGET 就再真的連一次 RDP、打一行字。
# 由 scripts/guacd/verify.sh 呼叫。
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
. /src/source.env
. /etc/os-release
PKG="$1"          # 不含副檔名的檔名
if [ -n "${APT_MIRROR:-}" ] && [ "$ID" = debian ]; then
  sed -i -e "s#//deb.debian.org/debian\$#//$APT_MIRROR/debian#" -e "s#//deb.debian.org/debian #//$APT_MIRROR/debian #" \
    /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null || true
fi
if [ -n "${UBUNTU_MIRROR:-}" ] && [ "$ID" = ubuntu ]; then
  sed -i "s#//archive.ubuntu.com#//$UBUNTU_MIRROR#g" /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null || true
fi
apt-get update -qq
# 實際連線要用的工具：測試客戶端（python3＋PIL）、SSH 靶（openssh-server，只在這個拋棄式容器裡）
EXTRA=""; [ -n "${RDP_TARGET:-}" ] && EXTRA="python3 python3-pil openssh-server"
# shellcheck disable=SC2046
apt-get install -y -qq --no-install-recommends $(cat /dist/"$PKG".deps) $EXTRA >/dev/null
tar -C / -xzf /dist/"$PKG".tar.gz
G="$GUACD_PREFIX/sbin/guacd"
"$G" -v
# 各目標同時跑、共用主機網路 → 埠要錯開（verify.sh 給），不然只有第一個綁得到
PORT="${GUACD_PORT:-4822}"
# 跟 systemd 單元一樣用 UTF-8 locale 跑：guacd 用 wcwidth() 算一個字佔幾格，
# 非 UTF-8 的 locale 會把中文當成一格寬、縮小塞進去（2026-09-25 實測）
LANG=C.UTF-8 "$G" -b 127.0.0.1 -l "$PORT" -L info -f > /tmp/guacd.log 2>&1 &
sleep 1
for proto in rdp vnc ssh; do
  exec 3<>/dev/tcp/127.0.0.1/$PORT
  printf '6.select,%d.%s;' "${#proto}" "$proto" >&3
  REPLY=$(timeout 5 head -c 200 <&3 || true)
  exec 3>&-
  case "$REPLY" in *args*) echo "plugin $proto: ok" ;;
    *) echo "plugin $proto: FAIL"; tail -5 /tmp/guacd.log; exit 1 ;; esac
done
check() {   # check <協定> <結果行>：要有畫面、沒有錯誤；會打字的協定要打得出去
  case "$2" in *"err=None"*) ;; *) echo "$1 失敗"; tail -20 /tmp/guacd.log; exit 1 ;; esac
  case "$2" in *"images=0 "*) echo "$1 連上了但沒有畫面"; exit 1 ;; esac
  # 有畫圖指令不等於畫出東西：合成後全黑（例如只合成了 0 號圖層）一樣算失敗
  px=$(printf '%s' "$2" | sed -n 's/.*painted_px=\([0-9]*\).*/\1/p')
  [ "${px:-0}" -ge 200 ] || { echo "$1 畫面合成後幾乎全黑（非黑像素 ${px:-0}）"; exit 1; }
  if [ "$1" != vnc ]; then case "$2" in *"typed=True"*) ;; *) echo "$1 沒有打字"; exit 1 ;; esac; fi
}
if [ -n "${RDP_TARGET:-}" ]; then
  IFS=: read -r H P U W <<< "$RDP_TARGET"
  R=$(flock /dist/.rdp.lock python3 /src/guacli.py "$PORT" /dist/"$PKG".rdp.png rdp "$H" "$P" "$U" "$W" | tail -1)
  echo "rdp: $R"; check rdp "$R"

  # VNC：同一個容器裡起最小 RFB 測試靶（e2e/fixtures/vnc-target.py，接受任何密碼）
  VPORT=$((PORT + 1000))
  python3 /vnc-target.py --host 127.0.0.1 --port "$VPORT" > /tmp/vnc.log 2>&1 &
  sleep 1
  R=$(python3 /src/guacli.py "$PORT" /dist/"$PKG".vnc.png vnc 127.0.0.1 "$VPORT" "" any | tail -1)
  echo "vnc: $R"; check vnc "$R"

  # SSH：同一個容器裡起 sshd（只綁 127.0.0.1、拋棄式帳號）
  SPORT=$((PORT + 2000))
  useradd -m -s /bin/bash guactest && echo 'guactest:Guac-Test-123' | chpasswd
  mkdir -p /run/sshd && ssh-keygen -A >/dev/null 2>&1
  /usr/sbin/sshd -p "$SPORT" -o ListenAddress=127.0.0.1 -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes
  sleep 1
  R=$(python3 /src/guacli.py "$PORT" /dist/"$PKG".ssh.png ssh 127.0.0.1 "$SPORT" guactest Guac-Test-123 | tail -1)
  echo "ssh: $R"; check ssh "$R"
fi
if grep -q "does not use UTF-8" /tmp/guacd.log; then echo "guacd 不在 UTF-8 locale 下（中文會畫錯）"; exit 1; fi
echo "VERIFIED $PKG"
