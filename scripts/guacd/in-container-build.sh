#!/bin/bash
# 在目標作業系統的容器裡編 guacd（RDP／VNC／SSH），輸出到 /out：
#   jt-ipam-guacd-<版本>-<os>-<arch>.tar.gz   預編檔（已 strip、不含標頭與靜態庫）
#   jt-ipam-guacd-<版本>-<os>-<arch>.deps     執行期要 apt 安裝的套件（只列直接相依，其餘 apt 會帶）
# 由 scripts/guacd/build.sh 呼叫；不要直接在自己的機器上跑（會裝一堆 -dev 套件）。
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
. /src/source.env
. /etc/os-release
OS_TAG="${ID}${VERSION_ID}"
ARCH="$(dpkg --print-architecture)"
NAME="jt-ipam-guacd-${GUACD_VERSION}-${GUACD_BUILD_REV}-${OS_TAG}-${ARCH}"

# 鏡像站只影響這個拋棄式容器（同 test-fresh-install.sh）；security 來源維持官方
if [ -n "${APT_MIRROR:-}" ] && [ "$ID" = debian ]; then
  sed -i -e "s#//deb.debian.org/debian\$#//$APT_MIRROR/debian#" -e "s#//deb.debian.org/debian #//$APT_MIRROR/debian #" \
    /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null || true
fi
if [ -n "${UBUNTU_MIRROR:-}" ] && [ "$ID" = ubuntu ]; then
  sed -i "s#//archive.ubuntu.com#//$UBUNTU_MIRROR#g" /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null || true
fi

apt-get update -qq
# FreeRDP 2 還是 3 看發行版有哪個（Debian 12／Ubuntu 22.04 只有 2）
if apt-cache show freerdp3-dev >/dev/null 2>&1; then FRDP=freerdp3-dev; else FRDP=freerdp2-dev; fi
apt-get install -y -qq --no-install-recommends build-essential pkg-config ca-certificates curl \
  autoconf automake libtool \
  libcairo2-dev libjpeg-dev libpng-dev uuid-dev libssl-dev libwebp-dev libvncserver-dev "$FRDP" \
  libssh2-1-dev libpango1.0-dev >/dev/null

mkdir -p /build && cd /build
curl -fsSL -o src.tar.gz "$GUACD_SRC_URL"
echo "$GUACD_SRC_SHA256  src.tar.gz" | sha256sum -c - >/dev/null || { echo "原始碼檢查碼不符：$GUACD_SRC_URL"; exit 1; }
tar xzf src.tar.gz && cd "$(find . -maxdepth 1 -mindepth 1 -type d | head -1)"
# 我們自己的修補（scripts/guacd/patches/，依檔名順序）：每一個都要寫清楚為什麼、上游有沒有對應的修正
PATCHES=""
for pf in $(ls /src/patches/*.patch 2>/dev/null | sort); do
  patch -p1 --forward < "$pf" > /dev/null || { echo "修補套不上：$(basename "$pf")（上游改了這段？）"; exit 1; }
  PATCHES="$PATCHES $(basename "$pf")"
done
[ -x configure ] || autoreconf -fi >/dev/null 2>&1

# -Wno-error 兩處都要：
#   CFLAGS   —— 新版 FreeRDP 3 的標頭有 deprecated 宣告，guacamole 用 -Werror 編會直接失敗。
#   CPPFLAGS —— 更要緊。configure 的功能偵測程式也帶 -Werror（加在 CPPFLAGS 前面），撞到同樣的
#               警告就把「structs 有 context」「有 LoadChannels」誤判成沒有 → 走 FreeRDP 2 的程式路徑
#               → 編譯錯誤。放在 CPPFLAGS 後面才蓋得掉。1.6.0 與 staging/1.6.1 都是這樣（2026-09-25 實測）。
# rpath：程式與外掛從自己的目錄載入函式庫，安裝時不必動系統的 ld.so 設定。
CPPFLAGS="-Wno-error" CFLAGS="-O2 -g0 -Wno-error" \
LDFLAGS="-Wl,-rpath,${GUACD_PREFIX}/lib" \
./configure --prefix="$GUACD_PREFIX" \
  --with-freerdp-plugin-dir="${GUACD_PREFIX}/lib/freerdp" \
  --disable-guacenc --disable-guaclog --disable-static \
  --without-telnet --without-kubernetes --without-pulse \
  > /out/"$NAME".configure.log 2>&1 || { tail -30 /out/"$NAME".configure.log; exit 1; }
# 偵測結果要對：FreeRDP 3 卻說沒有 context 就是上面那個誤判又回來了
if [ "$FRDP" = freerdp3-dev ] && ! grep -q "whether freerdp structs have a context... yes" /out/"$NAME".configure.log; then
  echo "configure 誤判 FreeRDP 3 的 API（見上面 CPPFLAGS 的說明）"; exit 1
fi
make -j"$(nproc)" > /out/"$NAME".make.log 2>&1 || { tail -40 /out/"$NAME".make.log; exit 1; }
make install DESTDIR=/stage > /dev/null

ROOT="/stage${GUACD_PREFIX}"
rm -rf "$ROOT/include" "$ROOT/share/man" "$ROOT"/lib/*.la "$ROOT"/lib/freerdp/*.la
find "$ROOT" -type f \( -name '*.so*' -o -path '*/sbin/*' \) -exec strip --strip-unneeded {} + 2>/dev/null || true
# 授權：Apache-2.0 要附 LICENSE 與 NOTICE；另外寫明對應原始碼從哪來、怎麼編的
DOC="$ROOT/share/doc/jt-ipam-guacd"; mkdir -p "$DOC"
cp LICENSE NOTICE "$DOC/"
cat > "$DOC/SOURCE" <<SRC
Built from Apache Guacamole (guacamole-server) source. This is not an official Apache release.
source:   $GUACD_SRC_URL
sha256:   $GUACD_SRC_SHA256
version:  $GUACD_VERSION (build $GUACD_BUILD_REV) for $PRETTY_NAME ($ARCH)
freerdp:  $FRDP
patches: ${PATCHES:- (none)}
scripts:  https://github.com/jasoncheng7115/jt-ipam/tree/main/scripts/guacd
SRC

# 執行期相依：只取 ELF 的 NEEDED（直接相依）對應到套件；遞迴的交給 apt
NEEDED=$(find "$ROOT" -type f \( -name '*.so*' -o -path '*/sbin/*' \) -exec objdump -p {} \; 2>/dev/null \
  | awk '/NEEDED/{print $2}' | sort -u)
: > /out/"$NAME".deps
# ⚠️ 管線裡不可以提早結束讀取（awk 的 exit、head -1）：上游還在寫就收到 SIGPIPE，
# 在 pipefail 下整條算失敗，set -e 讓腳本安靜地結束（exit 141）。看時機發生，第 2 版剛好沒遇到。
for lib in $NEEDED; do
  case "$lib" in libguac*) continue ;; esac
  path=$(ldconfig -p | awk -v l="$lib" '$1==l && !f {print $NF; f=1}')
  [ -n "$path" ] || { echo "找不到 $lib 的位置"; exit 1; }
  pkg=$( { dpkg -S "$(readlink -f "$path")" 2>/dev/null || dpkg -S "$path" 2>/dev/null || true; } \
         | awk -F: 'NR==1 {print $1}')
  [ -n "$pkg" ] || { echo "找不到 $path 屬於哪個套件"; exit 1; }
  echo "$pkg" >> /out/"$NAME".deps
done
# SSH 的終端機由 guacd 用 pango 在伺服器端畫，字型不是 ELF 相依、objdump 看不到 —— 要自己列：
# DejaVu 是等寬主字型；文泉驛微米黑補中日韓字（沒有它，中文檔名、中文輸出全是方框）
printf '%s\n' fonts-dejavu-core fonts-wqy-microhei >> /out/"$NAME".deps
sort -u -o /out/"$NAME".deps /out/"$NAME".deps
# 編出來要真的有三個協定，少一個就是相依沒裝好（configure 只會安靜地略過）
for p in rdp vnc ssh; do
  [ -e "$ROOT/lib/libguac-client-$p.so" ] || { echo "缺 $p 的外掛（configure 沒有找到它的相依套件）"; exit 1; }
done

tar -C /stage -czf /out/"$NAME".tar.gz "${GUACD_PREFIX#/}"
echo "BUILT $NAME ($(du -k /out/"$NAME".tar.gz | cut -f1) KB, freerdp=$FRDP, deps=$(wc -l < /out/"$NAME".deps))"
