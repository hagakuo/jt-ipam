#!/bin/bash
# 預編 guacd：每個目標作業系統起一個拋棄式容器編一份，輸出到 dist/guacd/<版本>/，並產生 SHA256SUMS。
#
# 用法：scripts/guacd/build.sh [映像 …]        不給就編 targets.txt 全部（平行）
# 鏡像：APT_MIRROR=ftp.tw.debian.org UBUNTU_MIRROR=tw.archive.ubuntu.com（只影響拋棄式容器）
# 需要：docker。編好之後跑 scripts/guacd/verify.sh 驗（含實際連 RDP），驗過才可以發。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/source.env"
OUT="$(cd "$HERE/../.." && pwd)/dist/guacd/${GUACD_VERSION}-${GUACD_BUILD_REV}"
mkdir -p "$OUT"
command -v docker >/dev/null || { echo "需要 docker"; exit 1; }
if [ $# -gt 0 ]; then TARGETS=("$@"); else mapfile -t TARGETS < <(grep -v '^\s*#' "$HERE/targets.txt" | grep -v '^\s*$'); fi

fail=0
for img in "${TARGETS[@]}"; do
  tag="${img//[:.]/}"
  (
    docker run --rm --network host -e APT_MIRROR="${APT_MIRROR:-}" -e UBUNTU_MIRROR="${UBUNTU_MIRROR:-}" \
      -v "$HERE":/src:ro -v "$OUT":/out "$img" bash /src/in-container-build.sh > "$OUT/.build-$tag.log" 2>&1 \
      && grep -h '^BUILT' "$OUT/.build-$tag.log" || { echo "FAILED $img（見 $OUT/.build-$tag.log）"; exit 1; }
  ) &
done
for job in $(jobs -p); do wait "$job" || fail=1; done
(cd "$OUT" && sha256sum ./*.tar.gz | sed 's# \./# #' > SHA256SUMS)
echo "輸出：$OUT"
cat "$OUT/SHA256SUMS"
exit $fail
