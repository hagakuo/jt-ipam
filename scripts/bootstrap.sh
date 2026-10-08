#!/usr/bin/env bash
#
# jt-ipam one-shot install bootstrap: clone to /opt/jt-ipam then run install directly.
# Usage (no manual git needed):
#   curl -fsSL https://raw.githubusercontent.com/jasoncheng7115/jt-ipam/main/scripts/bootstrap.sh | sudo bash
#   # arguments can be passed: ... | sudo bash -s -- --tls-mode direct
#
set -euo pipefail

# Same troubleshooting pointer as scripts/jt-ipam.sh, for the failures that happen
# before this script ever reaches it (not root, no network, clone refused).
# Language follows the OS locale; anything that is not Chinese or Japanese gets English.
DOCS_BASE="${JT_IPAM_DOCS_BASE:-https://jasoncheng7115.github.io/jt-ipam}"
troubleshooting_url() {
  case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
    zh_*|zh|zh-*|zh.*) echo "${DOCS_BASE}/troubleshooting.html?lang=zh-TW" ;;
    ja_*|ja|ja-*|ja.*) echo "${DOCS_BASE}/troubleshooting.html?lang=ja" ;;
    *)                 echo "${DOCS_BASE}/troubleshooting.html?lang=en" ;;
  esac
}
on_exit_hint() {
  local rc=$?
  [[ $rc -eq 0 ]] && return 0
  echo >&2
  echo "Install troubleshooting: $(troubleshooting_url)" >&2
}
trap on_exit_hint EXIT

REPO="${JT_IPAM_REPO:-https://github.com/jasoncheng7115/jt-ipam.git}"
DIR="${JT_IPAM_DIR:-/opt/jt-ipam}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[error] Please run as root (sudo)." >&2
  exit 1
fi

# install git first if missing (Debian/Ubuntu)
if ! command -v git >/dev/null 2>&1; then
  echo "[*] Installing git..."
  apt-get update -qq && apt-get install -y -qq git
fi

if [[ -d "$DIR/.git" ]]; then
  echo "[*] $DIR exists; updating to latest origin/main…"
  git config --global --add safe.directory "$DIR" 2>/dev/null || true
  git -C "$DIR" remote set-url origin "$REPO" 2>/dev/null || true
  if ! git -C "$DIR" pull --ff-only 2>/dev/null; then
    # diverged / local edits → hard-reset the install dir to the published main
    git -C "$DIR" fetch origin main && git -C "$DIR" reset --hard origin/main \
      || echo "[warn] could not update existing repo; proceeding with current code."
  fi
else
  echo "[*] git clone $REPO -> $DIR"
  git clone "$REPO" "$DIR"
fi

cd "$DIR"
echo "[*] Running scripts/jt-ipam.sh install $*"
exec bash scripts/jt-ipam.sh install "$@"
