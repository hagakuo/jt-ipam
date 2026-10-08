#!/usr/bin/env bash
# =============================================================================
# jt-ipam — backend uvicorn launch wrapper
#
# Invoked by systemd (jt-ipam-backend.service) or dev.sh; decides whether to
# enable uvicorn's built-in TLS based on BACKEND_TLS_MODE.
#
# Environment variables (read from /etc/jt-ipam/backend.env or backend/.env):
#   BACKEND_TLS_MODE         nginx | direct (default nginx)
#   BACKEND_BIND_HOST        bind host (must be loopback in nginx mode)
#   BACKEND_BIND_PORT        bind port
#   BACKEND_TLS_CERT_FILE    PEM certificate for direct mode
#   BACKEND_TLS_KEY_FILE     PEM private key for direct mode
#   UVICORN_WORKERS          number of workers (default: 2 on 2-core or <=4.5 GB machines, else 4)
#   UVICORN_EXTRA_OPTS       extra flags (e.g. --reload)
#
# OWASP mapping:
#   * A02: enforce TLS — in direct mode, verify cert/key exist + sane permissions before start
#   * A05: replace the current process via exec so the systemd watchdog can manage it correctly
# =============================================================================
set -euo pipefail

VENV_BIN="/opt/jt-ipam/backend/.venv/bin"
if [[ ! -x "$VENV_BIN/uvicorn" ]]; then
    echo "[run-backend] uvicorn not found in $VENV_BIN; run install or dev.sh setup first" >&2
    exit 1
fi

mode="${BACKEND_TLS_MODE:-nginx}"
host="${BACKEND_BIND_HOST:-127.0.0.1}"
port="${BACKEND_BIND_PORT:-8000}"
# Worker count when UVICORN_WORKERS is not set. Each worker is ~250 MB resident; a
# 4 GB machine with four of them has too little left for the ~1.6 GB frontend build an
# upgrade runs (measured 2026-10-02), and a 2-core machine gains nothing from four.
# In a container without lxcfs /proc/meminfo shows the host, so the cgroup limit wins.
# JT_IPAM_NPROC / JT_IPAM_MEMINFO / JT_IPAM_CGROUP_DIR only exist for the tests.
default_workers() {
    local cpus mem_mb cg
    cpus="${JT_IPAM_NPROC:-$(nproc 2>/dev/null || echo 4)}"
    mem_mb="$(awk '/^MemTotal:/ {print int($2/1024)}' "${JT_IPAM_MEMINFO:-/proc/meminfo}" 2>/dev/null || echo 0)"
    cg="$(cat "${JT_IPAM_CGROUP_DIR:-/sys/fs/cgroup}/memory.max" 2>/dev/null || echo max)"
    if [[ "$cg" =~ ^[0-9]+$ ]] && { (( mem_mb == 0 )) || (( cg / 1048576 < mem_mb )); }; then
        mem_mb=$(( cg / 1048576 ))
    fi
    if (( cpus <= 2 )) || (( mem_mb > 0 && mem_mb <= 4608 )); then echo 2; else echo 4; fi
}
workers="${UVICORN_WORKERS:-$(default_workers)}"
extra_opts="${UVICORN_EXTRA_OPTS:-}"

args=(
    "app.main:app"
    --host "$host"
    --port "$port"
    --workers "$workers"
    --proxy-headers
    --forwarded-allow-ips "127.0.0.1"
    --no-server-header
    # WebSocket keepalive. uvicorn defaults to pinging every 20s and dropping the
    # connection when no pong arrives within 20s -- and that default breaks file
    # uploads over the SFTP console on a slow uplink. The browser answers the ping
    # at once, but the pong is queued behind the megabytes of upload data already
    # sitting in the same TCP stream, so it arrives late and the server hangs up
    # mid-transfer. The client sees "connection lost" with no explanation.
    #
    # The ping interval stays short so a genuinely dead peer is still reaped; only
    # the patience for the reply grows. What the pong waits behind is bounded, not
    # the whole file: the SFTP client keeps at most its ack window (4 MB) plus its
    # send-buffer high-water mark (4 MB) in flight. 600s therefore covers uplinks
    # down to roughly 14 KB/s for ANY file size -- the SFTP size limit is a system
    # setting since 0.6.48 and can be raised to GBs without touching this. If that
    # client flow control ever changes, re-read the above before lowering this.
    --ws-ping-interval 20
    --ws-ping-timeout 600
    # No WebSocket compression. The console carries file bytes -- usually already
    # compressed archives and executables -- so deflate buys nothing on the wire
    # while adding a stateful layer between "the browser called send()" and "the
    # server received bytes" that can swallow data with no error anywhere. It also
    # burns CPU per frame on both ends. Turning it off removes a whole class of
    # interop failures from the transport.
    --ws-per-message-deflate false
)

case "$mode" in
    nginx)
        # Backend serves plain HTTP; nginx terminates HTTPS.
        # _tls_guards in config.py rejects any non-loopback host.
        if [[ "$host" != "127.0.0.1" && "$host" != "::1" && "$host" != "localhost" ]]; then
            echo "[run-backend] BACKEND_TLS_MODE=nginx requires loopback BACKEND_BIND_HOST" >&2
            echo "             got: $host" >&2
            exit 1
        fi
        ;;
    direct)
        cert="${BACKEND_TLS_CERT_FILE:-}"
        key="${BACKEND_TLS_KEY_FILE:-}"
        if [[ -z "$cert" || -z "$key" ]]; then
            echo "[run-backend] BACKEND_TLS_MODE=direct requires BACKEND_TLS_CERT_FILE and BACKEND_TLS_KEY_FILE" >&2
            exit 1
        fi
        if [[ ! -r "$cert" ]]; then
            echo "[run-backend] cannot read TLS cert: $cert" >&2
            exit 1
        fi
        if [[ ! -r "$key" ]]; then
            echo "[run-backend] cannot read TLS key: $key" >&2
            exit 1
        fi
        # Private key permission check (OWASP A02 / A05): reject world-readable / writable
        # POSIX stat flag differences: try GNU first, then fall back to BSD
        key_perm="$(stat -c '%a' "$key" 2>/dev/null || stat -f '%Lp' "$key" 2>/dev/null || echo '?')"
        if [[ "$key_perm" =~ ^[0-9]+$ ]]; then
            # take the last digit (the others permission bits)
            others_octal="${key_perm: -1}"
            if (( others_octal != 0 )); then
                echo "[run-backend] TLS key $key has world-accessible bits ($key_perm); chmod 0640 (or 0600) and retry" >&2
                exit 1
            fi
        fi
        args+=(--ssl-keyfile "$key" --ssl-certfile "$cert")
        ;;
    *)
        echo "[run-backend] unknown BACKEND_TLS_MODE: $mode (expected: nginx | direct)" >&2
        exit 1
        ;;
esac

if [[ -n "$extra_opts" ]]; then
    # shellcheck disable=SC2206
    extra=( $extra_opts )
    args+=("${extra[@]}")
fi

cd /opt/jt-ipam/backend
exec "$VENV_BIN/uvicorn" "${args[@]}"
