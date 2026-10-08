#!/usr/bin/env python3
"""測試用的最小 VNC（RFB 3.8）伺服器 —— 給主控台端到端測試當靶。

為什麼要自己寫一個：驗證「我們的 VNC 主控台會不會動」不能只靠對著客戶的機器試 ——
對方連不上時，我們分不出是我們的問題還是對方的問題。這支只依賴標準函式庫，
畫一張固定的圖，可以在 CI 或本機隨時起來，讓「客戶端這一半」有確定的答案。

實作範圍刻意最小：RFB 3.8、raw 編碼、單一連線。預設走**安全型別 2（VNC 密碼驗證）**，
因為那才是實機上會遇到的路徑；**任何密碼都會被接受**（這是測試靶，不是真的驗證：
真的驗證要自己實作 DES，對測試沒有幫助）。

`--no-auth` 改用安全型別 1（None）。⚠️ 我們用的 aardwolf 在型別 1 時**不會把選擇的
安全型別送回伺服器**（vncconnection.__authenticate 的 type 1 分支是空的），於是交握卡住 ——
這個模式留著就是為了讓那個缺陷可以被重現。

用法：
    python3 vnc-target.py [--port 5900] [--width 640] [--height 480] [--no-auth]
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed")
        buf += chunk
    return buf


def _framebuffer(width: int, height: int) -> bytearray:
    """一張看得出「有畫出來」的圖：綠底 + 左上角一塊白方塊（32bpp BGRX）。"""
    fb = bytearray(width * height * 4)
    for y in range(height):
        for x in range(width):
            i = (y * width + x) * 4
            if x < width // 4 and y < height // 4:
                fb[i:i + 4] = b"\xff\xff\xff\x00"      # 白
            else:
                fb[i:i + 4] = b"\x58\xa0\x18\x00"      # 綠（BGR）
    return fb


def serve_one(conn: socket.socket, width: int, height: int, *,
              auth: bool = True, verbose: bool = True) -> None:
    def log(*a):
        if verbose:
            print("   ", *a, flush=True)

    conn.sendall(b"RFB 003.008\n")
    log("sent server version")
    client_ver = _recv_exactly(conn, 12)
    log("client version:", client_ver)
    if not client_ver.startswith(b"RFB "):
        raise ConnectionError(f"unexpected client version: {client_ver!r}")

    if auth:
        conn.sendall(bytes([1, 2]))                         # 只提供 2 = VNC 密碼驗證
        chosen = _recv_exactly(conn, 1)[0]
        log("client chose security type", chosen)
        if chosen != 2:
            conn.sendall(struct.pack("!I", 1))
            raise ConnectionError(f"client chose {chosen}, only 2 is offered")
        conn.sendall(b"\x01" * 16)                          # 16 bytes challenge（固定值，測試用）
        _recv_exactly(conn, 16)                             # 回應一律接受（測試靶不做 DES 驗證）
        conn.sendall(struct.pack("!I", 0))                  # SecurityResult = OK
        log("security OK (VNC auth, any password accepted)")
    else:
        conn.sendall(bytes([1, 1]))                         # 只提供 1 = None
        chosen = _recv_exactly(conn, 1)[0]                  # ⚠️ aardwolf 不會送這個位元組
        log("client chose security type", chosen)
        if chosen != 1:
            conn.sendall(struct.pack("!I", 1))
            raise ConnectionError(f"client chose {chosen}, only 1 is offered")
        conn.sendall(struct.pack("!I", 0))                  # SecurityResult = OK
        log("security OK (None)")

    _recv_exactly(conn, 1)                                  # ClientInit（shared flag，忽略）
    log("client init received")

    name = b"jt-ipam test target"
    # ServerInit：尺寸 + PIXEL_FORMAT(32bpp, true colour, BGR) + 名稱
    conn.sendall(
        struct.pack("!HH", width, height)
        + struct.pack("!BBBB", 32, 24, 0, 1)                # bpp, depth, big-endian, true-colour
        + struct.pack("!HHH", 255, 255, 255)                # max R,G,B
        + struct.pack("!BBB", 16, 8, 0)                     # shift R,G,B
        + b"\x00\x00\x00"                                   # padding
        + struct.pack("!I", len(name)) + name
    )

    log("server init sent")
    fb = _framebuffer(width, height)
    while True:
        msg_type = _recv_exactly(conn, 1)[0]
        if msg_type == 0:                                   # SetPixelFormat
            pf = _recv_exactly(conn, 19)
            log("SetPixelFormat", pf[3:].hex())
        elif msg_type == 2:                                 # SetEncodings
            _, count = struct.unpack("!BH", _recv_exactly(conn, 3))
            _recv_exactly(conn, 4 * count)
            log(f"SetEncodings ({count})")
        elif msg_type == 3:                                 # FramebufferUpdateRequest
            _inc, x, y, w, h = struct.unpack("!BHHHH", _recv_exactly(conn, 9))
            w = min(w, width - x); h = min(h, height - y)
            header = struct.pack("!BBH", 0, 0, 1) + struct.pack("!HHHHi", x, y, w, h, 0)
            rows = [bytes(fb[((y + r) * width + x) * 4:((y + r) * width + x + w) * 4])
                    for r in range(h)]
            conn.sendall(header + b"".join(rows))
            log(f"sent framebuffer update {w}x{h} at {x},{y}")
        elif msg_type == 4:                                 # KeyEvent
            _recv_exactly(conn, 7)
        elif msg_type == 5:                                 # PointerEvent
            _recv_exactly(conn, 5)
        elif msg_type == 6:                                 # ClientCutText
            _recv_exactly(conn, 3)
            (length,) = struct.unpack("!I", _recv_exactly(conn, 4))
            _recv_exactly(conn, length)
        else:
            raise ConnectionError(f"unknown client message type {msg_type}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5900)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--width", type=int, default=640)
    ap.add_argument("--height", type=int, default=480)
    ap.add_argument("--once", action="store_true", help="serve a single connection and exit")
    ap.add_argument("--no-auth", action="store_true",
                    help="offer security type 1 (None) instead of VNC password auth")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(4)
    print(f"vnc-target listening on {args.host}:{args.port} ({args.width}x{args.height}, "
          f"{'security type 1 = None' if args.no_auth else 'VNC auth, any password'})", flush=True)

    while True:
        conn, addr = srv.accept()
        print(f"connection from {addr[0]}:{addr[1]}", flush=True)

        def handle(c: socket.socket = conn) -> None:
            try:
                serve_one(c, args.width, args.height, auth=not args.no_auth)
            except (ConnectionError, OSError, struct.error) as exc:
                print(f"  session ended: {exc}", flush=True)
            finally:
                c.close()

        if args.once:
            handle()
            return 0
        threading.Thread(target=handle, daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
