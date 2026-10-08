"""SFTP 傳輸路徑測試：從瀏覽器實際送一次資料，看整條路（瀏覽器 → 前端反向代理 → IPAM 的
nginx → 後端）吃不吃得下（2026-09-26，使用者要求「前面的比設定值小要自動檢查出來並提示」）。

為什麼要實測：SFTP 的檔案走主控台的 WebSocket、每次 256 KB 一塊，一般 HTTP 的上傳大小上限
（nginx 的 client_max_body_size 之類）管不到它。真正會擋的是別的東西 —— 代理不讓 WebSocket
過、WAF 限制單一訊息大小、路上吞掉連續的大資料 —— 這些設定我們讀不到，只能送一次看看。
而且只能由瀏覽器發起：只有瀏覽器那條路會經過前面的代理。

走哪條路：跟 SFTP **同一個 WebSocket 路徑**（`/api/v1/addresses/<id>/sftp/ws`，id 用全 0 的
保留值）。代理的放行規則多半照範例只寫主控台那組路徑 —— 開在別的路徑上，量到的就不是 SFTP
會走的那條。進入這個模式靠管理者才拿得到的測試票證（`/system/sftp-probe/ticket`）。

協定刻意與 SFTP 的 put／get 相同（put_ready、每 16 KB 一個 put_ack、file_begin／file_end），
前端的流量控制才會被一併測到。不連任何主機、不碰檔案系統；每張票證能測的總量有上限。
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from app.core.ui_error import ui_detail
from app.services.sftp import CHUNK_BYTES

#: 測試模式用的保留位址 id（全 0）；真的 IP 記錄不會是這個值
PROBE_ADDRESS_ID = uuid.UUID(int=0)
#: 單次上傳／下載的上限，以及一張票證（一條連線）總共能測的量
PROBE_MAX = 32 * 1024 * 1024
SESSION_MAX = 4 * PROBE_MAX
#: 與 SFTP 相同：每收到這麼多就回一次確認（前端靠它做流量控制）
ACK_EVERY = 16 * 1024
#: 上傳時等下一個資料框的上限（秒）；等閒置的指令也用它，測試不需要長時間掛著
STALL_TIMEOUT = 30.0
#: 前端建議的測試量（上下各一次）
DEFAULT_TEST_BYTES = 8 * 1024 * 1024

Receive = Callable[[], Awaitable[dict[str, Any]]]
SendText = Callable[[str], Awaitable[None]]
SendBytes = Callable[[bytes], Awaitable[None]]


async def run(receive: Receive, send_text: SendText, send_bytes: SendBytes) -> None:
    """測試模式的主迴圈。回傳＝對方說 bye、斷線、閒置太久或用完額度。"""
    async def send(obj: dict[str, Any]) -> None:
        await send_text(json.dumps(obj, ensure_ascii=False))

    # 隨機內容：路上若有任何一層壓縮，一整片 0 會讓量到的大小與速度完全失真
    block = os.urandom(CHUNK_BYTES)
    used = 0
    await send({"type": "ready", "probe": True, "max_bytes": PROBE_MAX,
                "chunk": CHUNK_BYTES, "ack_every": ACK_EVERY})
    while True:
        try:
            message = await asyncio.wait_for(receive(), timeout=STALL_TIMEOUT)
        except TimeoutError:
            return
        if message.get("type") == "websocket.disconnect":
            return
        text = message.get("text")
        if text is None:
            continue                        # 上一次上傳的殘餘框，丟掉
        try:
            req = json.loads(text)
        except ValueError:
            continue
        op, rid = req.get("type"), req.get("id")
        if op == "bye":
            return
        if op not in ("put", "get"):
            continue
        try:
            size = int(req.get("size") or 0)
        except (TypeError, ValueError):
            size = -1
        if not 0 < size <= PROBE_MAX:
            await send({"type": "error", "op": op, "id": rid,
                        **ui_detail("sftp_probe_too_large", "測試量超出範圍",
                                    max=PROBE_MAX // (1024 * 1024))})
            continue
        if used + size > SESSION_MAX:
            await send({"type": "error", "op": op, "id": rid,
                        **ui_detail("sftp_probe_session_limit", "這次測試的額度用完了")})
            return
        used += size
        t0 = time.monotonic()
        if op == "get":
            await send({"type": "file_begin", "id": rid, "name": "probe", "size": size})
            sent = 0
            while sent < size:
                n = min(CHUNK_BYTES, size - sent)
                await send_bytes(block if n == CHUNK_BYTES else block[:n])
                sent += n
            await send({"type": "file_end", "id": rid, "sent": sent,
                        "ms": round((time.monotonic() - t0) * 1000)})
            continue
        # put：與 SFTP 相同的節奏 —— 先 put_ready，收到就確認，收滿回 ok
        await send({"type": "put_ready", "id": rid})
        written, next_ack, stalled = 0, 0, False
        while written < size:
            try:
                m = await asyncio.wait_for(receive(), timeout=STALL_TIMEOUT)
            except TimeoutError:
                stalled = True
                break
            if m.get("type") == "websocket.disconnect":
                return
            chunk = m.get("bytes")
            if chunk is None:               # 對方中途改送指令（put_abort）＝放棄
                stalled = True
                break
            written += len(chunk[: size - written])
            if written >= next_ack or written >= size:
                next_ack = written + ACK_EVERY
                await send({"type": "put_ack", "id": rid, "bytes": written})
        if stalled:
            await send({"type": "error", "op": "put", "id": rid,
                        **ui_detail("sftp_probe_stalled", f"測試上傳中斷（已收到 {written}/{size} 位元組）",
                                    written=written, size=size)})
            continue
        await send({"type": "ok", "op": "put", "id": rid, "bytes": written,
                    "ms": round((time.monotonic() - t0) * 1000)})
