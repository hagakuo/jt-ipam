"""掃描代理撥回來的主控台中繼（issue #24 階段二）：worker A 那一端。

代理領到 `relay_open` 工作、確認目標在自己被指派的子網路內、先連上目標，然後撥這個 WebSocket：

    wss://<伺服器>/api/v1/scan-agents/relay/{sid}/ws
    X-Agent-Key: <代理金鑰>       X-Relay-Ticket: <單次票證>

這裡驗金鑰與票證（票證必須是發給這台代理的、只能用一次），在 **127.0.0.1** 開一個監聽埠，經 Redis
把埠號交給正在等的主控台（可能在別的 worker），然後在「主控台的 TCP」與「代理的 WebSocket」之間搬位元組。

監聽埠的暴露面跟階段一跳板的本機轉發相同：只綁 127.0.0.1、**只接受第一個連線**、只在就緒後 10 秒內接受。
不吃 JWT：這條是代理用的，跟使用者的登入無關；誰能開主控台在主控台那一端已經檢查過。
"""
from __future__ import annotations

import asyncio
import contextlib
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, WebSocket
from sqlalchemy import select

from app.core.audit import append_audit
from app.core.db import SessionLocal
from app.models.scan_agent import ScanAgent
from app.services import console_relay

router = APIRouter(prefix="/scan-agents", tags=["scan-agents"])

#: 開好監聽埠之後，主控台要在幾秒內連進來；過了就關掉（不留一個沒人用的埠）
ACCEPT_WINDOW = 10.0
#: 閒置多久送一次應用層保活（nginx 與代理端都有閒置逾時；主控台可能長時間沒有輸入）
KEEPALIVE_SECONDS = 25.0
#: 一次從 TCP 讀多少送一框（代理端的單框上限是 64 KiB）
CHUNK = 64 * 1024

_SID = re.compile(r"^[0-9a-f]{32}$")


async def _agent_for(key: str | None) -> ScanAgent | None:
    from app.api.v1.endpoints.scan_agents import _key_hash
    if not key:
        return None
    async with SessionLocal() as s:
        agent = (await s.execute(
            select(ScanAgent).where(ScanAgent.enroll_key_hash == _key_hash(key)))).scalar_one_or_none()
        if agent is None or not agent.enabled:
            return None
        s.expunge(agent)
        return agent


async def _relay_switch_on() -> bool:
    from app.services.system_config import get_console_relay_enabled
    async with SessionLocal() as s:
        return await get_console_relay_enabled(s)


@router.websocket("/relay/{sid}/ws")
async def agent_relay_ws(websocket: WebSocket, sid: str) -> None:
    if not _SID.match(sid):
        await websocket.close(code=4400)
        return
    agent = await _agent_for(websocket.headers.get("x-agent-key"))
    if agent is None:
        await websocket.close(code=4401)
        return
    # 縱深：主控台那端已經檢查過兩道網頁開關，這裡再看一次（代理主機的否決在代理自己）
    if not agent.relay_allowed or not await _relay_switch_on():
        await websocket.close(code=4403)
        return
    ticket = await console_relay.redeem_ticket(
        sid, websocket.headers.get("x-relay-ticket") or "", agent_id=agent.id)
    if ticket is None:
        await websocket.close(code=4403)
        return
    await websocket.accept()
    await serve_relay(websocket, sid=sid, ticket=ticket, agent_id=agent.id, agent_name=agent.name)


async def serve_relay(websocket: WebSocket, *, sid: str, ticket: dict[str, Any],
                      agent_id: uuid.UUID, agent_name: str) -> dict[str, Any]:
    """開監聽埠、通知等待的主控台、搬位元組，結束時寫稽核。回傳統計（測試用）。"""
    loop = asyncio.get_running_loop()
    first: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = loop.create_future()

    async def on_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if first.done():
            writer.close()              # 只接受第一個連線
            return
        first.set_result((reader, writer))

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    stats: dict[str, Any] = {"to_target": 0, "from_target": 0, "reason": "closed"}
    started = datetime.now(UTC)
    writer: asyncio.StreamWriter | None = None
    send_lock = asyncio.Lock()
    last = [time.monotonic()]

    try:
        await console_relay.push_ready(sid, {"port": port})
        try:
            reader, writer = await asyncio.wait_for(first, timeout=ACCEPT_WINDOW)
        except TimeoutError:
            stats["reason"] = "console_never_connected"
            return stats
        finally:
            server.close()

        async def console_to_agent() -> str:
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    return "console_closed"
                async with send_lock:
                    await websocket.send_bytes(data)
                stats["to_target"] += len(data)
                last[0] = time.monotonic()

        async def agent_to_console() -> str:
            assert writer is not None
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    return "agent_closed"
                data = msg.get("bytes")
                if data:                # 文字框是代理的保活，不轉給主控台
                    writer.write(data)
                    await writer.drain()
                    stats["from_target"] += len(data)
                    last[0] = time.monotonic()

        async def keepalive() -> str:
            while True:
                await asyncio.sleep(KEEPALIVE_SECONDS / 5)
                if time.monotonic() - last[0] >= KEEPALIVE_SECONDS:
                    async with send_lock:
                        await websocket.send_text("ka")
                    last[0] = time.monotonic()

        tasks = [asyncio.create_task(console_to_agent()), asyncio.create_task(agent_to_console()),
                 asyncio.create_task(keepalive())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            exc = t.exception()
            stats["reason"] = (f"error:{type(exc).__name__}" if exc is not None else t.result())
        await asyncio.gather(*pending, return_exceptions=True)
        return stats
    finally:
        server.close()
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
        with contextlib.suppress(Exception):
            await websocket.close(code=1000)
        await _audit_end(sid=sid, ticket=ticket, agent_id=agent_id, agent_name=agent_name,
                         started=started, stats=stats)


async def _audit_end(*, sid: str, ticket: dict[str, Any], agent_id: uuid.UUID, agent_name: str,
                     started: datetime, stats: dict[str, Any]) -> None:
    """每條中繼一筆稽核：誰、經由哪台代理、目標、起訖、雙向位元組數、結束原因。"""
    with contextlib.suppress(Exception):
        async with SessionLocal() as s:
            await append_audit(
                s, actor_user_id=ticket.get("user_id"), actor_ip=None, actor_user_agent=None,
                object_type="scan_agent", object_id=str(agent_id), action="console_relay",
                diff={"sid": sid, "agent": agent_name, "target": ticket.get("target"),
                      "port": ticket.get("port"), "console": ticket.get("kind"),
                      "started_at": started.isoformat(), "ended_at": datetime.now(UTC).isoformat(),
                      "bytes_to_target": stats["to_target"], "bytes_from_target": stats["from_target"],
                      "reason": stats["reason"]},
                request_id=None,
            )
            await s.commit()
