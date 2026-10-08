"""BMC OOB主控台（IPMI SOL）：ticket 換發 + WebSocket↔SOL 橋接（xterm.js 前端）。

比照 SSH 連線管理：
- A01：ticket 與 WS 兩處都重查 can_use_bmc（deny-by-default）。
- A07/A09：ticket 單次用 + 60s TTL + 綁 user×ip；發放限流；session 開/關都寫稽核（不記密碼）。
- 傳輸：後端起 `ipmitool sol activate` 子行程（pty），雙向中繼 master_fd ↔ WebSocket（binary）。
- 非破壞：只做 SOL（鍵盤 + 文字畫面），不含電源/感測/開機覆寫。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.audit import append_audit
from app.core.db import SessionLocal, get_session
from app.core.rate_limit import _redis_client
from app.core.security import envelope_decrypt
from app.core.tickets import take_once
from app.core.ui_error import detail_of, ui_detail
from app.core.ws_timeouts import HANDSHAKE_TIMEOUT, WsTimeout, receive_text_within
from app.models.address import IPAddress
from app.models.ssh_credential import SSHCredential
from app.models.user import User
from app.services import bmc as bmc_svc
from app.services import console_route
from app.services.permission import can_use_bmc

router = APIRouter(prefix="/addresses", tags=["bmc"])

_TICKET_TTL = 60


def _ticket_key(ticket: str) -> str:
    return f"bmc:tk:{ticket}"


@router.post("/{address_id}/bmc/ticket")
async def issue_bmc_ticket(
    address_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """換發短期一次性 ticket；之後用它開 WebSocket。"""
    from app.core.rate_limit import limit_per_ip

    await limit_per_ip(request, name="bmc")
    if not bmc_svc.bmc_available():
        raise HTTPException(status_code=503, detail=ui_detail("bmc_no_ipmitool", "後端未安裝 IPMI 工具（ipmitool）"))
    ip = await session.get(IPAddress, address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="Address not found")
    if not await can_use_bmc(session, user=user, ip=ip):
        raise HTTPException(status_code=403, detail=ui_detail("bmc_forbidden", "無 BMC 連線權限"))

    ticket = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": str(user.id), "ip_id": str(ip.id)})
    await _redis_client().set(_ticket_key(ticket), payload, ex=_TICKET_TTL)
    return {
        "ticket": ticket,
        "ws_path": f"/api/v1/addresses/{ip.id}/bmc/ws",
        "ttl": _TICKET_TTL,
    }


async def _redeem_ticket(ticket: str, address_id: uuid.UUID) -> uuid.UUID | None:
    if not ticket:
        return None
    raw = await take_once(_redis_client(), _ticket_key(ticket))
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if str(data.get("ip_id")) != str(address_id):
            return None
        return uuid.UUID(str(data["user_id"]))
    except (ValueError, KeyError, TypeError):
        return None


async def _audit_bmc(action: str, *, user_id: uuid.UUID, ip_id: uuid.UUID, actor_ip: str | None,
                     diff: dict[str, Any] | None = None) -> None:
    async with SessionLocal() as s:
        with contextlib.suppress(Exception):
            await append_audit(
                s, actor_user_id=str(user_id), actor_ip=actor_ip, actor_user_agent=None,
                object_type="ip", object_id=str(ip_id), action=action, diff=diff,
                request_id=None,
            )
            await s.commit()


@router.websocket("/{address_id}/bmc/ws")
async def bmc_ws(websocket: WebSocket, address_id: uuid.UUID, ticket: str = "") -> None:
    user_id = await _redeem_ticket(ticket, address_id)
    if user_id is None:
        await websocket.close(code=4401)
        return
    # 重查權限 + 取 BMC IP 字串
    async with SessionLocal() as s:
        ip = await s.get(IPAddress, address_id)
        user = await s.get(User, user_id)
        if ip is None or user is None:
            await websocket.close(code=4403)
            return
        if not await can_use_bmc(s, user=user, ip=ip):
            await websocket.close(code=4403)
            return
        bmc_ip = str(ip.ip).split("/")[0]
        route = await console_route.resolve_route(s, ip)

    # 這個 IP 被指派了跳板，但 BMC 走不了跳板 —— **必須擋下來，不能默默直連**。
    # IPMI（SOL）是 UDP 623，而 SSH 的本機轉發只支援 TCP。默默改走直連的後果不是
    # 「連不上」而是更糟的「連到別人」：會用跳板的站台多半正是私網網段重疊的站台，
    # 後端直連同一個私網位址，很可能打到另一個客戶的 BMC。
    if not isinstance(route, console_route.Direct):
        await websocket.accept()
        with contextlib.suppress(Exception):
            await websocket.send_text(json.dumps({
                "type": "error",
                **ui_detail(
                    "console_bmc_jump_unsupported",
                    f"這個位址設定了跳板「{console_route.route_label(route)}」，"
                    "但 BMC 主控台無法經由跳板：IPMI／SOL 走 UDP 623，"
                    "SSH 通道只能轉發 TCP。請改由能直接連到該 BMC 的網路操作。",
                    name=console_route.route_label(route),
                ),
            }, ensure_ascii=False))
            await websocket.close()
        return

    if not bmc_svc.bmc_available():
        await websocket.close(code=1011)
        return

    await websocket.accept()
    actor_ip = websocket.client.host if websocket.client else None

    async def send(obj: dict[str, Any]) -> None:
        await websocket.send_text(json.dumps(obj))

    # 1) 收設定（憑證：金庫 credential_id 或臨時 username/password）
    try:
        # 連上來卻不送設定的客戶端不可以無限期佔住這條連線（見 core/ws_timeouts）
        try:
            cfg = json.loads(await receive_text_within(
                websocket, HANDSHAKE_TIMEOUT, what="config"))
        except WsTimeout as exc:
            with contextlib.suppress(Exception):
                await websocket.send_text(json.dumps(
                    {"type": "error", **detail_of(exc, "console_handshake_timeout")},
                    ensure_ascii=False))
            await websocket.close(code=4408)
            return
    except (WebSocketDisconnect, json.JSONDecodeError):
        await websocket.close()
        return
    if cfg.get("type") != "config":
        await send({"type": "error", **ui_detail("console_no_config", "缺少連線設定")})
        await websocket.close()
        return

    username = (cfg.get("username") or "").strip()
    password = ""
    credential_id = cfg.get("credential_id")
    if credential_id:
        from app.api.v1.endpoints.ssh_credentials import cred_aad
        async with SessionLocal() as s:
            try:
                cred = await s.get(SSHCredential, uuid.UUID(str(credential_id)))
            except ValueError:
                cred = None
            if (cred is None or cred.owner_user_id != user_id
                    or (cred.target_ip_id is not None and str(cred.target_ip_id) != str(address_id))):
                await send({"type": "error",
                            **ui_detail("console_no_saved_credential", "找不到可用的已存帳密")})
                await websocket.close()
                return
            username = cred.username
            try:
                password = envelope_decrypt(dict(cred.secrets_enc or {})["password"],
                                            aad=cred_aad(user_id, "password"))
            except Exception:
                await send({"type": "error",
                            **ui_detail("console_saved_credential_decrypt", "已存帳密解密失敗")})
                await websocket.close()
                return
            cred.last_used_at = datetime.now(UTC)
            await s.commit()
    else:
        password = cfg.get("password") or ""
    if not username or not password:
        await send({"type": "error", **ui_detail("console_bmc_creds_required", "帳號與密碼必填")})
        await websocket.close()
        return

    # 2) 自我檢查（cipher 回退 / SOL 是否啟用）
    await send({"type": "status", "state": "connecting"})
    chk = await bmc_svc.self_check(bmc_ip, username, password)
    if not chk["ok"]:
        await send({"type": "error", **ui_detail("console_connect_failed",
                                      f"連線失敗：{chk['error']}",
                                      reason=str(chk["error"])[:200])})
        await websocket.close()
        return
    if not chk["sol_enabled"]:
        await send({"type": "error",
                    **ui_detail("console_bmc_sol_disabled",
                                "此 BMC 的 SOL 未啟用（請在 BMC／BIOS 啟用 Serial-over-LAN）")})
        await websocket.close()
        return
    cipher = int(cfg.get("cipher") or chk["cipher"])

    # 3) 釋放殘留 SOL session（單一 session）後起 pty 子行程
    await bmc_svc.deactivate_sol(bmc_ip, username, password, cipher)
    proc, master = bmc_svc.spawn_sol(bmc_ip, username, password, cipher)
    del password
    await _audit_bmc("bmc.session_open", user_id=user_id, ip_id=address_id, actor_ip=actor_ip)
    opened = time.monotonic()
    await send({"type": "status", "state": "connected", "cipher": cipher, "vendor": chk["vendor"]})

    loop = asyncio.get_event_loop()

    async def pump_out() -> None:
        while True:
            data = await loop.run_in_executor(None, _safe_read, master)
            if not data:
                break
            await websocket.send_bytes(data)

    async def pump_in() -> None:
        while True:
            msg = await websocket.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            b = msg.get("bytes")
            if b is None and msg.get("text") is not None:
                b = msg["text"].encode("utf-8", "replace")
            if b:
                os.write(master, b)

    try:
        _done, pending = await asyncio.wait(
            {asyncio.create_task(pump_out()), asyncio.create_task(pump_in())},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
    except WebSocketDisconnect:
        pass
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
        with contextlib.suppress(Exception):
            os.close(master)
        with contextlib.suppress(Exception):
            proc.wait(timeout=3)
        with contextlib.suppress(Exception):
            proc.kill()
        # 跟其他主控台一樣記連了多久（使用者 2026-10-06 問到；以前只有開與關兩筆，要自己相減）
        await _audit_bmc("bmc.session_close", user_id=user_id, ip_id=address_id, actor_ip=actor_ip,
                         diff={"duration_seconds": round(time.monotonic() - opened, 1)})
        with contextlib.suppress(Exception):
            await websocket.close()


def _safe_read(fd: int) -> bytes:
    try:
        return os.read(fd, 4096)
    except OSError:
        return b""
