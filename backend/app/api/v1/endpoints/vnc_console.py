"""IP 位址 VNC 連線管理：ticket 換發 + WebSocket↔VNC 橋接（瀏覽器 canvas 前端）。

完全比照 SSH/RDP（ssh_console / rdp_console）的安全架構：ticket 單次用 + WS 兩處重查
can_use_vnc（deny-by-default）、密碼用完即丟不落 DB、目標 host 鎖死該 IP（防 SSRF）、稽核開關場。

相依：與 RDP 同一個選用 aardwolf（`VNCConnection` 介面與 RDP 相同）。未安裝 → VNC_AVAILABLE=False。

aardwolf 0.2.13 的 VNC `send_mouse` 有 bug（按鍵 mask 反向、無滾輪、無 steps 參數）→ 本模組於
import 時 monkeypatch 一個正確的 RFB PointerEvent 實作（維護累積 button mask；滾輪用 button 4/5
一次按放）。VNC 桌面尺寸由「伺服器」決定（connect 後讀 conn.width/height），非用戶端指定解析度。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import secrets
import uuid
from datetime import UTC, datetime
from struct import pack
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.audit import append_audit
from app.core.config import get_settings
from app.core.db import SessionLocal, get_session
from app.core.rate_limit import _redis_client
from app.core.security import envelope_decrypt
from app.core.tickets import take_once
from app.core.ui_error import detail_of, ui_detail
from app.core.ws_timeouts import HANDSHAKE_TIMEOUT, WsTimeout, receive_text_within
from app.models.address import IPAddress
from app.models.ssh_credential import SSHCredential
from app.models.user import User
from app.services import console_route
from app.services.permission import can_use_vnc

try:  # 與 RDP 同一個選用 aardwolf
    from aardwolf.commons.factory import RDPConnectionFactory
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.queuedata import RDPDATATYPE
    from aardwolf.commons.queuedata.constants import MOUSEBUTTON, VIDEO_FORMAT
    from aardwolf.vncconnection import VNCConnection

    VNC_AVAILABLE = True
except Exception:  # 任何 import 問題都視為未安裝
    VNC_AVAILABLE = False

router = APIRouter(prefix="/addresses", tags=["vnc"])

_TICKET_TTL = 60
_CONNECT_TIMEOUT = 20.0
#: guacd：等到第一個畫面才算連上
_CONNECT_TIMEOUT_GUACD = 30.0
_DEFAULT_PORT = 5900

# VNC（RFB）鍵盤用 X11 keysym（非 PC scancode）。特殊鍵對應表：
_VNC_KEYSYMS: dict[str, int] = {
    "Enter": 0xFF0D, "Backspace": 0xFF08, "Tab": 0xFF09, "Escape": 0xFF1B,
    "Delete": 0xFFFF, "Home": 0xFF50, "End": 0xFF57, "PageUp": 0xFF55,
    "PageDown": 0xFF56, "Insert": 0xFF63, "ArrowUp": 0xFF52, "ArrowDown": 0xFF54,
    "ArrowLeft": 0xFF51, "ArrowRight": 0xFF53,
    "Control": 0xFFE3, "Shift": 0xFFE1, "Alt": 0xFFE9, "Meta": 0xFFEB, " ": 0x20,  # Meta = Super_L (Win/⌘)
    "F1": 0xFFBE, "F2": 0xFFBF, "F3": 0xFFC0, "F4": 0xFFC1, "F5": 0xFFC2, "F6": 0xFFC3,
    "F7": 0xFFC4, "F8": 0xFFC5, "F9": 0xFFC6, "F10": 0xFFC7, "F11": 0xFFC8, "F12": 0xFFC9,
}

_active_sessions = 0


def _ticket_key(ticket: str) -> str:
    return f"vnc:tk:{ticket}"


# ── 修正 aardwolf VNC send_mouse（正確 RFB PointerEvent）──────────────────────
if VNC_AVAILABLE:
    _VNC_BTN_BITS = {
        MOUSEBUTTON.MOUSEBUTTON_LEFT: 1,
        MOUSEBUTTON.MOUSEBUTTON_MIDDLE: 2,
        MOUSEBUTTON.MOUSEBUTTON_RIGHT: 4,
    }

    async def _vnc_send_mouse(self, button, x_pos, y_pos, is_pressed, steps=0):  # type: ignore[no-untyped-def]
        try:
            if x_pos < 0 or y_pos < 0:
                return True, None
            writer = getattr(self, "_VNCConnection__writer", None)
            if writer is None:
                return True, None
            mask = getattr(self, "_jt_btnmask", 0)
            if button in (MOUSEBUTTON.MOUSEBUTTON_WHEEL_UP, MOUSEBUTTON.MOUSEBUTTON_WHEEL_DOWN):
                wbit = 8 if button == MOUSEBUTTON.MOUSEBUTTON_WHEEL_UP else 16
                await writer.write(pack("!BBHH", 5, mask | wbit, x_pos, y_pos))
                await writer.write(pack("!BBHH", 5, mask, x_pos, y_pos))
                return True, None
            bit = _VNC_BTN_BITS.get(button)
            if bit is None:  # HOVER / move：只更新座標、維持目前 mask
                await writer.write(pack("!BBHH", 5, mask, x_pos, y_pos))
                return True, None
            mask = (mask | bit) if is_pressed else (mask & ~bit)
            self._jt_btnmask = mask
            await writer.write(pack("!BBHH", 5, mask, x_pos, y_pos))
            return True, None
        except Exception as e:
            return None, e

    async def _vnc_send_keysym(self, keysym, is_pressed):  # type: ignore[no-untyped-def]
        """正確的 RFB KeyEvent（msg 4 + down flag + u32 keysym）。"""
        try:
            writer = getattr(self, "_VNCConnection__writer", None)
            if writer is None:
                return True, None
            await writer.write(pack("!BBxxI", 4, 1 if is_pressed else 0, int(keysym) & 0xFFFFFFFF))
            return True, None
        except Exception as e:
            return None, e

    async def _vnc_send_key_char(self, char, is_pressed):  # type: ignore[no-untyped-def]
        """字元→X11 keysym（Latin-1 直接用碼位；其餘走 0x01000000+unicode）。"""
        if not char:
            return True, None
        cp = ord(char[0])
        keysym = cp if cp < 0x100 else (0x01000000 + cp)
        return await _vnc_send_keysym(self, keysym, is_pressed)

    _orig_authenticate = VNCConnection._VNCConnection__authenticate  # type: ignore[attr-defined]

    async def _vnc_authenticate(self):  # type: ignore[no-untyped-def]
        """沒有密碼的 VNC（安全型別 1 = None）也要把「選了哪個型別」送回去。

        RFB 3.7 以後，伺服器送出支援的安全型別清單之後，**客戶端必須回一個位元組**說明
        自己選哪一個。aardwolf 只在型別 2（密碼）那條路徑送，型別 1 的分支是空的 ——
        於是雙方互等：伺服器等那個位元組，我們等 SecurityResult，直到逾時。
        畫面上看到的是「連線逾時」，完全指不出原因。

        （實機 2026-09-02：用不設密碼的 VNC 靶重現，交握停在版本交換之後。）
        """
        if getattr(self, "_VNCConnection__selected_security_type", None) == 1:
            await self._VNCConnection__writer.write(bytes([1]))
        return await _orig_authenticate(self)

    if not getattr(VNCConnection, "_jt_patched", False):
        VNCConnection._VNCConnection__authenticate = _vnc_authenticate  # type: ignore[attr-defined]
        VNCConnection.send_mouse = _vnc_send_mouse  # type: ignore[method-assign]
        VNCConnection.send_keysym = _vnc_send_keysym  # type: ignore[attr-defined]
        VNCConnection.send_key_char = _vnc_send_key_char  # type: ignore[method-assign]
        VNCConnection._jt_patched = True


def _mouse_button(b: int) -> Any:
    return {0: MOUSEBUTTON.MOUSEBUTTON_LEFT, 1: MOUSEBUTTON.MOUSEBUTTON_RIGHT,
            2: MOUSEBUTTON.MOUSEBUTTON_MIDDLE}.get(int(b), MOUSEBUTTON.MOUSEBUTTON_LEFT)


def vnc_unavailable_detail() -> dict[str, Any]:
    """內建 VNC 引擎用不了：講出原因（這台的 Python 沒有 aardwolf 的預編譯套件，issue #39），
    並指出另一條路 —— 改用 guacd 引擎（不需要 aardwolf）。"""
    import sys
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    return ui_detail("console_vnc_not_installed",
                     f"內建的 VNC 引擎無法使用：需要 aardwolf，而 Python {py} 沒有它的預編譯套件。"
                     "可以安裝 guacd，再到「管理 → 系統設定」把 VNC 連線引擎改成 guacd。",
                     python=py)


def guacd_vnc_params(host: str, port: int, username: str, password: str) -> dict[str, str]:
    """交給 guacd 的 VNC 連線參數。

    帳號只在有填時才帶：guacd 會在伺服器要求帳號的認證方式（macOS 螢幕共享的 ARD、
    UltraVNC MS 登入、VeNCrypt 帳密）時拿它來用；傳統 VncAuth 只看密碼。
    VNC 原本就沒有剪貼簿，這裡兩個方向都關。
    """
    params = {"hostname": host, "port": str(port), "password": password,
              "disable-copy": "true", "disable-paste": "true"}
    if username:
        params["username"] = username
    return params

@router.post("/{address_id}/vnc/ticket")
async def issue_vnc_ticket(
    address_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    from app.services import console_engine
    # 預設 guacd；這台的 guacd 處理不了 VNC 時退回內建引擎（見 services/console_engine.py）
    engine = await console_engine.resolve(session, "vnc", fallbacks=[("builtin", VNC_AVAILABLE)])
    if engine == "guacd":
        # guacd 引擎不需要 aardwolf
        from app.services import guacd as guac
        try:
            await guac.require("vnc")
        except guac.GuacdError as exc:
            raise HTTPException(status_code=503, detail=exc.ui()) from exc
    elif not VNC_AVAILABLE:
        raise HTTPException(status_code=503, detail=vnc_unavailable_detail())
    from app.core.rate_limit import limit_per_ip

    await limit_per_ip(request, name="vnc")

    ip = await session.get(IPAddress, address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="Address not found")
    if not await can_use_vnc(session, user=user, ip=ip):
        raise HTTPException(status_code=403, detail=ui_detail("console_vnc_forbidden", "無 VNC 連線權限"))

    saved = (await session.execute(
        select(SSHCredential.id).where(
            SSHCredential.owner_user_id == user.id,
            SSHCredential.protocol == "vnc",
            (SSHCredential.target_ip_id == ip.id) | (SSHCredential.target_ip_id.is_(None)),
        ).limit(1)
    )).first()

    ticket = secrets.token_urlsafe(32)
    # 引擎寫進票證：WebSocket 照這個用，不自己再判斷（guacd 剛好起落時兩邊會講不同協定）
    payload = json.dumps({"user_id": str(user.id), "ip_id": str(ip.id), "engine": engine})
    await _redis_client().set(_ticket_key(ticket), payload, ex=_TICKET_TTL)

    return {
        "ticket": ticket,
        "ws_path": f"/api/v1/addresses/{ip.id}/vnc/ws",
        "default_port": _DEFAULT_PORT,
        "has_saved_creds": saved is not None,
        "engine": engine,
        "ttl": _TICKET_TTL,
    }


async def _redeem_ticket(ticket: str, address_id: uuid.UUID) -> tuple[uuid.UUID | None, str | None]:
    """單次取出 → (user_id, 發票證時決定的引擎)。舊票證沒有引擎欄位 → None（呼叫端照設定）。"""
    if not ticket:
        return None, None
    raw = await take_once(_redis_client(), _ticket_key(ticket))
    if not raw:
        return None, None
    try:
        data = json.loads(raw)
        if data.get("ip_id") != str(address_id):
            return None, None
        return uuid.UUID(data["user_id"]), data.get("engine")
    except (ValueError, KeyError, TypeError):
        return None, None


async def _audit_vnc(
    *, actor_user_id: str, actor_ip: str | None, object_id: str,
    action: str, diff: dict[str, Any],
) -> None:
    async with SessionLocal() as s:
        await append_audit(
            s, actor_user_id=actor_user_id, actor_ip=actor_ip, actor_user_agent=None,
            object_type="ip", object_id=object_id, action=action, diff=diff, request_id=None,
        )
        await s.commit()


def _classify_connect_error(err: BaseException) -> tuple[str, str]:
    """把底層連線錯誤翻成「看得出下一步」的訊息。

    原本一律回「連線/認證失敗（密碼錯誤或 VNC 設定）」—— 但這句在最常見的那個情況
    下是**錯的指引**：目標根本沒送出 RFB 版本字串就把 TCP 關掉時，密碼連送都沒送出去，
    使用者卻會被指去檢查密碼。實機遇過一次：某個位址同時被三台虛擬機宣稱（ARP 有三個
    MAC 回應），連線落到沒有 VNC 的那台，於是接受連線後立刻關閉。

    與整合頁同一個原則（core/safe_http.transport_detail）：**帶底層原文**，
    否則畫面上的錯誤對使用者與對我們都一樣沒有資訊。
    """
    from app.core.safe_http import transport_detail

    detail = transport_detail(err, limit=160)
    text = str(err).lower()
    if "stream ended" in text or "connection reset" in text or "closed" in text:
        return "handshake_failed", (
            "目標在 VNC 交握完成前就關閉連線 —— 對方不是 VNC 服務、被允許清單／防火牆擋掉，"
            f"或這個位址同時被多台主機使用（原始錯誤：{detail}）"
        )
    if "refused" in text:
        return "connect_failed", f"目標拒絕連線（連接埠沒有服務在聽）：{detail}"
    if "timed out" in text or "timeout" in text:
        return "connect_failed", f"連線逾時（位址或連接埠不通）：{detail}"
    return "auth_failed", f"連線/認證失敗（密碼錯誤或 VNC 設定）：{detail}"


@router.websocket("/{address_id}/vnc/ws")
async def vnc_ws(websocket: WebSocket, address_id: uuid.UUID, ticket: str = "") -> None:
    global _active_sessions

    user_id, ticket_engine = await _redeem_ticket(ticket, address_id)
    if user_id is None:
        await websocket.close(code=4401)
        return

    async with SessionLocal() as s:
        user = await s.get(User, user_id)
        ip = await s.get(IPAddress, address_id)
        if user is None or not user.is_active or ip is None:
            await websocket.close(code=4403)
            return
        allowed = await can_use_vnc(s, user=user, ip=ip)
        host = str(ip.ip).split("/")[0]
        # 連線出口：直連或經由跳板（IP 覆寫 > 子網路 > 直連）
        route = await console_route.resolve_route(s, ip)
        from app.services.system_config import VNC_ENGINES, get_vnc_engine
        engine = ticket_engine if ticket_engine in VNC_ENGINES else await get_vnc_engine(s)
    if not allowed:
        await websocket.close(code=4403)
        return
    if engine != "guacd" and not VNC_AVAILABLE:
        await websocket.close(code=4503)
        return

    await websocket.accept()
    actor_ip = websocket.client.host if websocket.client else None

    async def send(obj: dict[str, Any]) -> None:
        await websocket.send_text(json.dumps(obj))

    cap = get_settings().rdp_max_sessions
    if cap and _active_sessions >= cap:
        await send({"type": "error", **ui_detail("console_vnc_too_many",
                                      f"連線已達上限（{cap}）", max=cap)})
        await websocket.close()
        return

    conn = None
    counted = False
    tunnel: console_route.Tunnel | None = None
    started: datetime | None = None
    # guacd 連上之後這條 WebSocket 改講 Guacamole 協定：不可以再送 JSON
    guac_mode = False
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
        if cfg.get("type") != "config":
            await send({"type": "error", **ui_detail("console_no_config", "缺少連線設定")})
            await websocket.close()
            return
        port = int(cfg.get("port") or _DEFAULT_PORT)
        if not (1 <= port <= 65535):
            await send({"type": "error", **ui_detail("console_bad_port", "連接埠須為 1–65535")})
            await websocket.close()
            return
        password = cfg.get("password") or ""
        # 帳號：macOS 螢幕共享（ARD）、UltraVNC MS 登入、VeNCrypt 帳密等認證要用；傳統 VNC 沒有
        username = str(cfg.get("username") or "").strip()[:128]
        credential_id = cfg.get("credential_id")

        used_cred_id: uuid.UUID | None = None
        if credential_id:
            from app.api.v1.endpoints.ssh_credentials import cred_aad
            async with SessionLocal() as s:
                try:
                    cred = await s.get(SSHCredential, uuid.UUID(str(credential_id)))
                except ValueError:
                    cred = None
                if (cred is None or cred.owner_user_id != user_id or cred.protocol != "vnc"
                        or (cred.target_ip_id is not None and str(cred.target_ip_id) != str(address_id))):
                    await send({"type": "error",
                                **ui_detail("console_no_saved_password", "找不到可用的已存密碼")})
                    await websocket.close()
                    return
                used_cred_id = cred.id
                username = (cred.username or "").strip()
                secrets_enc = dict(cred.secrets_enc or {})
            try:
                password = envelope_decrypt(secrets_enc["password"], aad=cred_aad(user_id, "password"))
            except Exception:
                await send({"type": "error",
                            **ui_detail("console_saved_password_decrypt", "已存密碼解密失敗")})
                await websocket.close()
                return
            async with SessionLocal() as s:
                c2 = await s.get(SSHCredential, used_cred_id)
                if c2 is not None:
                    c2.last_used_at = datetime.now(UTC)
                    await s.commit()

        if username and engine != "guacd":
            # 內建引擎（aardwolf）只會送密碼；默默忽略帳號的話，使用者只會看到「認證失敗」而不知道為什麼
            await send({"type": "error", **ui_detail(
                "console_vnc_username_needs_guacd",
                "內建的 VNC 引擎不支援帳號，請到「管理 → 系統設定」把 VNC 連線引擎改成 guacd")})
            await websocket.close()
            return

        await send({"type": "status", "state": "connecting"})

        # 經跳板時把目標換成本機轉發埠（直連時 open_route 是零成本的）
        try:
            tunnel = await console_route.open_route(route, host, port, user_id=user_id, purpose="vnc")
        except console_route.JumpHostError as exc:
            await send({"type": "error", **detail_of(exc, "jump_failed")})
            await websocket.close()
            return
        if tunnel.via:
            await send({"type": "status", "state": "via_jump", "via": tunnel.via,
                        "via_kind": tunnel.via_kind})
        dial_host, dial_port = tunnel.host, tunnel.port

        if engine == "guacd":
            from app.services import guacd as guac
            # 密碼只交給本機的 guacd；目標是通道的位址。VNC 原本就沒有剪貼簿，這裡也兩個方向都關
            params = guacd_vnc_params(dial_host, dial_port, username, password)
            del password
            try:
                conn = await guac.GuacdConnection.open()
                # 桌面大小由 VNC 伺服器決定；這裡給的尺寸只是 guacd 需要一個初始值
                await conn.handshake("vnc", params, width=1024, height=768,
                                     dpi=guac.client_dpi(cfg.get("dpi")),
                                     timezone=guac.client_timezone(cfg.get("timezone")))
                del params
                initial = await conn.wait_first_frame(_CONNECT_TIMEOUT_GUACD)
            except guac.GuacdError as exc:
                if exc.code == "guacd_upstream_not_found":
                    # guacd 對「連不到」與「密碼錯」回的是同一句話 —— 失敗之後才自己試 TCP 分辨。
                    # 不可以在連線前先試：TigerVNC 等會把「連上就斷」算成一次認證失敗，
                    # 連幾次就把 jt-ipam 列入封鎖清單（2026-09-25 實測，7 次就回 Too many security failures）
                    unreachable = await guac.tcp_reachable(dial_host, dial_port)
                    if unreachable is not None:
                        await send({"type": "error", **ui_detail(
                            "console_connect_failed", f"連線失敗：{host}:{port} {unreachable}",
                            reason=f"{host}:{port} {unreachable}")})
                        await websocket.close()
                        return
                await send({"type": "error", **guac.refine_vnc_error(exc).ui()})
                await websocket.close()
                return
            width, height = guac.initial_size(initial) or (1024, 768)
            _active_sessions += 1
            counted = True
            started = datetime.now(UTC)
            await _audit_vnc(
                actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
                action="vnc.session_open",
                diff={"host": host, "port": port, "username": username or None,
                      "size": f"{width}x{height}", "engine": "guacd",
                      "via_jump_host": tunnel.via, "via_kind": tunnel.via_kind,
                      "credential_id": str(used_cred_id) if used_cred_id else None},
            )
            await send({"type": "status", "state": "connected", "engine": "guacd",
                        "width": width, "height": height})
            guac_mode = True
            await guac.relay(websocket, conn, initial=initial)
            return

        io = RDPIOSettings()
        io.video_out_format = VIDEO_FORMAT.PNG
        io.clipboard_use_pyperclip = False

        # 連接埠寫在 URL 裡（`create_connection_newtarget()` 只換 ip/hostname，不動埠）
        if password:
            url = (f"vnc+plain-password://{quote(password, safe='')}@{dial_host}:{dial_port}/"
                   f"?timeout={int(_CONNECT_TIMEOUT)}")
        else:
            url = f"vnc://{dial_host}:{dial_port}/?timeout={int(_CONNECT_TIMEOUT)}"
        del password

        factory = RDPConnectionFactory.from_url(url, io)
        conn = factory.create_connection_newtarget(dial_host, io)
        try:
            async with asyncio.timeout(_CONNECT_TIMEOUT):
                _result, err = await conn.connect()
        except TimeoutError:
            await send({"type": "error", **ui_detail("console_connect_timeout", "連線逾時")})
            await websocket.close()
            return
        if err is not None:
            code, message = _classify_connect_error(err)
            await send({"type": "error", "code": code, "message": message})
            await websocket.close()
            return

        _active_sessions += 1
        counted = True
        started = datetime.now(UTC)
        # VNC 桌面尺寸由伺服器決定（ServerInit）→ 告知前端 canvas 尺寸
        width = int(getattr(conn, "width", 0) or 1024)
        height = int(getattr(conn, "height", 0) or 768)
        await _audit_vnc(
            actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
            action="vnc.session_open",
            diff={"host": host, "port": port, "size": f"{width}x{height}",
                  "via_jump_host": tunnel.via, "via_kind": tunnel.via_kind,
                  "credential_id": str(used_cred_id) if used_cred_id else None},
        )
        await send({"type": "status", "state": "connected", "width": width, "height": height})

        await _bridge(websocket, conn, send)

    except WebSocketDisconnect:
        pass
    except Exception:
        if not guac_mode:
            with contextlib.suppress(Exception):
                await send({"type": "error", **ui_detail("console_internal", "連線發生未預期錯誤")})
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                await conn.terminate()
        # 通道與 WS session 同生共死（連線收掉之後才還轉發）
        if tunnel is not None:
            await tunnel.aclose()
        if counted:
            _active_sessions -= 1
            if started is not None:
                dur = (datetime.now(UTC) - started).total_seconds()
                with contextlib.suppress(Exception):
                    await _audit_vnc(
                        actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
                        action="vnc.session_close", diff={"host": host, "duration_seconds": round(dur, 1)},
                    )
        with contextlib.suppress(Exception):
            if not guac_mode:
                await send({"type": "status", "state": "disconnected"})
            await websocket.close()


async def _bridge(websocket: WebSocket, conn: Any, send: Any) -> None:
    """雙向 pump：VNC 視訊→ws（PNG tile）、ws→send_mouse/send_key（已修正的 VNC 實作）。"""

    async def pump_out() -> None:
        with contextlib.suppress(Exception):
            while True:
                data = await conn.ext_out_queue.get()
                if data is None:
                    break
                if getattr(data, "type", None) == RDPDATATYPE.VIDEO and data.data:
                    await send({
                        "type": "img", "x": data.x, "y": data.y,
                        "w": data.width, "h": data.height,
                        "d": base64.b64encode(data.data).decode("ascii"),
                    })

    async def pump_in() -> None:
        with contextlib.suppress(WebSocketDisconnect, Exception):
            while True:
                # 不做應用層 idle-timeout（背景分頁 heartbeat 會被節流誤判斷線）；保活靠 WS
                # 傳輸層 uvicorn ws-ping/pong，真正斷線走 WebSocketDisconnect。
                raw = await websocket.receive_text()
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "m":
                    x, y = int(msg.get("x", 0)), int(msg.get("y", 0))
                    if msg.get("wheel"):
                        btn = (MOUSEBUTTON.MOUSEBUTTON_WHEEL_UP if int(msg.get("dir", -1)) > 0
                               else MOUSEBUTTON.MOUSEBUTTON_WHEEL_DOWN)
                        await conn.send_mouse(btn, x, y, False)
                    elif msg.get("move"):
                        await conn.send_mouse(MOUSEBUTTON.MOUSEBUTTON_HOVER, x, y, False)
                    else:
                        await conn.send_mouse(_mouse_button(msg.get("b", 0)), x, y, bool(msg.get("p")))
                elif t == "k":
                    pressed = bool(msg.get("p"))
                    key = msg.get("key", "")
                    if key in _VNC_KEYSYMS:
                        await conn.send_keysym(_VNC_KEYSYMS[key], pressed)
                    else:
                        ch = msg.get("ch", "")
                        if len(ch) == 1:
                            await conn.send_key_char(ch, pressed)
                elif t == "ping":
                    await send({"type": "pong"})
                elif t == "close":
                    break

    out_task = asyncio.create_task(pump_out())
    in_task = asyncio.create_task(pump_in())
    done, pending = await asyncio.wait({out_task, in_task}, return_when=asyncio.FIRST_COMPLETED)
    # 畫面那一端先結束、瀏覽器還開著＝VNC 伺服器結束了連線。以前畫面只是停住，
    # 使用者會以為網路慢而一直等（與 RDP 主控台同一個處理，GitHub issue #42）。
    remote_ended = out_task in done and in_task not in done
    for p in pending:
        p.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    if remote_ended:
        with contextlib.suppress(Exception):
            await send({"type": "error", **ui_detail(
                "console_remote_ended", "遠端主機結束了這個工作階段（沒有提供原因）")})
