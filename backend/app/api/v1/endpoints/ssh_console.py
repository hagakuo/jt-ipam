"""IP 位址 SSH 連線管理：ticket 換發 + WebSocket↔SSH 橋接（xterm.js 前端）。

安全設計（OWASP）：
- A01：ticket 與 WS 兩處都重查 `can_use_ssh`（deny-by-default）；看不到的 IP 不能連。
- A07/A09：ticket 單次用 + 60s TTL + 綁 user×ip；發放限流；session 開/關都寫稽核。
- 憑證（密碼/私鑰）只在連線過程存記憶體，用完即丟，**絕不寫 DB / 不記錄**。
- 目標主機固定為該 IP 記錄上的位址（不接受使用者指定 host）→ 防被當成通用 SSH/SSRF proxy。
- A02：host key 採 TOFU 信任後釘選（存 ip.ssh_host_key）；日後不符即警告 MITM。

WS 無法帶 Authorization header → 改用「先以 JWT 打 POST .../ssh/ticket 換 ticket，
再用 ?ticket= 開 WS」。
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.audit import append_audit
from app.core.db import SessionLocal, get_session
from app.core.rate_limit import _redis_client
from app.core.security import envelope_decrypt
from app.core.sqlin import in_values
from app.core.tickets import take_once
from app.core.ui_error import detail_of, ui_detail
from app.core.ws_timeouts import (
    HANDSHAKE_TIMEOUT,
    PROMPT_TIMEOUT,
    WsTimeout,
    receive_text_within,
)
from app.models.address import IPAddress
from app.models.device import Device
from app.models.ssh_credential import SSHCredential
from app.models.user import User
from app.schemas.address import IPAddressRead
from app.services import console_route
from app.services.permission import (
    can_use_ssh,
    get_object_permission,
    has_permission,
    visible_ids,
)
from app.services.ssh_tunnel import (
    LEGACY_SSH_ALGS,
    SSHHostKeyMismatch,
    _parse_pubkey_line,
    fetch_host_key,
    server_key_fingerprint_sha256,
)

router = APIRouter(prefix="/addresses", tags=["ssh"])

_TICKET_TTL = 60              # 秒；ticket 單次用、短壽
_CONNECT_TIMEOUT = 15.0       # SSH 連線逾時
#: guacd：等到第一個畫面（終端機畫好）才算連上
_CONNECT_TIMEOUT_GUACD = 30.0
_READ_CHUNK = 4096


def _ticket_key(ticket: str) -> str:
    return f"ssh:tk:{ticket}"



def _guac_font_pt(value: object) -> int:
    """guacd 終端機字級（pt）。沒給或不合法就用 12；夾在 6～32 之間。"""
    try:
        pt = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 12
    return max(6, min(32, pt))

@router.get("/ssh/targets", response_model=list[IPAddressRead])
async def list_ssh_targets(
    user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[IPAddressRead]:
    """列出所有已啟用 SSH 且目前使用者可連線的 IP（連線管理頁用）。

    與 can_use_ssh 一致的 deny-by-default：admin 全部；否則限可見子網路，
    再依「對該子網路有 write」或「具 can_ssh 能力且至少 read」逐筆放行。
    """
    stmt = select(IPAddress).where(IPAddress.ssh_enabled.is_(True))
    if not user.is_admin:
        vis = await visible_ids(session, user=user, object_type="subnet")
        if vis is not None:
            if not vis:
                return []
            stmt = stmt.where(in_values(IPAddress.subnet_id, vis))
    rows = (await session.execute(stmt)).scalars().all()

    # 逐 IP 過可連線（per-subnet 權限快取，避免重複查）
    perm_cache: dict[uuid.UUID, str] = {}
    kept: list[IPAddress] = []
    for ip in rows:
        if user.is_admin:
            kept.append(ip)
            continue
        lvl = perm_cache.get(ip.subnet_id)
        if lvl is None:
            lvl = await get_object_permission(
                session, user=user, object_type="subnet", object_id=ip.subnet_id
            )
            perm_cache[ip.subnet_id] = lvl
        if lvl == "none":
            continue
        if has_permission(lvl, "write") or user.can_ssh:
            kept.append(ip)

    # device 名稱批次帶上（清單顯示用）
    dev_ids = {ip.device_id for ip in kept if ip.device_id}
    dev_names: dict[uuid.UUID, str] = {}
    if dev_ids:
        drows = (await session.execute(
            select(Device.id, Device.name).where(in_values(Device.id, dev_ids))
        )).all()
        dev_names = {d[0]: d[1] for d in drows}

    from app.services.os_precedence import effective_os
    out: list[IPAddressRead] = []
    for ip in kept:
        r = IPAddressRead.model_validate(ip)
        r.ssh_available = True
        r.device_name = dev_names.get(ip.device_id) if ip.device_id else None
        # OS 與 IP 詳細資料頁一致：依來源優先序解析有效值
        _os = await effective_os(session, ip)
        r.os_guess = _os["os_guess"]; r.os_family = _os["os_family"]; r.os_source = _os["os_source"]
        out.append(r)
    return out


@router.post("/{address_id}/ssh/ticket")
async def issue_ssh_ticket(
    address_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """換發短期一次性 ticket；之後用它開 WebSocket。"""
    from app.core.rate_limit import limit_per_ip

    await limit_per_ip(request, name="ssh")

    ip = await session.get(IPAddress, address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="Address not found")
    if not await can_use_ssh(session, user=user, ip=ip):
        # A01：不洩漏存在性差異 — 一律 403
        raise HTTPException(status_code=403, detail=ui_detail("console_ssh_forbidden", "無 SSH 連線權限"))

    from app.services import console_engine
    # 選了 guacd、這台的 guacd 卻處理不了 SSH → 退回內建（asyncssh 一定在）
    engine = await console_engine.resolve(session, "ssh", fallbacks=[("builtin", True)])
    if engine == "guacd":
        from app.services import guacd as guac
        try:
            await guac.require("ssh")
        except guac.GuacdError as exc:
            raise HTTPException(status_code=503, detail=exc.ui()) from exc

    ticket = secrets.token_urlsafe(32)
    # 引擎寫進票證：WebSocket 照這個用，不自己再判斷（guacd 剛好起落時兩邊會講不同協定）
    payload = json.dumps({"user_id": str(user.id), "ip_id": str(ip.id), "engine": engine})
    await _redis_client().set(_ticket_key(ticket), payload, ex=_TICKET_TTL)

    return {
        "ticket": ticket,
        "ws_path": f"/api/v1/addresses/{ip.id}/ssh/ws",
        "host_key_pinned": bool(ip.ssh_host_key),
        "default_port": 22,
        "engine": engine,
        "ttl": _TICKET_TTL,
    }


async def _redeem_ticket(ticket: str, address_id: uuid.UUID) -> tuple[uuid.UUID | None, str | None]:
    """單次取出 ticket → (user_id, 發票證時決定的引擎)；舊票證沒有引擎欄位 → None（呼叫端照設定）。"""
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


async def _audit_ssh(
    *, actor_user_id: str, actor_ip: str | None, object_id: str,
    action: str, diff: dict[str, Any],
) -> None:
    """以獨立短交易寫一筆 SSH 稽核（不含任何憑證）。"""
    async with SessionLocal() as s:
        await append_audit(
            s,
            actor_user_id=actor_user_id,
            actor_ip=actor_ip,
            actor_user_agent=None,
            object_type="ip",
            object_id=object_id,
            action=action,
            diff=diff,
            request_id=None,
        )
        await s.commit()


async def _pin_host_key(address_id: uuid.UUID, known_host: str, *, actor_user_id: str, actor_ip: str | None) -> None:
    async with SessionLocal() as s:
        ip = await s.get(IPAddress, address_id)
        if ip is not None:
            ip.ssh_host_key = known_host
            await append_audit(
                s,
                actor_user_id=actor_user_id,
                actor_ip=actor_ip,
                actor_user_agent=None,
                object_type="ip",
                object_id=str(address_id),
                action="ssh.hostkey_pin",
                diff={"fingerprint": server_key_fingerprint_sha256(_parse_pubkey_line(known_host))},
                request_id=None,
            )
            await s.commit()


def _strict_client_factory(known_host: str) -> type[asyncssh.SSHClient]:
    """回傳一個會嚴格比對釘選 host key 的 SSHClient（不符 → SSHHostKeyMismatch）。"""
    expected_fp = server_key_fingerprint_sha256(_parse_pubkey_line(known_host))

    class _StrictClient(asyncssh.SSHClient):
        def validate_host_public_key(self, host, addr, port, key):  # type: ignore[no-untyped-def]
            actual = key.export_public_key("openssh").decode("ascii").split()
            actual_fp = server_key_fingerprint_sha256(_parse_pubkey_line(f"{actual[0]} {actual[1]}"))
            if actual_fp != expected_fp:
                raise SSHHostKeyMismatch(expected_fp, actual_fp)
            return True

    return _StrictClient


def _host_key_algs(known_host: str) -> list[str]:
    """釘選的金鑰類型 → 要求伺服器用的主機金鑰演算法（RSA 金鑰有三種簽章演算法）。"""
    key_type = known_host.split()[0]
    return ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"] if key_type == "ssh-rsa" else [key_type]


async def _pinned_key_still_matches(host: str, port: int, known_host: str) -> bool:
    """用釘選的那一種演算法向伺服器要主機金鑰，比對指紋。

    guacd 對主機金鑰不符只回一句「Aborted. See logs.」（原因只寫在它自己的日誌），
    使用者看到的會是「guacd 內部錯誤」—— 而這是可能遭中間人攻擊的警訊，一定要講清楚。
    所以交給 guacd 之前先自己比一次，訊息跟內建引擎一樣；guacd 那層照樣再比（縱深）。
    伺服器已經不提供這種演算法＝金鑰換了，一樣視為不符。連不上則往外丟（照一般連線錯誤處理）。
    """
    # ⚠️ 演算法一定要用 get_server_host_key 自己的參數傳：它的預設值會蓋掉 options 裡的設定，
    # 塞在 options 裡的話不管指定哪種都拿到伺服器偏好的那把 —— 正確的 ed25519 也會被判成不符
    # （2026-09-25 正式機實測；本機測試靶釘的剛好是 RSA，所以測不出來）
    opts = asyncssh.SSHClientConnectionOptions(**LEGACY_SSH_ALGS)
    try:
        async with asyncio.timeout(_CONNECT_TIMEOUT):
            key = await asyncssh.get_server_host_key(
                host, port=port, options=opts, server_host_key_algs=_host_key_algs(known_host))
    except asyncssh.KeyExchangeFailed:
        return False
    if key is None:
        return False
    actual = key.export_public_key("openssh").decode("ascii").split()
    return (server_key_fingerprint_sha256(_parse_pubkey_line(f"{actual[0]} {actual[1]}"))
            == server_key_fingerprint_sha256(_parse_pubkey_line(known_host)))


@router.websocket("/{address_id}/ssh/ws")
async def ssh_ws(websocket: WebSocket, address_id: uuid.UUID, ticket: str = "") -> None:
    # 1) 驗 ticket（單次取出）
    user_id, ticket_engine = await _redeem_ticket(ticket, address_id)
    if user_id is None:
        await websocket.close(code=4401)
        return

    # 2) 載入 user + ip，縱深重查權限
    async with SessionLocal() as s:
        user = await s.get(User, user_id)
        ip = await s.get(IPAddress, address_id)
        if user is None or not user.is_active or ip is None:
            await websocket.close(code=4403)
            return
        allowed = await can_use_ssh(s, user=user, ip=ip)
        host = str(ip.ip).split("/")[0]
        pinned = ip.ssh_host_key
        # 連線出口：直連或經由跳板（IP 覆寫 > 子網路 > 直連）
        route = await console_route.resolve_route(s, ip)
        from app.services.system_config import SSH_ENGINES, get_ssh_engine
        engine = ticket_engine if ticket_engine in SSH_ENGINES else await get_ssh_engine(s)
    if not allowed:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    actor_ip = websocket.client.host if websocket.client else None
    tunnel: console_route.Tunnel | None = None
    # guacd 連上之後這條 WebSocket 改講 Guacamole 協定：不可以再送 JSON
    guac_mode = False

    async def send(obj: dict[str, Any]) -> None:
        await websocket.send_text(json.dumps(obj))

    try:
        # 3) 收第一個設定訊息
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
        username = (cfg.get("username") or "").strip()
        port = int(cfg.get("port") or 22)
        auth = cfg.get("auth")
        cols = int(cfg.get("cols") or 80)
        rows = int(cfg.get("rows") or 24)
        credential_id = cfg.get("credential_id")
        if not (1 <= port <= 65535):
            await send({"type": "error", **ui_detail("console_bad_port", "連接埠須為 1–65535")})
            await websocket.close()
            return

        # 4) 認證憑證（明文只在記憶體存活，用完即丟；前端只持 credential_id reference）
        from app.api.v1.endpoints.ssh_credentials import cred_aad
        connect_kw: dict[str, Any] = {}
        used_cred_id: uuid.UUID | None = None
        if credential_id:
            # 以已存憑證連線：owner-only + 目標相符；明文不離後端
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
                used_cred_id = cred.id
                username = cred.username
                auth = cred.auth_type
                secrets_enc = dict(cred.secrets_enc or {})
            try:
                if auth == "password":
                    connect_kw["password"] = envelope_decrypt(secrets_enc["password"], aad=cred_aad(user_id, "password"))
                else:
                    pk = envelope_decrypt(secrets_enc["private_key"], aad=cred_aad(user_id, "private_key"))
                    pp = (envelope_decrypt(secrets_enc["passphrase"], aad=cred_aad(user_id, "passphrase"))
                          if "passphrase" in secrets_enc else None)
                    connect_kw["client_keys"] = [asyncssh.import_private_key(pk, passphrase=pp)]
                    connect_kw["preferred_auth"] = ("publickey",)
                    del pk, pp
            except Exception:
                await send({"type": "error",
                            **ui_detail("console_saved_credential_bad", "已存帳密解密／解析失敗")})
                await websocket.close()
                return
            # 標記最近使用
            async with SessionLocal() as s:
                c2 = await s.get(SSHCredential, used_cred_id)
                if c2 is not None:
                    c2.last_used_at = datetime.now(UTC)
                    await s.commit()
        else:
            if not username:
                await send({"type": "error", **ui_detail("console_no_username", "帳號必填")})
                await websocket.close()
                return
            if auth == "password":
                connect_kw["password"] = cfg.get("password") or ""
            elif auth == "key":
                try:
                    connect_kw["client_keys"] = [
                        asyncssh.import_private_key(
                            cfg.get("private_key") or "", passphrase=cfg.get("passphrase") or None
                        )
                    ]
                except Exception:  # 私鑰格式 / passphrase 錯
                    await send({"type": "error",
                                **ui_detail("console_private_key_bad",
                                            "私鑰無法解析（格式或密碼短語錯誤）")})
                    await websocket.close()
                    return
                connect_kw["preferred_auth"] = ("publickey",)
            else:
                await send({"type": "error", **ui_detail("console_auth_unsupported", "不支援的認證方式")})
                await websocket.close()
                return

        # 4b) 連線出口：經跳板時把目標換成本機轉發埠。
        # 一定要在 host key 步驟**之前**——`fetch_host_key` 也得走同一條路，
        # 否則會去釘到「後端直連看到的那台」的金鑰（可能根本是另一台機器）。
        try:
            tunnel = await console_route.open_route(route, host, port, user_id=user_id, purpose="ssh")
        except console_route.JumpHostError as exc:
            await send({"type": "error", **detail_of(exc, "jump_failed")})
            await websocket.close()
            return
        host, port = tunnel.host, tunnel.port
        if tunnel.via:
            await send({"type": "status", "state": "via_jump", "via": tunnel.via,
                        "via_kind": tunnel.via_kind})

        # 5) host key — TOFU：未釘選先取指紋給使用者確認再釘選
        known_host = pinned
        if not known_host:
            try:
                hk = await fetch_host_key(host, port=port)
            except Exception as exc:
                await send({"type": "error", **ui_detail("console_host_key_fetch_failed",
                                              f"無法連線取得主機金鑰：{exc}",
                                              reason=str(exc)[:200])})
                await websocket.close()
                return
            await send({"type": "hostkey", "fingerprint": hk["fingerprint"]})
            # 等人回答「要不要信任這把金鑰」也要有時限：要留時間讓人讀完再決定，
            # 但不能無限 —— 那等於把連線資源的釋放時機交給對方決定。
            try:
                ans = json.loads(await receive_text_within(
                    websocket, PROMPT_TIMEOUT, what="host_key"))
            except WsTimeout as exc:
                await send({"type": "error", **detail_of(exc, "console_host_key_timeout")})
                await websocket.close(code=4408)
                return
            if ans.get("type") != "hostkey_accept":
                await send({"type": "error", **ui_detail("console_host_key_rejected", "已取消（未信任主機金鑰）")})
                await websocket.close()
                return
            known_host = hk["known_host"]
            await _pin_host_key(address_id, known_host, actor_user_id=str(user_id), actor_ip=actor_ip)

        # 6) 連線（嚴格比對已釘選的 host key）
        await send({"type": "status", "state": "connecting"})
        if engine == "guacd":
            from app.services import guacd as guac
            try:
                key_ok = await _pinned_key_still_matches(host, port, known_host)
            except (TimeoutError, asyncssh.Error, OSError) as exc:
                await send({"type": "error", **ui_detail("console_connect_failed", f"連線失敗：{exc}",
                                              reason=str(exc)[:200])})
                await websocket.close()
                return
            if not key_ok:
                await send({"type": "error",
                            **ui_detail("console_host_key_mismatch",
                                        "主機金鑰與先前釘選不符，可能遭中間人攻擊（連線中止）")})
                await websocket.close()
                return
            # 帳密／私鑰只交給本機的 guacd，不經過瀏覽器；目標是通道的位址。
            # 主機金鑰：把上面釘選（或剛經使用者確認）的那一把交給 guacd 嚴格比對，
            # 安全性跟內建引擎一樣 —— 不符就中止，不會「先連再說」。
            params: dict[str, str] = {
                "hostname": host, "port": str(port), "username": username,
                "host-key": guac.known_hosts_line(host, port, known_host),
                "terminal-type": "xterm-256color", "font-name": "monospace",
                # 字級（pt）由前端帶（使用者調過會記住）；連線中可再用 argv 串流改，不必重連
                "font-size": str(_guac_font_pt(cfg.get("font_size"))),
                "scrollback": "2000", "server-alive-interval": "15",
                # 跟內建的 xterm.js 一樣可以複製、貼上
                "disable-copy": "false", "disable-paste": "false",
            }
            if "password" in connect_kw:
                params["password"] = connect_kw["password"]
            elif connect_kw.get("client_keys"):
                # 在這裡解開（密碼短語已用過），交給 guacd 的是不加密的 OpenSSH 格式：
                # libssh2 對各種私鑰格式與加密方式的支援不一，這樣最不會出意外
                params["private-key"] = connect_kw["client_keys"][0].export_private_key(
                    "openssh").decode("ascii")
            connect_kw.clear()
            width = max(320, min(3840, int(cfg.get("width") or 1024)))
            height = max(200, min(2160, int(cfg.get("height") or 640)))
            gconn = None
            try:
                try:
                    gconn = await guac.GuacdConnection.open()
                    await gconn.handshake("ssh", params, width=width, height=height,
                                          dpi=guac.client_dpi(cfg.get("dpi")),
                                          timezone=guac.client_timezone(cfg.get("timezone")))
                    params.clear()
                    initial = await gconn.wait_first_frame(_CONNECT_TIMEOUT_GUACD)
                except guac.GuacdError as exc:
                    await send({"type": "error", **exc.ui()})
                    await websocket.close()
                    return
                started = datetime.now(UTC)
                await _audit_ssh(
                    actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
                    action="ssh.session_open",
                    diff={"host": host, "port": port, "username": username, "auth": auth,
                          "via_jump_host": tunnel.via, "via_kind": tunnel.via_kind, "engine": "guacd",
                          "credential_id": str(used_cred_id) if used_cred_id else None},
                )
                await send({"type": "status", "state": "connected", "engine": "guacd",
                            "width": width, "height": height})
                guac_mode = True
                # 連線中只允許改字級（A−／A+），值是 6～32 的整數（pt）
                await guac.relay(websocket, gconn, initial=initial,
                                 argv_allow={"font-size": lambda v: v.isdigit() and 6 <= int(v) <= 32})
                dur = (datetime.now(UTC) - started).total_seconds()
                await _audit_ssh(
                    actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
                    action="ssh.session_close", diff={"host": host, "duration_seconds": round(dur, 1)},
                )
            finally:
                if gconn is not None:
                    await gconn.aclose()
                with contextlib.suppress(Exception):
                    await websocket.close()
            return
        try:
            async with asyncio.timeout(_CONNECT_TIMEOUT):
                conn = await asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    client_factory=_strict_client_factory(known_host),
                    known_hosts=None,
                    agent_path=None,
                    # keepalive：目標端靜默斷線（斷電/拔線）約 45s 內偵測 → bridge 結束 → 前端顯示已斷
                    keepalive_interval=15,
                    keepalive_count_max=3,
                    # 相容老裝置（老 switch / 防火牆只支援 CBC / sha1 / ssh-rsa）
                    **LEGACY_SSH_ALGS,
                    **connect_kw,
                )
        except SSHHostKeyMismatch:
            await send({"type": "error",
                        **ui_detail("console_host_key_mismatch",
                                    "主機金鑰與先前釘選不符，可能遭中間人攻擊（連線中止）")})
            await websocket.close()
            return
        except asyncssh.PermissionDenied:
            await send({"type": "error",
                        **ui_detail("console_auth_failed", "認證失敗（帳號／密碼／金鑰錯誤）")})
            await websocket.close()
            return
        except (TimeoutError, asyncssh.Error, OSError) as exc:
            await send({"type": "error", **ui_detail("console_connect_failed", f"連線失敗：{exc}",
                                          reason=str(exc)[:200])})
            await websocket.close()
            return

        # 7) 開互動 shell + 雙向橋接
        started = datetime.now(UTC)
        await _audit_ssh(
            actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
            action="ssh.session_open",
            diff={"host": host, "port": port, "username": username, "auth": auth,
                  "via_jump_host": tunnel.via, "via_kind": tunnel.via_kind,
                  "credential_id": str(used_cred_id) if used_cred_id else None},
        )
        async with conn:
            await send({"type": "status", "state": "connected"})
            async with conn.create_process(
                term_type="xterm-256color", term_size=(cols, rows),
                encoding="utf-8", errors="replace",
            ) as proc:
                await _bridge(websocket, proc, send)

        dur = (datetime.now(UTC) - started).total_seconds()
        await _audit_ssh(
            actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
            action="ssh.session_close", diff={"host": host, "duration_seconds": round(dur, 1)},
        )
        with contextlib.suppress(Exception):
            await send({"type": "status", "state": "disconnected"})
            await websocket.close()

    except WebSocketDisconnect:
        return
    except Exception:  # 任何未預期錯誤都不可洩漏堆疊給前端
        with contextlib.suppress(Exception):
            if not guac_mode:
                await send({"type": "error", **ui_detail("console_internal", "連線發生未預期錯誤")})
            await websocket.close()
    finally:
        # 通道與 WS session 同生共死：不論怎麼離開（正常結束、斷線、例外）都要還回去，
        # 否則跳板上會累積轉發，而同時連線數上限會慢慢把自己鎖死
        if tunnel is not None:
            await tunnel.aclose()


async def _bridge(websocket: WebSocket, proc: Any, send: Any) -> None:
    """雙向 pump：proc.stdout→ws、ws→proc.stdin / resize。任一端結束即收掉另一端。"""

    async def pump_out() -> None:
        # shell 輸出 → ws；任一端斷線/EOF 即結束（吞例外，避免未取回的 task 例外噪音）
        with contextlib.suppress(Exception):
            while True:
                data = await proc.stdout.read(_READ_CHUNK)
                if not data:
                    break
                await send({"type": "data", "data": data})

    async def pump_in() -> None:
        with contextlib.suppress(WebSocketDisconnect, Exception):
            while True:
                # 不做應用層 idle-timeout：背景分頁的 setInterval heartbeat 會被瀏覽器節流、
                # 誤判斷線。連線保活改靠 WS 傳輸層（uvicorn ws-ping/pong；瀏覽器即使在背景分頁
                # 也會回應 protocol ping）；真正斷線由 WebSocketDisconnect 偵測，dead peer 由
                # uvicorn ws-ping 逾時關閉 → 一樣走 WebSocketDisconnect 收尾（不留 orphan）。
                raw = await websocket.receive_text()
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "data":
                    proc.stdin.write(msg.get("data", ""))
                elif t == "resize":
                    proc.change_terminal_size(int(msg.get("cols", 80)), int(msg.get("rows", 24)))
                elif t == "ping":
                    await send({"type": "pong"})
                elif t == "close":
                    break

    out_task = asyncio.create_task(pump_out())
    in_task = asyncio.create_task(pump_in())
    _done, pending = await asyncio.wait({out_task, in_task}, return_when=asyncio.FIRST_COMPLETED)
    for p in pending:
        p.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
