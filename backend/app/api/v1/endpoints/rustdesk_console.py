"""相容 RustDesk 的網頁連線：票證換發＋WebSocket（瀏覽器 ↔ 後端 ↔ hbbr）。

依據 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md（乾淨室實作）。分工（第 1 節）：
- 瀏覽器：protobuf、安全握手、加解密、登入、解碼畫面、鍵盤滑鼠。**密碼與金鑰只在瀏覽器**
- 後端（這裡）：票證、權限、稽核、限流；連 hbbs 做會合、連 hbbr 做中繼，之後只轉送密文

安全（比照其他主控台）：
- A01：票證與 WS 兩處都重查 `can_use_rustdesk`（IP 要開 rustdesk_enabled）＋伺服器開放網頁連線＋
  受控端仍對應到這個 IP；票證 30 秒、單次（take_once，不用 GETDEL）、綁使用者×IP×伺服器×受控端 ID
- A10：只連這台 RustDesk 伺服器設定的 hbbs／hbbr 位址（連線當下套用出站規則），不接受瀏覽器指定位址
- A09：每次連線開始、結束都寫稽核（瀏覽器回報的登入結果標明來源）；不記密碼、金鑰、畫面
- 7.8：受控端以 jt-ipam 後端的 IP 計算錯誤次數（所有使用者共用），後端要自己先擋

瀏覽器 ↔ 後端的外層（2.3，jt-ipam 自己的設計）：一則 binary＝一則 RustDesk 訊息；text 放控制 JSON `{"t": …}`。

記住密碼（附錄 D）：已存的密碼放在連線帳密金庫（protocol=rustdesk）。瀏覽器只持有 credential_id，
收到受控端的 Hash 後送 `login_assist`（salt、challenge），後端解密、算出這一次連線的 h2 回給瀏覽器；
**密碼明文與 h1 都不離開後端**（h1 對同一台受控端等同密碼）。

檔案傳輸（附錄 J.6）：另外一條連線，票證帶 `kind = "file"`，要伺服器設定「允許網頁檔案傳輸」打開（預設關），
權限照舊是 can_use_rustdesk。後端照舊只轉送密文、看不到檔案內容；瀏覽器把每個動作的摘要另外送來
（`{"t": "file_audit", "op", "path", "size", "result"}`），後端驗過格式、限流後寫稽核 `rustdesk.file_<op>`，
並標明是瀏覽器自報的。登入時的 union file_transfer 在密文裡，後端看不到也擋不了：開關管的是「發不發檔案傳輸的
票證、畫面給不給入口」，能開遠端桌面的人本來就能操作那台電腦。

請求提權（附錄 K.2）：Windows 免安裝受控端的提權（Misc.elevation_request）在密文裡，後端看不到請求也看不到回覆。
提權是對受控端取得系統管理員權限，所以瀏覽器在送出請求時、以及得到結果時，各送一則摘要（沿用 file_audit 的作法，
這次在一般遠端桌面連線上）：`{"t": "elevation_audit", "method", "result", "detail"}`。後端只取這四個欄位
（瀏覽器多帶帳號密碼也不會進稽核）、method／result 不在清單內就丟掉，寫稽核 `rustdesk.elevation_request`
並標明是瀏覽器自報的；檔案傳輸的連線上收到不處理。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.audit import append_audit
from app.core.config import get_settings
from app.core.db import SessionLocal, get_session
from app.core.rate_limit import _redis_client
from app.core.security import envelope_decrypt
from app.core.tickets import take_once
from app.core.ui_error import ui_detail
from app.models.address import IPAddress
from app.models.rustdesk import RustDeskServer
from app.models.ssh_credential import SSHCredential
from app.models.user import User
from app.schemas.rustdesk import RustDeskTicketIn
from app.services import rustdesk as rustdesk_svc
from app.services import rustdesk_web
from app.services import rustdesk_web_proto as proto
from app.services.permission import can_use_rustdesk

router = APIRouter(prefix="/addresses", tags=["rustdesk-web"])

_log = logging.getLogger("jt-ipam.rustdesk-web")

_TICKET_TTL = 30                 # 14：30 秒內有效、只能用一次
_IDLE_SECONDS = 120.0            # 兩個方向都沒有資料就收（受控端每秒送 TestDelay，正常連線不會閒置）
_TEXT_MAX = 4096                 # 瀏覽器送的控制 JSON 上限
_INBOX_MAX = 64                  # 瀏覽器 → 受控端的佇列：滿了就不再讀瀏覽器（背壓）
_LOGIN_RESULTS_KEPT = 20         # 稽核裡留幾筆瀏覽器回報的登入結果
#: 附錄 D.3：每條連線最多處理幾次 login_assist（不讓這條連線變成「幫忙算 h2」的服務）
_LOGIN_ASSIST_MAX = 3
#: 附錄 D.3：salt、challenge 是 1～64 個字元的可列印 ASCII（實測都是 6 個英數字，7.1）
_HASH_FIELD = re.compile(r"[\x20-\x7e]{1,64}")

#: 登入前，瀏覽器送出的密文長度到這個值以上就當成一次登入嘗試（後端看不到內容，只能看大小）。
#: 依據規格的訊息定義：LoginRequest 至少帶受控端 ID 與 32 bytes 的密碼雜湊，加上 MAC 遠超過 60 bytes；
#: TestDelay 必須原封不動送回（8.6），最多四個數值欄位，加 MAC 不到 40 bytes。第一則是明文的 PublicKey，不算。
_LOGIN_ATTEMPT_MIN_BYTES = 60

#: 附錄 J.6：file_audit 的 op 只收這幾種（稽核動作是 rustdesk.file_<op>）、result 只收這幾種
_FILE_OPS = frozenset({"download", "upload", "delete", "rename", "mkdir"})
_FILE_RESULTS = frozenset({"ok", "error", "cancelled"})
#: 路徑截到 512 個字元（J.6）
_FILE_PATH_MAX = 512
#: size 的上限（PostgreSQL bigint）
_FILE_SIZE_MAX = 2**63 - 1
#: 每條連線的瀏覽器自報稽核（file_audit、elevation_audit）限流（權杖桶）：一次最多 30 則，之後每秒補 2 則；
#: 超過的丟掉並記數量
_AUDIT_BURST = 30.0
_AUDIT_PER_SECOND = 2.0
#: 控制字元拿掉（PostgreSQL 的 JSONB 存不了 \u0000；其他的也只會讓稽核難讀）
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_FILE_AUDIT_NOTE = "reported by the browser (the backend relays ciphertext only and cannot verify it)"

#: 附錄 K.2：elevation_audit 的 method、result 只收這幾種（稽核動作是 rustdesk.elevation_request）
_ELEVATION_METHODS = frozenset({"direct", "logon"})
_ELEVATION_RESULTS = frozenset({"requested", "ok", "error", "timeout"})
#: detail（受控端的錯誤原文）截到 200 個字元
_ELEVATION_DETAIL_MAX = 200
_ELEVATION_AUDIT_NOTE = _FILE_AUDIT_NOTE

# 同時連線數（本行程內；與其他主控台一致）
_active_total = 0
_active_by_user: dict[str, int] = {}


def _ticket_key(ticket: str) -> str:
    return f"rdweb:tk:{ticket}"


def _my_name(user: User) -> str:
    """7.3：讓受控端看得出是誰（會顯示在對方的連線視窗與它的稽核裡）。"""
    return f"{user.username} (jt-ipam)"


@router.post("/{address_id}/rustdesk/ticket")
async def issue_rustdesk_ticket(
    address_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    payload: RustDeskTicketIn | None = None,
) -> dict[str, Any]:
    """換發 30 秒、單次有效的票證；之後用它開 WebSocket。

    body 的 kind：desktop（預設，沒有 body 也是）或 file（檔案傳輸，附錄 J.6：伺服器設定「允許網頁檔案傳輸」
    沒開就拒絕；權限與遠端桌面相同）。"""
    from app.core.rate_limit import limit_per_ip

    kind = payload.kind if payload is not None else "desktop"
    await limit_per_ip(request, name="rustdesk")
    ip = await session.get(IPAddress, address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="Address not found")
    if not await can_use_rustdesk(session, user=user, ip=ip):
        raise HTTPException(status_code=403, detail=ui_detail(
            "rd_not_permitted", "沒有權限，或這個 IP 沒有開啟 RustDesk 連線"))
    row = await rustdesk_svc.matched_peer(session, ip.id)
    if row is None:
        raise HTTPException(status_code=404, detail=ui_detail("rd_no_peer", "這個 IP 沒有對應到 RustDesk 裝置"))
    peer, srv = row
    problem = rustdesk_svc.web_problem(srv)
    if problem:
        raise HTTPException(status_code=409, detail=ui_detail(problem, "這台 RustDesk 伺服器沒有開放網頁連線",
                                                              server=srv.name))
    if kind == "file" and rustdesk_svc.file_problem(srv):
        raise HTTPException(status_code=409, detail=ui_detail(
            "rd_file_disabled", "這台 RustDesk 伺服器沒有開放網頁檔案傳輸", server=srv.name))
    if await rustdesk_web.is_blocked(_redis_client(), user.id, srv.id, peer.rustdesk_id):
        raise HTTPException(status_code=429, detail=ui_detail(
            "rd_rate_limited", "登入失敗次數太多，請稍後再試"))
    # 附錄 D.5：這個人在這個 IP 有沒有記住的 RustDesk 密碼（比照 VNC 票證的 has_saved_creds；
    # RustDesk 的一律綁定 IP，沒有個人預設）
    saved = (await session.execute(
        select(SSHCredential.id).where(
            SSHCredential.owner_user_id == user.id,
            SSHCredential.protocol == "rustdesk",
            SSHCredential.target_ip_id == ip.id,
        ).limit(1)
    )).first()

    ticket = secrets.token_urlsafe(32)
    data = json.dumps({"user_id": str(user.id), "ip_id": str(ip.id), "server_id": str(srv.id),
                       "peer_id": peer.rustdesk_id, "kind": kind})
    await _redis_client().set(_ticket_key(ticket), data, ex=_TICKET_TTL)
    extra: dict[str, Any] = {"file_limits": rustdesk_svc.file_limits(srv)} if kind == "file" else {}
    return {
        "ticket": ticket,
        "kind": kind,
        **extra,
        "ws_path": f"/api/v1/addresses/{ip.id}/rustdesk/ws",
        "peer_id": peer.rustdesk_id,
        "server_name": srv.name,
        "my_name": _my_name(user),
        "transport": srv.transport,
        "has_saved_password": saved is not None,
        "ttl": _TICKET_TTL,
    }


async def _redeem(ticket: str, address_id: uuid.UUID) -> dict[str, str] | None:
    if not ticket or len(ticket) > 128:
        return None
    raw = await take_once(_redis_client(), _ticket_key(ticket))
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if data.get("ip_id") != str(address_id):
            return None
        uuid.UUID(data["user_id"])
        uuid.UUID(data["server_id"])
        kind = data.get("kind") or "desktop"
        if kind not in ("desktop", "file"):
            return None
        return {**{k: str(data[k]) for k in ("user_id", "ip_id", "server_id", "peer_id")}, "kind": kind}
    except (ValueError, KeyError, TypeError):
        return None


async def _audit(*, user_id: str, actor_ip: str | None, user_agent: str | None, ip_id: str,
                 action: str, diff: dict[str, Any]) -> None:
    async with SessionLocal() as s:
        await append_audit(s, actor_user_id=user_id, actor_ip=actor_ip, actor_user_agent=user_agent,
                           object_type="ip", object_id=ip_id, action=action, diff=diff, request_id=None)
        await s.commit()


class _RateLimited(Exception):
    pass


class _PeerKeyRefused(Exception):
    """中繼等不到受控端，而 RustDesk 代理從 hbbr 日誌看到這段時間它因為 Key 被拒（受控端的 Key 設錯）。"""

    def __init__(self, at: datetime) -> None:
        super().__init__(at.isoformat())
        self.at = at


@dataclass
class _State:
    """一條網頁連線的狀態（稽核與限流用；不含任何密碼、金鑰或畫面內容）。"""

    user_id: str
    server_id: str
    peer_id: str
    ip_id: str = ""
    actor_ip: str | None = None
    user_agent: str | None = None
    started: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    paired: bool = False
    logged_in: bool = False
    up_messages: int = 0
    unanswered_attempts: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    login_results: list[dict[str, Any]] = field(default_factory=list)
    login_assists: int = 0               # 附錄 D.3：已處理幾次 login_assist
    saved_password_used: bool = False    # 這條連線用過已存的密碼（稽核用）
    relay_server: str = ""
    relay_address: str = ""
    via_request_relay: bool = False
    restarted: bool = False
    kind: str = "desktop"                # desktop／file（附錄 J.6）
    file_audits: int = 0                 # 寫進稽核的 file_audit 則數
    file_audits_dropped: int = 0         # 被限流或格式不對而丟掉的
    elevation_audits: int = 0            # 寫進稽核的 elevation_audit 則數（附錄 K.2）
    elevation_audits_dropped: int = 0    # 被限流或格式不對而丟掉的
    audit_tokens: float = _AUDIT_BURST
    audit_tokens_at: float = field(default_factory=time.monotonic)


@router.websocket("/{address_id}/rustdesk/ws")
async def rustdesk_ws(websocket: WebSocket, address_id: uuid.UUID, ticket: str = "") -> None:
    global _active_total

    # 先接受再驗：失敗時瀏覽器才收得到錯誤代碼（只回錯誤就關，不洩漏任何資料）
    await websocket.accept()
    actor_ip = websocket.client.host if websocket.client else None
    user_agent = (websocket.headers.get("user-agent") or "")[:300] or None

    async def send_json(obj: dict[str, Any]) -> None:
        await websocket.send_text(json.dumps(obj, ensure_ascii=False))

    async def fail(code: str, detail: str = "", *, close_code: int = 1000, **params: Any) -> None:
        with contextlib.suppress(Exception):
            await send_json({"t": "error", "code": code, "detail": detail, "params": params})
        with contextlib.suppress(Exception):
            await websocket.close(code=close_code)

    # 1) 票證（單次取出、綁定這個 IP）
    data = await _redeem(ticket, address_id)
    if data is None:
        await fail("rd_ticket_invalid", close_code=4401)
        return
    user_id, server_id, peer_id = data["user_id"], data["server_id"], data["peer_id"]
    kind = data["kind"]

    # 2) 縱深重查：使用者、權限、伺服器設定、受控端仍對應到這個 IP
    async with SessionLocal() as s:
        user = await s.get(User, uuid.UUID(user_id))
        ip = await s.get(IPAddress, address_id)
        allowed = bool(user is not None and user.is_active and ip is not None
                       and await can_use_rustdesk(s, user=user, ip=ip))
        row = await rustdesk_svc.matched_peer(s, address_id) if allowed else None
        if row is None or str(row[1].id) != server_id or row[0].rustdesk_id != peer_id:
            allowed = False
        srv: RustDeskServer | None = row[1] if row else None
        problem = rustdesk_svc.web_problem(srv) if srv is not None else None
        if problem is None and srv is not None and kind == "file":
            problem = rustdesk_svc.file_problem(srv)      # 附錄 J.6：拿到票證之後被關掉也不行
        hbbs = rustdesk_web.hbbs_endpoint(srv) if srv is not None else None
        relay = rustdesk_web.relay_endpoint(srv) if srv is not None else None
        licence_key = (srv.public_key or "") if srv is not None else ""
        transport = srv.transport if srv is not None and srv.transport in rustdesk_web.PORTS else "tcp"
        server_name = srv.name if srv is not None else ""
    if not allowed:
        await fail("rd_not_permitted", close_code=4403)
        return
    if problem or hbbs is None or relay is None:
        await fail(problem or "rd_web_no_address", server=server_name)
        return
    redis = _redis_client()
    if await rustdesk_web.is_blocked(redis, user_id, server_id, peer_id):
        await fail("rd_rate_limited")
        return

    # 3) 資源上限
    settings = get_settings()
    cap_total = settings.rustdesk_web_max_sessions
    cap_user = settings.rustdesk_web_max_sessions_per_user
    if (cap_total and _active_total >= cap_total) or (cap_user and _active_by_user.get(user_id, 0) >= cap_user):
        await fail("rd_too_many", max=cap_user if cap_user and _active_by_user.get(user_id, 0) >= cap_user
                   else cap_total)
        return
    _active_total += 1
    _active_by_user[user_id] = _active_by_user.get(user_id, 0) + 1

    st = _State(user_id=user_id, server_id=server_id, peer_id=peer_id, ip_id=str(address_id),
                actor_ip=actor_ip, user_agent=user_agent, kind=kind)
    started_at = datetime.now(UTC)
    base = {"peer_id": peer_id, "server_id": server_id, "server_name": server_name, "transport": transport,
            "hbbs_address": hbbs.label(), "kind": kind}
    end_reason = "unknown"
    error_detail = ""
    channel: rustdesk_web.Channel | None = None
    reader_task: asyncio.Task[None] | None = None
    _log.info("rustdesk-web: 開始 peer=%s server=%s user=%s transport=%s kind=%s", peer_id, server_name, user_id,
              transport, kind)
    try:
        await _audit(user_id=user_id, actor_ip=actor_ip, user_agent=user_agent, ip_id=str(address_id),
                     action="rustdesk.web_session_open", diff=base)

        # 瀏覽器那一端只有一個讀取者，從頭到尾把訊息放進有上限的佇列（滿了就不讀＝背壓）
        inbox: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=_INBOX_MAX)
        reader_task = asyncio.create_task(_read_browser(websocket, inbox))

        # 4) 會合與中繼。期間瀏覽器關掉就立刻放棄（不要佔著 hbbs／hbbr 到逾時）
        async def attempt(wait: float | None) -> tuple[rustdesk_web.Channel, bytes, rustdesk_web.Rendezvous]:
            await send_json({"t": "stage", "stage": "rendezvous"})
            rv = await rustdesk_web.rendezvous(hbbs, transport, peer_id, licence_key)
            st.relay_server = rv.relay_server
            st.via_request_relay = rv.via_request_relay
            # 6.1：hbbs 簽章過的受控端身分。瀏覽器也會驗；後端先驗，不過就不佔用中繼
            proto.verify_signed_id_pk(rv.pk, licence_key, peer_id)
            await send_json({"t": "stage", "stage": "relay"})
            st.relay_address = relay.label()
            ch, first = await rustdesk_web.open_relay(relay, transport, peer_id, rv.uuid, licence_key, wait=wait)
            return ch, first, rv

        async def key_refused() -> datetime | None:
            # 受控端的 Key 設錯時 hbbr 直接拒絕它，這邊只看得到逾時；RustDesk 代理每 10 秒把 hbbr 日誌裡
            # 被拒的 IP 送上來（只記在那個 IP 唯一的裝置上）。往前多留幾秒：代理與這台的時鐘不會完全一致
            async with SessionLocal() as ks:
                return await rustdesk_svc.key_refused_since(ks, uuid.UUID(server_id), peer_id,
                                                            started_at - timedelta(seconds=5))

        async def setup() -> tuple[rustdesk_web.Channel, bytes, rustdesk_web.Rendezvous]:
            try:
                return await attempt(rustdesk_web.RESTART_AFTER)
            except rustdesk_web.RdWebError as exc:
                if exc.code != "rd_relay_timeout":
                    raise
                refused_at = await key_refused()
                if refused_at is not None:      # 已經知道是對方 Key 錯，重來也一樣
                    raise _PeerKeyRefused(refused_at) from exc
            # 附錄 C-3：等不到第一則＝同時到達的競態裡對方那條被蓋掉了。從會合重來一次（新 uuid），只重來一次
            st.restarted = True
            _log.info("rustdesk-web: %s 秒沒有配對，從會合重來一次 peer=%s", rustdesk_web.RESTART_AFTER, peer_id)
            return await attempt(None)

        setup_task = asyncio.create_task(setup())
        waiter = asyncio.create_task(_wait_browser_close(
            inbox, lambda obj: _login_assist(send_json, st, obj)))
        done, _pending = await asyncio.wait({setup_task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        if setup_task not in done:
            setup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                ch_partial = await setup_task
                await ch_partial[0].close()       # 剛好在取消前完成：連上的中繼也要收掉
            end_reason = waiter.result()
            return
        waiter.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await waiter
        channel, first, rv = setup_task.result()        # 例外在這裡丟出來，由下面分類
        st.paired = True
        await send_json({"t": "stage", "stage": "paired"})
        await send_json({"t": "ready", "signed_id_pk": base64.b64encode(rv.pk).decode("ascii"),
                         "server_key": licence_key, "peer_id": peer_id, "transport": transport})
        await websocket.send_bytes(first)
        st.bytes_down += len(first)
        _log.info("rustdesk-web: 已配對 peer=%s relay=%s via_request_relay=%s",
                  peer_id, st.relay_address, st.via_request_relay)

        # 5) 轉送
        end_reason = await _pump(websocket, channel, inbox, st, redis, send_json)
        if end_reason == "peer_closed":
            with contextlib.suppress(Exception):
                await send_json({"t": "close", "reason": "peer_closed"})
    except _PeerKeyRefused as exc:
        end_reason, error_detail = "rd_peer_key_mismatch", st.relay_address
        _log.info("rustdesk-web: 失敗 peer=%s code=%s（hbbr 日誌：Key 不符被拒 %s）", peer_id, end_reason, exc.at)
        await fail(end_reason, error_detail, at=exc.at.isoformat())
    except rustdesk_web.RdWebError as exc:
        end_reason, error_detail = exc.code or "rd_handshake_failed", exc.detail
        refused_at = await key_refused() if end_reason == "rd_relay_timeout" else None
        if refused_at is not None:
            end_reason = "rd_peer_key_mismatch"
            _log.info("rustdesk-web: 失敗 peer=%s code=%s（hbbr 日誌：Key 不符被拒 %s）", peer_id, end_reason,
                      refused_at)
            await fail(end_reason, error_detail, at=refused_at.isoformat())
        else:
            _log.info("rustdesk-web: 失敗 peer=%s code=%s detail=%s", peer_id, end_reason, error_detail)
            await fail(end_reason, error_detail)
    except proto.HandshakeError as exc:
        # 原因只進稽核與日誌：翻譯已經說清楚了，後端的中文句子接在英文／日文畫面後面只會礙眼
        end_reason, error_detail = exc.code, str(exc)
        _log.info("rustdesk-web: 身分驗證失敗 peer=%s code=%s", peer_id, exc.code)
        await fail(exc.code)
    except _RateLimited as exc:
        end_reason, error_detail = "rd_rate_limited", str(exc)
        _log.info("rustdesk-web: 限流 peer=%s user=%s：%s", peer_id, user_id, exc)
        await fail("rd_rate_limited")
    except Exception:
        end_reason = "internal_error"
        _log.exception("rustdesk-web: 未預期錯誤 peer=%s", peer_id)
        await fail("rd_internal")
    finally:
        if channel is not None:
            await channel.close()
        if reader_task is not None:
            reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader_task
        _active_total -= 1
        n = _active_by_user.get(user_id, 1) - 1
        if n > 0:
            _active_by_user[user_id] = n
        else:
            _active_by_user.pop(user_id, None)
        duration = round(time.monotonic() - st.started, 1)
        with contextlib.suppress(Exception):
            await _audit(user_id=user_id, actor_ip=actor_ip, user_agent=user_agent, ip_id=str(address_id),
                         action="rustdesk.web_session_close", diff={
                             **base, "end_reason": end_reason, "error_detail": error_detail or None,
                             "started_at": started_at.isoformat(), "ended_at": datetime.now(UTC).isoformat(),
                             "duration_seconds": duration, "paired": st.paired,
                             "relay_server": st.relay_server or None, "relay_address": st.relay_address or None,
                             "via_request_relay": st.via_request_relay, "restarted": st.restarted,
                             "login_results": st.login_results, "login_results_source": "browser",
                             "saved_password_used": st.saved_password_used,
                             "bytes_up": st.bytes_up, "bytes_down": st.bytes_down,
                             **({"file_audits": st.file_audits, "file_audits_dropped": st.file_audits_dropped,
                                 "file_audits_source": "browser"} if st.kind == "file" else {}),
                             # 附錄 K.2：有提權的稽核才記數量（絕大多數連線沒有，不多出欄位）
                             **({"elevation_audits": st.elevation_audits,
                                 "elevation_audits_dropped": st.elevation_audits_dropped,
                                 "elevation_audits_source": "browser"}
                                if st.elevation_audits or st.elevation_audits_dropped else {})})
        _log.info("rustdesk-web: 結束 peer=%s reason=%s duration=%ss", peer_id, end_reason, duration)
        with contextlib.suppress(Exception):
            await websocket.close()


async def _read_browser(websocket: WebSocket, inbox: asyncio.Queue[tuple[str, Any]]) -> None:
    """瀏覽器 → 佇列。binary 原樣；text 解析成 dict（太長、不是物件的丟掉）；斷線放 ("closed", 原因)。"""
    try:
        while True:
            m = await websocket.receive()
            if m.get("type") == "websocket.disconnect":
                await inbox.put(("closed", "browser_disconnected"))
                return
            b = m.get("bytes")
            if b is not None:
                if len(b) > proto.MAX_MESSAGE:
                    await inbox.put(("closed", "rd_message_too_large"))
                    return
                await inbox.put(("bin", b))
                continue
            t = m.get("text")
            if t is not None and len(t) <= _TEXT_MAX:
                with contextlib.suppress(ValueError):
                    obj = json.loads(t)
                    if isinstance(obj, dict):
                        await inbox.put(("text", obj))
    except Exception:
        with contextlib.suppress(Exception):
            inbox.put_nowait(("closed", "browser_disconnected"))


async def _wait_browser_close(inbox: asyncio.Queue[tuple[str, Any]],
                              on_assist: Callable[[dict[str, Any]], Awaitable[None]] | None = None) -> str:
    """會合／配對期間：瀏覽器關掉或送 close 就結束；其他東西（配對前不該送）丟掉。

    login_assist 例外：要有回覆（附錄 D.3：失敗也回、不關連線），交給 on_assist（它會因為還沒配對而回失敗）。
    """
    while True:
        kind, val = await inbox.get()
        if kind == "closed":
            return str(val)
        if kind == "text" and val.get("t") == "close":
            return "browser_close"
        if kind == "text" and val.get("t") == "login_assist" and on_assist is not None:
            await on_assist(val)


async def _pump(websocket: WebSocket, ch: rustdesk_web.Channel, inbox: asyncio.Queue[tuple[str, Any]],
                st: _State, redis: Any, send_json: Callable[[dict[str, Any]], Awaitable[None]]) -> str:
    """雙向轉送，回傳結束原因。每個方向都是「讀一則、寫完再讀下一則」，寫不出去就停讀（背壓）。"""

    async def down() -> str:
        while True:
            try:
                data = await ch.recv()
            except rustdesk_web.ChannelClosed:
                return "peer_closed"
            st.last_activity = time.monotonic()
            st.bytes_down += len(data)
            try:
                await websocket.send_bytes(data)      # 寫不出去就停在這裡，不再讀中繼（背壓）
            except Exception:
                return "browser_disconnected"         # 瀏覽器已經走了，不是錯誤

    async def up() -> str:
        while True:
            kind, val = await inbox.get()
            if kind == "closed":
                return str(val)
            if kind == "bin":
                st.last_activity = time.monotonic()
                st.bytes_up += len(val)
                await _count_login_attempt(st, val, redis)
                try:
                    await ch.send(val)
                except rustdesk_web.ChannelClosed:
                    return "peer_closed"
                continue
            t = val.get("t")
            if t == "close":
                return "browser_close"
            if t == "login_result":
                await _login_result(st, val, redis)
            elif t == "login_assist":
                await _login_assist(send_json, st, val)
            elif t == "file_audit":
                await _file_audit(st, val)
            elif t == "elevation_audit":
                await _elevation_audit(st, val)

    async def idle() -> str:
        while True:
            await asyncio.sleep(5)
            if time.monotonic() - st.last_activity > _IDLE_SECONDS:
                return "idle"

    tasks = [asyncio.create_task(down()), asyncio.create_task(up()), asyncio.create_task(idle())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        task = next(iter(done))
        return task.result()          # _RateLimited／RdWebError 從這裡往外丟
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _count_login_attempt(st: _State, data: bytes, redis: Any) -> None:
    """登入前的密文：大小像登入請求的就記一次「還沒回報結果的嘗試」。

    規格 2.3：瀏覽器回報的 login_result 不可信。誠實的瀏覽器每送一次登入請求都會回報一次結果，
    所以「還沒回報」的嘗試最多 1 次；累積到 2 次＝不回報卻一直試，記一次失敗並切斷。
    """
    st.up_messages += 1
    if st.logged_in or st.up_messages == 1 or len(data) < _LOGIN_ATTEMPT_MIN_BYTES:
        return
    st.unanswered_attempts += 1
    if st.unanswered_attempts >= 2:
        await rustdesk_web.record_failure(redis, st.user_id, st.server_id, st.peer_id, "password")
        raise _RateLimited("unreported login attempts")


async def _login_result(st: _State, obj: dict[str, Any], redis: Any) -> None:
    """瀏覽器解密後看到的登入結果（只當參考，見 2.3、14）：寫進稽核、計入 7.8 的失敗次數。"""
    ok = bool(obj.get("ok"))
    err = str(obj.get("error") or "")[:200]
    if len(st.login_results) < _LOGIN_RESULTS_KEPT:
        st.login_results.append({"ok": ok, "error": err, "at": datetime.now(UTC).isoformat()})
    st.unanswered_attempts = max(0, st.unanswered_attempts - 1)
    if ok:
        st.logged_in = True
        return
    kind = rustdesk_web.failure_kind(err)
    if kind and await rustdesk_web.record_failure(redis, st.user_id, st.server_id, st.peer_id, kind):
        raise _RateLimited(f"too many failures ({kind})")


class _AssistRefused(Exception):
    """login_assist 不通過：code 回給瀏覽器（errors.<code>），why 只進日誌。"""

    def __init__(self, *, code: str, why: str) -> None:
        super().__init__(why)
        self.code = code
        self.why = why


async def _login_assist(send_json: Callable[[dict[str, Any]], Awaitable[None]], st: _State,
                        obj: dict[str, Any]) -> None:
    """附錄 D.3：用已存的密碼算這一次連線的 h2。依序檢查，任何一項不過就回失敗（不關連線，瀏覽器改請使用者輸入）。

    回覆只有 h2（只對這次的 challenge 有效）；密碼明文與 h1 不回、不記、不進日誌與稽核。
    失敗的原因只進日誌（代碼刻意不分「不是你的／別的 IP／別的用途／不存在」，不洩漏別人的憑證是否存在）。
    """
    try:
        h2 = await _saved_password_h2(st, obj)
    except _AssistRefused as exc:
        _log.info("rustdesk-web: login_assist 不通過 peer=%s user=%s：%s", st.peer_id, st.user_id, exc.why)
        with contextlib.suppress(Exception):
            await send_json({"t": "login_assist", "ok": False, "code": exc.code})
        return
    except Exception:
        # 資料庫等意外：一樣只回失敗、不切斷連線（瀏覽器改請使用者輸入密碼）
        _log.exception("rustdesk-web: login_assist 未預期錯誤 peer=%s", st.peer_id)
        with contextlib.suppress(Exception):
            await send_json({"t": "login_assist", "ok": False, "code": "rd_saved_password_unavailable"})
        return
    st.saved_password_used = True
    with contextlib.suppress(Exception):      # 瀏覽器剛好走了：讀取那一端會收到斷線，這裡不必處理
        await send_json({"t": "login_assist", "ok": True, "hash": base64.b64encode(h2).decode("ascii")})


async def _saved_password_h2(st: _State, obj: dict[str, Any]) -> bytes:
    """附錄 D.3 的五項檢查（依序），全部通過才解密、算 h2、更新 last_used_at、寫稽核。"""
    # 1) 已經配對、還沒登入成功
    if not st.paired:
        raise _AssistRefused(code="rd_saved_password_unavailable", why="not paired")
    if st.logged_in:
        raise _AssistRefused(code="rd_saved_password_unavailable", why="already logged in")
    # 2) 每條連線最多 3 次
    st.login_assists += 1
    if st.login_assists > _LOGIN_ASSIST_MAX:
        raise _AssistRefused(code="rd_login_assist_limit", why=f"over {_LOGIN_ASSIST_MAX} per connection")
    # 3) salt、challenge：1～64 個字元的可列印 ASCII
    salt, challenge = obj.get("salt"), obj.get("challenge")
    if not (isinstance(salt, str) and _HASH_FIELD.fullmatch(salt)
            and isinstance(challenge, str) and _HASH_FIELD.fullmatch(challenge)):
        raise _AssistRefused(code="rd_saved_password_unavailable", why="bad salt or challenge")
    # 4) 憑證：存在、用途是 rustdesk、是這個人的、綁的是這條連線的 IP。
    #    權限（can_use_rustdesk）沿用這條連線建立時的檢查結果（附錄 D.3 第 4 項）
    try:
        cred_id = uuid.UUID(str(obj.get("credential_id") or ""))
    except ValueError:
        raise _AssistRefused(code="rd_saved_password_unavailable", why="bad credential_id") from None
    async with SessionLocal() as s:
        cred = await s.get(SSHCredential, cred_id)
        if (cred is None or cred.protocol != "rustdesk" or str(cred.owner_user_id) != st.user_id
                or cred.target_ip_id is None or str(cred.target_ip_id) != st.ip_id):
            raise _AssistRefused(code="rd_saved_password_unavailable", why=f"credential {cred_id} not usable here")
        enc = (cred.secrets_enc or {}).get("password")
        if not enc:
            raise _AssistRefused(code="rd_saved_password_unavailable", why=f"credential {cred_id} has no password")
        # 5) 解密（AAD 與存的時候相同：綁擁有者＋欄位）
        from app.api.v1.endpoints.ssh_credentials import cred_aad
        try:
            password = envelope_decrypt(enc, aad=cred_aad(cred.owner_user_id, "password"))
        except Exception:
            raise _AssistRefused(code="rd_saved_password_decrypt",
                                 why=f"credential {cred_id} decrypt failed") from None
        h2 = proto.password_h2(password, salt, challenge)
        del password
        cred.last_used_at = datetime.now(UTC)
        await append_audit(s, actor_user_id=st.user_id, actor_ip=st.actor_ip, actor_user_agent=st.user_agent,
                           object_type="ip", object_id=st.ip_id, action="rustdesk.saved_password_used",
                           diff={"peer_id": st.peer_id, "server_id": st.server_id,
                                 "credential_id": str(cred_id)},
                           request_id=None)
        await s.commit()
    return h2


def _browser_audit_allowed(st: _State) -> bool:
    """瀏覽器自報稽核（file_audit、elevation_audit）每條連線的權杖桶：一次最多 _AUDIT_BURST 則，
    之後每秒補 _AUDIT_PER_SECOND 則。"""
    now = time.monotonic()
    st.audit_tokens = min(_AUDIT_BURST, st.audit_tokens + (now - st.audit_tokens_at) * _AUDIT_PER_SECOND)
    st.audit_tokens_at = now
    if st.audit_tokens < 1.0:
        return False
    st.audit_tokens -= 1.0
    return True


def _clean_path(v: Any) -> str | None:
    """受控端的路徑（瀏覽器轉述）：要是字串；控制字元拿掉，截到 512 個字元。"""
    if not isinstance(v, str):
        return None
    return _CONTROL_CHARS.sub("", v)[:_FILE_PATH_MAX]


def _parse_file_audit(obj: dict[str, Any]) -> dict[str, Any] | None:
    """附錄 J.6 的 file_audit：op、result 只收固定的值；path 要是字串（截到 512）；size 沒給或是非負整數。"""
    op, result = obj.get("op"), obj.get("result")
    if not isinstance(op, str) or op not in _FILE_OPS or not isinstance(result, str) or result not in _FILE_RESULTS:
        return None
    path = _clean_path(obj.get("path"))
    if path is None:
        return None
    size = obj.get("size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= _FILE_SIZE_MAX):
        return None
    out: dict[str, Any] = {"path": path, "size": size, "result": result}
    if op == "rename" and obj.get("to") is not None:
        to = _clean_path(obj.get("to"))
        if to is None:
            return None
        out["to"] = to
    return {"op": op, **out}


async def _file_audit(st: _State, obj: dict[str, Any]) -> None:
    """附錄 J.6：瀏覽器自報的檔案動作摘要 → 稽核 rustdesk.file_<op>（誰、哪台、路徑、大小、結果）。

    後端只看得到密文，內容無法驗證，所以稽核裡標明是瀏覽器回報的。只收檔案傳輸、而且已經登入的連線；
    格式不對、超過限流的丟掉（記數量，連線結束的稽核看得到），不切斷連線。不含任何檔案內容。
    """
    if st.kind != "file" or not st.logged_in:
        return
    if not _browser_audit_allowed(st):
        st.file_audits_dropped += 1
        if st.file_audits_dropped in (1, 100, 1000):
            _log.info("rustdesk-web: file_audit 太頻繁，丟掉 peer=%s user=%s（累計 %s 則）",
                      st.peer_id, st.user_id, st.file_audits_dropped)
        return
    entry = _parse_file_audit(obj)
    if entry is None:
        st.file_audits_dropped += 1
        _log.info("rustdesk-web: file_audit 格式不對，丟掉 peer=%s user=%s", st.peer_id, st.user_id)
        return
    op = entry.pop("op")
    try:
        await _audit(user_id=st.user_id, actor_ip=st.actor_ip, user_agent=st.user_agent, ip_id=st.ip_id,
                     action=f"rustdesk.file_{op}",
                     diff={"peer_id": st.peer_id, "server_id": st.server_id, **entry,
                           "source": "browser", "description": _FILE_AUDIT_NOTE})
    except Exception:
        st.file_audits_dropped += 1
        _log.exception("rustdesk-web: file_audit 寫入失敗 peer=%s", st.peer_id)
        return
    st.file_audits += 1


def _parse_elevation_audit(obj: dict[str, Any]) -> dict[str, Any] | None:
    """附錄 K.2 的 elevation_audit：只取 method、result、detail（t 已經看過）；其他欄位（例如帳號密碼）一律不看。

    method、result 只收固定的值，否則整則丟掉；detail 是受控端的錯誤原文，要是字串（不是字串就不記內容，
    事件本身照記），控制字元換成空白、截到 200 個字元。
    """
    method, result = obj.get("method"), obj.get("result")
    if (not isinstance(method, str) or method not in _ELEVATION_METHODS
            or not isinstance(result, str) or result not in _ELEVATION_RESULTS):
        return None
    raw = obj.get("detail")
    detail = _CONTROL_CHARS.sub(" ", raw)[:_ELEVATION_DETAIL_MAX] if isinstance(raw, str) else ""
    return {"method": method, "result": result, "detail": detail}


async def _elevation_audit(st: _State, obj: dict[str, Any]) -> None:
    """附錄 K.2：瀏覽器自報的請求提權（送出時、得到結果時各一則）→ 稽核 rustdesk.elevation_request
    （誰、哪台、方式、結果、錯誤原文）。

    後端只看得到密文，內容無法驗證，所以稽核裡標明是瀏覽器回報的。只收一般遠端桌面、而且已經登入的連線
    （檔案傳輸的連線上收到不處理）；格式不對、超過限流的丟掉（記數量，連線結束的稽核看得到），不切斷連線。
    不含帳號密碼：只取 _parse_elevation_audit 挑出來的三個欄位。
    """
    if st.kind != "desktop" or not st.logged_in:
        return
    if not _browser_audit_allowed(st):
        st.elevation_audits_dropped += 1
        if st.elevation_audits_dropped in (1, 100, 1000):
            _log.info("rustdesk-web: elevation_audit 太頻繁，丟掉 peer=%s user=%s（累計 %s 則）",
                      st.peer_id, st.user_id, st.elevation_audits_dropped)
        return
    entry = _parse_elevation_audit(obj)
    if entry is None:
        st.elevation_audits_dropped += 1
        _log.info("rustdesk-web: elevation_audit 格式不對，丟掉 peer=%s user=%s", st.peer_id, st.user_id)
        return
    try:
        await _audit(user_id=st.user_id, actor_ip=st.actor_ip, user_agent=st.user_agent, ip_id=st.ip_id,
                     action="rustdesk.elevation_request",
                     diff={"peer_id": st.peer_id, "server_id": st.server_id, **entry,
                           "source": "browser", "description": _ELEVATION_AUDIT_NOTE})
    except Exception:
        st.elevation_audits_dropped += 1
        _log.exception("rustdesk-web: elevation_audit 寫入失敗 peer=%s", st.peer_id)
        return
    st.elevation_audits += 1
