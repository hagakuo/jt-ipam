"""IP 位址 RDP 連線管理：ticket 換發 + WebSocket↔RDP 橋接（瀏覽器 canvas 前端）。

比照 SSH 連線管理（ssh_console.py）的安全架構：
- A01：ticket 與 WS 兩處都重查 `can_use_rdp`（deny-by-default）；看不到的 IP 不能連。
- A07/A09：ticket 單次用 + 60s TTL + 綁 user×ip；發放限流；session 開/關都寫稽核。
- 帳密只在連線過程存記憶體，用完即丟，**絕不寫 DB / 不記錄**；已存帳密走金庫 reference。
- 目標主機固定為該 IP 記錄上的位址（不接受使用者指定 host）→ 防被當成通用 RDP/SSRF proxy。

相依：**aardwolf 為選用**（pin 0.2.13，有 wheel→免 Rust）。未安裝時 `RDP_AVAILABLE=False`，
所有端點回 503、前端隱藏入口。

實作備註（避開 aardwolf 0.2.13 已知 bug，不需 fork / monkeypatch）：
- 輸入直接呼叫 `conn.send_mouse` / `conn.send_key_*`（單一 pump_in 協程序列送出），
  不走 `ext_in_queue`（其 `__external_reader` 傳給 send_mouse 的 wheel steps 恆 0）。
- 滾輪一律用 `MOUSEBUTTON_WHEEL_UP` 並把方向放進 steps：向下 = `0x100`(WHEEL_NEGATIVE 位) | 量值，
  讓 WHEEL_UP 分支自動帶上 `PTRFLAGS.WHEEL`（修掉 WHEEL_DOWN 漏設 WHEEL flag 的 bug）。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import String, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser
from app.core.audit import append_audit
from app.core.config import get_settings
from app.core.db import SessionLocal, get_session
from app.core.rate_limit import _redis_client
from app.core.security import envelope_decrypt
from app.core.sqlin import in_values
from app.core.tickets import take_once
from app.core.ui_error import detail_of, ui_detail
from app.core.ws_timeouts import HANDSHAKE_TIMEOUT, WsTimeout, receive_text_within
from app.models.address import IPAddress
from app.models.device import Device
from app.models.ssh_credential import SSHCredential
from app.models.user import User
from app.schemas.address import IPAddressRead
from app.services import console_route
from app.services.permission import (
    can_use_rdp,
    get_object_permission,
    has_permission,
    visible_ids,
)
from app.services.rdp_freerdp import UnsupportedCharacter  # 模組層沒有硬相依，沒裝也載得起來

try:  # aardwolf 為選用相依（pin 0.2.13）；未裝則 RDP 功能停用
    from aardwolf.commons.factory import RDPConnectionFactory
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.queuedata import RDPDATATYPE
    from aardwolf.commons.queuedata.constants import VIDEO_FORMAT

    RDP_AVAILABLE = True
except Exception:  # 任何 import 問題都視為未安裝
    RDP_AVAILABLE = False

router = APIRouter(prefix="/addresses", tags=["rdp"])

# 這條路原本幾乎沒有日誌：WS 一旦卡住，伺服器端只看得到 "connection open"，
# 接下來發生什麼完全看不見（2026-09-17 查 FreeRDP 引擎時整整卡在這裡）。
# 每一個會停下來等的步驟都要留一行，否則下次還是只能猜。
_log = logging.getLogger("jt-ipam.rdp")

_TICKET_TTL = 60              # 秒；ticket 單次用、短壽
_CONNECT_TIMEOUT = 20.0       # RDP（NLA）連線逾時（aardwolf：單純的 socket 連線）
#: FreeRDP 這條路要起虛擬顯示、起 xfreerdp、等視窗畫出來、再起畫面擷取 ——
#: 本來就比「開一條 socket」久。共用 20 秒會在機器有負載時把成功的連線判成逾時
#: （2026-09-17 正式環境上就是這樣）。
_CONNECT_TIMEOUT_FREERDP = 45.0
#: guacd：等到第一個畫面才算連上（NLA 登入、慢的目標都在這段時間裡）
_CONNECT_TIMEOUT_GUACD = 45.0
#: RDP 標準埠。原本沒有這個常數（靠 aardwolf 的預設），但走跳板時
#: 必須明確知道要轉發到哪個埠，而且 URL 也要帶上（見下方註解）。
_RDP_PORT = 3389
_WHEEL_DELTA = 120            # 一格滾輪
_WHEEL_NEGATIVE = 0x100       # PTRFLAGS.WHEEL_NEGATIVE 位（放進 steps 表向下）
_MAX_DIM = 2560              # 解析度上限保護

# 鍵盤特殊鍵 → (PC set-1 scancode, is_extended)
_SPECIAL_KEYS: dict[str, tuple[int, bool]] = {
    "Enter": (0x1C, False), "Backspace": (0x0E, False), "Tab": (0x0F, False),
    "Escape": (0x01, False), "Delete": (0x53, True), "Home": (0x47, True),
    "End": (0x4F, True), "PageUp": (0x49, True), "PageDown": (0x51, True),
    "Insert": (0x52, True), "ArrowUp": (0x48, True), "ArrowDown": (0x50, True),
    "ArrowLeft": (0x4B, True), "ArrowRight": (0x4D, True),
    "Control": (0x1D, False), "Shift": (0x2A, False), "Alt": (0x38, False),
    "Meta": (0x5B, True), " ": (0x39, False),  # Meta = 左 Windows 鍵（extended）
    "F1": (0x3B, False), "F2": (0x3C, False), "F3": (0x3D, False), "F4": (0x3E, False),
    "F5": (0x3F, False), "F6": (0x40, False), "F7": (0x41, False), "F8": (0x42, False),
    "F9": (0x43, False), "F10": (0x44, False), "F11": (0x57, False), "F12": (0x58, False),
}

# DOM e.code → PC Set-1 掃描碼。按住修飾鍵（Ctrl/Alt/Meta）時，字母/數字鍵要走 scancode，
# 否則 unicode 字元事件不會與 scancode 修飾鍵組合（→ Ctrl+V、Ctrl+C… 全失效，只會打出字元）。
_CODE_SCANCODES: dict[str, int] = {
    "KeyA": 0x1E, "KeyB": 0x30, "KeyC": 0x2E, "KeyD": 0x20, "KeyE": 0x12, "KeyF": 0x21,
    "KeyG": 0x22, "KeyH": 0x23, "KeyI": 0x17, "KeyJ": 0x24, "KeyK": 0x25, "KeyL": 0x26,
    "KeyM": 0x32, "KeyN": 0x31, "KeyO": 0x18, "KeyP": 0x19, "KeyQ": 0x10, "KeyR": 0x13,
    "KeyS": 0x1F, "KeyT": 0x14, "KeyU": 0x16, "KeyV": 0x2F, "KeyW": 0x11, "KeyX": 0x2D,
    "KeyY": 0x15, "KeyZ": 0x2C,
    "Digit1": 0x02, "Digit2": 0x03, "Digit3": 0x04, "Digit4": 0x05, "Digit5": 0x06,
    "Digit6": 0x07, "Digit7": 0x08, "Digit8": 0x09, "Digit9": 0x0A, "Digit0": 0x0B,
    "Minus": 0x0C, "Equal": 0x0D, "BracketLeft": 0x1A, "BracketRight": 0x1B,
    "Backslash": 0x2B, "Semicolon": 0x27, "Quote": 0x28, "Backquote": 0x29,
    "Comma": 0x33, "Period": 0x34, "Slash": 0x35,
}

# 同時在線 session 計數（單核 GIL 下限制並發；0 = 不限）
_active_sessions = 0


def _ticket_key(ticket: str) -> str:
    return f"rdp:tk:{ticket}"


class _Button:
    """按鍵的中性表示。

    兩個引擎都只看 `.name`：aardwolf 的 MOUSEBUTTON 有這個屬性，FreeRDP 那邊也照這個
    名字查 X 的按鈕編號。以前這裡直接回 aardwolf 的列舉 —— 那讓「用 FreeRDP 引擎」
    仍然得先裝 aardwolf，等於兩個引擎沒有真的分開。
    """

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


_BTN_LEFT = _Button("MOUSEBUTTON_LEFT")
_BTN_RIGHT = _Button("MOUSEBUTTON_RIGHT")
_BTN_MIDDLE = _Button("MOUSEBUTTON_MIDDLE")
_BTN_HOVER = _Button("MOUSEBUTTON_HOVER")
_BTN_WHEEL = _Button("MOUSEBUTTON_WHEEL_UP")


def _mouse_button(b: int) -> Any:
    return {0: _BTN_LEFT, 1: _BTN_RIGHT, 2: _BTN_MIDDLE}.get(int(b), _BTN_LEFT)


@router.get("/connections/targets", response_model=list[IPAddressRead])
async def list_connection_targets(
    user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[IPAddressRead]:
    """列出所有已啟用 SSH 或 RDP、且目前使用者可連線的 IP（進階→連線管理頁用）。

    與 can_use_ssh/can_use_rdp 一致的 deny-by-default：admin 全部；否則限可見子網路，
    再依「對該子網路有 write」或「具 can_ssh 能力且至少 read」逐筆放行。每筆回 ssh/rdp 兩旗標。
    相容 RustDesk 的網頁連線（can_use_rustdesk 同一套權限）：IP 開了 rustdesk_enabled、對應到的 RustDesk
    裝置所在的伺服器開放網頁連線，才算一種可用的連線；只開了 RustDesk 卻不能網頁連線的 IP 不列出。
    """
    stmt = select(IPAddress).where(
        IPAddress.ssh_enabled.is_(True)
        | IPAddress.rdp_enabled.is_(True)
        | IPAddress.vnc_enabled.is_(True)
        | IPAddress.novnc_enabled.is_(True)
        | IPAddress.bmc_enabled.is_(True)
        | IPAddress.rustdesk_enabled.is_(True)
    )
    vis: set[uuid.UUID] | None = None  # None = 不限（admin 或萬用可見）
    if not user.is_admin:
        vis = await visible_ids(session, user=user, object_type="subnet")
        if vis is not None:
            if not vis:
                return []
            stmt = stmt.where(in_values(IPAddress.subnet_id, vis))
    rows = (await session.execute(stmt)).scalars().all()

    perm_cache: dict[uuid.UUID, str] = {}
    kept: list[tuple[IPAddress, bool, bool, bool, bool]] = []
    for ip in rows:
        if user.is_admin:
            usable = True
        else:
            lvl = perm_cache.get(ip.subnet_id)
            if lvl is None:
                lvl = await get_object_permission(
                    session, user=user, object_type="subnet", object_id=ip.subnet_id
                )
                perm_cache[ip.subnet_id] = lvl
            if lvl == "none":
                continue
            usable = has_permission(lvl, "write") or bool(user.can_ssh)
        if not usable:
            continue
        kept.append((ip, bool(ip.ssh_enabled), bool(ip.rdp_enabled), bool(ip.vnc_enabled), bool(ip.bmc_enabled)))

    # 相容 RustDesk 的網頁連線：一次查完（IP 可能上萬筆，不逐筆查）
    rd_web = await _rustdesk_web_ready(session, [ip.id for ip, *_ in kept if ip.rustdesk_enabled])
    kept = [k for k in kept
            if k[0].ssh_enabled or k[0].rdp_enabled or k[0].vnc_enabled or k[0].novnc_enabled
            or k[0].bmc_enabled or k[0].id in rd_web]

    dev_ids = {ip.device_id for ip, *_ in kept if ip.device_id}
    dev_names: dict[uuid.UUID, str] = {}
    if dev_ids:
        drows = (await session.execute(
            select(Device.id, Device.name).where(in_values(Device.id, dev_ids))
        )).all()
        dev_names = {d[0]: d[1] for d in drows}

    # 借用「同一 IP、使用者可見範圍內其它記錄」的最新存活時間 —— 解重疊子網路把同一台
    # 實體機拆成多筆、掃描 / LibreNMS 只 stamp 其中一筆（.limit(1)）導致連線頁那筆顯示離線。
    # 只借用可見記錄：多租戶下不會拿到別單位的存活證據（RBAC 安全）。
    live_map: dict[str, tuple[Any, Any, Any]] = {}
    ip_values = list({str(ip.ip) for ip, *_ in kept})
    if ip_values:
        lstmt = (
            select(
                func.host(IPAddress.ip),
                func.max(IPAddress.last_seen_scanner),
                func.max(IPAddress.last_seen_librenms),
                func.max(IPAddress.last_seen_dns),
            )
            .where(in_values(func.host(IPAddress.ip), ip_values, type_=String()))
            .group_by(func.host(IPAddress.ip))
        )
        if vis is not None:
            lstmt = lstmt.where(in_values(IPAddress.subnet_id, vis))
        for lr in (await session.execute(lstmt)).all():
            live_map[str(lr[0])] = (lr[1], lr[2], lr[3])

    from app.services.os_precedence import effective_os
    from app.services.oui import vendor_for_mac
    out: list[IPAddressRead] = []
    for ip, ssh_ok, rdp_ok, vnc_ok, bmc_ok in kept:
        r = IPAddressRead.model_validate(ip)
        r.mac_vendor = await vendor_for_mac(session, ip.mac)
        lm = live_map.get(str(ip.ip))
        if lm:
            # lm 為同 IP 可見記錄的最新值（已含自身），直接採用 → 連線頁的燈反映實際存活
            r.last_seen_scanner, r.last_seen_librenms, r.last_seen_dns = lm
        r.ssh_available = ssh_ok
        r.rdp_available = rdp_ok
        r.vnc_available = vnc_ok
        r.bmc_available = bmc_ok
        r.rustdesk_web_available = ip.id in rd_web
        if ip.novnc_enabled:  # PVE 主控台：已啟用且對應到 PVE VM/CT（權限已在 kept 過濾）
            from app.services.pve_console import resolve_pve_target
            tgt = await resolve_pve_target(session, ip)
            if tgt is not None:
                r.novnc_available = True
                from app.schemas.address import PveConsoleTarget
                r.pve = PveConsoleTarget(kind=tgt.kind, node=tgt.node, vmid=tgt.vmid, cluster=tgt.cluster_name)
        r.device_name = dev_names.get(ip.device_id) if ip.device_id else None
        # OS 與 IP 詳細資料頁一致：依來源優先序（librenms/wazuh/scanner）解析有效值
        _os = await effective_os(session, ip)
        r.os_guess = _os["os_guess"]; r.os_family = _os["os_family"]; r.os_source = _os["os_source"]
        out.append(r)
    return out


async def _rustdesk_web_ready(session: AsyncSession, ip_ids: list[uuid.UUID]) -> set[uuid.UUID]:
    """這些 IP 裡，哪些可以走相容 RustDesk 的網頁連線（伺服器設定面；權限已在呼叫端過濾）。

    與 IP 詳細資料同一個選法（rustdesk.matched_peer：取最近上線的那一台），所以清單上的按鈕與
    詳細資料頁的按鈕一致。
    """
    if not ip_ids:
        return set()
    from app.models.rustdesk import RustDeskPeer, RustDeskServer
    from app.services.rustdesk import web_problem
    rows = (await session.execute(
        select(RustDeskPeer.address_id, RustDeskServer)
        .join(RustDeskServer, RustDeskServer.id == RustDeskPeer.server_id)
        .where(in_values(RustDeskPeer.address_id, ip_ids), RustDeskPeer.match_status == "matched")
        .order_by(RustDeskPeer.address_id, RustDeskPeer.online.desc(),
                  RustDeskPeer.last_online_at.desc().nulls_last())
    )).all()
    out: set[uuid.UUID] = set()
    seen: set[uuid.UUID] = set()
    for addr_id, srv in rows:
        if addr_id in seen:
            continue                    # 每個 IP 只看排第一的那台（同 matched_peer）
        seen.add(addr_id)
        if web_problem(srv) is None:
            out.add(addr_id)
    return out


def engine_available(engine: str) -> tuple[bool, str]:
    """這個引擎在這台機器上能不能用，不能的話缺什麼。

    兩個引擎的相依完全不同：aardwolf 是一個 Python 套件，FreeRDP 是外部程式加虛擬顯示。
    所以「RDP 能不能用」不是一個全域旗標，而是逐引擎的問題 —— 以前只看 aardwolf，
    會在只裝了 FreeRDP 的機器上把整個功能關掉。
    """
    if engine == "freerdp":
        from app.services.rdp_freerdp import availability
        av = availability()
        if av["ok"]:
            return True, ""
        missing = av["missing_packages"] + av["missing_modules"]
        return False, "、".join(missing)
    return (RDP_AVAILABLE, "" if RDP_AVAILABLE else "aardwolf")


def python_version() -> str:
    import sys
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def rdp_unavailable_detail(engine: str, missing: str) -> dict[str, Any]:
    """RDP 用不了時給使用者看的說明：原因加出路（GitHub issue #39）。

    以前只說「缺 aardwolf」。實際最常見的原因是這台的 Python 太新（aardwolf 0.2.13 只有
    CPython 3.9–3.13 的預編譯 wheel，安裝時刻意不現場編 Rust）—— 而 RDP 其實可以改用
    FreeRDP 引擎，只是使用者不會知道。
    """
    if engine == "freerdp":
        return ui_detail(
            "console_rdp_freerdp_missing",
            f"FreeRDP 引擎缺少 {missing}：請在伺服器上執行 jt-ipam.sh upgrade 安裝。",
            engine=engine, missing=missing)
    py = python_version()
    return ui_detail(
        "console_rdp_no_aardwolf",
        f"這台伺服器沒有 aardwolf（Python {py} 沒有它的預編譯套件）。"
        "請管理員到「系統設定 → RDP 連線引擎」改用 FreeRDP。",
        engine=engine, missing=missing, python=py)


@router.post("/{address_id}/rdp/ticket")
async def issue_rdp_ticket(
    address_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """換發短期一次性 ticket；之後用它開 WebSocket。"""
    from app.core.rate_limit import limit_per_ip

    await limit_per_ip(request, name="rdp")

    ip = await session.get(IPAddress, address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="Address not found")
    if not await can_use_rdp(session, user=user, ip=ip):
        raise HTTPException(status_code=403, detail=ui_detail("console_rdp_forbidden", "無 RDP 連線權限"))

    saved = (await session.execute(
        select(SSHCredential.id).where(
            SSHCredential.owner_user_id == user.id,
            SSHCredential.protocol == "rdp",
            (SSHCredential.target_ip_id == ip.id) | (SSHCredential.target_ip_id.is_(None)),
        ).limit(1)
    )).first()

    from app.services import console_engine
    from app.services.system_config import get_rdp_clipboard_paste
    clip_enabled = await get_rdp_clipboard_paste(session)
    # 預設 guacd；這台的 guacd 處理不了 RDP 時退回可用的內建引擎（見 services/console_engine.py）
    engine = await console_engine.resolve(session, "rdp", fallbacks=[
        ("aardwolf", engine_available("aardwolf")[0]), ("freerdp", engine_available("freerdp")[0])])
    if engine == "guacd":
        from app.services import guacd as guac
        try:
            await guac.require("rdp")
        except guac.GuacdError as exc:
            raise HTTPException(status_code=503, detail=exc.ui()) from exc
    else:
        ok, missing = engine_available(engine)
        if not ok:
            raise HTTPException(status_code=503, detail=rdp_unavailable_detail(engine, missing))

    ticket = secrets.token_urlsafe(32)
    # 引擎寫進票證：WebSocket 照這個用，不自己再判斷（guacd 剛好起落時兩邊會講不同協定）
    payload = json.dumps({"user_id": str(user.id), "ip_id": str(ip.id), "engine": engine})
    await _redis_client().set(_ticket_key(ticket), payload, ex=_TICKET_TTL)

    return {
        "ticket": ticket,
        "ws_path": f"/api/v1/addresses/{ip.id}/rdp/ws",
        "default_size": {"width": 1280, "height": 800},
        "has_saved_creds": saved is not None,
        "clipboard_paste": clip_enabled,
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


async def _audit_rdp(
    *, actor_user_id: str, actor_ip: str | None, object_id: str,
    action: str, diff: dict[str, Any],
) -> None:
    async with SessionLocal() as s:
        await append_audit(
            s, actor_user_id=actor_user_id, actor_ip=actor_ip, actor_user_agent=None,
            object_type="ip", object_id=object_id, action=action, diff=diff, request_id=None,
        )
        await s.commit()


def _build_aardwolf_conn(*, tunnel: Any, username: str, password: str, domain: str | None,
                         width: int, height: int, clip_enabled: bool) -> Any:
    """aardwolf（預設引擎）：純 Python、零外部行程。"""
    io = RDPIOSettings()
    # 預設不啟用任何虛擬通道；僅在管理者開啟「控制端貼上」時才掛剪貼簿通道（cliprdr）
    if clip_enabled:
        from aardwolf.extensions.RDPECLIP.channel import RDPECLIPChannel
        io.channels = [RDPECLIPChannel]
    else:
        io.channels = []
    io.video_width = width
    io.video_height = height
    io.video_bpp_min = 24
    io.video_bpp_max = 32
    io.video_out_format = VIDEO_FORMAT.PNG
    io.clipboard_use_pyperclip = False

    user_in_url = quote(f"{domain}\\{username}" if domain else username, safe="")
    b64pw = base64.b64encode(password.encode("utf-8")).decode("ascii")
    # ⚠️ 連接埠一定要寫進 URL：`create_connection_newtarget()` 只換 ip/hostname，
    # **不動連接埠**（它是 from_url 解析出來的）。少了這一段，走跳板時會連到
    # 127.0.0.1:3389 —— 也就是後端主機自己，而不是通道的另一端。
    url = (f"rdp+ntlm-pwb64://{user_in_url}:{b64pw}@{tunnel.host}:{tunnel.port}/"
           f"?timeout={int(_CONNECT_TIMEOUT)}")
    factory = RDPConnectionFactory.from_url(url, io)
    return factory.create_connection_newtarget(tunnel.host, io)


def _build_freerdp_conn(*, tunnel: Any, username: str, password: str, domain: str | None,
                        width: int, height: int, clip_enabled: bool) -> Any:
    """FreeRDP：相容性較好（xrdp／GNOME 遠端登入），代價是外部行程與虛擬顯示。

    回傳的物件與 aardwolf 的連線同介面，所以 `_bridge()` 不必分辨用的是哪一個。
    """
    from app.services.rdp_freerdp import FreeRdpConnection
    return FreeRdpConnection(
        host=tunnel.host, port=tunnel.port, username=username,
        password=password, domain=domain, width=width, height=height,
        clip_enabled=clip_enabled)



@router.websocket("/{address_id}/rdp/ws")
async def rdp_ws(websocket: WebSocket, address_id: uuid.UUID, ticket: str = "") -> None:
    global _active_sessions

    # 引擎在建立連線時才決定；這裡先不擋 —— aardwolf 沒裝不代表 FreeRDP 不能用
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
        allowed = await can_use_rdp(s, user=user, ip=ip)
        host = str(ip.ip).split("/")[0]
        # 連線出口：直連或經由跳板（IP 覆寫 > 子網路 > 直連）
        route = await console_route.resolve_route(s, ip)
        from app.services.system_config import RDP_ENGINES, get_rdp_clipboard_paste, get_rdp_engine
        clip_enabled = await get_rdp_clipboard_paste(s)
        engine = ticket_engine if ticket_engine in RDP_ENGINES else await get_rdp_engine(s)
    if not allowed:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    actor_ip = websocket.client.host if websocket.client else None

    async def send(obj: dict[str, Any]) -> None:
        await websocket.send_text(json.dumps(obj))

    # 並發上限（避免單核被多 session 拖垮）
    cap = get_settings().rdp_max_sessions
    if cap and _active_sessions >= cap:
        await send({"type": "error", **ui_detail("console_rdp_too_many",
                                      f"RDP 同時連線已達上限（{cap}）", max=cap)})
        await websocket.close()
        return

    conn = None
    counted = False
    tunnel: console_route.Tunnel | None = None
    started: datetime | None = None
    # guacd 連上之後這條 WebSocket 改講 Guacamole 協定：不可以再送 JSON（瀏覽器那端會解析錯誤）
    guac_mode = False
    _log.info("rdp: ws 已接受 host=%s engine=%s user=%s", host, engine, user_id)
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
        _log.info("rdp: 收到設定 host=%s %sx%s", host, cfg.get("width"), cfg.get("height"))
        width = max(640, min(_MAX_DIM, int(cfg.get("width") or 1280)))
        height = max(480, min(_MAX_DIM, int(cfg.get("height") or 800)))
        username = (cfg.get("username") or "").strip()
        password = cfg.get("password") or ""
        domain = (cfg.get("domain") or "").strip()
        credential_id = cfg.get("credential_id")

        # 4) 已存帳密（金庫）— 明文只在記憶體
        used_cred_id: uuid.UUID | None = None
        if credential_id:
            from app.api.v1.endpoints.ssh_credentials import cred_aad
            async with SessionLocal() as s:
                try:
                    cred = await s.get(SSHCredential, uuid.UUID(str(credential_id)))
                except ValueError:
                    cred = None
                if (cred is None or cred.owner_user_id != user_id or cred.protocol != "rdp"
                        or (cred.target_ip_id is not None and str(cred.target_ip_id) != str(address_id))):
                    await send({"type": "error",
                                **ui_detail("console_no_saved_credential", "找不到可用的已存帳密")})
                    await websocket.close()
                    return
                used_cred_id = cred.id
                username = cred.username
                domain = cred.domain or ""
                secrets_enc = dict(cred.secrets_enc or {})
            try:
                password = envelope_decrypt(secrets_enc["password"], aad=cred_aad(user_id, "password"))
            except Exception:
                await send({"type": "error",
                            **ui_detail("console_saved_credential_decrypt", "已存帳密解密失敗")})
                await websocket.close()
                return
            async with SessionLocal() as s:
                c2 = await s.get(SSHCredential, used_cred_id)
                if c2 is not None:
                    c2.last_used_at = datetime.now(UTC)
                    await s.commit()
        if not username:
            await send({"type": "error", **ui_detail("console_no_username", "帳號必填")})
            await websocket.close()
            return

        # 5) 建立 RDP 連線
        await send({"type": "status", "state": "connecting"})

        # 經跳板時把目標換成本機轉發埠（直連時 open_route 是零成本的）
        try:
            tunnel = await console_route.open_route(route, host, _RDP_PORT, user_id=user_id, purpose="rdp")
        except console_route.JumpHostError as exc:
            await send({"type": "error", **detail_of(exc, "jump_failed")})
            await websocket.close()
            return

        if tunnel.via:
            await send({"type": "status", "state": "via_jump", "via": tunnel.via,
                        "via_kind": tunnel.via_kind})

        _log.info("rdp: 開始連線 host=%s engine=%s via_jump=%s", host, engine, tunnel.via)
        if engine == "guacd":
            from app.services import guacd as guac
            # 帳密只交給本機的 guacd，不經過瀏覽器；目標是通道的位址（走跳板時是本機轉發埠）
            params = {
                "hostname": tunnel.host, "port": str(tunnel.port),
                "username": username, "password": password, "domain": domain,
                # 憑證不驗：跟另外兩個引擎一致（內網主機多半是自簽憑證）
                "security": "any", "ignore-cert": "true",
                "resize-method": "display-update",
                # 剪貼簿維持單向：被控端的內容不回傳；控制端貼上要管理者開啟
                "disable-copy": "true", "disable-paste": "false" if clip_enabled else "true",
                "disable-audio": "true", "client-name": "jt-ipam",
            }
            del password
            try:
                conn = await guac.GuacdConnection.open()
                await conn.handshake("rdp", params, width=width, height=height,
                                     dpi=guac.client_dpi(cfg.get("dpi")),
                                     timezone=guac.client_timezone(cfg.get("timezone")))
                del params
                initial = await conn.wait_first_frame(_CONNECT_TIMEOUT_GUACD)
            except guac.GuacdError as exc:
                _log.info("rdp: guacd 連線失敗 host=%s code=%s reason=%s", host, exc.code, exc.reason)
                await send({"type": "error", **exc.ui()})
                await websocket.close()
                return
            _active_sessions += 1
            counted = True
            started = datetime.now(UTC)
            await _audit_rdp(
                actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
                action="rdp.session_open",
                diff={"host": host, "username": username, "domain": domain or None,
                      "via_jump_host": tunnel.via, "via_kind": tunnel.via_kind, "size": f"{width}x{height}", "engine": "guacd",
                      "credential_id": str(used_cred_id) if used_cred_id else None},
            )
            _log.info("rdp: 已連上（guacd）host=%s", host)
            await send({"type": "status", "state": "connected", "engine": "guacd",
                        "width": width, "height": height})
            guac_mode = True
            res = await guac.relay(websocket, conn, initial=initial)
            _log.info("rdp: guacd 工作階段結束 host=%s ended_by=%s dropped=%s", host, res.ended_by, res.dropped)
            return
        if engine == "freerdp":
            conn = _build_freerdp_conn(
                tunnel=tunnel, username=username, password=password,
                domain=domain, width=width, height=height, clip_enabled=clip_enabled)
        else:
            conn = _build_aardwolf_conn(
                tunnel=tunnel, username=username, password=password,
                domain=domain, width=width, height=height, clip_enabled=clip_enabled)
        del password
        budget = _CONNECT_TIMEOUT_FREERDP if engine == "freerdp" else _CONNECT_TIMEOUT
        try:
            async with asyncio.timeout(budget):
                _result, err = await conn.connect()
        except TimeoutError:
            await send({"type": "error", **ui_detail("console_connect_timeout", "連線逾時")})
            await websocket.close()
            return
        if err is not None:
            _log.info("rdp: 連線失敗 host=%s engine=%s err=%r", host, engine, err)
            from app.services.rdp_freerdp import FreeRdpError
            if isinstance(err, FreeRdpError):
                # FreeRDP 引擎已經把原因講清楚了（它看得到 xfreerdp／Xvfb 說了什麼）。
                # ⚠️ 不要再丟給下面那個分類器：那是照 aardwolf 的失敗樣態寫的，會把
                # 「虛擬顯示起不來」說成「帳號、密碼、網域或 NLA 設定」——
                # 指著完全無關的方向（2026-09-17 正式環境實際發生過）。
                # ⚠️ 一定要走 detail_of：它保證帶上 `reason` 參數。翻譯是
                # 「RDP 引擎無法建立連線：{reason}」—— 只送 message 不送參數的話，
                # 前端會優先用翻譯，`{reason}` 變成空字串，整句診斷就這樣不見了
                # （2026-09-17 正式環境上真的發生，畫面只剩一個冒號）。
                await send({"type": "error", **detail_of(err, "console_engine_failed")})
                await websocket.close()
                return
            # 不回堆疊，但**要帶底層原因**：只說「認證失敗」會把「對方在交握前就關掉連線」
            # 這種情況指去查密碼（見 vnc_console._classify_connect_error 的由來）
            from app.api.v1.endpoints.vnc_console import _classify_connect_error
            code, message = _classify_connect_error(err)
            if code == "auth_failed":
                from app.core.safe_http import transport_detail
                message = (f"連線/認證失敗（帳號、密碼、網域或 NLA 設定）："
                           f"{transport_detail(err, limit=160)}")
            await send({"type": "error", "code": code, "message": message})
            await websocket.close()
            return

        _active_sessions += 1
        counted = True
        started = datetime.now(UTC)
        await _audit_rdp(
            actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
            action="rdp.session_open",
            diff={"host": host, "username": username, "domain": domain or None,
                  "via_jump_host": tunnel.via, "via_kind": tunnel.via_kind,
                  "size": f"{width}x{height}",
                  "credential_id": str(used_cred_id) if used_cred_id else None},
        )
        _log.info("rdp: 已連上 host=%s engine=%s", host, engine)
        # 回報**實際**拿到的尺寸：FreeRDP 會把寬度捨成偶數，前端照要求的開 canvas
        # 會多出一欄永遠黑著的像素，座標換算也跟著差那一格。
        fb_w, fb_h = getattr(conn, "framebuffer_size", (width, height))
        await send({"type": "status", "state": "connected", "width": fb_w, "height": fb_h})

        if clip_enabled:
            # 預先放一個空字串到剪貼簿，讓 clipboard.data 不為 None。
            # 否則被控端一發 CB_FORMAT_DATA_REQUEST（想讀我們的剪貼簿）時，
            # aardwolf 的 _handle_format_data_request 會存取 None.datatype → 整條 RDP 斷線。
            with contextlib.suppress(Exception):
                await conn.set_current_clipboard_text("")

        await _bridge(websocket, conn, send, clip_enabled=clip_enabled)

    except WebSocketDisconnect:
        _log.info("rdp: 控制端離線 host=%s", host)
    except Exception:  # 對外不洩漏堆疊，但伺服器端一定要留下來
        _log.exception("rdp: 未預期錯誤 host=%s engine=%s", host, engine)
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
                    await _audit_rdp(
                        actor_user_id=str(user_id), actor_ip=actor_ip, object_id=str(address_id),
                        action="rdp.session_close", diff={"host": host, "duration_seconds": round(dur, 1)},
                    )
        with contextlib.suppress(Exception):
            if not guac_mode:
                await send({"type": "status", "state": "disconnected"})
            await websocket.close()


def _is_video(data: Any) -> bool:
    """這一筆是不是畫面更新。

    兩個引擎送的物件不同：aardwolf 的帶 `.type`（RDPDATATYPE.VIDEO），FreeRDP 那邊是
    我們自己的 `VideoTile`。不能只認 aardwolf 的列舉 —— 那會讓 FreeRDP 的畫面
    一張都送不出去，而且不會有任何錯誤，只是畫面永遠空白。
    """
    if not getattr(data, "data", None):
        return False
    t = getattr(data, "type", None)
    if t is None:                                  # VideoTile：沒有 type 欄位
        return True
    return RDP_AVAILABLE and t == RDPDATATYPE.VIDEO



async def _bridge(websocket: WebSocket, conn: Any, send: Any, *, clip_enabled: bool = False) -> None:
    """雙向 pump：RDP 視訊→ws（PNG tile）、ws→直接呼叫 send_mouse/send_key。

    clip_enabled 時額外接受 {type:"clip", text} → 單向把文字塞進被控端剪貼簿（控制端→被控端）。
    伺服器→控制端的剪貼簿一律不回傳（pump_out 只送視訊），維持單向、不外洩被控端剪貼簿。
    """

    frames = 0      # 送出過幾張畫面：一張都沒有就被結束＝伺服器在工作階段一開始就拒絕了

    async def pump_out() -> None:
        nonlocal frames
        with contextlib.suppress(Exception):
            while True:
                data = await conn.ext_out_queue.get()
                if data is None:
                    break
                if _is_video(data):
                    frames += 1
                    await send({
                        "type": "img", "x": data.x, "y": data.y,
                        "w": data.width, "h": data.height,
                        "d": base64.b64encode(data.data).decode("ascii"),
                    })

    async def pump_in() -> None:
        mods_down: set[str] = set()   # 目前按住的 Ctrl/Alt/Meta（決定字母鍵走 scancode 還是 unicode）
        char_warned = False           # 打不出來的字元只提醒一次（整句中文會逐字進來）
        # ⚠️ 不要用 suppress(Exception) 把整個迴圈包起來。輸入處理丟出例外時，畫面還在跑、
        # 滑鼠鍵盤卻全無反應，而伺服器端一行紀錄都沒有 —— 這種「看起來活著」的失效
        # 最難查（2026-09-17 為此查了一輪）。斷線是正常結束，其餘一律留下來。
        try:
            while True:
                # 不做應用層 idle-timeout（背景分頁 heartbeat 會被節流誤判斷線）；保活靠 WS
                # 傳輸層 uvicorn ws-ping/pong，真正斷線走 WebSocketDisconnect。
                raw = await websocket.receive_text()
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "m":
                    x, y = int(msg.get("x", 0)), int(msg.get("y", 0))
                    if msg.get("wheel"):
                        steps = _WHEEL_DELTA + (_WHEEL_NEGATIVE if int(msg.get("dir", -1)) < 0 else 0)
                        await conn.send_mouse(_BTN_WHEEL, x, y, False, steps)
                    elif msg.get("move"):
                        await conn.send_mouse(_BTN_HOVER, x, y, False)
                    else:
                        await conn.send_mouse(_mouse_button(msg.get("b", 0)), x, y, bool(msg.get("p")))
                elif t == "k":
                    pressed = bool(msg.get("p"))
                    key = msg.get("key", "")
                    code = msg.get("code", "")
                    if key in _SPECIAL_KEYS:
                        sc, ext = _SPECIAL_KEYS[key]
                        await conn.send_key_scancode(sc, pressed, ext)
                        if key in ("Control", "Alt", "Meta"):
                            mods_down.add(key) if pressed else mods_down.discard(key)
                    elif mods_down and code in _CODE_SCANCODES:
                        # 按住 Ctrl/Alt/Meta 時改用 scancode（unicode 字元不會與 scancode 修飾鍵組合）
                        await conn.send_key_scancode(_CODE_SCANCODES[code], pressed, False)
                    else:
                        ch = msg.get("ch", "")
                        if len(ch) == 1:
                            try:
                                await conn.send_key_char(ch, pressed)
                            except UnsupportedCharacter as bad:
                                # FreeRDP 引擎打不出非 ASCII 字元（xfreerdp 沒有 Unicode
                                # 輸入通道）。**不可以安靜吞掉** —— 使用者會以為鍵盤壞了。
                                # 整句中文會逐字丟過來，所以一條連線只講一次。
                                if not char_warned:
                                    char_warned = True
                                    await send({"type": "notice", **ui_detail(
                                        "console_char_not_typable",
                                        "這個字元無法直接輸入，請改用貼上",
                                        char=bad.char)})
                elif t == "clip":
                    # 控制端貼上：把文字寫進被控端剪貼簿（單向、純文字、長度上限 100k）
                    if clip_enabled:
                        text = str(msg.get("text", ""))[:100000]
                        ok = False
                        if text:
                            try:
                                await conn.set_current_clipboard_text(text)
                                ok = True
                            except Exception as e:
                                logging.getLogger("jt-ipam.rdp").warning("clip set failed: %r", e)
                        # 回報實際收到/設定的字數，前端據此提示
                        with contextlib.suppress(Exception):
                            await send({"type": "clip_ack", "n": len(text), "ok": ok})
                elif t == "ping":
                    await send({"type": "pong"})
                elif t == "close":
                    break
        except WebSocketDisconnect:
            pass
        except Exception:
            _log.exception("rdp: 輸入處理中止（畫面會還在，但滑鼠鍵盤不再有反應）")

    out_task = asyncio.create_task(pump_out())
    in_task = asyncio.create_task(pump_in())
    done, pending = await asyncio.wait({out_task, in_task}, return_when=asyncio.FIRST_COMPLETED)
    # 畫面那一端先結束、瀏覽器還開著＝被控端結束了工作階段（不是使用者關掉分頁）
    remote_ended = out_task in done and in_task not in done
    for p in pending:
        p.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    # 被控端主動結束時要說得出原因。少了這一段，畫面就只是停住不動，
    # 使用者會以為是網路慢而一直等下去。
    reason = getattr(conn, "exit_reason", None)
    if reason:
        _log.info("rdp: 被控端結束了工作階段：%s", reason)
        with contextlib.suppress(Exception):
            # 翻譯是「被控端結束了這個工作階段：{reason}」——「reason」要走參數，
            # 不能只放在 message，否則前端用翻譯時那一段會是空的
            await send({"type": "error",
                        **ui_detail("console_remote_closed", reason, reason=reason)})
    elif remote_ended:
        # aardwolf 不給中斷原因（GitHub issue #42：它的讀取迴圈拿到 None 就丟 TypeError，
        # 真正的原因被蓋掉）。至少分得出「還沒出畫面就被拒」與「用到一半被結束」。
        _log.info("rdp: 被控端結束了工作階段（沒有原因；已送出 %s 張畫面）", frames)
        detail = (ui_detail(
            "console_remote_ended_early",
            "遠端主機在工作階段一開始就結束了連線，還沒送出任何畫面。常見原因：這個帳號沒有"
            "遠端登入權限、遠端桌面授權或連線代理拒絕、工作階段數已滿。可改用 FreeRDP 引擎"
            "（系統設定 → RDP 引擎），它會顯示伺服器給的原因。")
            if frames == 0 else
            ui_detail("console_remote_ended", "遠端主機結束了這個工作階段（沒有提供原因）"))
        with contextlib.suppress(Exception):
            await send({"type": "error", **detail})
