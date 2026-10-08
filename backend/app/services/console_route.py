"""主控台的連線出口：直連，或經由一台 SSH 跳板（issue #24 階段一）。

六個主控台（ssh / sftp / rdp / vnc / novnc / bmc）本來都是後端**直接**連目標 IP。
客戶站台若只能經由自己的跳板抵達，直連就到不了 —— 而且多個客戶用相同的私網網段時，
單看 IP 字串根本分不出要走哪一條路。

**歧義其實已被結構解決**：主控台是從一筆 IP 記錄啟動的，而每筆 IP 必然屬於唯一一個子網路，
所以把出口掛在子網路（IP 可覆寫）上天生不會弄錯。

用法（六個主控台共用同一個接縫）：

    route = await resolve_route(session, ip)
    async with dial(route, host, port) as (host, port):
        ...            # host/port 可能已被換成 127.0.0.1:<本機轉發埠>

`dial()` 對 `Direct` 是零成本的：原樣 yield 回去，不會建立任何連線。

## 為什麼不直接用 `ssh_tunnel.open_tunnel()`

規格原本寫「複用 `open_tunnel()`」，但它每呼叫一次就**開一條新的 SSH 連線**，
而這裡要求「同一跳板的多個 session 共用一條連線」。兩者不相容，所以這裡自己管連線集區，
但**沿用 `ssh_tunnel` 的安全零件**：`LEGACY_SSH_ALGS`（老舊網路裝置的相容演算法）、
host key 指紋計算與 `SSHHostKeyMismatch`。安全行為因此與既有的 SSH 通道一致。

## 這裡刻意不做的事

- **不接受呼叫端指定跳板**：出口只從資料庫的指派推導。否則主控台就會退化成
  「可以連任何地方的通用 proxy」，那正是原本每個主控台都特意防掉的（見各檔開頭）。
- **host key 沒釘選就不連**：跳板是整條路徑的中間人，這一步不能省。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.core.ui_error import ui_detail
from app.models.address import IPAddress
from app.models.jump_host import JumpHost
from app.models.subnet import Subnet
from app.services.ssh_tunnel import (
    LEGACY_SSH_ALGS,
    SSHHostKeyMismatch,
    SSHTunnelError,
    server_key_fingerprint_sha256,
)

#: 建立跳板連線的逾時。比主控台本身的逾時短 —— 跳板不通時要快點講，
#: 不要讓使用者盯著一個沒有回應的終端機。
CONNECT_TIMEOUT = 15.0


class JumpHostError(RuntimeError):
    """跳板連線失敗。訊息會直接顯示給使用者，要說得出原因。

    除了人話訊息，另外帶 `code` 與參數：那段文字會出現在畫面上，只給中文句子等於
    英文與日文的使用者也看到中文。翻譯由前端用 `errors.<code>` 做，這裡只負責
    「是哪一種錯、參數是什麼」。`str(exc)` 仍是中文，作為沒有翻譯時的退路。
    """

    def __init__(self, message: str, *, code: str | None = None, **params: object) -> None:
        super().__init__(message)
        self.code = code
        self.params = params


@dataclass(frozen=True)
class Direct:
    """不經跳板。"""


@dataclass(frozen=True)
class ViaJumpHost:
    """經由這台跳板。只帶連線需要的欄位，不把整個 ORM 物件拖進 WS 生命週期。"""

    id: uuid.UUID
    name: str
    host: str
    port: int
    username: str
    auth_kind: str
    secret: str                    # 私鑰 PEM 或密碼（已解密，僅存在記憶體）
    host_key_fingerprint: str | None
    max_sessions: int


@dataclass(frozen=True)
class ViaAgent:
    """經由掃描代理中繼（issue #24 階段二）：後端連不進客戶網路，由代理往外撥回來。"""

    id: uuid.UUID
    name: str
    max_sessions: int
    ports: tuple[int, ...] = ()        # 代理回報它允許中繼的埠（空＝不限，由代理自己把關）


Route = Direct | ViaJumpHost | ViaAgent


class RelayError(JumpHostError):
    """經由代理中繼失敗。繼承 JumpHostError：六個主控台既有的錯誤處理直接接得住。"""


#: 代理回報的錯誤代號 → (錯誤代碼, 退路文字)。代理只回代號與一段原因，句子在這裡組。
_AGENT_ERRORS: dict[str, tuple[str, str]] = {
    "relay_disabled": ("relay_agent_host_off", "代理主機以 JT_IPAM_RELAY=0 關閉了中繼"),
    "relay_busy": ("relay_agent_busy", "代理的同時中繼數已達上限"),
    "relay_target_not_allowed": ("relay_target_not_allowed", "代理拒絕：目標不在它被指派的子網路內"),
    "relay_port_not_allowed": ("relay_port_not_allowed", "代理拒絕：這個埠不在它允許中繼的清單內"),
    "relay_connect_failed": ("relay_connect_failed", "代理連不上目標"),
    "relay_ws_failed": ("relay_ws_failed", "代理撥回伺服器失敗"),
}


# ─────────────────── 機密欄位 ───────────────────
def _aad(jump_id: uuid.UUID, field: str) -> bytes:
    return f"jump_host:{jump_id}:{field}".encode()


def encrypt_secret_for(jump_id: uuid.UUID, field: str, value: str) -> tuple[bytes, bytes]:
    return encrypt_secret(value, aad=_aad(jump_id, field))


def _decrypt(jump: JumpHost) -> str:
    field = "private_key" if jump.auth_kind == "key" else "password"
    enc = jump.private_key_enc if field == "private_key" else jump.password_enc
    nonce = jump.private_key_nonce if field == "private_key" else jump.password_nonce
    if not enc or not nonce:
        raise JumpHostError(
            f"跳板「{jump.name}」還沒有設定{'金鑰' if field == 'private_key' else '密碼'}",
            code=("jump_host_no_key" if field == "private_key" else "jump_host_no_password"),
            name=jump.name,
        )
    return decrypt_secret(enc, nonce, aad=_aad(jump.id, field)).decode("utf-8")


# ─────────────────── 解析 ───────────────────
async def resolve_route(session: AsyncSession, ip: IPAddress) -> Route:
    """這筆 IP 的主控台該走哪條路：**IP 覆寫 > 子網路 > 直連**。

    指派了跳板、但跳板停用中 → **拒絕連線**（2026-10-02 改，issue #24）。以前是退回直連：
    用跳板的站台多半是多個客戶共用相同私網網段，直連等於拿同一個位址連到後端自己網路上的那台，
    也就是連錯主機，而且畫面上一切正常。要直連就把子網路／IP 的跳板指派拿掉（明確的動作）。
    """
    # IP 上有任何一種出口設定就用 IP 的（跳板或代理擇一）；沒有才看子網路
    jump_id, agent_id = ip.jump_host_id, ip.console_agent_id
    if jump_id is None and agent_id is None and ip.subnet_id is not None:
        subnet = await session.get(Subnet, ip.subnet_id)
        if subnet is not None:
            jump_id, agent_id = subnet.jump_host_id, subnet.console_agent_id
    if agent_id is not None:
        return await _resolve_agent(session, agent_id)
    if jump_id is None:
        return Direct()

    jump = await session.get(JumpHost, jump_id)
    if jump is None:
        return Direct()             # 外鍵是 SET NULL：刪掉跳板時指派一起清掉，這裡只是防禦
    if not jump.enabled:
        raise JumpHostError(
            f"跳板「{jump.name}」已停用：為避免在重疊網段連錯主機，不會改用直連。"
            "要直連請移除子網路或 IP 上的跳板指派",
            code="jump_host_disabled", name=jump.name,
        )
    return ViaJumpHost(
        id=jump.id, name=jump.name, host=jump.host, port=jump.port,
        username=jump.username, auth_kind=jump.auth_kind, secret=_decrypt(jump),
        host_key_fingerprint=jump.host_key_fingerprint,
        max_sessions=jump.max_sessions,
    )


async def describe_route(session: AsyncSession, ip: IPAddress) -> dict[str, Any]:
    """連線表單上的「連線路徑」：走哪條路、設定在 IP 還是子網路上、現在走不走得通。

    與實際連線用同一個 resolve_route，畫面講的就是按下連線後會發生的事；走不通時帶錯誤代碼，
    讓使用者在按連線之前就知道（而不是按下去才失敗）。"""
    source: str | None = None
    if ip.jump_host_id is not None or ip.console_agent_id is not None:
        source = "ip"
    elif ip.subnet_id is not None:
        subnet = await session.get(Subnet, ip.subnet_id)
        if subnet is not None and (subnet.jump_host_id is not None or subnet.console_agent_id is not None):
            source = "subnet"
    try:
        route = await resolve_route(session, ip)
    except JumpHostError as exc:
        kind = "agent" if isinstance(exc, RelayError) else "jump"
        params = dict(getattr(exc, "params", {}) or {})
        return {"kind": kind, "name": params.get("name"), "source": source, "ok": False,
                "code": getattr(exc, "code", None), "params": params, "message": str(exc)}
    if isinstance(route, ViaAgent):
        return {"kind": "agent", "name": route.name, "source": source, "ok": True}
    if isinstance(route, ViaJumpHost):
        if not route.host_key_fingerprint:
            return {"kind": "jump", "name": route.name, "source": source, "ok": False,
                    **ui_detail("jump_host_key_unpinned",
                                f"跳板「{route.name}」尚未信任主機金鑰：請先到管理頁按「測試連線」核對指紋",
                                name=route.name)}
        return {"kind": "jump", "name": route.name, "source": source, "ok": True}
    return {"kind": "direct", "name": None, "source": None, "ok": True}


async def _resolve_agent(session: AsyncSession, agent_id: uuid.UUID) -> Route:
    """出口是掃描代理：網頁上兩道開關（系統、逐台代理）都要開，代理主機沒有否決，
    **任何一道沒開就拒絕，不退回直連**。埠與上限照掃描代理頁的設定（代理主機有本機限縮時取交集）。"""
    from app.models.scan_agent import ScanAgent
    from app.services.system_config import get_console_relay_enabled

    agent = await session.get(ScanAgent, agent_id)
    if agent is None:
        return Direct()             # 外鍵是 SET NULL，這裡只是防禦
    name = agent.name
    if not await get_console_relay_enabled(session):
        raise RelayError(f"系統沒有開啟「經由掃描代理中繼主控台」，不會改用直連（代理「{name}」）",
                         code="relay_disabled_system", name=name)
    if not agent.enabled:
        raise RelayError(f"掃描代理「{name}」已停用，不會改用直連", code="relay_agent_disabled", name=name)
    if not agent.relay_allowed:
        raise RelayError(f"掃描代理「{name}」沒有被允許中繼主控台", code="relay_agent_not_allowed", name=name)
    caps = agent.relay_caps if isinstance(agent.relay_caps, dict) else {}
    if not caps:
        raise RelayError(f"掃描代理「{name}」沒有回報中繼能力（代理版本太舊，或還沒連上來）",
                         code="relay_agent_not_capable", name=name)
    if not caps.get("enabled"):
        raise RelayError(f"掃描代理「{name}」的主機以 JT_IPAM_RELAY=0 關閉了中繼",
                         code="relay_agent_host_off", name=name)
    from app.services.relay_scope import DEFAULT_PORTS, parse_ports
    ports = parse_ports(agent.relay_ports or DEFAULT_PORTS)
    local = {int(p) for p in (caps.get("ports") or []) if str(p).isdigit()}
    if local:
        ports = [p for p in ports if p in local]
    limit = agent.relay_max_sessions
    if str(caps.get("max") or "").isdigit() and int(caps["max"]) > 0:
        limit = min(limit, int(caps["max"]))
    return ViaAgent(id=agent.id, name=name, max_sessions=limit, ports=tuple(ports))


def route_label(route: Route) -> str | None:
    """稽核與 UI 用：經由哪個跳板或代理（直連回 None）。"""
    return route.name if isinstance(route, ViaJumpHost | ViaAgent) else None


def route_kind(route: Route) -> str | None:
    """`jump`／`agent`；直連回 None。主控台狀態列用來顯示「經由跳板」或「經由掃描代理」。"""
    if isinstance(route, ViaJumpHost):
        return "jump"
    if isinstance(route, ViaAgent):
        return "agent"
    return None


# ─────────────────── 連線集區 ───────────────────
@dataclass
class _Pooled:
    conn: asyncssh.SSHClientConnection
    refs: int = 0


#: jump_host_id → 共用連線。多個 session 共用一條 SSH 連線（asyncssh 一條連線可開多個轉發），
#: 最後一個 session 離開就關掉 —— 不留閒置連線掛在客戶的跳板上。
_pool: dict[uuid.UUID, _Pooled] = {}
_pool_lock = asyncio.Lock()


def _client_factory(expected_fp: str) -> type[asyncssh.SSHClient]:
    """比對釘選指紋；不符就丟 `SSHHostKeyMismatch`（＝可能有中間人）。"""

    class _Strict(asyncssh.SSHClient):
        def validate_host_public_key(self, host, addr, port, key):  # type: ignore[no-untyped-def]
            b64 = key.export_public_key("openssh").decode("ascii").split()[1]
            actual = server_key_fingerprint_sha256(base64.b64decode(b64))
            if actual != expected_fp:
                raise SSHHostKeyMismatch(expected_fp, actual)
            return True

    return _Strict


async def _connect(jump: ViaJumpHost) -> asyncssh.SSHClientConnection:
    if not jump.host_key_fingerprint:
        # 沒釘選就連＝接受任何 host key，而跳板是整條路徑的中間人。
        # 指紋要在管理頁按「測試連線」時取回並確認。
        raise JumpHostError(
            f"跳板「{jump.name}」尚未信任主機金鑰：請先到管理頁按「測試連線」核對指紋",
            code="jump_host_key_unpinned", name=jump.name,
        )
    opts: dict[str, Any] = {
        "username": jump.username,
        "client_factory": _client_factory(jump.host_key_fingerprint),
        "known_hosts": None,
        "agent_path": None,          # 不繼承 ssh-agent
        **LEGACY_SSH_ALGS,
    }
    if jump.auth_kind == "key":
        try:
            opts["client_keys"] = [asyncssh.import_private_key(jump.secret)]
        except Exception as exc:
            raise JumpHostError(
                f"跳板「{jump.name}」的私鑰無法解析：{exc}",
                code="jump_host_bad_key", name=jump.name, reason=str(exc)[:200],
            ) from exc
        opts["preferred_auth"] = ("publickey",)
    else:
        opts["password"] = jump.secret
        opts["client_keys"] = []      # 不要讓 asyncssh 去翻本機的 ~/.ssh
        opts["preferred_auth"] = ("keyboard-interactive", "password")

    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            return await asyncssh.connect(jump.host, port=jump.port, **opts)
    except SSHHostKeyMismatch as exc:
        raise JumpHostError(
            f"跳板「{jump.name}」的主機金鑰與釘選的不符（可能遭中間人攔截）：{exc}",
            code="jump_host_key_changed", name=jump.name, reason=str(exc)[:200],
        ) from exc
    except TimeoutError as exc:
        raise JumpHostError(
            f"連跳板「{jump.name}」（{jump.host}:{jump.port}）逾時 {CONNECT_TIMEOUT:.0f} 秒",
            code="jump_host_timeout", name=jump.name, host=jump.host, port=jump.port,
            seconds=f"{CONNECT_TIMEOUT:.0f}",
        ) from exc
    except asyncssh.PermissionDenied as exc:
        raise JumpHostError(
            f"跳板「{jump.name}」認證失敗：{exc}",
            code="jump_host_auth_failed", name=jump.name, reason=str(exc)[:200],
        ) from exc
    except (asyncssh.Error, OSError) as exc:
        # 帶上底層原文：ConnectError 一個名字底下有 DNS／拒絕／路由不通好幾種，
        # 少了原因就只能猜（與 core/safe_http.transport_detail 同一條原則）
        raise JumpHostError(
            f"連不上跳板「{jump.name}」（{jump.host}:{jump.port}）："
            f"{exc.__class__.__name__}: {exc}",
            code="jump_host_connect_failed", name=jump.name, host=jump.host, port=jump.port,
            reason=f"{exc.__class__.__name__}: {exc}"[:200],
        ) from exc


@dataclass
class Tunnel:
    """要連的位址，外加「用完要還」。

    直連時 `aclose()` 什麼都不做 —— 呼叫端因此不必分辨自己走的是哪一條路。
    做成命令式而不是只有 context manager：六個主控台的連線是一大段既有的
    try/except，包成 `async with` 得整段重新縮排，那種改法最容易在協定層改錯東西。
    """

    host: str
    port: int
    via: str | None = None                 # 經由哪個跳板或代理（稽核與 UI 用）
    via_kind: str | None = None            # "jump"／"agent"
    _listener: Any = None
    _jump_id: uuid.UUID | None = None
    _relay: tuple[uuid.UUID, str] | None = None     # (代理 id, session id)
    _closed: bool = False

    async def aclose(self) -> None:
        if self._closed:
            return                          # aclose() 要可以被呼叫兩次（finally 疊 finally）
        self._closed = True
        if self._listener is not None:
            self._listener.close()
        if self._relay is not None:
            from app.services import console_relay
            # 中繼本身由 worker A 那條 TCP 的關閉帶動結束；這裡只把同時連線的名額還回去
            with contextlib.suppress(Exception):
                await console_relay.release_slot(*self._relay)
            return
        if self._jump_id is None:
            return
        async with _pool_lock:
            pooled = _pool.get(self._jump_id)
            if pooled is None:
                return
            pooled.refs -= 1
            if pooled.refs <= 0:
                _pool.pop(self._jump_id, None)
                pooled.conn.close()


async def open_route(route: Route, host: str, port: int, *,
                     user_id: uuid.UUID | None = None, purpose: str = "console") -> Tunnel:
    """取得可連的位址。**呼叫端必須在 finally 裡 `await tunnel.aclose()`。**

    `user_id`／`purpose` 只有經由代理中繼時會用到（寫進票證，中繼結束的稽核記得是誰、哪個主控台）。
    """
    if isinstance(route, Direct):
        return Tunnel(host=host, port=port)
    if isinstance(route, ViaAgent):
        return await _open_via_agent(route, host, port, user_id=user_id, purpose=purpose)

    async with _pool_lock:
        pooled = _pool.get(route.id)
        if pooled is None:
            conn = await _connect(route)
            pooled = _Pooled(conn=conn)
            _pool[route.id] = pooled
        elif pooled.refs >= route.max_sessions:
            raise JumpHostError(
                f"跳板「{route.name}」同時連線數已達上限 {route.max_sessions}，請稍後再試",
                code="jump_host_at_capacity", name=route.name, max=route.max_sessions,
            )
        pooled.refs += 1

    tunnel = Tunnel(host="", port=0, via=route.name, via_kind="jump", _jump_id=route.id)
    try:
        listener = await pooled.conn.forward_local_port("127.0.0.1", 0, host, port)
    except (asyncssh.Error, OSError) as exc:
        await tunnel.aclose()               # 還沒轉發成功也要把 refs 還回去
        raise JumpHostError(
            f"跳板「{route.name}」無法轉發到 {host}:{port}："
            f"{exc.__class__.__name__}: {exc}",
            code="jump_host_forward_failed", name=route.name, host=host, port=port,
            reason=f"{exc.__class__.__name__}: {exc}"[:200],
        ) from exc
    tunnel.host, tunnel.port, tunnel._listener = "127.0.0.1", listener.get_port(), listener
    return tunnel


def _agent_error(name: str, raw: dict[str, Any]) -> RelayError:
    """代理回報的失敗 → 帶錯誤代碼的例外。舊代理不認得 relay_open 會回 unsupported。"""
    token = str(raw.get("error") or "")
    reason = str(raw.get("reason") or "")[:200]
    if token.startswith("unsupported"):
        return RelayError(f"掃描代理「{name}」的版本不支援中繼，請更新代理",
                          code="relay_agent_not_capable", name=name)
    code, text = _AGENT_ERRORS.get(token, ("relay_failed", "中繼失敗"))
    return RelayError(f"經由掃描代理「{name}」中繼失敗：{text}" + (f"（{reason}）" if reason else ""),
                      code=code, name=name, reason=reason)


async def _open_via_agent(route: ViaAgent, host: str, port: int, *,
                          user_id: uuid.UUID | None, purpose: str) -> Tunnel:
    """請代理開一條中繼，等 worker A 回報本機埠。**失敗一律報錯，絕不退回直連。**"""
    from app.core.db import SessionLocal
    from app.services import console_relay
    from app.services.agent_probe import cancel_relay_job, create_relay_job

    if route.ports and port not in route.ports:
        raise RelayError(f"掃描代理「{route.name}」不中繼 {port} 埠（代理允許：{', '.join(map(str, route.ports))}）",
                         code="relay_port_not_allowed", name=route.name, port=port)
    sid = console_relay.new_session_id()
    if not await console_relay.acquire_slot(route.id, sid, route.max_sessions):
        raise RelayError(f"掃描代理「{route.name}」同時中繼數已達上限 {route.max_sessions}，請稍後再試",
                         code="relay_at_capacity", name=route.name, max=route.max_sessions)
    job_id: uuid.UUID | None = None
    try:
        ticket = await console_relay.issue_ticket(sid, agent_id=route.id, target=host, port=port,
                                                  user_id=user_id, kind=purpose)
        async with SessionLocal() as s:
            from app.models.scan_agent import ScanAgent
            from app.services.relay_scope import relay_scope
            agent = await s.get(ScanAgent, route.id)
            scope = await relay_scope(s, agent) if agent is not None else None
            job = await create_relay_job(s, agent_id=route.id, sid=sid, ticket=ticket,
                                         target=host, port=port, requested_by=user_id, scope=scope)
            await s.commit()
            job_id = job.id
        ready = await console_relay.wait_ready(sid)
        if ready is None:
            await console_relay.discard_ticket(sid)
            async with SessionLocal() as s:
                await cancel_relay_job(s, job_id)
                await s.commit()
            raise RelayError(
                f"掃描代理「{route.name}」沒有在 {console_relay.READY_TIMEOUT} 秒內回應，可能離線或沒有開啟中繼",
                code="relay_agent_timeout", name=route.name, seconds=console_relay.READY_TIMEOUT)
        if "error" in ready:
            raise _agent_error(route.name, ready)
        local_port = int(ready["port"])
    except BaseException:
        with contextlib.suppress(Exception):
            await console_relay.release_slot(route.id, sid)
        raise
    return Tunnel(host="127.0.0.1", port=local_port, via=route.name, via_kind="agent",
                  _relay=(route.id, sid))


@contextlib.asynccontextmanager
async def dial(route: Route, host: str, port: int) -> AsyncIterator[tuple[str, int]]:
    """`open_route()` 的 context manager 版本（新程式碼與測試用）。"""
    tunnel = await open_route(route, host, port)
    try:
        yield tunnel.host, tunnel.port
    finally:
        await tunnel.aclose()


async def probe(jump: JumpHost) -> dict[str, Any]:
    """管理頁的「測試連線」：取回主機金鑰指紋，並在已釘選時實際登入一次。

    未釘選時**只取指紋、不登入** —— 指紋還沒被人確認之前，把帳密送過去就已經太遲了。
    """
    from app.services.ssh_tunnel import fetch_host_key

    out: dict[str, Any] = {"host": jump.host, "port": jump.port}
    try:
        hk = await fetch_host_key(jump.host, port=jump.port, timeout=CONNECT_TIMEOUT)
    except SSHTunnelError as exc:
        raise JumpHostError(
            f"連不上跳板：{exc}", code="jump_host_unreachable", reason=str(exc)[:200],
        ) from exc
    out["fingerprint"] = hk["fingerprint"]
    out["pinned"] = jump.host_key_fingerprint
    out["matches"] = (jump.host_key_fingerprint == hk["fingerprint"]
                      if jump.host_key_fingerprint else None)

    if not jump.host_key_fingerprint:
        out["authenticated"] = False
        out["note"] = "尚未釘選主機金鑰：請核對指紋後按「信任並儲存」，之後才會實際登入測試"
        return out
    if out["matches"] is False:
        raise JumpHostError(
            f"主機金鑰與釘選的不符（可能遭中間人攔截）：釘選 {jump.host_key_fingerprint}，"
            f"實際 {hk['fingerprint']}",
            code="jump_host_fingerprint_changed",
            pinned=jump.host_key_fingerprint, actual=hk["fingerprint"],
        )

    route = ViaJumpHost(
        id=jump.id, name=jump.name, host=jump.host, port=jump.port,
        username=jump.username, auth_kind=jump.auth_kind, secret=_decrypt(jump),
        host_key_fingerprint=jump.host_key_fingerprint, max_sessions=jump.max_sessions,
    )
    conn = await _connect(route)
    try:
        out["authenticated"] = True
        out["server_version"] = getattr(conn, "get_extra_info", lambda *_: None)("server_version")
    finally:
        conn.close()
    out["checked_at"] = datetime.now(UTC).isoformat()
    return out


# ─────────────────── 出口設定的驗證（子網路與 IP 的編輯共用）───────────────────
class EgressError(ValueError):
    def __init__(self, message: str, *, code: str, **params: object) -> None:
        super().__init__(message)
        self.code = code
        self.params = params


async def normalize_egress(session: AsyncSession, changes: dict[str, Any], *,
                           scan_agent_id: uuid.UUID | None) -> None:
    """編輯子網路／IP 時整理「主控台出口」：跳板與代理只能擇一，代理必須是這個子網路的掃描代理。

    只改一邊時另一邊自動清掉（選了代理就不再經跳板，反之亦然；能推的就不要求使用者先手動清空）。
    兩邊同時帶非空值才算矛盾。`scan_agent_id`：子網路（或 IP 所屬子網路）套用這次變更後的掃描代理。
    """
    from app.models.scan_agent import ScanAgent

    jump = changes.get("jump_host_id")
    agent = changes.get("console_agent_id")
    if jump is not None and agent is not None:
        raise EgressError("主控台出口只能選一種：跳板或掃描代理", code="console_egress_both")
    if agent is not None:
        changes["jump_host_id"] = None
        row = await session.get(ScanAgent, agent)
        if row is None:
            raise EgressError("找不到這台掃描代理", code="console_agent_not_found")
        if scan_agent_id != row.id:
            # 代理的自我允許清單只認它被指派掃描的子網路；指到別台的子網路，代理一定會拒絕
            raise EgressError(f"掃描代理「{row.name}」沒有被指派到這個子網路，無法經由它中繼",
                              code="console_agent_not_assigned", name=row.name)
    elif jump is not None:
        changes["console_agent_id"] = None
