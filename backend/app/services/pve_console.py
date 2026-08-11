"""PVE 主控台連線（noVNC / xterm）。

針對對應到 Proxmox VE 的 IP：用「使用者輸入的 PVE 帳密」向 Proxmox 取得 vncproxy（qemu VM→noVNC 圖形）
或 termproxy（lxc CT→xterm 終端機）ticket，再由後端對接 PVE 的 vncwebsocket、與瀏覽器位元組對接。

為何要使用者帳密：PVE 的 vncwebsocket **只認 PVEAuthCookie（登入 ticket），不接受 API token** —— 因此
無法沿用同步用的 token；且這樣 PVE 端的權限（VM.Console）會親自把關，權限不足就連不上。

安全：
- 所有對外請求走 safe_request（SSRF 防護）。
- PVE host 由 ProxmoxInstance.api_url 決定（管理員設定，非使用者提供）→ 不會被當開放代理。
- 帳密只在鑄票當下用一次；可選擇存進既有憑證金庫（protocol='pve'，AES-GCM），不落 log/不回前端。
"""

from __future__ import annotations

import ssl
import urllib.parse
from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request
from app.models.virt import ProxmoxInstance, VirtCluster, VirtualMachine, VMInterface


class PveConsoleError(Exception):
    def __init__(self, message: str, *, code: str = "pve_error", status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = status


@dataclass
class PveTarget:
    kind: str            # "vm"（qemu→noVNC）/ "ct"（lxc→xterm）
    node: str            # PVE 節點 host
    vmid: int            # Proxmox VMID
    cluster_name: str | None
    base_url: str        # https://host:8006
    verify_tls: bool


def _q(s: object) -> str:
    return urllib.parse.quote(str(s), safe="")


async def resolve_pve_target(session: AsyncSession, ip: object) -> PveTarget | None:
    """IP → 對應的 Proxmox VM/CT 主控台目標；非 PVE VM/CT 回 None。"""
    ip_id = getattr(ip, "id", None)
    if ip_id is None:
        return None
    vm = (await session.execute(
        select(VirtualMachine).where(VirtualMachine.primary_ip_id == ip_id)
    )).scalars().first()
    if vm is None:
        # 後援：用此 IP 的 MAC 對應到 VM 的網卡 —— 涵蓋「一台 VM 多個 IP」時的非主 IP
        # （resolve 只認 primary_ip_id 會讓 VM 的其他 IP 開不出主控台開關）。
        mac = getattr(ip, "mac", None)
        if mac:
            # MACADDR 欄位 Postgres 原生正規化比對（不需 lower）；以字串傳入由 PG cast。
            vm_id = (await session.execute(
                select(VMInterface.vm_id).where(VMInterface.mac == str(mac)).limit(1)
            )).scalars().first()
            if vm_id is not None:
                vm = await session.get(VirtualMachine, vm_id)
    if vm is None or vm.legacy_vmid is None or not vm.node:
        return None
    inst = (await session.execute(
        select(ProxmoxInstance).where(
            ProxmoxInstance.cluster_id == vm.cluster_id,
            ProxmoxInstance.enabled.is_(True),
        ).limit(1)
    )).scalars().first()
    if inst is None:
        return None
    cluster = (await session.execute(
        select(VirtCluster).where(VirtCluster.id == vm.cluster_id)
    )).scalars().first()
    kind = vm.kind if vm.kind in ("vm", "ct") else "vm"
    return PveTarget(
        kind=kind, node=vm.node, vmid=int(vm.legacy_vmid),
        cluster_name=cluster.name if cluster else None,
        base_url=inst.api_url.rstrip("/"), verify_tls=inst.verify_tls,
    )


def normalize_username(username: str, realm: str | None) -> str:
    """PVE 需要 user@realm；已含 @ 就照用，否則補上 realm（預設 pam）。"""
    username = (username or "").strip()
    if "@" in username:
        return username
    return f"{username}@{(realm or 'pam').strip() or 'pam'}"


async def _ticket_request(
    base_url: str, body: dict[str, object], verify_tls: bool,
) -> dict[str, object]:
    """打一次 POST /access/ticket，回 data 區塊。"""
    url = f"{base_url}/api2/json/access/ticket"
    try:
        resp = await safe_request("POST", url, json=body, timeout=15.0, verify=verify_tls)
    except UnsafeOutboundURL as e:
        raise PveConsoleError(f"SSRF guard: {e}", code="ssrf", status=400) from e
    except httpx.HTTPError as e:
        raise PveConsoleError(f"PVE 連線失敗：{e.__class__.__name__}", code="pve_unreachable") from e
    if resp.status_code in (401, 403):
        raise PveConsoleError("PVE 認證失敗（帳號或密碼錯誤）", code="auth_failed", status=401)
    if resp.status_code != 200:
        raise PveConsoleError(f"PVE /access/ticket：{resp.status_code}", code="pve_error")
    return (resp.json() or {}).get("data") or {}


async def pve_login(
    base_url: str, username: str, password: str, verify_tls: bool,
    *, tfa_code: str | None = None,
) -> tuple[str, str]:
    """POST /access/ticket → (PVEAuthCookie ticket, CSRFPreventionToken)。

    **兩階段驗證（TFA/MFA）**：PVE 對啟用 TFA 的帳號會回 HTTP 200，但內容是
    「挑戰票證」——`{"ticket": "PVE:!tfa!…", "NeedTFA": 1}`。那個 ticket 不能當
    PVEAuthCookie 用；直接拿去開 vncwebsocket 會失敗，而且錯誤訊息完全看不出
    真正原因（GitHub issue #23）。

    正確流程是再打一次 `/access/ticket`，帶 `tfa-challenge=<挑戰票證>` 與
    `password=totp:<6 位數>`，才會換到真正的 ticket。
    沒有提供驗證碼時，丟一個 `tfa_required` 讓上層去跟使用者要，
    而不是讓它變成莫名其妙的連線失敗。
    """
    data = await _ticket_request(
        base_url, {"username": username, "password": password}, verify_tls,
    )
    ticket = data.get("ticket")
    if not ticket:
        raise PveConsoleError("PVE 未回傳登入 ticket", code="auth_failed", status=401)

    # NeedTFA=1，或 ticket 長成挑戰票證的樣子（PVE:!tfa!…）
    needs_tfa = bool(data.get("NeedTFA")) or str(ticket).startswith("PVE:!tfa!")
    if needs_tfa:
        if not tfa_code:
            raise PveConsoleError(
                "此 PVE 帳號啟用了兩階段驗證，請輸入驗證器上的 6 位數驗證碼",
                code="tfa_required", status=401,
            )
        data = await _ticket_request(base_url, {
            "username": username,
            "tfa-challenge": ticket,
            # PVE 以 "<型別>:<碼>" 表示第二因素；TOTP 是最常見的一種
            "password": f"totp:{tfa_code.strip()}",
        }, verify_tls)
        ticket = data.get("ticket")
        if not ticket or str(ticket).startswith("PVE:!tfa!"):
            raise PveConsoleError(
                "兩階段驗證碼不正確或已逾時，請重新輸入",
                code="tfa_failed", status=401,
            )

    return ticket, data.get("CSRFPreventionToken") or ""


async def pve_console_proxy(target: PveTarget, ticket: str, csrf: str) -> tuple[str, int]:
    """qemu→vncproxy / lxc→termproxy（websocket=1）→ (vncticket, port)。"""
    api_path = "qemu" if target.kind == "vm" else "lxc"
    endpoint = "vncproxy" if target.kind == "vm" else "termproxy"
    url = f"{target.base_url}/api2/json/nodes/{_q(target.node)}/{api_path}/{target.vmid}/{endpoint}"
    headers = {"Cookie": f"PVEAuthCookie={ticket}"}
    if csrf:
        headers["CSRFPreventionToken"] = csrf
    # vncproxy（qemu）吃 websocket/generate-password；termproxy（lxc）不接受 websocket 參數（會 400）。
    body: dict[str, object] = {"websocket": 1, "generate-password": 0} if target.kind == "vm" else {}
    try:
        resp = await safe_request(
            "POST", url, headers=headers, json=body, timeout=15.0, verify=target.verify_tls,
        )
    except (UnsafeOutboundURL, httpx.HTTPError) as e:
        raise PveConsoleError(f"PVE proxy 失敗：{e.__class__.__name__}", code="pve_error") from e
    if resp.status_code in (401, 403):
        raise PveConsoleError("PVE 權限不足（此帳號需有該 VM/CT 的 Console 權限）",
                              code="forbidden", status=403)
    if resp.status_code != 200:
        raise PveConsoleError(f"PVE {endpoint}：{resp.status_code} {resp.text[:160]}", code="pve_error")
    data = (resp.json() or {}).get("data") or {}
    vt, port = data.get("ticket"), data.get("port")
    if not vt or not port:
        raise PveConsoleError("PVE 未回傳主控台 ticket/port", code="pve_error")
    return str(vt), int(port)


def pve_vncwebsocket_url(target: PveTarget, port: int, vncticket: str) -> str:
    """PVE vncwebsocket 的 wss URL（後端 client 連這個、再與瀏覽器位元組對接）。"""
    api_path = "qemu" if target.kind == "vm" else "lxc"
    host = target.base_url.split("://", 1)[-1]
    return (f"wss://{host}/api2/json/nodes/{_q(target.node)}/{api_path}/{target.vmid}"
            f"/vncwebsocket?port={port}&vncticket={_q(vncticket)}")


def pve_ssl_context(verify_tls: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
