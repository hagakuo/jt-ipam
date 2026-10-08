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

from app.core.safe_http import UnsafeOutboundURL, safe_request, transport_detail
from app.core.ui_error import UiError
from app.models.virt import ProxmoxInstance, VirtCluster, VirtualMachine, VMInterface


class PveConsoleError(UiError):
    """PVE 登入／proxy 失敗。`code` 同時是前端的 `errors.<code>` 翻譯鍵與流程判斷依據
    （`pve_tfa_required` 要跳出驗證碼欄位），所以改名時兩邊要一起改。"""

    def __init__(self, message: str, *, code: str = "pve_error",
                 status: int = 502, **params: object) -> None:
        super().__init__(message, code=code, **params)
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


def _host(base_url: str) -> str:
    """錯誤訊息裡要講「哪一台 PVE」：https://pve.example.com:8006 → pve.example.com:8006。"""
    return urllib.parse.urlsplit(base_url).netloc or base_url


async def _realms(base_url: str, verify_tls: bool) -> list[str] | None:
    """PVE 有哪些 realm（/access/domains 不用登入就能查，登入頁就是用它）。查不到回 None。"""
    try:
        resp = await safe_request("GET", f"{base_url}/api2/json/access/domains",
                                  timeout=5.0, verify=verify_tls)
    except (UnsafeOutboundURL, httpx.HTTPError):
        return None
    if resp.status_code != 200:
        return None
    rows = (resp.json() or {}).get("data") or []
    return [str(r.get("realm")) for r in rows if isinstance(r, dict) and r.get("realm")]


async def _rejected(base_url: str, username: str, verify_tls: bool) -> PveConsoleError:
    """/access/ticket 回 401／403 時該說什麼。

    PVE 對密碼錯、帳號不存在、帳號停用、realm 不對一律回 401、不給原因（詳細原因只寫在
    該節點的 pvedaemon 日誌）。以前全都翻成「帳號或密碼錯誤」—— 使用者回報用已存帳密
    連不上，看不出是哪裡不對。分得出來的先分：realm 不存在可以查；其餘至少講出是哪一台
    PVE、用哪個帳號，並點出最常見的誤會（填了 VM 自己的帳密）。
    """
    host = _host(base_url)
    realm = username.rsplit("@", 1)[1] if "@" in username else ""
    available = await _realms(base_url, verify_tls)
    if available and realm and realm not in available:
        return PveConsoleError(
            f"PVE（{host}）上沒有 realm「{realm}」，可用的有：{', '.join(available)}",
            code="pve_unknown_realm", status=401,
            host=host, realm=realm, available=", ".join(available),
        )
    return PveConsoleError(
        f"PVE（{host}）拒絕了 {username} 的登入。這裡要的是 Proxmox VE 的帳密，不是這台 VM／CT "
        "自己的；realm 也要對（pam＝PVE 主機的 Linux 帳號、pve＝PVE 內建帳號）。PVE 不會說是密碼錯、"
        "帳號不存在還是被停用，詳細原因在該節點的 journalctl -u pvedaemon",
        code="pve_auth_failed", status=401, user=username, host=host,
    )


async def _ticket_request(
    base_url: str, body: dict[str, object], verify_tls: bool,
) -> dict[str, object]:
    """打一次 POST /access/ticket，回 data 區塊。"""
    url = f"{base_url}/api2/json/access/ticket"
    try:
        # 10 秒：比前端等這個請求的時間短很多 —— PVE 連不上時，錯誤原因要來得及送回畫面。
        # 以前兩邊都是 15 秒，前端先放棄，使用者只看到「取得連線票證失敗」（2026-09-24 本機重現）。
        resp = await safe_request("POST", url, json=body, timeout=10.0, verify=verify_tls)
    except UnsafeOutboundURL as e:
        raise PveConsoleError(f"SSRF guard: {e}", code="pve_ssrf", status=400,
                              reason=str(e)) from e
    except httpx.HTTPError as e:
        # 類別名稱不夠：ConnectError 底下有連線被拒、名稱解析不到、TLS 驗不過好幾種
        why = transport_detail(e)
        raise PveConsoleError(f"PVE（{_host(base_url)}）連線失敗：{why}", code="pve_unreachable",
                              reason=why, host=_host(base_url)) from e
    if resp.status_code in (401, 403):
        raise await _rejected(base_url, str(body.get("username") or ""), verify_tls)
    if resp.status_code != 200:
        raise PveConsoleError(f"PVE /access/ticket：{resp.status_code}", code="pve_ticket_http",
                              status_code=resp.status_code)
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
        raise PveConsoleError("PVE 未回傳登入 ticket", code="pve_no_ticket", status=401)

    # NeedTFA=1，或 ticket 長成挑戰票證的樣子（PVE:!tfa!…）
    needs_tfa = bool(data.get("NeedTFA")) or str(ticket).startswith("PVE:!tfa!")
    if needs_tfa:
        if not tfa_code:
            raise PveConsoleError(
                "此 PVE 帳號啟用了兩階段驗證，請輸入驗證器上的 6 位數驗證碼",
                code="pve_tfa_required", status=401,
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
                code="pve_tfa_failed", status=401,
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
        raise PveConsoleError(f"PVE proxy 失敗：{e.__class__.__name__}", code="pve_proxy_failed",
                              reason=e.__class__.__name__) from e
    if resp.status_code in (401, 403):
        raise PveConsoleError("PVE 權限不足（此帳號需有該 VM/CT 的 Console 權限）",
                              code="pve_forbidden", status=403)
    if resp.status_code != 200:
        raise PveConsoleError(f"PVE {endpoint}：{resp.status_code} {resp.text[:160]}",
                              code="pve_proxy_http", status_code=resp.status_code,
                              body=resp.text[:160])
    data = (resp.json() or {}).get("data") or {}
    vt, port = data.get("ticket"), data.get("port")
    if not vt or not port:
        raise PveConsoleError("PVE 未回傳主控台 ticket/port", code="pve_no_console_ticket")
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
