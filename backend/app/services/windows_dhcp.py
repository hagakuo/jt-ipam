"""Windows DHCP Server 同步（Beta）—— WinRM + PowerShell，唯讀。

與 Windows DNS 共用同一套安全作法：
- `_check_address_safe`：SSRF 防護（封鎖 metadata/link-local；私網需 OUTBOUND_ALLOW_PRIVATE）
- `_safe_ps_arg`：PowerShell 參數允許清單，杜絕指令注入（A03）
- 阻塞式 pywinrm 包進 `asyncio.to_thread`，不卡住 event loop

只做 GET 類的 cmdlet（Get-*），絕不改 Windows DHCP 任何設定。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.safe_http import _BLOCKED_CIDRS, _PRIVATE_CIDRS, _ip_in
from app.core.security import decrypt_secret, encrypt_secret
from app.models.windows_dhcp import WindowsDhcpServer

_PS_SAFE = re.compile(r"^[A-Za-z0-9._:\-/]+$")


class WindowsDhcpError(Exception):
    pass


def _aad(instance_id: Any) -> bytes:
    return f"windows_dhcp_server:{instance_id}:password".encode()


def encrypt_password(instance_id: Any, raw: str) -> tuple[bytes, bytes]:
    return encrypt_secret(raw, aad=_aad(instance_id))


def _decrypt_password(inst: WindowsDhcpServer) -> str:
    return decrypt_secret(inst.password_enc, inst.password_nonce, aad=_aad(inst.id)).decode("utf-8")


def _safe_ps_arg(value: str) -> str:
    if not _PS_SAFE.match(value):
        raise WindowsDhcpError(f"unsafe PowerShell argument: {value!r}")
    return value


def _check_address_safe(host: str) -> None:
    settings = get_settings()
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise WindowsDhcpError(f"DNS resolution failed for {host}") from exc
        addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
    for ip in addrs:
        if _ip_in(ip, _BLOCKED_CIDRS):
            raise WindowsDhcpError(f"Blocked IP for SSRF: {ip}")
        if _ip_in(ip, _PRIVATE_CIDRS) and not settings.outbound_allow_private:
            raise WindowsDhcpError(f"Private IP {ip} not allowed without OUTBOUND_ALLOW_PRIVATE")


class WindowsDhcpClient:
    """對單一台 Windows DHCP Server 的唯讀 WinRM 用戶端。"""

    def __init__(self, *, host: str, username: str, password: str,
                 port: int = 5986, use_ssl: bool = True, verify_tls: bool = True,
                 timeout: float = 30.0) -> None:
        if not host:
            raise WindowsDhcpError("Windows DHCP: host is required")
        _check_address_safe(host)
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _session(self) -> Any:
        # winrm import 放這裡，讓單元測試不必裝齊全部相依
        import winrm
        scheme = "https" if self.use_ssl else "http"
        return winrm.Session(
            target=f"{scheme}://{self.host}:{self.port}/wsman",
            auth=(self.username, self.password),
            transport="ntlm",
            server_cert_validation="validate" if (self.use_ssl and self.verify_tls) else "ignore",
            operation_timeout_sec=int(self.timeout),
            read_timeout_sec=int(self.timeout) + 5,
        )

    def _run_ps(self, script: str) -> str:
        try:
            result = self._session().run_ps(script)
        except WindowsDhcpError:
            raise
        except Exception as exc:   # winrm/requests 的連線/認證/TLS/timeout 都不是我們的例外型別
            raise WindowsDhcpError(
                f"WinRM connection failed: {exc.__class__.__name__}: {exc}"
            ) from exc
        if result.status_code != 0:
            raise WindowsDhcpError(
                f"PowerShell error (rc={result.status_code}): "
                f"{(result.std_err or b'').decode('utf-8', errors='replace')[:300]}"
            )
        return (result.std_out or b"").decode("utf-8", errors="replace")

    def _run_json(self, script: str) -> list[dict[str, Any]]:
        """跑 PowerShell 並解析 JSON；單筆物件也正規化成 list。"""
        out = self._run_ps(script).strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise WindowsDhcpError(f"unexpected PowerShell output: {out[:200]}") from exc
        if isinstance(data, dict):
            return [data]
        return [d for d in data if isinstance(d, dict)]

    # ── 唯讀查詢 ──
    def get_scopes(self) -> list[dict[str, Any]]:
        return self._run_json(
            "Get-DhcpServerv4Scope | Select-Object ScopeId,SubnetMask,StartRange,EndRange,Name,State "
            "| ConvertTo-Json -Depth 4 -Compress"
        )

    def get_reservations(self, scope_id: str) -> list[dict[str, Any]]:
        """Get-DhcpServerv4Reservation：這個 scope 裡被綁定的位址。"""
        sid = _safe_ps_arg(scope_id)
        return self._run_json(
            f"Get-DhcpServerv4Reservation -ScopeId {sid} "
            "| Select-Object IPAddress,ClientId,Name,Description "
            "| ConvertTo-Json -Depth 4 -Compress"
        )

    def get_leases(self, scope_id: str) -> list[dict[str, Any]]:
        sid = _safe_ps_arg(scope_id)
        return self._run_json(
            f"Get-DhcpServerv4Lease -ScopeId {sid} "
            "| Select-Object IPAddress,ClientId,HostName,AddressState "
            "| ConvertTo-Json -Depth 4 -Compress"
        )


def _client(inst: WindowsDhcpServer) -> WindowsDhcpClient:
    return WindowsDhcpClient(
        host=inst.host, username=inst.username, password=_decrypt_password(inst),
        port=inst.port, use_ssl=inst.use_ssl, verify_tls=inst.verify_tls,
    )


def _as_str(v: Any) -> str | None:
    """PowerShell 的 IP 物件序列化後可能是 {'IPAddressToString': '10.0.0.1'} 這種形狀。"""
    if v is None:
        return None
    if isinstance(v, str):
        return v.strip() or None
    if isinstance(v, dict):
        for k in ("IPAddressToString", "Address", "Value"):
            got = v.get(k)
            if isinstance(got, str) and got.strip():
                return got.strip()
    return None


def _norm_mac(v: Any) -> str | None:
    """Windows 的 ClientId 常見為 aa-bb-cc-dd-ee-ff → 正規化成冒號分隔。"""
    s = _as_str(v)
    if not s:
        return None
    s = s.replace("-", ":").lower()
    return s if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", s) else None


async def healthcheck(inst: WindowsDhcpServer) -> dict[str, Any]:
    """測試連線：能列出 scope 就代表 WinRM 認證與 DHCP 權限都通。"""
    cli = _client(inst)
    scopes = await asyncio.to_thread(cli.get_scopes)
    return {"host": inst.host, "scopes": len(scopes)}


async def sync_reservations(session: AsyncSession, inst: WindowsDhcpServer) -> int:
    """Windows DHCP 的保留位址（每個 scope 各問一次）。

    `ClientId` 就是 MAC，格式是 `aa-bb-cc-dd-ee-ff`（共用寫入層會正規化成冒號式）。
    """
    from app.services.dhcp_reservations import Reservation, replace_reservations

    cli = _client(inst)
    scopes = await asyncio.to_thread(cli.get_scopes)
    rows: list[Reservation] = []
    for sc in scopes:
        sid = _as_str(sc.get("ScopeId"))
        if not sid:
            continue
        try:
            got = await asyncio.to_thread(cli.get_reservations, sid)
        except WindowsDhcpError:
            continue        # 單一 scope 失敗不該讓整台同步失敗
        for r in got:
            ip = _as_str(r.get("IPAddress"))
            if not ip:
                continue
            rows.append(Reservation(
                ip=ip, mac=_as_str(r.get("ClientId")),
                hostname=_as_str(r.get("Name")),
                description=_as_str(r.get("Description"))))
    return await replace_reservations(
        session, source_type="windows_dhcp", source_id=inst.id, source_name=inst.name,
        engine="windows", rows=rows,
    )


async def sync_scopes(session: AsyncSession, inst: WindowsDhcpServer) -> int:
    """把 Windows DHCP 的 scope 鏡像進 dhcp_pool_ranges（只清自己的列）。"""
    from app.models.dhcp import DHCPPoolRange

    cli = _client(inst)
    scopes = await asyncio.to_thread(cli.get_scopes)
    now = datetime.now(UTC)

    rows: list[tuple[str | None, str, str]] = []
    for sc in scopes:
        if str(sc.get("State") or "").lower() == "inactive":
            continue   # 停用的 scope 不會發放
        start, end = _as_str(sc.get("StartRange")), _as_str(sc.get("EndRange"))
        if not start or not end:
            continue
        scope_id, mask = _as_str(sc.get("ScopeId")), _as_str(sc.get("SubnetMask"))
        cidr = None
        if scope_id and mask:
            try:
                cidr = str(ipaddress.ip_network(f"{scope_id}/{mask}", strict=False))
            except ValueError:
                cidr = scope_id
        rows.append((cidr, start, end))

    await session.execute(delete(DHCPPoolRange).where(
        DHCPPoolRange.source_type == "windows_dhcp", DHCPPoolRange.source_id == inst.id,
    ))
    for cidr, start, end in rows:
        session.add(DHCPPoolRange(
            source_type="windows_dhcp", source_id=inst.id, source_name=inst.name,
            subnet_cidr=cidr, start_ip=start, end_ip=end,
            family=6 if ":" in start else 4, source="windows", synced_at=now,
        ))
    return len(rows)


async def sync_leases(session: AsyncSession, inst: WindowsDhcpServer) -> int:
    """把租約標記到「既有」IP 上（in_dhcp_lease + MAC/主機名稱），**不自動新建 IP**。

    租約旗標逐來源記錄（services/dhcp_leases.py）：每個 scope 都讀成功才清掉這台不再發的，
    不會清到別台 DHCP 還發著的。
    """
    from app.services.fw_sightings import SightingBatch

    cli = _client(inst)
    scopes = await asyncio.to_thread(cli.get_scopes)
    scope_ids = list(inst.scope_subnet_ids) if inst.scope_subnet_ids else None

    seen = 0
    failed_scopes: list[str] = []
    from app.models.windows_dhcp import WindowsDhcpServer as _Srv
    from app.services.dhcp_leases import LeaseRun
    from app.services.hostname_reports import HostnameRun, enabled_peers
    hn_run = HostnameRun(session, source="windows_dhcp", origin=f"windows_dhcp:{inst.id}",
                         peers=await enabled_peers(session, _Srv))
    lease_run = LeaseRun(session, source_type="windows_dhcp", source_id=inst.id)
    # 整批（以前每筆租約各比對一次 IP、再判斷一次 MAC：10 萬筆租約一輪約 40 萬次查詢）
    batch = SightingBatch(session, source="windows_dhcp", subnet_ids=scope_ids,
                          lease_run=lease_run, hn_run=hn_run)
    for sc in scopes:
        sid = _as_str(sc.get("ScopeId"))
        if not sid:
            continue
        try:
            leases = await asyncio.to_thread(cli.get_leases, sid)
        except WindowsDhcpError:
            failed_scopes.append(sid)
            continue   # 單一 scope 失敗不拖垮整批（但這一輪就不能清任何東西，見下方）
        for ls in leases:
            ip_text = _as_str(ls.get("IPAddress"))
            if not ip_text:
                continue
            # 清單也列出過期／被拒絕的（不屬於任何人）與沒人在用的保留位址（InactiveReservation）：
            # 前兩種整筆略過；後者名稱仍是這個位址設定的名字，但不算「有租約」
            state = (_as_str(ls.get("AddressState")) or "").lower()
            if state.startswith(("expired", "declined")):
                continue
            active = not state or state.startswith(("active", "offered"))
            # 唯一才算：重疊網段同 IP 多筆又沒設範圍時不猜（以前任意取一筆，見已知地雷 #7）
            hostname = _as_str(ls.get("HostName"))
            batch.add(ip_text, evidence=None, mac=_norm_mac(ls.get("ClientId")),
                      hostname=hostname.split(".")[0] if hostname else None, lease=active)
    seen = sum(1 for found, _e in await batch.flush() if found)

    # 有 scope 讀取失敗：那個 scope 的租約這一輪沒看到，不代表過期 —— 名稱與租約旗標都不清。
    # 以前會照清：失敗 scope 裡每一筆 IP 的「有 DHCP 租約」都被拿掉（2026-09-26 稽核）
    await hn_run.finish(complete=not failed_scopes)
    await lease_run.finish(complete=not failed_scopes)
    return seen


async def sync_instance(session: AsyncSession, inst: WindowsDhcpServer) -> dict[str, int]:
    """跑此實例所有啟用的同步；設定 last_sync_at / last_error。"""
    counts: dict[str, int] = {}
    if inst.sync_scopes:
        counts["scopes"] = await sync_scopes(session, inst)
        # 保留位址與 scope 同屬「DHCP 設定」，沿用同一個開關
        counts["reservations"] = await sync_reservations(session, inst)
    if inst.sync_leases:
        counts["leases"] = await sync_leases(session, inst)
    inst.last_sync_at = datetime.now(UTC)
    inst.last_error = None
    return counts
