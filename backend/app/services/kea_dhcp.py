"""獨立的 Kea DHCP Server（issue #45，使用者追加）—— 經 Kea 的 JSON 控制 API 拉取。

跟 OPNsense／pfSense 上的 Kea 不同：這裡直接連 Kea 自己的控制通道，不經過防火牆的 REST API。

- 控制代理（kea-ctrl-agent，Kea 2.x 常見）：POST JSON 到它的網址，指令要帶 `"service": ["dhcp4"]`，
  回的是清單（每個 service 一個結果）
- Kea 3.0 起 DHCP 伺服器自己就能開 HTTP 控制通道：直接連，不帶 service，回的是單一物件
  → 先不帶 service 問一次 `config-get`：拿到 `Dhcp4` 就是直連；拿到 `Control-agent` 就是控制代理，改帶 service

資料：
- 範圍與保留：`config-get`（subnet4 與 shared-networks 底下的 subnet4）
- 存在資料庫的保留（host_cmds）：`reservation-get-all`，不支援就只用設定裡的
- 租約（lease_cmds）：`lease4-get-page` 分頁；沒有載入 lease_cmds 時範圍與保留照樣同步、提示租約要開 lease_cmds

結果代碼：0 成功、1 錯誤、2 不支援的指令、3 沒有資料（不是錯誤）。
"""
from __future__ import annotations

import base64
import ipaddress
import json as _json
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request, transport_detail
from app.core.security import decrypt_secret, encrypt_secret

# 無限期租約（Kea 以 0xffffffff 表示）
_INFINITE_LFT = 4294967295


class KeaError(Exception):
    """連不上、認證失敗、Kea 回錯誤。訊息要帶 Kea 回的原文。"""


class KeaUnsupported(KeaError):
    """Kea 不支援這個指令（沒有載入對應的 hook，例如 lease_cmds／host_cmds）。"""


def unwrap(raw: Any, command: str) -> dict[str, Any]:
    """Kea 的回應 → arguments。控制代理回清單、直連回單一物件；result 3（沒有資料）回空字典。"""
    item = raw[0] if isinstance(raw, list) and raw else raw
    if not isinstance(item, dict) or "result" not in item:
        raise KeaError(f"{command}: unexpected response {str(raw)[:200]}")
    code = item.get("result")
    text = str(item.get("text") or "")
    if code == 0:
        args = item.get("arguments")
        return args if isinstance(args, dict) else {}
    if code == 3:
        return {}
    if code == 2:
        raise KeaUnsupported(f"{command}: {text or 'command not supported'}")
    raise KeaError(f"{command}: {text or f'result {code}'}")


def _mac(v: Any) -> str | None:
    hexs = "".join(ch for ch in str(v or "").lower() if ch in "0123456789abcdef")
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)) if len(hexs) == 12 else None


def _ip4(v: Any) -> str | None:
    try:
        a = ipaddress.ip_address(str(v or "").strip())
    except ValueError:
        return None
    return str(a) if a.version == 4 else None


def _pool_bounds(pool: str) -> tuple[str, str] | None:
    """`192.0.2.10 - 192.0.2.20`、`192.0.2.10-192.0.2.20` 或 `192.0.2.64/26`。"""
    s = str(pool or "").strip()
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
        return (str(net.network_address), str(net.broadcast_address)) if net.version == 4 else None
    parts = [p.strip() for p in s.split("-")]
    if len(parts) != 2:
        return None
    a, b = _ip4(parts[0]), _ip4(parts[1])
    if not a or not b:
        return None
    if ipaddress.ip_address(a) > ipaddress.ip_address(b):
        a, b = b, a
    return a, b


def _reservation(r: dict[str, Any], subnet: str | None) -> dict[str, Any] | None:
    ip = _ip4(r.get("ip-address"))
    if not ip:                     # 只給選項、不綁位址的保留跟 IPAM 無關
        return None
    return {"ip": ip, "mac": _mac(r.get("hw-address")), "hostname": r.get("hostname") or None,
            "subnet": subnet}


def parse_config(dhcp4: dict[str, Any]) -> tuple[list[dict], list[dict], dict[int, str]]:
    """`Dhcp4` 設定 → (範圍, 保留, {subnet-id: CIDR})。寫壞的單一項目略過，不讓整批失敗。"""
    pools: list[dict] = []
    reservations: list[dict] = []
    subnet_ids: dict[int, str] = {}
    subnets = list(dhcp4.get("subnet4") or [])
    for sn in dhcp4.get("shared-networks") or []:
        subnets.extend(sn.get("subnet4") or [])
    for sub in subnets:
        try:
            cidr = str(ipaddress.ip_network(str(sub.get("subnet")), strict=False))
        except ValueError:
            continue
        if isinstance(sub.get("id"), int):
            subnet_ids[sub["id"]] = cidr
        for p in sub.get("pools") or []:
            b = _pool_bounds(p.get("pool") if isinstance(p, dict) else p)
            if b:
                pools.append({"subnet": cidr, "start": b[0], "end": b[1]})
        for r in sub.get("reservations") or []:
            got = _reservation(r, cidr) if isinstance(r, dict) else None
            if got:
                reservations.append(got)
    for r in dhcp4.get("reservations") or []:
        got = _reservation(r, None) if isinstance(r, dict) else None
        if got:
            reservations.append(got)
    return pools, reservations, subnet_ids


def parse_leases(leases: list[dict[str, Any]], *, now: datetime | None = None) -> list[dict]:
    """只留 state=0（已指派）且還沒到期的租約。到期＝cltt + valid-lft；0xffffffff 是無限期。"""
    now = now or datetime.now(UTC)
    out: list[dict] = []
    for le in leases:
        ip = _ip4(le.get("ip-address"))
        if not ip or int(le.get("state") or 0) != 0:
            continue
        lft = int(le.get("valid-lft") or 0)
        ends: datetime | None = None
        if lft != _INFINITE_LFT:
            try:
                ends = datetime.fromtimestamp(int(le.get("cltt") or 0) + lft, tz=UTC)
            except (ValueError, OverflowError, OSError):
                continue
            if ends <= now:
                continue
        out.append({"ip": ip, "mac": _mac(le.get("hw-address")), "hostname": le.get("hostname") or None,
                    "ends": ends.isoformat() if ends else None})
    out.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return out


# ── 連線與同步 ──────────────────────────────────────────────────────────────────

MAX_LEASES = 100_000          # 分頁拉租約的上限（超過就停，摘要裡標出來）
LEASE_PAGE = 1000
MAX_SUBNETS_FOR_HOSTS = 2000  # reservation-get-all 是逐子網路問的


def _aad(instance_id: Any) -> bytes:
    return f"kea_dhcp_server:{instance_id}:password".encode()


def encrypt_password(instance_id: Any, raw: str) -> tuple[bytes, bytes]:
    return encrypt_secret(raw, aad=_aad(instance_id))


def _password(inst: Any) -> str | None:
    if not inst.password_enc or not inst.password_nonce:
        return None
    return decrypt_secret(inst.password_enc, inst.password_nonce, aad=_aad(inst.id)).decode("utf-8")


class KeaClient:
    """一次同步用的連線。第一次 `config-get` 時判斷是控制代理還是直連，之後的指令照那個方式送。"""

    def __init__(self, inst: Any) -> None:
        self.inst = inst
        self.password = _password(inst)
        self.mode: str | None = None          # "agent"（控制代理）／"direct"（Kea 3.0 直連）

    async def _post(self, body: dict[str, Any]) -> Any:
        auth = None
        if self.inst.username:
            token = base64.b64encode(f"{self.inst.username}:{self.password or ''}".encode()).decode()
            auth = {"Authorization": f"Basic {token}"}
        try:
            resp = await safe_request("POST", self.inst.api_url, json=body, headers=auth,
                                      timeout=30.0, verify=self.inst.verify_tls,
                                      max_bytes=200 * 1024 * 1024)
        except UnsafeOutboundURL as exc:
            raise KeaError(f"SSRF guard rejected URL: {exc}") from exc
        except httpx.HTTPError as exc:
            raise KeaError(f"transport: {transport_detail(exc)}") from exc
        if resp.status_code == 401:
            raise KeaError("401 Unauthorized — check the username/password (Kea HTTP basic auth)")
        if resp.status_code != 200:
            raise KeaError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json()
        except (ValueError, _json.JSONDecodeError) as exc:
            # 解析錯誤一定要帶底層原文，否則分不出是網址打錯（回了 HTML）還是別的
            raise KeaError(f"not JSON ({exc}): {resp.text[:120]!r}") from exc

    async def command(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"command": command}
        if self.mode == "agent":
            body["service"] = ["dhcp4"]
        if arguments is not None:
            body["arguments"] = arguments
        return unwrap(await self._post(body), command)

    async def config(self) -> dict[str, Any]:
        """`config-get` 並判斷連線方式：直連回 Dhcp4；控制代理不帶 service 時回自己的 Control-agent。"""
        args = await self.command("config-get")
        if "Dhcp4" in args:
            self.mode = self.mode or "direct"
            return args["Dhcp4"]
        if "Control-agent" in args and self.mode is None:
            self.mode = "agent"
            args = await self.command("config-get")
            if "Dhcp4" in args:
                return args["Dhcp4"]
        raise KeaError("config-get: no Dhcp4 configuration in the response "
                       f"(got {', '.join(args) or 'nothing'}) — is kea-dhcp4 running behind this URL?")

    async def version(self) -> str | None:
        """版本號：取 `version-get` 的 text（`2.4.1`、`3.0.4`）；`extended` 會帶上建置資訊，太長。"""
        body: dict[str, Any] = {"command": "version-get"}
        if self.mode == "agent":
            body["service"] = ["dhcp4"]
        try:
            raw = await self._post(body)
        except KeaError:
            return None
        item = raw[0] if isinstance(raw, list) and raw else raw
        if not isinstance(item, dict) or item.get("result") != 0:
            return None
        text = str(item.get("text") or "").strip()
        return text.split()[0] if text else None

    async def leases(self) -> tuple[list[dict[str, Any]], bool]:
        """lease4-get-page 分頁拉全部租約 → (租約, 是否因上限被截斷)。沒有 lease_cmds 時丟 KeaUnsupported。"""
        out: list[dict[str, Any]] = []
        start = "start"
        while True:
            args = await self.command("lease4-get-page", {"from": start, "limit": LEASE_PAGE})
            page = args.get("leases") or []
            out.extend(page)
            if len(page) < LEASE_PAGE or not page:
                return out, False
            if len(out) >= MAX_LEASES:
                return out[:MAX_LEASES], True
            start = str(page[-1].get("ip-address") or "")
            if not start:
                return out, False

    async def db_reservations(self, subnet_ids: dict[int, str]) -> list[dict[str, Any]] | None:
        """存在資料庫的保留（host_cmds 的 reservation-get-all，逐子網路）。沒有 host_cmds 回 None。"""
        out: list[dict[str, Any]] = []
        for sid, cidr in list(subnet_ids.items())[:MAX_SUBNETS_FOR_HOSTS]:
            try:
                args = await self.command("reservation-get-all", {"subnet-id": sid})
            except KeaUnsupported:
                return None
            for r in args.get("hosts") or []:
                got = _reservation(r, cidr) if isinstance(r, dict) else None
                if got:
                    out.append(got)
        return out


async def healthcheck(inst: Any) -> dict[str, Any]:
    """測試連線：讀得到 Dhcp4 設定＝網址、認證都通。順便回報版本與租約／資料庫保留是否可用。"""
    cli = KeaClient(inst)
    dhcp4 = await cli.config()
    pools, res, subnet_ids = parse_config(dhcp4)
    leases_ok = True
    try:
        await cli.command("lease4-get-page", {"from": "start", "limit": 1})
    except KeaUnsupported:
        leases_ok = False
    return {"mode": cli.mode, "version": await cli.version(), "subnets": len(subnet_ids),
            "pools": len(pools), "reservations": len(res), "leases_supported": leases_ok}


async def sync_instance(session: AsyncSession, inst: Any) -> dict[str, Any]:
    """拉一次：範圍＋保留（sync_scopes）、租約（sync_leases）。連不上就往上拋（作業顯示失敗）。"""
    from app.models.dhcp_standalone import KeaDhcpServer
    from app.services.dhcp_standalone import write_leases, write_pools, write_reservations

    cli = KeaClient(inst)
    try:
        dhcp4 = await cli.config()
    except KeaError as exc:
        inst.last_error = str(exc)
        await session.commit()
        raise
    pools, reservations, subnet_ids = parse_config(dhcp4)
    counts: dict[str, Any] = {}
    summary: dict[str, Any] = {"mode": cli.mode, "version": await cli.version(),
                               "subnets": len(subnet_ids)}
    if inst.sync_scopes:
        extra = await cli.db_reservations(subnet_ids)
        summary["host_cmds"] = extra is not None
        counts["pools"] = await write_pools(session, source_type="kea_dhcp", source_id=inst.id,
                                            source_name=inst.name, engine="kea", pools=pools)
        counts["reservations"] = await write_reservations(
            session, source_type="kea_dhcp", source_id=inst.id, source_name=inst.name, engine="kea",
            rows=reservations + (extra or []))
    if inst.sync_leases:
        try:
            raw, truncated = await cli.leases()
        except KeaUnsupported:
            # 沒載入 lease_cmds：範圍與保留照樣同步，租約不清（沒看到≠過期），畫面提示要開 lease_cmds
            summary["leases_unsupported"] = True
        else:
            leases = parse_leases(raw)
            counts["leases"] = await write_leases(
                session, source_type="kea_dhcp", source_id=inst.id, peers_model=KeaDhcpServer,
                scope_ids=list(inst.scope_subnet_ids) if inst.scope_subnet_ids else None,
                leases=leases, complete=not truncated)
            summary["leases_truncated"] = truncated
    inst.last_summary = {**summary, **counts}
    inst.last_sync_at = datetime.now(UTC)
    inst.last_error = None
    return {**counts, **{k: v for k, v in summary.items() if k in ("mode", "leases_unsupported")}}
