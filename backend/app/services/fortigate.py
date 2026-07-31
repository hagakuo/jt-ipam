"""FortiGate 同步服務（Beta）—— FortiOS REST API，**全程唯讀（只打 GET）**。

安全 / 相容重點：
- 認證用 `Authorization: Bearer <token>` **標頭**；不用 `?access_token=` 網址參數
  （PSIRT FG-IR-24-268；FortiOS 7.4.5 / 7.6.1 起預設停用該形式）
- 走既有 `safe_request`（SSRF 白名單）；金鑰 AES-GCM 加密、aad 綁實例 id
- 多 VDOM：`?vdom=<名稱>` 逐一撈；VDOM 清單可自動探索，非 VDOM 模式退回 root
- **無實機可驗** → 所有欄位一律容錯解析：抓不到就略過該筆／該項，不讓單一端點拖垮整輪同步
"""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request
from app.core.security import decrypt_secret, encrypt_secret
from app.models.address import IPAddress
from app.models.fortigate import (
    FortiGateAddressObject,
    FortiGateFirewall,
    FortiGatePolicy,
)
from app.services.hostname import apply_observation

# FortiOS v2 API：monitor=即時狀態、cmdb=設定物件
EP_VDOMS = "/api/v2/cmdb/system/vdom"
EP_DHCP_LEASES = "/api/v2/monitor/system/dhcp"
EP_DHCP_SERVERS = "/api/v2/cmdb/system.dhcp/server"
EP_ARP = "/api/v2/monitor/network/arp"
EP_VPN_IPSEC = "/api/v2/monitor/vpn/ipsec"
EP_VPN_SSL = "/api/v2/monitor/vpn/ssl"
EP_POLICY = "/api/v2/cmdb/firewall/policy"
EP_VIP = "/api/v2/cmdb/firewall/vip"
EP_IPPOOL = "/api/v2/cmdb/firewall/ippool"
EP_ADDRESS = "/api/v2/cmdb/firewall/address"
EP_ADDRGRP = "/api/v2/cmdb/firewall/addrgrp"

# 連線診斷單支探測的逾時。10 支並行跑，所以最壞情況約等於這個值，而不是它的 10 倍。
_DIAG_TIMEOUT = 10.0


class FortiGateError(Exception):
    pass


# ─────────────────── 認證 / 請求 ───────────────────
def _aad(fw_id: uuid.UUID) -> bytes:
    return f"fortigate_firewall:{fw_id}:api_token".encode()


def encrypt_api_token(fw_id: uuid.UUID, token: str) -> tuple[bytes, bytes]:
    return encrypt_secret(token, aad=_aad(fw_id))


def _decrypt_token(fw: FortiGateFirewall) -> str:
    return decrypt_secret(fw.api_token_enc, fw.api_token_nonce, aad=_aad(fw.id)).decode("utf-8")


async def _api_get(
    fw: FortiGateFirewall, path: str, *, vdom: str | None = None, timeout: float = 15.0,
) -> Any:
    """GET 一個 FortiOS 端點，回傳 `results` 內容（外層同時容忍 dict 與 list）。"""
    url = f"{fw.api_url.rstrip('/')}{path}"
    params = {"vdom": vdom} if vdom else None
    headers = {
        "Authorization": f"Bearer {_decrypt_token(fw)}",
        "Accept": "application/json",
    }
    try:
        resp = await safe_request(
            "GET", url, headers=headers, params=params, timeout=timeout, verify=fw.verify_tls,
        )
    except UnsafeOutboundURL as exc:
        raise FortiGateError(f"SSRF guard rejected URL: {exc}") from exc
    except httpx.HTTPError as exc:
        raise FortiGateError(f"transport: {exc.__class__.__name__}") from exc
    if resp.status_code == 401:
        raise FortiGateError(
            "401 未授權：請確認 API token 正確、該管理員有唯讀 API 權限，"
            "且來源 IP 在 trusthost 允許範圍內（註：FIPS-CC 模式不支援 API token）",
        )
    if resp.status_code == 403:
        raise FortiGateError("403 拒絕存取：API 管理員權限或 trusthost 設定不足")
    if resp.status_code != 200:
        raise FortiGateError(f"FortiGate GET {path}: {resp.status_code} {resp.text[:200]}")
    try:
        body = resp.json()
    except ValueError as exc:
        raise FortiGateError(f"回應不是 JSON（{path}）") from exc
    return _unwrap(body)


def _unwrap(body: Any) -> Any:
    """取出 results。FortiOS 一般回 {..., "results": [...]}；
    某些情境（如 global=1）可能回外層陣列 → 一併容忍，不硬寫 body["results"]。"""
    if isinstance(body, dict):
        return body.get("results", body)
    if isinstance(body, list):
        out: list[Any] = []
        for item in body:
            got = _unwrap(item)
            if isinstance(got, list):
                out.extend(got)
            elif got is not None:
                out.append(got)
        return out
    return body


def _rows(data: Any) -> list[dict[str, Any]]:
    """把 results 正規化成 list[dict]（單筆物件也接受）。"""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        return [data]
    return []


# ─────────────────── 小工具（容錯解析）───────────────────
def _first(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _valid_ip(v: object) -> str | None:
    if v is None:
        return None
    s = str(v).strip().split("/")[0]
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _norm_mac(v: object) -> str | None:
    if v is None:
        return None
    s = str(v).strip().lower().replace("-", ":")
    parts = s.split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            int(s.replace(":", ""), 16)
        except ValueError:
            return None
        return s
    return None


def _names(v: Any) -> str | None:
    """FortiOS 的 srcaddr/dstintf 等是 [{"name": "x"}, ...] → 併成可讀字串。"""
    if v is None:
        return None
    if isinstance(v, str):
        return v or None
    if isinstance(v, dict):
        return str(v.get("name") or "") or None
    if isinstance(v, list):
        got = [str(x.get("name")) if isinstance(x, dict) else str(x) for x in v]
        got = [g for g in got if g and g != "None"]
        return ", ".join(got) or None
    return str(v)


def _to_port(v: object) -> int | None:
    """FortiOS 埠可能是 "80" 或 "80-90" → 取起始值；非數字回 None。"""
    if v is None:
        return None
    s = str(v).strip().split("-")[0]
    if not s.isdigit():
        return None
    n = int(s)
    return n if 1 <= n <= 65535 else None


# ─────────────────── VDOM ───────────────────
async def list_vdoms(fw: FortiGateFirewall) -> list[str]:
    """要同步的 VDOM 清單：使用者指定優先；否則自動探索；探索失敗退回 ['root']。"""
    if fw.vdoms:
        return [v for v in fw.vdoms if v]
    try:
        rows = _rows(await _api_get(fw, EP_VDOMS, timeout=10.0))
    except FortiGateError:
        return ["root"]        # 非 VDOM 模式或無權限 → 單一預設 VDOM
    names = [str(r.get("name")) for r in rows if r.get("name")]
    return names or ["root"]


# ─────────────────── IP stamp（重疊網段安全）───────────────────
async def _stamp_ip_seen(
    session: AsyncSession, ip: str, *, mac: str | None = None, hostname: str | None = None,
    subnet_ids: list[uuid.UUID] | None = None, dhcp: bool = False,
) -> bool:
    """只標記「既有」IP，絕不新建（與 OPNsense / pfSense 行為一致）。"""
    ipx = _valid_ip(ip)
    if ipx is None:
        return False
    stmt = select(IPAddress).where(IPAddress.ip == ipx)
    if subnet_ids:
        stmt = stmt.where(IPAddress.subnet_id.in_(subnet_ids))
    ipa = (await session.execute(stmt.limit(1))).scalars().first()   # 重疊網段：取一筆
    if ipa is None:
        return False
    ipa.last_seen_scanner = datetime.now(UTC)
    if dhcp:
        ipa.in_dhcp_lease = True
    if mac:
        from app.services.arp_precedence import consider_mac
        await consider_mac(session, ip=ipa, mac=mac, source="fortigate")
    if hostname:
        await apply_observation(session, ip=ipa, source="fortigate", hostname=hostname)
    return True


def _scope(fw: FortiGateFirewall) -> list[uuid.UUID] | None:
    return list(fw.scope_subnet_ids) if fw.scope_subnet_ids else None


# ─────────────────── 各項同步 ───────────────────
async def sync_dhcp_leases(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    scope_ids = _scope(fw)
    seen = 0
    leased: set[str] = set()
    for vdom in vdoms:
        for d in _rows(await _api_get(fw, EP_DHCP_LEASES, vdom=vdom)):
            ip = _valid_ip(_first(d, "ip", "ip_address", "address"))
            if not ip:
                continue
            leased.add(ip)
            if await _stamp_ip_seen(
                session, ip, mac=_norm_mac(_first(d, "mac", "mac_address")),
                hostname=(_first(d, "hostname", "host") or None),
                subnet_ids=scope_ids, dhcp=True,
            ):
                seen += 1
    # 撤銷：只在有設 scope 時做，避免多來源在全域互相清掉標記
    if scope_ids:
        stmt = sa_update(IPAddress).where(
            IPAddress.subnet_id.in_(scope_ids), IPAddress.in_dhcp_lease.is_(True))
        if leased:
            stmt = stmt.where(func.host(IPAddress.ip).notin_(leased))
        await session.execute(stmt.values(in_dhcp_lease=False))
    return seen


async def sync_dhcp_ranges(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    """FortiGate DHCP server 的發放範圍 → 共用的 dhcp_pool_ranges（只清自己的列）。"""
    from app.models.dhcp import DHCPPoolRange

    now = datetime.now(UTC)
    parsed: list[tuple[str | None, str, str]] = []
    for vdom in vdoms:
        try:
            rows = _rows(await _api_get(fw, EP_DHCP_SERVERS, vdom=vdom))
        except FortiGateError:
            continue        # 該 VDOM 沒開 DHCP / 無權限 → 略過，不影響其他
        for d in rows:
            if str(d.get("status") or "enable").lower() == "disable":
                continue
            iface = d.get("interface") or vdom
            for rg in (d.get("ip-range") or d.get("ip_range") or []):
                if not isinstance(rg, dict):
                    continue
                a = _valid_ip(_first(rg, "start-ip", "start_ip", "startip"))
                b = _valid_ip(_first(rg, "end-ip", "end_ip", "endip"))
                if a and b:
                    parsed.append((str(iface)[:64], a, b))
    await session.execute(delete(DHCPPoolRange).where(
        DHCPPoolRange.source_type == "fortigate", DHCPPoolRange.source_id == fw.id,
    ))
    for iface, a, b in parsed:
        session.add(DHCPPoolRange(
            source_type="fortigate", source_id=fw.id, source_name=fw.name,
            subnet_cidr=iface, start_ip=a, end_ip=b,
            family=6 if ":" in a else 4, source="fortigate", synced_at=now,
        ))
    return len(parsed)


async def sync_arp(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    scope_ids = _scope(fw)
    matched = 0
    for vdom in vdoms:
        for d in _rows(await _api_get(fw, EP_ARP, vdom=vdom)):
            ip = _valid_ip(_first(d, "ip", "address"))
            if not ip:
                continue
            # 欄位為 ip / mac / interface / age（hwaddr、intf 是 CLI 用語，JSON 沒有）
            if await _stamp_ip_seen(
                session, ip, mac=_norm_mac(d.get("mac")), subnet_ids=scope_ids,
            ):
                matched += 1
    return matched


async def sync_vpn(
    session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str],
) -> dict[str, Any]:
    """IPsec 站對站 → 共用 vpn_tunnels；SSL-VPN 連線 → 只 stamp 配發到的 IP。

    回傳除了計數，端點整個讀不到時還會多一個 `*_unavailable` 旗標。
    沒有它的話 `ssl_sessions: 0` 有兩種完全不同的意思 ——「當下沒人連線」與
    「端點失敗被吞掉」—— 從稽核摘要看不出是哪一種，而這正是判斷解析對不對
    最需要分辨的地方。"""
    from app.models.physical import VPNTunnel

    scope_ids = _scope(fw)
    prefix = f"{fw.name}/ipsec/"
    seen_names: set[str] = set()
    tunnels = 0
    ipsec_ok = False
    for vdom in vdoms:
        try:
            rows = _rows(await _api_get(fw, EP_VPN_IPSEC, vdom=vdom))
            ipsec_ok = True
        except FortiGateError:
            rows = []
        for d in rows:
            label = _first(d, "name", "p1name", "tunnel")
            if not label:
                continue
            name = f"{prefix}{vdom}/{label}"[:128]
            seen_names.add(name)
            # 通道狀態在巢狀 proxyid[].status（頂層沒有 status 欄位）；
            # 撥入式（dialup）則以 connection_count 判斷。
            phase2 = d.get("proxyid") or []
            up = any(
                isinstance(p, dict) and str(p.get("status") or "").lower() == "up"
                for p in phase2
            ) or bool(_first(d, "connection_count"))
            existing = (await session.execute(
                select(VPNTunnel).where(VPNTunnel.name == name)
            )).scalars().first()
            if existing is None:
                existing = VPNTunnel(name=name, type="ipsec_ikev2")
                session.add(existing)
            existing.status = "active" if up else "offline"
            # 對端位址是 rgwy（remote_gateway 不是 FortiOS 的欄位名）
            existing.b_endpoint = str(d.get("rgwy") or "")[:255] or None
            existing.pairing_method = "ipsec_endpoint"
            tunnels += 1
    # 清掉這台先前建立、這次沒看到的隧道（只動自己的命名首碼）
    stale = (await session.execute(
        select(VPNTunnel).where(VPNTunnel.name.like(f"{prefix}%"))
    )).scalars().all()
    for t in stale:
        if t.name not in seen_names:
            await session.delete(t)

    sessions = 0
    ssl_ok = False
    for vdom in vdoms:
        try:
            rows = _rows(await _api_get(fw, EP_VPN_SSL, vdom=vdom))
        except FortiGateError:
            continue
        ssl_ok = True
        for d in rows:
            # 配發到的通道 IP 在巢狀 subsessions[].aip（頂層沒有 assigned_ip/tunnel_ip）；
            # subsession_desc 形如 "aip:2.3.4.5"，當退路。remote_host 是用戶端來源位址、
            # 通常不在 IPAM 內，故不拿來 stamp。
            cands: list[str] = []
            for sub in (d.get("subsessions") or []):
                if isinstance(sub, dict) and sub.get("aip"):
                    cands.append(str(sub["aip"]))
            desc = str(d.get("subsession_desc") or "")
            if not cands and desc.startswith("aip:"):
                cands.append(desc[4:])
            for cand in cands:
                ip = _valid_ip(cand)
                if ip and await _stamp_ip_seen(session, ip, subnet_ids=scope_ids):
                    sessions += 1
    out: dict[str, Any] = {"tunnels": tunnels, "ssl_sessions": sessions}
    if not ssl_ok:
        # 所有 VDOM 的 SSL-VPN 端點都讀不到 → 明講，別讓它偽裝成「0 個連線」
        out["ssl_unavailable"] = True
    if not ipsec_ok:
        out["ipsec_unavailable"] = True
    return out


async def sync_policies(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    """防火牆政策 → fortigate_policies（鏡像取代此防火牆的列）。"""
    now = datetime.now(UTC)
    await session.execute(delete(FortiGatePolicy).where(FortiGatePolicy.firewall_id == fw.id))
    n = 0
    seen: set[tuple[str, str]] = set()
    for vdom in vdoms:
        try:
            rows = _rows(await _api_get(fw, EP_POLICY, vdom=vdom))
        except FortiGateError:
            continue
        for d in rows:
            pid = _first(d, "policyid", "id", "q_origin_key")
            if pid is None:
                continue
            key = (vdom, str(pid))
            if key in seen:      # 同 VDOM 內 policyid 應唯一；重複就跳過（防唯一鍵衝突）
                continue
            seen.add(key)
            session.add(FortiGatePolicy(
                firewall_id=fw.id, vdom=vdom[:64], policyid=str(pid)[:64],
                name=(str(d.get("name"))[:255] if d.get("name") else None),
                status=(str(d.get("status"))[:16] if d.get("status") else None),
                action=(str(d.get("action"))[:16] if d.get("action") else None),
                srcintf=_names(d.get("srcintf")), dstintf=_names(d.get("dstintf")),
                srcaddr=_names(d.get("srcaddr")), dstaddr=_names(d.get("dstaddr")),
                service=_names(d.get("service")),
                nat=(str(d.get("nat")).lower() in ("enable", "true", "1")
                     if d.get("nat") is not None else None),
                comments=(str(d.get("comments")) if d.get("comments") else None),
                raw=d, last_sync_at=now,
            ))
            n += 1
    return n


async def sync_nat(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    """VIP（DNAT/port forward）+ IP pool（SNAT）→ 共用 nat_translations。

    external_id 用 `<vdom>:<物件名>`；只刪自己的 source_origin，不動其他來源。
    """
    from app.models.nat import NATTranslation

    origin = f"fortigate:{fw.id}"
    await session.execute(delete(NATTranslation).where(NATTranslation.source_origin == origin))
    scope_ids = _scope(fw)
    n = 0
    for vdom in vdoms:
        # VIP → port_forward / one_to_one
        try:
            vips = _rows(await _api_get(fw, EP_VIP, vdom=vdom))
        except FortiGateError:
            vips = []
        for d in vips:
            name = d.get("name")
            if not name:
                continue
            mapped = d.get("mappedip")
            if isinstance(mapped, list) and mapped:
                first = mapped[0]
                mapped_val = first.get("range") if isinstance(first, dict) else first
            else:
                mapped_val = mapped
            target_ip = _valid_ip(mapped_val)
            dst_ip_id = None
            if target_ip:
                stmt = select(IPAddress.id).where(IPAddress.ip == target_ip)
                if scope_ids:
                    stmt = stmt.where(IPAddress.subnet_id.in_(scope_ids))
                dst_ip_id = (await session.execute(stmt.limit(1))).scalars().first()
            is_pf = str(d.get("portforward") or "").lower() in ("enable", "true", "1")
            session.add(NATTranslation(
                name=str(name)[:200],
                type="port_forward" if is_pf else "one_to_one",
                protocol=str(d.get("protocol") or "any")[:8],
                src_interface=(_names(d.get("extintf")) or None),
                dst_ip_id=dst_ip_id,
                dst_port=_to_port(d.get("mappedport")),
                src_port=_to_port(d.get("extport")),
                description=(str(d.get("comment")) if d.get("comment") else None),
                source_origin=origin, external_id=f"{vdom}:{name}"[:200],
            ))
            n += 1
        # IP pool → many_to_one（SNAT）
        try:
            pools = _rows(await _api_get(fw, EP_IPPOOL, vdom=vdom))
        except FortiGateError:
            pools = []
        for d in pools:
            name = d.get("name")
            if not name:
                continue
            # ippool 的範圍欄位無連字號：startip / endip
            rng = f"{d.get('startip') or ''}-{d.get('endip') or ''}".strip("-")
            note = str(d.get("comments") or d.get("comment") or "").strip()
            desc = " ".join(x for x in (f"IP pool {rng}".strip() if rng else "", note) if x)
            session.add(NATTranslation(
                name=str(name)[:200], type="many_to_one", protocol="any",
                description=desc or None,
                source_origin=origin, external_id=f"{vdom}:pool:{name}"[:200],
            ))
            n += 1
    return n


async def sync_addresses(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    """位址物件 + 位址群組 → fortigate_address_objects（鏡像取代）。"""
    now = datetime.now(UTC)
    await session.execute(
        delete(FortiGateAddressObject).where(FortiGateAddressObject.firewall_id == fw.id))
    n = 0
    seen: set[tuple[str, str, str]] = set()
    for vdom in vdoms:
        try:
            addrs = _rows(await _api_get(fw, EP_ADDRESS, vdom=vdom))
        except FortiGateError:
            addrs = []
        for d in addrs:
            name = d.get("name")
            if not name or (vdom, str(name), "address") in seen:
                continue
            seen.add((vdom, str(name), "address"))
            otype = str(d.get("type") or "ipmask")
            if otype in ("iprange",):
                value = f"{d.get('start-ip') or ''}-{d.get('end-ip') or ''}".strip("-") or None
            elif otype == "fqdn":
                value = str(d.get("fqdn") or "") or None
            else:
                value = str(d.get("subnet") or "").replace(" ", "/") or None
            session.add(FortiGateAddressObject(
                firewall_id=fw.id, vdom=vdom[:64], name=str(name)[:255],
                obj_type=otype[:32], kind="address", value=value,
                comment=(str(d.get("comment")) if d.get("comment") else None),
                last_sync_at=now,
            ))
            n += 1
        try:
            grps = _rows(await _api_get(fw, EP_ADDRGRP, vdom=vdom))
        except FortiGateError:
            grps = []
        for d in grps:
            name = d.get("name")
            if not name or (vdom, str(name), "group") in seen:
                continue
            seen.add((vdom, str(name), "group"))
            members = [str(m.get("name")) for m in (d.get("member") or [])
                       if isinstance(m, dict) and m.get("name")]
            session.add(FortiGateAddressObject(
                firewall_id=fw.id, vdom=vdom[:64], name=str(name)[:255],
                obj_type="addrgrp", kind="group", value=None, members=members,
                comment=(str(d.get("comment")) if d.get("comment") else None),
                last_sync_at=now,
            ))
            n += 1
    return n


# ─────────────────── 連線診斷 / 整批同步 ───────────────────
async def diagnose(fw: FortiGateFirewall) -> dict[str, Any]:
    """測試連線：逐端點回報通不通與筆數（無實機開發，這是收斂欄位的主要依據）。"""
    out: dict[str, Any] = {"api_url": fw.api_url}
    try:
        vdoms = await list_vdoms(fw)
    except FortiGateError as exc:
        raise FortiGateError(f"無法取得 VDOM 清單：{exc}") from exc
    out["vdoms"] = vdoms
    probes = (
        ("dhcp_leases", EP_DHCP_LEASES), ("dhcp_servers", EP_DHCP_SERVERS), ("arp", EP_ARP),
        ("vpn_ipsec", EP_VPN_IPSEC), ("vpn_ssl", EP_VPN_SSL), ("policy", EP_POLICY),
        ("vip", EP_VIP), ("ippool", EP_IPPOOL), ("address", EP_ADDRESS), ("addrgrp", EP_ADDRGRP),
    )

    async def _probe(label: str, path: str) -> dict[str, Any]:
        try:
            rows = _rows(await _api_get(fw, path, vdom=vdoms[0], timeout=_DIAG_TIMEOUT))
            return {"endpoint": label, "ok": True, "rows": len(rows)}
        except FortiGateError as exc:
            return {"endpoint": label, "ok": False, "error": str(exc)[:200]}

    # 並行探測：這 10 支是彼此獨立的 GET，循序跑的話對「不可達主機」會累加成
    # 10 × 逾時 ≈ 100 秒，前端診斷視窗看起來像凍住 —— 而 IP 填錯／防火牆丟包
    # 正是客戶第一次設定最常遇到的情況。並行後最壞情況約等於單一逾時。
    checks = list(await asyncio.gather(*(_probe(lbl, p) for lbl, p in probes)))
    out["checks"] = checks
    out["ok_count"] = sum(1 for c in checks if c["ok"])
    return out


async def sync_instance(session: AsyncSession, fw: FortiGateFirewall) -> dict[str, Any]:
    """跑此實例所有啟用的同步；設定 last_sync_at / last_error。"""
    vdoms = await list_vdoms(fw)
    counts: dict[str, Any] = {"vdoms": len(vdoms)}
    if fw.sync_dhcp:
        counts["dhcp"] = await sync_dhcp_leases(session, fw, vdoms)
    if fw.sync_dhcp_ranges:
        counts["dhcp_ranges"] = await sync_dhcp_ranges(session, fw, vdoms)
    if fw.sync_arp:
        counts["arp"] = await sync_arp(session, fw, vdoms)
    if fw.sync_vpn:
        counts.update(await sync_vpn(session, fw, vdoms))
    if fw.sync_policies:
        counts["policies"] = await sync_policies(session, fw, vdoms)
    if fw.sync_nat:
        counts["nat"] = await sync_nat(session, fw, vdoms)
    if fw.sync_addresses:
        counts["addresses"] = await sync_addresses(session, fw, vdoms)
    fw.last_sync_at = datetime.now(UTC)
    fw.last_error = None
    return counts
