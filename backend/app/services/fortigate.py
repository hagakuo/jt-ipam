"""FortiGate 同步服務 —— FortiOS REST API，**全程唯讀（只打 GET）**。

安全 / 相容重點：
- 認證用 `Authorization: Bearer <token>` **標頭**；不用 `?access_token=` 網址參數
  （PSIRT FG-IR-24-268；FortiOS 7.4.5 / 7.6.1 起預設停用該形式）
- 走既有 `safe_request`（SSRF 允許清單）；金鑰 AES-GCM 加密、aad 綁實例 id
- 多 VDOM：`?vdom=<名稱>` 逐一撈；VDOM 清單可自動探索，非 VDOM 模式退回 root
- 容錯解析：欄位抓不到就略過該筆／該項；**單一端點失敗不拖垮整輪**（實機常態是「10 支有 9 支可讀」）
- 已於客戶實機驗證（v0.5.195 區段隔離、v0.5.196 多份 JSON 相接的解析）
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request, transport_detail
from app.core.security import decrypt_secret, encrypt_secret
from app.core.ui_error import UiError
from app.models.fortigate import (
    FortiGateAddressObject,
    FortiGateFirewall,
    FortiGatePolicy,
)
from app.services.dhcp_leases import LeaseRun
from app.services.fw_sightings import SightingBatch
from app.services.hostname_reports import HostnameRun, enabled_peers
from app.services.ip_autocreate import match_existing

# FortiOS v2 API：monitor=即時狀態、cmdb=設定物件
EP_VDOMS = "/api/v2/cmdb/system/vdom"
EP_GLOBAL = "/api/v2/cmdb/system/global"
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


class FortiGateError(UiError):
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
        raise FortiGateError(f"SSRF guard rejected URL: {exc}",
                             code="fgt_ssrf", reason=str(exc)[:200]) from exc
    except httpx.HTTPError as exc:
        raise FortiGateError(f"transport: {transport_detail(exc)}",
                             code="fgt_transport", reason=transport_detail(exc)) from exc
    if resp.status_code == 401:
        raise FortiGateError(
            "401 未授權：請確認 API token 正確、該管理員有唯讀 API 權限，"
            "且來源 IP 在 trusthost 允許範圍內（註：FIPS-CC 模式不支援 API token）",
            code="fgt_401",
        )
    if resp.status_code == 403:
        raise FortiGateError("403 拒絕存取：API 管理員權限或 trusthost 設定不足", code="fgt_403")
    if resp.status_code != 200:
        raise FortiGateError(f"FortiGate GET {path}: {resp.status_code} {resp.text[:200]}",
                             code="fgt_http", path=path, status=resp.status_code,
                             body=resp.text[:200])
    try:
        body = _loads_tolerant(resp.text)
    except ValueError as exc:
        # 200 但不是 JSON，實務上幾乎都是 FortiOS 直接回了網頁介面的 HTML
        # （該韌體版本／機型沒有這支端點，或 token 走不到 monitor 範圍被導去登入頁）。
        # 訊息一定要帶回證據，否則現場只看到「不是 JSON」無從判斷要調什麼。
        ctype = resp.headers.get("content-type", "?")
        snippet = " ".join(resp.text[:120].split())
        hint = ""
        if "html" in ctype.lower() or snippet.lower().startswith(("<!doctype", "<html")):
            hint = "（回的是網頁而非 API：此韌體版本可能沒有這支端點，或 API 管理員讀不到該資源）"
        # 解析器的原始訊息要帶上（例如 Extra data 就直指「多份文件相接」），
        # 否則看到開頭是合法 JSON 會誤判成端點不存在
        raise FortiGateError(
            f"回應不是 JSON（{path}）：{exc} content-type={ctype} 內容開頭={snippet!r}{hint}",
            code="fgt_not_json", path=path, reason=str(exc), ctype=ctype,
            snippet=snippet, hint=hint,
        ) from exc
    return _unwrap(body)


def _loads_tolerant(text: str) -> Any:
    """解析 FortiOS 回應，容忍「多個 JSON 文件相接」。

    實機（FortiOS，客戶站台）對 `monitor/system/dhcp` 回的是好幾份 JSON 直接串在一起
    （每個 VDOM／範圍一份，外面沒有陣列包起來）。`resp.json()` 會在第二份的開頭丟
    `Extra data`，於是一份**內容完全合法**的回應被判成「不是 JSON」，整段 DHCP 同步
    直接失效。逐份解析後交給 `_unwrap` 合併 results。
    """
    dec = json.JSONDecoder()
    docs: list[Any] = []
    idx, n = 0, len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, idx = dec.raw_decode(text, idx)   # 任何一份壞掉就照樣拋 ValueError
        docs.append(obj)
    if not docs:
        raise ValueError("empty response")
    return docs[0] if len(docs) == 1 else docs


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
#: 沒有 VDOM 分割時用的保留值：代表「**不要**帶 vdom 參數」。
#: `_api_get` 對 falsy 的 vdom 會直接省略該參數，所以空字串就是「不指定範圍」。
NO_VDOM = ""

#: `vdom` 只是查詢範圍，不是資料 —— 但有幾個地方會把它寫進名稱／識別字裡
#: （介面名退路、VPN 通道名、NAT external_id）。那些位置需要一個看得懂的字。
VDOM_LABEL_WHEN_NONE = "root"


def vdom_label(vdom: str) -> str:
    """給「要寫進資料」的位置用的顯示字（不是拿去打 API 的）。"""
    return vdom or VDOM_LABEL_WHEN_NONE


async def detect_vdom_mode(fw: FortiGateFirewall) -> str | None:
    """問裝置自己有沒有開 VDOM：`system/global` 的 `vdom-mode`。

    回 `no-vdom` / `split-vdom` / `multi-vdom`；讀不到回 None（權限或韌體差異）。
    """
    try:
        rows = _rows(await _api_get(fw, EP_GLOBAL, timeout=10.0))
    except FortiGateError:
        return None
    for d in rows:
        mode = _first(d, "vdom-mode", "vdom_mode", "vdom-admin")
        if mode:
            return str(mode).strip().lower()
    return None


async def list_vdoms(fw: FortiGateFirewall) -> list[str]:
    return (await list_vdoms_ex(fw))[0]


async def list_vdoms_ex(fw: FortiGateFirewall) -> tuple[list[str], bool]:
    """要同步的 VDOM 清單，以及這份清單是不是**權威的**。

    權威＝使用者指定、裝置明講沒開 VDOM、或成功列出來。讀不到清單而退回「不指定範圍」時
    只看得到管理 VDOM —— 拿它當完整清單去清資料，會把其他 VDOM 的租約、名稱、政策全部
    清掉（2026-09-26 稽核）。所以清除類的動作只在權威時做。

    順序：使用者指定 → 問裝置的 `vdom-mode` → 列 `system/vdom` → 都問不到就**不指定範圍**。

    ⚠️ 最後那一步是 2026-09-04（issue #26）改的。原本問不到時退回 `["root"]`，
    等於**猜一個 VDOM 名稱塞進每一支請求**。沒有分割 VDOM 的機器上 `root` 通常是對的，
    但這是猜的：一旦某個韌體版本對「VDOM 關閉時仍帶 vdom 參數」有意見，
    受影響的就是**每一支端點**，而畫面上只會看到一整排錯誤，看不出共同原因是我們多送了
    一個參數。不知道就不要指定 —— FortiOS 自己會用管理 VDOM，那正是我們要的。
    """
    if fw.vdoms:
        return [v for v in fw.vdoms if v], True
    mode = await detect_vdom_mode(fw)
    if mode == "no-vdom":
        return [NO_VDOM], True     # 裝置明講沒開 VDOM → 一支都不要帶
    try:
        rows = _rows(await _api_get(fw, EP_VDOMS, timeout=10.0))
    except FortiGateError:
        return [NO_VDOM], False    # 讀不到清單就不要猜名字（也不能當完整清單）
    names = [str(r.get("name")) for r in rows if r.get("name")]
    return (names, True) if names else ([NO_VDOM], False)


# ─────────────────── IP stamp（重疊網段安全）───────────────────


def _scope(fw: FortiGateFirewall) -> list[uuid.UUID] | None:
    return list(fw.scope_subnet_ids) if fw.scope_subnet_ids else None


# ─────────────────── 各項同步 ───────────────────
async def _fetch_all_vdoms(fw: FortiGateFirewall, path: str, vdoms: list[str]) -> dict[str, list[Any]]:
    """每個 VDOM 各讀一次；**任何一個失敗就往外拋**（區段失敗、既有資料保留）。

    以前逐 VDOM `continue`／當成空清單，接著照樣把整份快照取代：連不上或權限不足時政策、NAT、
    位址物件、發放範圍、固定分配全部被清空，同步卻顯示成功；政策清空還會讓規則異動偵測發出
    「全部移除」的假告警（2026-09-26 稽核）。FortiOS 對「這個 VDOM 沒開 DHCP」回的是空清單、
    不是錯誤，所以錯誤＝真的沒讀到。
    """
    out: dict[str, list[Any]] = {}
    failed: list[str] = []
    for vdom in vdoms:
        try:
            out[vdom] = _rows(await _api_get(fw, path, vdom=vdom))
        except FortiGateError as exc:
            failed.append(f"{vdom_label(vdom) or '-'}: {str(exc)[:120]}")
    if failed:
        raise FortiGateError(f"{path} 讀取失敗，保留既有資料：" + "；".join(failed))
    return out


async def sync_dhcp_leases(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str],
                           *, vdoms_authoritative: bool = True) -> int:
    scope_ids = _scope(fw)
    seen = 0
    hn_run = HostnameRun(session, source="fortigate", origin=f"fortigate:{fw.id}",
                         peers=await enabled_peers(session, FortiGateFirewall))
    lease_run = LeaseRun(session, source_type="fortigate", source_id=fw.id)
    batch = SightingBatch(session, source="fortigate", subnet_ids=scope_ids, lease_run=lease_run,
                          hn_run=hn_run)
    for vdom in vdoms:
        for d in _rows(await _api_get(fw, EP_DHCP_LEASES, vdom=vdom)):
            ip = _valid_ip(_first(d, "ip", "ip_address", "address"))
            if not ip:
                continue
            batch.add(ip, evidence="lease:fortigate", mac=_norm_mac(_first(d, "mac", "mac_address")),
                      hostname=(_first(d, "hostname", "host") or None))
    seen = sum(1 for found, _e in await batch.flush() if found)
    # 任何一個 VDOM 讀取失敗會往外拋（區段失敗）；VDOM 清單不是權威的就不算完整
    await hn_run.finish(complete=vdoms_authoritative)
    await lease_run.finish(complete=vdoms_authoritative)
    return seen


async def sync_dhcp_ranges(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    """FortiGate DHCP server 的發放範圍 → 共用的 dhcp_pool_ranges（只清自己的列）。"""
    from app.models.dhcp import DHCPPoolRange

    now = datetime.now(UTC)
    parsed: list[tuple[str | None, str, str]] = []
    by_vdom = await _fetch_all_vdoms(fw, EP_DHCP_SERVERS, vdoms)
    for vdom in vdoms:
        rows = by_vdom[vdom]
        for d in rows:
            if str(d.get("status") or "enable").lower() == "disable":
                continue
            iface = d.get("interface") or vdom_label(vdom)
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


async def sync_dhcp_reservations(
    session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str],
) -> int:
    """FortiGate 的 DHCP 固定分配：`system.dhcp/server` 每台底下的 `reserved-address`。

    FortiGate 沒有獨立的 reservation 端點 —— 保留位址是 DHCP server 設定的一部分。
    """
    from app.services.dhcp_reservations import Reservation, replace_reservations

    rows: list[Reservation] = []
    by_vdom = await _fetch_all_vdoms(fw, EP_DHCP_SERVERS, vdoms)
    for vdom in vdoms:
        servers = by_vdom[vdom]
        for d in servers:
            for r in (d.get("reserved-address") or d.get("reserved_address") or []):
                if not isinstance(r, dict):
                    continue
                ip = _valid_ip(_first(r, "ip", "ip-address", "ip_address"))
                if not ip:
                    continue
                rows.append(Reservation(
                    ip=ip, mac=_first(r, "mac", "mac-address"),
                    description=_first(r, "description", "descr")))
    return await replace_reservations(
        session, source_type="fortigate", source_id=fw.id, source_name=fw.name,
        engine="fortigate", rows=rows,
    )


async def sync_arp(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    scope_ids = _scope(fw)
    batch = SightingBatch(session, source="fortigate", subnet_ids=scope_ids)
    for vdom in vdoms:
        for d in _rows(await _api_get(fw, EP_ARP, vdom=vdom)):
            ip = _valid_ip(_first(d, "ip", "address"))
            if not ip:
                continue
            # 欄位為 ip / mac / interface / age（hwaddr、intf 是 CLI 用語，JSON 沒有）。
            # `age`＝這筆條目已經幾秒沒被更新 → 用它推回真正被看到的時間，
            # 不要一律蓋同步當下（見 services/arp_seen.seen_from_age）。
            from app.services.arp_seen import seen_from_age
            batch.add(ip, evidence="arp:fortigate", mac=_norm_mac(d.get("mac")),
                      seen_at=seen_from_age(d.get("age")))
    return sum(1 for found, _e in await batch.flush() if found)


async def sync_vpn(
    session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str], *, authoritative: bool = True,
) -> dict[str, Any]:
    """IPsec 站對站 → 共用 vpn_tunnels；SSL-VPN 連線 → 只 stamp 配發到的 IP。

    回傳除了計數，端點整個讀不到時還會多一個 `*_unavailable` 旗標。
    沒有它的話 `ssl_sessions: 0` 有兩種完全不同的意思 ——「當下沒人連線」與
    「端點失敗被吞掉」—— 從稽核摘要看不出是哪一種，而這正是判斷解析對不對
    最需要分辨的地方。"""
    from app.models.physical import VPNTunnel
    from app.services.vpn_pairing import link_peers, resolve_device_for

    scope_ids = _scope(fw)
    prefix = f"{fw.name}/ipsec/"
    origin = f"fortigate:{fw.id}"
    # 通道屬於哪台裝置：拓樸圖畫通道至少要知道一端（以前沒記，FortiGate 的通道從沒出現在圖上）
    fw_dev = await resolve_device_for(session, api_url=fw.api_url, name=fw.name)
    seen_names: set[str] = set()
    tunnels = 0
    ipsec_ok = False
    ipsec_failed = False
    for vdom in vdoms:
        try:
            rows = _rows(await _api_get(fw, EP_VPN_IPSEC, vdom=vdom))
            ipsec_ok = True
        except FortiGateError:
            rows = []
            ipsec_failed = True
        for d in rows:
            label = _first(d, "name", "p1name", "tunnel")
            if not label:
                continue
            name = f"{prefix}{vdom_label(vdom)}/{label}"[:128]
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
            existing.source_origin = origin
            existing.status = "active" if up else "offline"
            # 對端位址是 rgwy（remote_gateway 不是 FortiOS 的欄位名）
            existing.b_endpoint = str(d.get("rgwy") or "")[:255] or None
            existing.a_device_id = fw_dev
            tunnels += 1
    # 清掉這台先前建立、這次沒看到的隧道 —— 只在每個 VDOM 都讀到、而且 VDOM 清單是權威的時候。
    # 以前算了 ipsec_ok 卻沒拿來擋：任何 VDOM 讀取失敗就清空。歸屬看 source_origin 而不是名稱前綴：
    # 防火牆改名後，舊名字的通道也是這台的（以前會變成孤兒）
    if not ipsec_failed and authoritative:
        stale = (await session.execute(
            select(VPNTunnel).where(VPNTunnel.source_origin == origin)
        )).scalars().all()
        for t in stale:
            if t.name not in seen_names:
                await session.delete(t)
    # 兩端配對（整張表一起看：對端可能是 OPNsense、Palo Alto、MikroTik）
    if ipsec_ok:
        await link_peers(session)

    vpn_batch = SightingBatch(session, source="fortigate", subnet_ids=scope_ids)
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
                if ip:
                    vpn_batch.add(ip, evidence="vpn:fortigate")
    sessions = sum(1 for found, _e in await vpn_batch.flush() if found)
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
    by_vdom = await _fetch_all_vdoms(fw, EP_POLICY, vdoms)   # 全部讀到才取代
    await session.execute(delete(FortiGatePolicy).where(FortiGatePolicy.firewall_id == fw.id))
    n = 0
    seen: set[tuple[str, str]] = set()
    for vdom in vdoms:
        rows = by_vdom[vdom]
        for d in rows:
            pid = _first(d, "policyid", "id", "q_origin_key")
            if pid is None:
                continue
            key = (vdom, str(pid))
            if key in seen:      # 同 VDOM 內 policyid 應唯一；重複就跳過（防唯一鍵衝突）
                continue
            seen.add(key)
            session.add(FortiGatePolicy(
                firewall_id=fw.id, vdom=vdom_label(vdom)[:64], policyid=str(pid)[:64],
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
    vips_by = await _fetch_all_vdoms(fw, EP_VIP, vdoms)       # 全部讀到才取代
    pools_by = await _fetch_all_vdoms(fw, EP_IPPOOL, vdoms)
    await session.execute(delete(NATTranslation).where(NATTranslation.source_origin == origin))
    scope_ids = _scope(fw)
    n = 0
    for vdom in vdoms:
        # VIP → port_forward / one_to_one
        vips = vips_by[vdom]
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
                hit, _amb = await match_existing(session, target_ip, scope_ids)   # 唯一才連
                dst_ip_id = hit.id if hit is not None else None
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
                source_origin=origin,
                external_id=f"{vdom_label(vdom)}:{name}"[:200],
            ))
            n += 1
        # IP pool → many_to_one（SNAT）
        pools = pools_by[vdom]
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
                source_origin=origin, external_id=f"{vdom_label(vdom)}:pool:{name}"[:200],
            ))
            n += 1
    return n


async def sync_addresses(session: AsyncSession, fw: FortiGateFirewall, vdoms: list[str]) -> int:
    """位址物件 + 位址群組 → fortigate_address_objects（鏡像取代）。"""
    now = datetime.now(UTC)
    addrs_by = await _fetch_all_vdoms(fw, EP_ADDRESS, vdoms)     # 全部讀到才取代
    grps_by = await _fetch_all_vdoms(fw, EP_ADDRGRP, vdoms)
    await session.execute(
        delete(FortiGateAddressObject).where(FortiGateAddressObject.firewall_id == fw.id))
    n = 0
    seen: set[tuple[str, str, str]] = set()
    for vdom in vdoms:
        addrs = addrs_by[vdom]
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
                firewall_id=fw.id, vdom=vdom_label(vdom)[:64], name=str(name)[:255],
                obj_type=otype[:32], kind="address", value=value,
                comment=(str(d.get("comment")) if d.get("comment") else None),
                last_sync_at=now,
            ))
            n += 1
        grps = grps_by[vdom]
        for d in grps:
            name = d.get("name")
            if not name or (vdom, str(name), "group") in seen:
                continue
            seen.add((vdom, str(name), "group"))
            members = [str(m.get("name")) for m in (d.get("member") or [])
                       if isinstance(m, dict) and m.get("name")]
            session.add(FortiGateAddressObject(
                firewall_id=fw.id, vdom=vdom_label(vdom)[:64], name=str(name)[:255],
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
    out["vdom_mode"] = await detect_vdom_mode(fw)
    try:
        vdoms = await list_vdoms(fw)
    except FortiGateError as exc:
        raise FortiGateError(f"無法取得 VDOM 清單：{exc}",
                             code="fgt_vdom_list", reason=str(exc)[:200]) from exc
    # 空字串代表「不指定 VDOM 範圍」。前端要看得出這件事 —— 一個空白的 VDOM 清單
    # 和「有一個叫 root 的 VDOM」在畫面上長得一樣，但意義完全不同（issue #26）。
    out["vdoms"] = [v for v in vdoms if v]
    out["vdom_scoped"] = bool(out["vdoms"])
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
            first = str(exc)[:200]
            if not vdoms[0]:
                return {"endpoint": label, "ok": False, "error": first}
            # 帶著 VDOM 失敗時，再試一次「不指定 VDOM」。兩種結果的差別是可行動的資訊：
            # 若不帶就成功，代表這台的 VDOM 範圍設錯了（或這個韌體不吃該參數），
            # 而不是端點不存在或權限不足 —— 使用者回報「整合怪怪的」時，
            # 光看一排相同的錯誤訊息是分不出來的（issue #26）。
            try:
                rows = _rows(await _api_get(fw, path, timeout=_DIAG_TIMEOUT))
            except FortiGateError:
                return {"endpoint": label, "ok": False, "error": first}
            return {"endpoint": label, "ok": True, "rows": len(rows),
                    "without_vdom": True, "vdom_error": first}

    # 並行探測：這 10 支是彼此獨立的 GET，循序跑的話對「不可達主機」會累加成
    # 10 × 逾時 ≈ 100 秒，前端診斷視窗看起來像凍住 —— 而 IP 填錯／防火牆丟包
    # 正是客戶第一次設定最常遇到的情況。並行後最壞情況約等於單一逾時。
    checks = list(await asyncio.gather(*(_probe(lbl, p) for lbl, p in probes)))
    out["checks"] = checks
    out["ok_count"] = sum(1 for c in checks if c["ok"])
    return out


async def sync_instance(session: AsyncSession, fw: FortiGateFirewall) -> dict[str, Any]:
    """跑此實例所有啟用的同步；設定 last_sync_at / last_error。

    **每個區段各自隔離**：實機上很常見「10 支端點有 9 支可讀」（某支在該韌體版本
    不存在、或 API 管理員讀不到）。若不隔離，DHCP 租約一掛就會讓 ARP／政策／位址
    物件全部不同步，而畫面上只看得到一行錯誤 —— 看起來像整台壞掉。
    """
    vdoms, vdoms_ok = await list_vdoms_ex(fw)
    counts: dict[str, Any] = {"vdoms": len(vdoms)}
    errors: dict[str, str] = {}
    if not vdoms_ok:
        # 看得到的只有管理 VDOM：照常同步看得到的部分，但不清任何東西，並講出來
        errors["vdoms"] = "讀不到 VDOM 清單，這一輪只同步看得到的部分、不清除任何資料（可在整合設定明確指定 VDOM）"

    async def _section(name: str, coro_factory: Any) -> None:
        try:
            result = await coro_factory()
            if isinstance(result, dict):
                counts.update(result)
            else:
                counts[name] = result
        except FortiGateError as exc:
            errors[name] = str(exc)[:200]

    if fw.sync_dhcp:
        await _section("dhcp", lambda: sync_dhcp_leases(session, fw, vdoms,
                                                        vdoms_authoritative=vdoms_ok))
    # 發放範圍／固定分配／政策／NAT／位址物件是「整份取代」：VDOM 清單不是權威的時候
    # 只看得到管理 VDOM，取代下去會把其他 VDOM 的資料清掉 → 這一輪不動（見上方 errors["vdoms"]）
    if fw.sync_dhcp_ranges and vdoms_ok:
        await _section("dhcp_ranges", lambda: sync_dhcp_ranges(session, fw, vdoms))
        await _section("dhcp_reservations", lambda: sync_dhcp_reservations(session, fw, vdoms))
    if fw.sync_arp:
        await _section("arp", lambda: sync_arp(session, fw, vdoms))
    if fw.sync_vpn:
        await _section("vpn", lambda: sync_vpn(session, fw, vdoms, authoritative=vdoms_ok))
    if fw.sync_policies and vdoms_ok:
        await _section("policies", lambda: sync_policies(session, fw, vdoms))
        if "policies" not in errors:
            from app.services.fw_review import run_sentinel
            await run_sentinel(session, source_type="fortigate", instance=fw)
    if fw.sync_nat and vdoms_ok:
        await _section("nat", lambda: sync_nat(session, fw, vdoms))
    if fw.sync_addresses and vdoms_ok:
        await _section("addresses", lambda: sync_addresses(session, fw, vdoms))

    fw.last_sync_at = datetime.now(UTC)
    # 部分失敗要留下痕跡（否則使用者以為全部同步成功），但不影響其他區段
    fw.last_error = ("部分區段失敗：" + "；".join(f"{k}: {v}" for k, v in errors.items())
                     if errors else None)
    if errors:
        counts["errors"] = errors
    return counts
