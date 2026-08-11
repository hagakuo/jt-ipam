"""Wazuh API client + agent inventory 同步。

API ref: https://documentation.wazuh.com/current/user-manual/api/reference.html

主要 endpoints：
  POST /security/user/authenticate     拿 JWT (basic auth)
  GET  /agents                         列出所有 agent
  GET  /sca/{agent_id}                 資安組態評估（SCA）各政策的通過／未通過數

漏洞（CVE）資料**不在這裡**：Wazuh 4.8 起 manager API 已無漏洞端點（實機 4.14.5 的
150 條路徑裡一條都沒有），唯一來源是 Wazuh Indexer —— 那需要另一組能讀取整個 SIEM
事件的憑證，代價與收益不成比例，因此不接。資安體質改用 SCA 呈現。

OWASP：
- A02：API password 雙欄 AES-GCM，aad 綁 instance id
- A05/A10：safe_request；verify_tls 旗標
- A09：sync 寫 audit；missing-agent 異常事件
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request
from app.core.security import decrypt_secret, encrypt_secret
from app.models.address import IPAddress
from app.models.wazuh import WazuhAgent, WazuhInstance


class WazuhError(RuntimeError):
    pass


def _scope_subnet_uuids(obj: WazuhInstance) -> set[Any]:
    """obj.scope_subnet_ids（JSONB 字串陣列）→ UUID set；空回空 set（不限範圍）。"""
    out: set[Any] = set()
    for s in (obj.scope_subnet_ids or []):
        try:
            out.add(uuid.UUID(str(s)))
        except (ValueError, TypeError):
            pass
    return out


# ─────────────────── 加解密 ───────────────────


def _aad(instance_id) -> bytes:  # type: ignore[no-untyped-def]
    return f"wazuh_instance:{instance_id}:api_password".encode()


def encrypt_password(instance_id, raw: str) -> tuple[bytes, bytes]:  # type: ignore[no-untyped-def]
    return encrypt_secret(raw, aad=_aad(instance_id))


def _decrypt_password(inst: WazuhInstance) -> str:
    return decrypt_secret(
        inst.api_password_enc, inst.api_password_nonce, aad=_aad(inst.id)
    ).decode("utf-8")


# ─────────────────── JWT cache ───────────────────


@dataclass
class _Token:
    jwt: str
    expires_at: float


_token_cache: dict[str, _Token] = {}   # key: instance.id


async def _authenticate(inst: WazuhInstance) -> str:
    """拿 Wazuh JWT；TTL ~15 分鐘，本端 cache 12 分。"""
    cached = _token_cache.get(str(inst.id))
    if cached and cached.expires_at > time.time() + 30:
        return cached.jwt

    pwd = _decrypt_password(inst)
    auth = base64.b64encode(f"{inst.api_user}:{pwd}".encode()).decode("ascii")
    url = f"{inst.api_url.rstrip('/')}/security/user/authenticate"
    try:
        resp = await safe_request(
            "POST", url,
            headers={"Authorization": f"Basic {auth}"},
            timeout=15.0, verify=inst.verify_tls,
        )
    except UnsafeOutboundURL as exc:
        raise WazuhError(f"SSRF guard rejected URL: {exc}") from exc
    except httpx.HTTPError as exc:
        raise WazuhError(f"transport: {exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise WazuhError(f"Wazuh auth {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    token = (data.get("data") or {}).get("token") or data.get("token")
    if not token:
        raise WazuhError(f"Wazuh auth: no token in response: {data}")
    _token_cache[str(inst.id)] = _Token(jwt=token, expires_at=time.time() + 12 * 60)
    return token  # type: ignore[no-any-return]


def _invalidate_token(inst: WazuhInstance) -> None:
    _token_cache.pop(str(inst.id), None)


# ─────────────────── 低階 HTTP ───────────────────


async def _api_get(
    inst: WazuhInstance, path: str, params: dict[str, Any] | None = None,
    *, timeout: float = 30.0,
) -> dict[str, Any]:
    token = await _authenticate(inst)
    url = f"{inst.api_url.rstrip('/')}{path}"
    try:
        resp = await safe_request(
            "GET", url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params, timeout=timeout, verify=inst.verify_tls,
        )
    except UnsafeOutboundURL as exc:
        raise WazuhError(f"SSRF guard rejected URL: {exc}") from exc
    except httpx.HTTPError as exc:
        raise WazuhError(f"transport: {exc.__class__.__name__}") from exc
    if resp.status_code == 401:
        # token 失效；重發
        _invalidate_token(inst)
        token = await _authenticate(inst)
        resp = await safe_request(
            "GET", url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params, timeout=timeout, verify=inst.verify_tls,
        )
    if resp.status_code != 200:
        raise WazuhError(f"Wazuh GET {path}: {resp.status_code} {resp.text[:200]}")
    return resp.json()  # type: ignore[no-any-return]


async def healthcheck(inst: WazuhInstance) -> dict[str, Any]:
    return await _api_get(inst, "/", timeout=8.0)


# ─────────────────── Agent inventory ───────────────────


def _index_by_ip(ip_rows: Any) -> tuple[dict[str, Any], set[str]]:
    """IP 字串 → IPAddress.id；**對應到多筆的一律不收**。

    重疊網段（例如甲乙兩單位都用 192.168.1.0/24）下，同一個 IP 字串是兩台不同機器。
    以前這裡用 dict 覆寫，等於依資料庫回傳順序任意挑一筆 —— 掛錯比沒有更糟：
    沒有資料使用者會去查，掛錯了不會知道，而且在多單位環境下是跨單位的資料外洩。

    要讓這些位址對應得上，就在該整合實例設定「限定子網路範圍」，把候選縮到一個單位。
    """
    seen: dict[str, Any] = {}
    ambiguous: set[str] = set()
    for aid, ip in ip_rows:
        key = str(ip).split("/", 1)[0]
        if key in ambiguous:
            continue
        if key in seen and seen[key] != aid:
            del seen[key]
            ambiguous.add(key)
            continue
        seen[key] = aid
    return seen, ambiguous


async def build_ip_map(
    session: AsyncSession, *, scope_ids: set[Any],
) -> tuple[dict[str, Any], set[str]]:
    """取得（IP→IPAddress.id 對應表, 不明確的 IP 集合），已套用限定子網路範圍。"""
    stmt = select(IPAddress.id, IPAddress.ip)
    if scope_ids:
        stmt = stmt.where(IPAddress.subnet_id.in_(scope_ids))
    return _index_by_ip((await session.execute(stmt)).all())


def _clean_ip(s: str | None) -> str | None:
    """register_ip / ip 欄位是 INET；Wazuh 可能回 'any' 等非 IP 值 → 存 NULL 避免 DataError。"""
    if not s:
        return None
    import ipaddress
    try:
        ipaddress.ip_address(s.strip())
    except ValueError:
        return None
    return s.strip()


def _parse_keep_alive(s: str | None) -> datetime | None:
    if not s:
        return None
    # Wazuh: "2024-01-15T10:23:45Z" 或 "9999-12-31T23:59:59Z"（never disconnected）
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.year > 9000:
        return None
    return dt


def agent_represents_ip(agent: Any, ip: Any, *, grace_hours: int = 24) -> bool:
    """這個 Wazuh agent 現在還代表這個 IP 嗎？

    只比對 IP 位址是不夠的：**DHCP 位址會被回收**。實機上 agent 015
    （`laptop-a1.local`，macOS）失聯後，它登記的 192.168.1.187 被 Proxmox 上的
    Linux VM 拿去用，我們卻把 macOS 貼到了那台 VM 上。

    判準：agent 還連著就算數；已失聯的話，只要這個 IP 在它失聯**之後**還被偵測到活著，
    就代表現在佔用這個位址的是別台機器。

    只是關機的機器不受影響 —— 沒有更新的存活證據時仍然採用它的資料，否則修掉一個錯誤
    會製造另一個（每台關機的主機都立刻失去 OS 資訊）。
    """
    from datetime import timedelta

    if (getattr(agent, "status", "") or "").lower() == "active":
        return True
    ka = getattr(agent, "last_keep_alive", None)
    if ka is None:
        return False   # 從未回報過，又不是 active → 沒有理由相信這個對映
    seen = [t for t in (getattr(ip, "last_seen_scanner", None),
                        getattr(ip, "last_seen_librenms", None)) if t is not None]
    if not seen:
        return True    # 沒有其他存活證據 → 可能只是關機，仍然採用
    return ka >= max(seen) - timedelta(hours=grace_hours)


async def fetch_agents(inst: WazuhInstance, *, batch: int = 500) -> list[dict[str, Any]]:
    """分頁拉所有 agent。"""
    out: list[dict[str, Any]] = []
    offset = 0
    while True:
        data = await _api_get(
            inst, "/agents",
            params={"limit": batch, "offset": offset, "select":
                    "id,name,ip,registerIP,status,os.platform,os.version,version,"
                    "group,node_name,lastKeepAlive"},
        )
        items = (data.get("data") or {}).get("affected_items") or []
        if not items:
            break
        out.extend(items)
        total = (data.get("data") or {}).get("total_affected_items") or len(items)
        offset += len(items)
        if offset >= int(total):
            break
    return out


async def sync_agents(session: AsyncSession, inst: WazuhInstance) -> dict[str, Any]:
    """從 Wazuh 拉 agents，upsert 到 wazuh_agents；對映到 IPAddress。"""
    agents_raw = await fetch_agents(inst)
    now = datetime.now(UTC)
    seen_ids: set[str] = set()
    matched_ip = 0
    new_count = 0
    upd_count = 0

    # 預先把 IPAddress 的 IP → id 撈出來（小型部署足夠；大型可改 chunk）
    # 重疊網段：若 instance 設了 scope_subnet_ids，IP→IPAddress 比對限定在這些子網路內
    scope_ids = _scope_subnet_uuids(inst)
    ip_map, ambiguous = await build_ip_map(session, scope_ids=scope_ids)

    for raw in agents_raw:
        agent_id = str(raw.get("id") or "").strip()
        if not agent_id or agent_id == "000":
            # 000 是 manager 自己；不算 agent
            continue
        seen_ids.add(agent_id)

        ip = _clean_ip(raw.get("ip"))
        register_ip = _clean_ip(raw.get("registerIP"))
        os_block = raw.get("os") or {}

        existing = (
            await session.execute(
                select(WazuhAgent).where(
                    WazuhAgent.instance_id == inst.id,
                    WazuhAgent.agent_id == agent_id,
                )
            )
        ).scalar_one_or_none()

        addr_id = ip_map.get(ip) if ip else None
        if addr_id is not None:
            matched_ip += 1
            # 回填 IP 主機名稱（來源 "wazuh"，依名稱順序決定是否採用）
            agent_name = (raw.get("name") or "").strip()
            if agent_name:
                from app.services.hostname import apply_observation
                ipa = await session.get(IPAddress, addr_id)
                if ipa is not None:
                    await apply_observation(session, ip=ipa, source="wazuh", hostname=agent_name)

        if existing is None:
            obj = WazuhAgent(
                instance_id=inst.id,
                agent_id=agent_id,
                name=raw.get("name"),
                ip=ip, register_ip=register_ip,
                status=raw.get("status"),
                os_platform=os_block.get("platform"),
                os_version=os_block.get("version"),
                agent_version=raw.get("version"),
                group=",".join(raw.get("group") or []) if isinstance(raw.get("group"), list) else raw.get("group"),
                node_name=raw.get("node_name"),
                last_keep_alive=_parse_keep_alive(raw.get("lastKeepAlive")),
                last_seen_at=now,
                jt_ipam_address_id=addr_id,
            )
            session.add(obj)
            new_count += 1
        else:
            existing.name = raw.get("name") or existing.name
            existing.ip = ip
            existing.register_ip = register_ip
            existing.status = raw.get("status")
            existing.os_platform = os_block.get("platform")
            existing.os_version = os_block.get("version")
            existing.agent_version = raw.get("version")
            existing.group = (
                ",".join(raw.get("group") or [])
                if isinstance(raw.get("group"), list)
                else raw.get("group")
            )
            existing.node_name = raw.get("node_name")
            existing.last_keep_alive = _parse_keep_alive(raw.get("lastKeepAlive"))
            existing.last_seen_at = now
            existing.jt_ipam_address_id = addr_id
            upd_count += 1

    inst.last_sync_at = now
    inst.last_error = None

    return {
        "fetched": len(agents_raw),
        "new": new_count,
        "updated": upd_count,
        "matched_ip": matched_ip,
        # 因為同一個 IP 字串在多個子網路中都有紀錄而**沒有**對應的數量。
        # 不是零的話，該實例應設定「限定子網路範圍」把候選縮到一個單位。
        "ambiguous_ip": len(ambiguous),
        "synced_at": now.isoformat(),
    }


async def find_missing_agents(
    session: AsyncSession, *, instance_id: uuid.UUID | None = None, hostnamed_only: bool = True,
) -> list[dict[str, Any]]:
    """找應該裝 Wazuh 卻沒有 active agent 的 IP。

    判斷條件：
    - IP 在 jt_ipam 有設 hostname（hostnamed_only=True）
    - 該 IP 沒有對映到 active 狀態的 WazuhAgent

    `instance_id`=None → 跨所有 Wazuh instance 比對。
    """
    sub = select(WazuhAgent.jt_ipam_address_id).where(
        WazuhAgent.status == "active",
        WazuhAgent.jt_ipam_address_id.is_not(None),
    )
    if instance_id is not None:
        sub = sub.where(WazuhAgent.instance_id == instance_id)
    stmt = select(IPAddress.id, IPAddress.ip, IPAddress.hostname).where(
        IPAddress.id.not_in(sub),
    )
    if hostnamed_only:
        stmt = stmt.where(IPAddress.hostname.is_not(None), IPAddress.hostname != "")
    rows = (await session.execute(stmt)).all()
    return [
        {
            "ip_address_id": str(rid),
            "ip": str(rip).split("/", 1)[0] if rip else None,
            "hostname": hostname,
        }
        for rid, rip, hostname in rows
    ]


async def fetch_sca(inst: WazuhInstance, agent_id: str) -> list[dict[str, Any]]:
    """某個 agent 的 SCA 政策結果。用現有的 manager API 帳號即可，不需要額外憑證。"""
    resp = await _api_get(inst, f"/sca/{agent_id}")
    rows = ((resp.get("data") or {}).get("affected_items") or [])
    return [r for r in rows if isinstance(r, dict)]


async def sync_sca(session: AsyncSession, inst: WazuhInstance) -> int:
    """把每個 agent 的 SCA 摘要寫回 wazuh_agents。

    一台機器可能同時跑多個基準（CIS、廠商自訂…）。畫面上只放得下一個數字時，
    存**分數最低**的那一個 —— 挑最好看的等於自我安慰。

    單一 agent 查詢失敗不影響其他台：SCA 沒跑過的 agent 本來就會回空清單。
    """
    agents = (await session.execute(
        select(WazuhAgent).where(WazuhAgent.instance_id == inst.id)
    )).scalars().all()
    now = datetime.now(UTC)
    n = 0
    for a in agents:
        try:
            rows = await fetch_sca(inst, a.agent_id)
        except WazuhError:
            continue
        if not rows:
            continue
        worst = min(rows, key=lambda r: int(r.get("score") or 0))
        a.sca_policy = str(worst.get("name") or "")[:128] or None
        a.sca_score = int(worst.get("score") or 0)
        a.sca_pass = int(worst.get("pass") or 0)
        a.sca_fail = int(worst.get("fail") or 0)
        a.sca_policy_count = len(rows)
        a.sca_scanned_at = now
        n += 1
    return n
