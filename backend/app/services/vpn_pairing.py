"""站對站 VPN：通道屬於哪台裝置、兩端怎麼配對（各廠牌共用）。

拓樸圖畫一條 VPN 至少要知道一端是哪台裝置（`a_device_id`），兩端都知道才畫成兩台之間的線。
以前只有 OPNsense 的同步會做這兩件事；FortiGate、Palo Alto、MikroTik 的通道因此從沒出現在圖上
（2026-10-01 使用者回報）。這裡把「整合 → 裝置」與配對抽出來，各整合同步完都呼叫 `link_peers`。

配對規則：
- WireGuard：A 的對端公鑰＝B 的本機公鑰（加密身分，可靠）→ `wireguard_pubkey`
- IPsec：A 的對端閘道位址正好是另一台已知防火牆的位址（API 位址或它自己通道記的本機端點）
  → `ipsec_endpoint`（沒有加密身分，best-effort；對不到就不連，不猜）
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


def url_host(url: str | None) -> str | None:
    """`https://192.0.2.1:8443/` → `192.0.2.1`（通道的本機端點要的是位址，不是整個網址）。"""
    if not url:
        return None
    return (urlsplit(url if "://" in url else f"https://{url}").hostname or "").strip().lower() or None


async def resolve_device_for(session: AsyncSession, *, api_url: str | None, name: str | None) -> uuid.UUID | None:
    """整合對應的 jt-ipam 裝置：API 位址對到的 IP 所屬裝置 → 名稱就是那個位址的裝置 → 與整合同名的裝置。"""
    from app.models.address import IPAddress
    from app.models.device import Device

    host = url_host(api_url)
    if host:
        did = (await session.execute(
            select(IPAddress.device_id).where(
                func.host(IPAddress.ip) == host, IPAddress.device_id.isnot(None)).limit(1)
        )).scalar_one_or_none()
        if did:
            return did
        did = (await session.execute(
            select(Device.id).where(func.lower(Device.name) == host).limit(1))).scalar_one_or_none()
        if did:
            return did
    if not name:
        return None
    return (await session.execute(
        select(Device.id).where(func.lower(Device.name) == name.lower()).limit(1)
    )).scalar_one_or_none()


async def link_wireguard_peers(session: AsyncSession) -> int:
    """WireGuard 對接：A.peer_public_key == B.local_public_key → A 的對端就是 B 的裝置。

    雙向都成立時兩條通道互指對方裝置（拓樸圖以裝置對去重）。回傳本次有變動的數量。
    """
    from app.models.physical import VPNTunnel

    tunnels = list((await session.execute(
        select(VPNTunnel).where(VPNTunnel.type == "wireguard")
    )).scalars().all())

    # 本機公鑰 → 那條通道的裝置，以及那條通道本身（拿對端記錄的我方 WAN）
    by_local: dict[str, uuid.UUID] = {}
    by_local_tunnel: dict[str, Any] = {}
    for t in tunnels:
        if t.local_public_key and t.a_device_id:
            by_local.setdefault(t.local_public_key, t.a_device_id)
            by_local_tunnel.setdefault(t.local_public_key, t)

    linked = 0
    for t in tunnels:
        if not t.peer_public_key:
            continue
        peer_dev = by_local.get(t.peer_public_key)
        # 不要連到自己（同一台的 server／client）
        if peer_dev and peer_dev != t.a_device_id:
            if t.b_device_id != peer_dev:
                t.b_device_id = peer_dev
                t.pairing_method = "wireguard_pubkey"   # 公鑰配對：可靠
                linked += 1
            # 本端 a_endpoint 常是 LAN／管理位址；對端通道記的 b_endpoint 正是「對端看到的我方位址」
            # ＝我方 WAN 公網位址 → 拿來補正
            recip = by_local_tunnel.get(t.peer_public_key)
            if recip is not None and recip.b_endpoint and t.a_endpoint != recip.b_endpoint:
                t.a_endpoint = recip.b_endpoint
        elif peer_dev is None and t.b_device_id is not None and t.pairing_method == "wireguard_pubkey":
            # 對端已不再宣告這把公鑰 → 還原成遠端站點
            t.b_device_id = None
            t.pairing_method = None
            linked += 1
    return linked


async def _known_addresses(session: AsyncSession) -> dict[str, uuid.UUID]:
    """位址 → 防火牆／路由器的裝置。來源：各整合的 API 位址，以及各通道自己記的本機端點（通常就是 WAN）。"""
    from app.models.firewall import OPNsenseFirewall
    from app.models.fortigate import FortiGateFirewall
    from app.models.mikrotik import MikroTikRouter
    from app.models.paloalto import PaloAltoFirewall
    from app.models.physical import VPNTunnel

    out: dict[str, uuid.UUID] = {}
    for model in (OPNsenseFirewall, FortiGateFirewall, PaloAltoFirewall):
        for fw in (await session.execute(select(model))).scalars().all():
            host = url_host(fw.api_url)
            dev = await resolve_device_for(session, api_url=fw.api_url, name=fw.name)
            if dev and host:
                out.setdefault(host, dev)
    for r in (await session.execute(select(MikroTikRouter))).scalars().all():
        host = url_host(r.api_url)
        dev = r.device_id or await resolve_device_for(session, api_url=r.api_url, name=r.name)
        if dev and host:
            out.setdefault(host, dev)
    for a_dev, a_ep in (await session.execute(
            select(VPNTunnel.a_device_id, VPNTunnel.a_endpoint).where(
                VPNTunnel.a_device_id.isnot(None), VPNTunnel.a_endpoint.isnot(None)))).all():
        for a in str(a_ep).replace(";", ",").split(","):
            a = a.strip().lower()
            if a:
                out.setdefault(a, a_dev)
    return out


async def link_ipsec_peers(session: AsyncSession) -> int:
    """IPsec 對接（best-effort）：對端閘道位址（b_endpoint）正好是另一台已知防火牆的位址才連。"""
    from app.models.physical import VPNTunnel

    addr_to_dev = await _known_addresses(session)
    tunnels = list((await session.execute(
        select(VPNTunnel).where(VPNTunnel.type.in_(("ipsec_ikev1", "ipsec_ikev2"))))).scalars().all())
    linked = 0
    for t in tunnels:
        # b_endpoint 可能是「1.2.3.4」或「1.2.3.4,5.6.7.8」
        remotes = [a.strip().lower() for a in (t.b_endpoint or "").replace(";", ",").split(",") if a.strip()]
        peer_dev = next((addr_to_dev[a] for a in remotes
                         if a in addr_to_dev and addr_to_dev[a] != t.a_device_id), None)
        if peer_dev:
            if t.b_device_id != peer_dev:
                t.b_device_id = peer_dev
                t.pairing_method = "ipsec_endpoint"   # 端點比對：best-effort（沒有加密身分）
                linked += 1
        elif t.b_device_id is not None and t.pairing_method == "ipsec_endpoint":
            # 之前連的對端位址已不再對應任何防火牆 → 還原
            t.b_device_id = None
            t.pairing_method = None
            linked += 1
    return linked


async def link_peers(session: AsyncSession) -> int:
    """兩種配對都跑一次（各整合同步 VPN 之後呼叫；整張表一起看，跨廠牌也配得到）。"""
    await session.flush()
    return await link_wireguard_peers(session) + await link_ipsec_peers(session)
