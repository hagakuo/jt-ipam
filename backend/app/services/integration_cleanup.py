"""刪除整合實例時，收回它寫進共用表的資料（2026-09-26 稽核）。

各整合自己的鏡像表大多有外鍵 CASCADE（政策、位址物件、DNS 記錄…），刪實例就跟著走；
但下面這些是多來源共用、沒有外鍵的表，以前刪了實例它們還在，而且再也不會有同步去清：

- `ip_hostname_reports`：它回報的主機名稱（觀測重算，ip.hostname 跟著變）
- `dhcp_lease_sightings`／`dhcp_reservations`／`dhcp_pool_ranges`：租約、固定分配、發放範圍
  （`in_dhcp_lease`／`dhcp_reserved` 旗標重算）
- `nat_translations`／`vpn_tunnels`：以 `source_origin = "<來源>:<id>"` 標記的列
- `device_ports`（MikroTik 介面，0170）：沒接線的刪、已接線的留著並拿掉來源標記

每個條件都帶來源類型＋實例 id，只清自己的列。**不 commit**，交易邊界由呼叫端決定。
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from app.models.virt import ProxmoxInstance


async def forget_instance(session: AsyncSession, *, source: str, source_id: uuid.UUID,
                          hostname_sources: tuple[str, ...] | None = None) -> None:
    """清掉 `source`（opnsense／fortigate／dns／wazuh…）這台實例寫進共用表的列。

    hostname_sources：這個實例用哪些來源名稱回報主機名稱（預設就是 source；
    掃描代理一台回報 scanner／netbios／mdns 三種）。
    """
    from app.models.dhcp import DHCPPoolRange, DHCPReservation
    from app.models.ip_hostname import HOSTNAME_SOURCES
    from app.models.nat import NATTranslation
    from app.models.physical import VPNTunnel
    from app.services import dhcp_leases, dhcp_reservations
    from app.services.hostname_reports import forget_origin

    origin = f"{source}:{source_id}"
    await session.execute(delete(DHCPPoolRange).where(
        DHCPPoolRange.source_type == source, DHCPPoolRange.source_id == source_id))
    # 依它的發放範圍自動建立的「位址範圍（集區）」（手動建立的 source_origin 是 NULL，不會被刪）
    from app.models.ip_range import IPRange
    await session.execute(delete(IPRange).where(IPRange.source_origin == origin))
    await session.execute(delete(DHCPReservation).where(
        DHCPReservation.source_type == source, DHCPReservation.source_id == source_id))
    await dhcp_reservations._recompute_flags(session)
    await dhcp_leases.forget_source(session, source_type=source, source_id=source_id)
    await session.execute(delete(NATTranslation).where(NATTranslation.source_origin == origin))
    await session.execute(delete(VPNTunnel).where(VPNTunnel.source_origin == origin))
    for hs in hostname_sources or (source,):
        if hs in HOSTNAME_SOURCES:
            await forget_origin(session, source=hs, origin_prefix=f"{hs}:{source_id}")
    if source == "librenms":
        # ARP／FDB 的外鍵是 SET NULL：不先刪會留下沒有歸屬的觀測，繼續參與交換器埠推算與拓樸
        from app.models.librenms import ARPEntry, FDBEntry
        await session.execute(delete(ARPEntry).where(ARPEntry.instance_id == source_id))
        await session.execute(delete(FDBEntry).where(FDBEntry.instance_id == source_id))
    if source == "mikrotik":
        # FDB／鄰居有外鍵 CASCADE 跟著路由器走；介面寫進裝置連接埠（0170）沒有，要自己收回
        await release_origin_ports(session, origin)
    # 作業頁上它的排程心跳列（每個實例一列，target_id＝實例 id）：不刪的話作業頁永遠留著一台已經不存在的來源。
    # 手動作業是歷史記錄（誰在什麼時候按了同步），留著。
    from app.services.background_tasks import forget_scheduled_rows
    await forget_scheduled_rows(session, source_id)


async def release_origin_ports(session: AsyncSession, origin: str) -> int:
    """收回某個來源寫進 `device_ports` 的埠：沒接線的刪掉；已接線、有穿透對應的留著，
    只拿掉來源標記（變成使用者的埠，不會被別的同步誤刪）。回傳刪除數。"""
    from sqlalchemy import select, update

    from app.core.sqlin import in_values
    from app.models.physical import CableTermination, DevicePort

    ids = list((await session.execute(
        select(DevicePort.id).where(DevicePort.source_origin == origin))).scalars().all())
    if not ids:
        return 0
    keep = set((await session.execute(select(DevicePort.id).where(
        in_values(DevicePort.id, ids), DevicePort.peer_port_id.is_not(None)))).scalars().all())
    keep |= set((await session.execute(
        select(DevicePort.peer_port_id).where(in_values(DevicePort.peer_port_id, ids)))).scalars().all())
    keep |= set((await session.execute(
        select(CableTermination.object_id).where(in_values(CableTermination.object_id, ids)))).scalars().all())
    gone = [i for i in ids if i not in keep]
    if gone:
        await session.execute(delete(DevicePort).where(in_values(DevicePort.id, gone)))
    kept = [i for i in ids if i in keep]
    if kept:
        await session.execute(update(DevicePort).where(in_values(DevicePort.id, kept)).values(source_origin=None))
    return len(gone)


async def forget_proxmox_instance(session: AsyncSession, instance: ProxmoxInstance) -> None:
    """刪除 PVE 實例：主機名稱的 origin 是叢集（`proxmox:<叢集 id>`），VM 鏡像也掛在叢集上。
    同一個叢集還有別的實例（備援進入點）→ 那些資料它還會繼續同步，不動。"""
    from sqlalchemy import select

    from app.models.virt import ProxmoxInstance, VirtualMachine

    inst_id = instance.id
    cluster_id = instance.cluster_id
    await forget_instance(session, source="proxmox", source_id=inst_id)
    if cluster_id is None:
        return
    others = (await session.execute(select(ProxmoxInstance.id).where(
        ProxmoxInstance.cluster_id == cluster_id, ProxmoxInstance.id != inst_id))).first()
    if others is not None:
        return
    await forget_instance(session, source="proxmox", source_id=cluster_id)
    # VM 鏡像（網卡列 CASCADE）；叢集本身留著 —— 上面可能有使用者設的地點／客戶
    await session.execute(delete(VirtualMachine).where(VirtualMachine.cluster_id == cluster_id))
