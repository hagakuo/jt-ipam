"""Device endpoints。"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin, require_object_perm
from app.core.audit import append_audit
from app.core.db import get_session
from app.models.device import Device
from app.models.librenms import LibreNMSDevice
from app.models.vlan import VLAN, DeviceVLAN
from app.schemas.base import Paginated, StrictModel
from app.schemas.device import DeviceCreate, DeviceRead, DeviceUpdate
from app.services.custom_field import CustomFieldError, validate_custom_fields

router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceVLANRead(StrictModel):
    vlan_id: uuid.UUID
    number: int
    name: str
    source: str
    last_seen_at: Any


@router.get(
    "/{device_id}/librenms",
    dependencies=[Depends(require_object_perm("device", "read", path_param="device_id"))],
)
async def get_device_librenms(
    device_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any] | None:
    """連結到此裝置的 LibreNMS 資料（os/hardware/serial/version/uptime/status）。"""
    if await session.get(Device, device_id) is None:
        raise HTTPException(404, detail="Device not found")
    r = (await session.execute(
        select(LibreNMSDevice).where(LibreNMSDevice.jt_ipam_device_id == device_id).limit(1)
    )).scalar_one_or_none()
    if r is None:
        return None
    return {
        "hostname": r.hostname, "sysname": r.sysname, "primary_ip": str(r.primary_ip) if r.primary_ip else None,
        "hardware": r.hardware, "os": r.os, "version": r.version, "serial": r.serial,
        "uptime": r.uptime, "status": r.status,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
    }


@router.get(
    "/{device_id}/integrations",
    dependencies=[Depends(require_object_perm("device", "read", path_param="device_id"))],
)
async def get_device_integrations(
    device_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """此裝置在其他整合系統的資料：Wazuh agent / Proxmox VM（依裝置的 IP 比對）。"""
    from app.models.address import IPAddress
    from app.models.virt import VirtCluster, VirtualMachine
    from app.models.wazuh import WazuhAgent, WazuhInstance
    dev = await session.get(Device, device_id)
    if dev is None:
        raise HTTPException(404, detail="Device not found")
    ip_ids: list[Any] = []
    ip_strs: list[str] = []
    for ipid, ipv in (await session.execute(
        select(IPAddress.id, IPAddress.ip).where(IPAddress.device_id == device_id)
    )).all():
        ip_ids.append(ipid)
        ip_strs.append(str(ipv).split("/")[0])
    if dev.primary_ip_id and dev.primary_ip_id not in ip_ids:
        pr = await session.get(IPAddress, dev.primary_ip_id)
        if pr:
            ip_ids.append(pr.id)
            ip_strs.append(str(pr.ip).split("/")[0])
    out: dict[str, Any] = {"wazuh": None, "vm": None}
    if not ip_ids:
        return out
    wa = (await session.execute(
        select(WazuhAgent).where(WazuhAgent.jt_ipam_address_id.in_(ip_ids)).limit(1)
    )).scalar_one_or_none()
    if wa is None and ip_strs:
        wa = (await session.execute(
            select(WazuhAgent).where(WazuhAgent.ip.in_(ip_strs)).limit(1)
        )).scalar_one_or_none()
    if wa is not None:
        inst = await session.get(WazuhInstance, wa.instance_id)
        out["wazuh"] = {
            "agent_id": wa.agent_id, "name": wa.name,
            "ip": str(wa.ip) if wa.ip else None, "status": wa.status,
            "os_platform": wa.os_platform, "os_version": wa.os_version,
            "agent_version": wa.agent_version, "group": wa.group,
            "cve_critical": wa.cve_critical_count, "cve_high": wa.cve_high_count,
            # 資安組態評估（SCA）—— 目前唯一拿得到的資安體質指標
            "sca_policy": wa.sca_policy, "sca_score": wa.sca_score,
            "sca_pass": wa.sca_pass, "sca_fail": wa.sca_fail,
            "sca_policy_count": wa.sca_policy_count,
            "sca_scanned_at": wa.sca_scanned_at.isoformat() if wa.sca_scanned_at else None,
            "instance": inst.name if inst else None,
            "last_keep_alive": wa.last_keep_alive.isoformat() if wa.last_keep_alive else None,
        }
    vm = (await session.execute(
        select(VirtualMachine).where(VirtualMachine.primary_ip_id.in_(ip_ids)).limit(1)
    )).scalar_one_or_none()
    if vm is not None:
        cl = await session.get(VirtCluster, vm.cluster_id)
        out["vm"] = {
            "name": vm.name, "node": vm.node, "status": vm.status,
            "vcpus": vm.vcpus, "memory_mb": vm.memory_mb,
            "cluster": cl.name if cl else None,
        }
    return out


@router.get(
    "/{device_id}/vlans",
    response_model=list[DeviceVLANRead],
    dependencies=[Depends(require_object_perm("device", "read", path_param="device_id"))],
)
async def get_device_vlans(
    device_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[DeviceVLANRead]:
    """裝置的 VLAN 清單（feature C）。

    VLAN 對應掛在 LibreNMS 裝置；這裡透過 librenms_devices.jt_ipam_device_id 連結
    到此 jt-ipam Device 來解析（裝置未連結 LibreNMS 時會是空清單）。
    """
    if await session.get(Device, device_id) is None:
        raise HTTPException(404, detail="Device not found")
    rows = (await session.execute(
        select(VLAN.id, VLAN.number, VLAN.name, DeviceVLAN.source,
               func.max(DeviceVLAN.last_seen_at).label("last_seen_at"))
        .join(DeviceVLAN, DeviceVLAN.vlan_id == VLAN.id)
        .join(LibreNMSDevice, LibreNMSDevice.id == DeviceVLAN.librenms_device_id)
        .where(LibreNMSDevice.jt_ipam_device_id == device_id)
        .group_by(VLAN.id, VLAN.number, VLAN.name, DeviceVLAN.source)
        .order_by(VLAN.number)
    )).all()
    return [
        DeviceVLANRead(vlan_id=r.id, number=r.number, name=r.name,
                       source=r.source, last_seen_at=r.last_seen_at)
        for r in rows
    ]


async def _resolve_device_ips(session: AsyncSession, devices: list[Any]) -> dict[Any, Any]:
    """解析每台 device 的「有效管理 IP」供清單/明細顯示。
    優先序：primary_ip_id → LibreNMS 已知管理 IP（primary_ip/hostname）→ 裝置名稱本身是 IP。
    （多數 device 沒有連 IPAddress，但 LibreNMS 知道、或名稱就是 IP，否則 IP 欄會整排空白。）
    """
    import ipaddress as _ip

    from app.models.address import IPAddress
    from app.models.librenms import LibreNMSDevice

    pip_ids = {d.primary_ip_id for d in devices if d.primary_ip_id}
    pip_map: dict[Any, Any] = {}
    if pip_ids:
        for pid, ip in (await session.execute(
            select(IPAddress.id, IPAddress.ip).where(IPAddress.id.in_(pip_ids))
        )).all():
            pip_map[pid] = str(ip).split("/")[0]
    dev_ids = [d.id for d in devices]
    ln_map: dict[Any, Any] = {}
    if dev_ids:
        for jid, pip, host in (await session.execute(
            select(LibreNMSDevice.jt_ipam_device_id, LibreNMSDevice.primary_ip,
                   LibreNMSDevice.hostname).where(LibreNMSDevice.jt_ipam_device_id.in_(dev_ids))
        )).all():
            for cand in (pip, host):
                if not cand:
                    continue
                try:
                    ln_map[jid] = str(_ip.ip_address(str(cand).split("/")[0].strip()))
                    break
                except ValueError:
                    continue
    out: dict[Any, Any] = {}
    for d in devices:
        ip = pip_map.get(d.primary_ip_id) if d.primary_ip_id else None
        if not ip:
            ip = ln_map.get(d.id)
        if not ip:
            try:
                ip = str(_ip.ip_address((d.name or "").strip()))
            except ValueError:
                ip = None
        if ip:
            out[d.id] = ip
    return out


@router.get("", response_model=Paginated[DeviceRead])
async def list_devices(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    type: str | None = Query(None),
    location_id: uuid.UUID | None = Query(None),
    rack_id: uuid.UUID | None = Query(None),
    subnet_id: uuid.UUID | None = Query(None),
    q: Annotated[str | None, Query(max_length=128)] = None,
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(50, ge=1, le=500),
) -> Paginated[DeviceRead]:
    """裝置清單。

    `q` 是**伺服器端**搜尋（名稱／型號／序號／製造商，不分大小寫）。
    這一支一定要有：畫面只載得下前幾百筆，若搜尋只在已載入的那幾筆上做，
    使用者新增的裝置只要排序落在載入範圍之外，就會「列表看不到、用名字也搜不到」，
    但從機櫃點進去卻看得到 —— 客戶就是這樣回報的。
    """
    stmt = select(Device)
    cstmt = select(func.count()).select_from(Device)
    if q:
        like = f"%{q.strip()}%"
        cond = or_(
            Device.name.ilike(like),
            Device.model.ilike(like),
            Device.serial.ilike(like),
            Device.description.ilike(like),
        )
        stmt = stmt.where(cond); cstmt = cstmt.where(cond)
    if type is not None:
        stmt = stmt.where(Device.type == type); cstmt = cstmt.where(Device.type == type)
    if location_id is not None:
        stmt = stmt.where(Device.location_id == location_id)
        cstmt = cstmt.where(Device.location_id == location_id)
    if rack_id is not None:
        stmt = stmt.where(Device.rack_id == rack_id); cstmt = cstmt.where(Device.rack_id == rack_id)
    if subnet_id is not None:
        # 「這個網段裡有哪些裝置」——「某某網段要停電維護，會影響誰」這種問題的第一步。
        # 用 EXISTS 而非 JOIN：一台裝置在同一個網段可能有多個 IP，JOIN 會讓它重複出現。
        from app.models.address import IPAddress as _IPA
        cond_sub = select(_IPA.id).where(
            _IPA.device_id == Device.id, _IPA.subnet_id == subnet_id).exists()
        stmt = stmt.where(cond_sub); cstmt = cstmt.where(cond_sub)
    # RBAC：只回該 user 可見的裝置（admin / wildcard → vis is None → 不過濾）
    from app.services.permission import visible_ids
    vis = await visible_ids(session, user=_user, object_type="device")
    if vis is not None:
        stmt = stmt.where(Device.id.in_(vis)); cstmt = cstmt.where(Device.id.in_(vis))
    stmt = stmt.order_by(Device.name).offset((page - 1) * page_size).limit(page_size)
    rows = list((await session.execute(stmt)).scalars().all())
    total = int(await session.scalar(cstmt) or 0)
    # 批次解析每台 device 的有效管理 IP（primary_ip → LibreNMS → 名稱是 IP）
    ip_map = await _resolve_device_ips(session, rows)
    # 找出與裝置有效 IP 相符、但還沒連到本裝置的 IPAddress → 提供「一鍵關聯」按鈕
    from sqlalchemy import func as _func

    from app.models.address import IPAddress
    eff_ips = {v for v in ip_map.values() if v}
    addr_by_ip: dict[str, tuple[Any, ...]] = {}
    if eff_ips:
        for aid, ahost, adev in (await session.execute(
            select(IPAddress.id, _func.host(IPAddress.ip), IPAddress.device_id)
            .where(_func.host(IPAddress.ip).in_(eff_ips))
        )).all():
            addr_by_ip.setdefault(str(ahost), (aid, adev))
    # 虛擬 / 實體：一次撈出所有 VM 名稱，避免逐台查
    from app.models.virt import VirtualMachine as _VM
    vm_names = {
        (n or "").strip().lower()
        for n in (await session.execute(select(_VM.name))).scalars().all() if n
    }
    items = []
    for r in rows:
        d = DeviceRead.model_validate(r)
        d.is_virtual = (r.name or "").strip().lower() in vm_names
        d.ip = ip_map.get(r.id)
        if d.ip and d.ip in addr_by_ip:
            aid, adev = addr_by_ip[d.ip]
            d.ip_address_id = str(aid)   # 有對應的 IPAddress → IP 欄可點進該位址
            if adev != r.id:   # 還沒連到本裝置 → 可一鍵關聯
                d.ip_match_id = str(aid)
        items.append(d)
    return Paginated[DeviceRead](
        items=items, total=total, page=page, page_size=page_size,
    )


@router.get(
    "/{device_id}/relations",
    dependencies=[Depends(require_object_perm("device", "read", path_param="device_id"))],
)
async def get_device_relations(
    device_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """裝置的上下關係鏈：機房 → 機櫃 → 裝置 → 主要 IP → 子網路 → 區段。"""
    from app.models.address import IPAddress
    from app.models.location import Location, Rack
    from app.models.section import Section
    from app.models.subnet import Subnet

    dev = await session.get(Device, device_id)
    if dev is None:
        raise HTTPException(404, detail="Device not found")
    chain: list[dict[str, Any]] = []
    if dev.location_id:
        loc = await session.get(Location, dev.location_id)
        if loc is not None:
            chain.append({"type": "location", "id": str(loc.id), "label": loc.name})
    if dev.rack_id:
        rk = await session.get(Rack, dev.rack_id)
        if rk is not None:
            chain.append({"type": "rack", "id": str(rk.id), "label": rk.name})
    # 若這台「裝置」其實是某台 Proxmox VM 的客體（無機櫃/機房），補上它所在的 PVE 節點
    # （節點的機房 / 機櫃 → 節點 → 本客體）。
    if not dev.location_id and not dev.rack_id:
        from sqlalchemy import func as _func

        from app.models.virt import VirtCluster, VirtualMachine
        vm = (await session.execute(
            select(VirtualMachine).where(_func.lower(VirtualMachine.name) == dev.name.lower()).limit(1)
        )).scalar_one_or_none()
        if vm is None:
            ip_ids = [r for (r,) in (await session.execute(
                select(IPAddress.id).where(IPAddress.device_id == dev.id)
            )).all()]
            if ip_ids:
                vm = (await session.execute(
                    select(VirtualMachine).where(VirtualMachine.primary_ip_id.in_(ip_ids)).limit(1)
                )).scalar_one_or_none()
        if vm is not None:
            node_dev = await session.get(Device, vm.device_id) if vm.device_id else None
            if node_dev is None and vm.node:
                node_dev = (await session.execute(
                    select(Device).where(_func.lower(Device.name) == vm.node.lower()).limit(1)
                )).scalar_one_or_none()
                if node_dev is None:
                    node_dev = (await session.execute(
                        select(Device).where(_func.lower(Device.fqdn) == vm.node.lower()).limit(1)
                    )).scalar_one_or_none()
            cluster = await session.get(VirtCluster, vm.cluster_id) if vm.cluster_id else None
            csub = cluster.name if cluster is not None else None
            # 平台要跟著節點走：關係圖原本一律標成「PVE 節點」並連到 PVE 那一頁，
            # 但 VMware 的 VM 掛的是 ESXi 主機 —— 標錯名字、也連錯地方。
            plat = (cluster.type if cluster is not None else None) or "proxmox"
            if node_dev is not None and node_dev.id != dev.id:
                if node_dev.location_id:
                    nloc = await session.get(Location, node_dev.location_id)
                    if nloc is not None:
                        chain.append({"type": "location", "id": str(nloc.id), "label": nloc.name})
                if node_dev.rack_id:
                    nrk = await session.get(Rack, node_dev.rack_id)
                    if nrk is not None:
                        chain.append({"type": "rack", "id": str(nrk.id), "label": nrk.name})
                chain.append({"type": "vmnode", "id": str(node_dev.id), "label": node_dev.name,
                              "sub": csub, "platform": plat})
            elif vm.node:
                chain.append({"type": "vmnode", "id": "host:" + vm.node, "label": vm.node,
                              "sub": csub, "platform": plat})
            # 虛擬機本身也要畫（實體節點 → 虛擬機 → 這台裝置）。
            # 少了它，同一台機器在 IP 詳細資料頁看得到虛擬機、在裝置詳細資料頁卻看不到，
            # 兩頁講的是同一件事卻長得不一樣。
            chain.append({"type": "vm", "id": str(vm.id), "label": vm.name, "sub": csub,
                          "platform": plat})
    chain.append({"type": "device", "id": str(dev.id), "label": dev.name})
    # 主要 IP（沒設就抓任一連到本裝置的 IP）→ 子網路 → 區段
    ip = None
    if dev.primary_ip_id:
        ip = await session.get(IPAddress, dev.primary_ip_id)
    if ip is None:
        ip = (await session.execute(
            select(IPAddress).where(IPAddress.device_id == dev.id).limit(1)
        )).scalar_one_or_none()
    if ip is not None:
        chain.append({"type": "ip", "id": str(ip.id),
                      "label": str(ip.ip).split("/")[0], "sub": ip.hostname})
        if ip.subnet_id:
            sn = await session.get(Subnet, ip.subnet_id)
            if sn is not None:
                chain.append({"type": "subnet", "id": str(sn.id),
                              "label": str(sn.cidr), "sub": sn.description})
                if sn.section_id:
                    sec = await session.get(Section, sn.section_id)
                    if sec is not None:
                        chain.append({"type": "section", "id": str(sec.id), "label": sec.name})
    return {"chain": chain}


@router.get(
    "/{device_id}",
    response_model=DeviceRead,
    dependencies=[Depends(require_object_perm("device", "read", path_param="device_id"))],
)
async def get_device(
    device_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DeviceRead:
    obj = await session.get(Device, device_id)
    if obj is None:
        raise HTTPException(404, detail="Device not found")
    d = DeviceRead.model_validate(obj)
    ips = await _resolve_device_ips(session, [obj])
    d.ip = ips.get(obj.id)
    # 虛擬 / 實體：詳細資料頁也要看得到（與清單同一套判斷）
    from app.models.virt import VirtualMachine as _VM
    d.is_virtual = bool(await session.scalar(
        select(_VM.id).where(func.lower(_VM.name) == (obj.name or "").strip().lower()).limit(1)
    ))
    return d


@router.post("", response_model=DeviceRead, status_code=201,
             dependencies=[Depends(require_admin)])
async def create_device(
    payload: DeviceCreate,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DeviceRead:
    try:
        cf = await validate_custom_fields(
            session, object_type="device", payload=payload.custom_fields
        )
    except CustomFieldError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    data = payload.model_dump()
    data["custom_fields"] = cf or None
    obj = Device(**data)
    # 放進機櫃時先防呆：U 位不可越界或與其他裝置重疊
    if obj.rack_id is not None and obj.u_position is not None and obj.u_size is not None:
        from app.services.rack import RackPlacementError, assert_placement_ok
        try:
            await assert_placement_ok(
                session, rack_id=obj.rack_id, u_position=obj.u_position,
                u_size=obj.u_size, rack_face=obj.rack_face, rack_side=obj.rack_side,
            )
        except RackPlacementError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.add(obj)
    await session.flush()
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="device", object_id=str(obj.id), action="create",
        diff={"after": payload.model_dump(mode="json")},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return DeviceRead.model_validate(obj)


@router.patch("/{device_id}", response_model=DeviceRead,
              dependencies=[Depends(require_admin)])
async def update_device(
    device_id: uuid.UUID,
    payload: DeviceUpdate,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DeviceRead:
    obj = await session.get(Device, device_id)
    if obj is None:
        raise HTTPException(404, detail="Device not found")
    before = {"name": obj.name, "type": obj.type, "vendor": obj.vendor, "model": obj.model}
    changes = payload.model_dump(exclude_unset=True)
    if "custom_fields" in changes:
        try:
            changes["custom_fields"] = await validate_custom_fields(
                session, object_type="device", payload=changes["custom_fields"]
            ) or None
        except CustomFieldError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    for k, v in changes.items():
        setattr(obj, k, v)
    # 放進機櫃時先防呆：U 位不可越界或與其他裝置（同安裝方向）重疊
    if obj.rack_id is not None and obj.u_position is not None and obj.u_size is not None:
        from app.services.rack import RackPlacementError, assert_placement_ok
        try:
            await assert_placement_ok(
                session, rack_id=obj.rack_id, u_position=obj.u_position,
                u_size=obj.u_size, rack_face=obj.rack_face, rack_side=obj.rack_side,
                exclude_device_id=obj.id,
            )
        except RackPlacementError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    # 設了主要 IP → 同時把該 IP 的 device_id 指回本裝置（雙向連結，IP 清單/拓樸才接得起來）
    if changes.get("primary_ip_id"):
        from app.models.address import IPAddress
        pip = await session.get(IPAddress, changes["primary_ip_id"])
        if pip is not None and pip.device_id != obj.id:
            pip.device_id = obj.id
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="device", object_id=str(obj.id), action="update",
        diff={"before": before, "changes": changes},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    await session.refresh(obj)
    return DeviceRead.model_validate(obj)


@router.delete("/{device_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_device(
    device_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    obj = await session.get(Device, device_id)
    if obj is None:
        raise HTTPException(404, detail="Device not found")
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="device", object_id=str(obj.id), action="delete",
        diff={"before": {"name": obj.name, "type": obj.type}},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.delete(obj)
    await session.commit()


class _DeviceBulkDeletePayload(StrictModel):
    ids: list[uuid.UUID]


@router.post("/bulk-delete", dependencies=[Depends(require_admin)])
async def bulk_delete_devices(
    payload: _DeviceBulkDeletePayload,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    if not payload.ids:
        return {"deleted": 0, "failed": 0, "errors": []}
    if len(payload.ids) > 500:
        raise HTTPException(400, detail="too many ids (max 500)")
    deleted = 0
    errors: list[dict[str, str]] = []
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)
    for did in payload.ids:
        obj = await session.get(Device, did)
        if obj is None:
            errors.append({"id": str(did), "error": "not_found"}); continue
        await append_audit(
            session, actor_user_id=str(user.id),
            actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="device", object_id=str(obj.id), action="delete",
            diff={"before": {"name": obj.name, "type": obj.type}, "bulk": True},
            request_id=request_id,
        )
        await session.delete(obj)
        deleted += 1
    await session.commit()
    return {"deleted": deleted, "failed": len(errors), "errors": errors[:50]}


@router.get(
    "/{device_id}/uptime",
    dependencies=[Depends(require_object_perm("device", "read", path_param="device_id"))],
)
async def get_device_uptime(
    device_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    days: int = Query(90, ge=7, le=365),
) -> dict[str, Any]:
    """裝置的每日存活狀態，由它名下所有 IP 的狀態轉換合併而成。

    多個 IP 時：**當天任一 IP 曾中斷就標中斷**。與單一 IP 的每日規則一致，
    且傾向浮現問題而非掩蓋（某個介面斷了仍然值得看見）。
    重建規則與「沒資料不得算成正常」等原則見 `app/services/uptime.py`。
    """
    from app.models.address import IPAddress
    from app.services.uptime import uptime_for_ips

    ip_ids = list((await session.execute(
        select(IPAddress.id).where(IPAddress.device_id == device_id)
    )).scalars().all())
    return await uptime_for_ips(session, ip_ids, days=days)
