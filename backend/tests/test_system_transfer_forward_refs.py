"""匯入時「指向還沒建立的那一列」的外鍵。

客戶回報：把資料匯出到另一台機器再匯入，**裝置少了一半**。原因是匯入照外鍵相依序
逐表寫入，但有六個欄位是往後指的：

    devices.primary_ip_id      → ip_addresses（devices 排在 ip_addresses 前面）
    sections.parent_id         → sections     （自我參照）
    subnets.master_subnet_id   → subnets      （自我參照）
    device_ports.peer_port_id  → device_ports （自我參照）
    contact_groups.parent_id / tenant_groups.parent_id（自我參照）

輪到寫這一列時，它指向的那一列還不存在 → 外鍵違反 → **那一列整筆進不去**。
「少一半」正是因為只有設了主要 IP 的裝置會失敗，沒設的照常匯入 —— 看起來像隨機掉資料。

自我參照的情況更陰險：同一張表內誰先誰後由匯出順序決定，於是巢狀區段／子網路
會掉一部分、留一部分。
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

from app.services.system_transfer import exporter, importer


async def _seed_forward_refs(session) -> dict[str, uuid.UUID]:
    from app.models.address import IPAddress
    from app.models.device import Device
    from app.models.physical import Cable, CableTermination, DevicePort
    from app.models.section import Section
    from app.models.subnet import Subnet

    parent = Section(name="HQ")
    session.add(parent)
    await session.flush()
    child = Section(name="HQ / 3F", parent_id=parent.id)      # 巢狀區段
    session.add(child)
    await session.flush()

    master = Subnet(section_id=parent.id, cidr="10.20.0.0/16")
    session.add(master)
    await session.flush()
    sub = Subnet(section_id=child.id, cidr="10.20.30.0/24",
                 master_subnet_id=master.id)                   # 巢狀子網路
    session.add(sub)
    await session.flush()

    dev = Device(name="sw-1", type="switch")
    session.add(dev)
    await session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="10.20.30.9", device_id=dev.id)
    session.add(ipa)
    await session.flush()
    dev.primary_ip_id = ipa.id                                 # 往後指的外鍵
    await session.flush()

    p1 = DevicePort(device_id=dev.id, name="Gi1/0/1")
    p2 = DevicePort(device_id=dev.id, name="Gi1/0/2")
    session.add_all([p1, p2])
    await session.flush()
    p1.peer_port_id = p2.id                                    # 自我參照
    cable = Cable(label="patch-1")
    session.add(cable)
    await session.flush()
    session.add_all([
        CableTermination(cable_id=cable.id, side="A", object_type="device", object_id=dev.id),
        CableTermination(cable_id=cable.id, side="B", object_type="device", object_id=dev.id),
    ])
    await session.commit()
    return {"section": child.id, "subnet": sub.id, "device": dev.id,
            "ip": ipa.id, "port": p1.id, "peer": p2.id}


async def test_forward_reference_rows_survive_a_roundtrip(db_session):
    from app.models.device import Device
    from app.models.physical import DevicePort
    from app.models.section import Section
    from app.models.subnet import Subnet

    ids = await _seed_forward_refs(db_session)
    dump = await exporter.build_export(db_session, ["core"])
    report = await importer.apply_import(db_session, dump, mode="replace", dry_run=False)

    # 沒有任何一列因為外鍵而掉：這正是客戶看到「裝置少一半」的地方
    for name in ("devices", "sections", "subnets", "device_ports", "ip_addresses"):
        assert report["tables"][name]["errored"] == 0, \
            f"{name} 匯入失敗：{report['tables'][name].get('errors')}"

    n_dev = (await db_session.execute(select(func.count()).select_from(Device))).scalar_one()
    assert n_dev == 1, "裝置整筆消失（外鍵違反時該列不會寫進去）"

    # 往後指的值不能只是「有進去」，還要真的指對
    dev = (await db_session.execute(
        select(Device).where(Device.id == ids["device"]))).scalar_one()
    assert dev.primary_ip_id == ids["ip"], "主要 IP 的連結掉了"

    sect = (await db_session.execute(
        select(Section).where(Section.id == ids["section"]))).scalar_one()
    assert sect.parent_id is not None, "巢狀區段的上層關係掉了"

    sub = (await db_session.execute(
        select(Subnet).where(Subnet.id == ids["subnet"]))).scalar_one()
    assert sub.master_subnet_id is not None, "巢狀子網路的上層關係掉了"

    port = (await db_session.execute(
        select(DevicePort).where(DevicePort.id == ids["port"]))).scalar_one()
    assert port.peer_port_id == ids["peer"], "佈線對接埠的關係掉了"


async def test_merge_mode_also_keeps_forward_references(db_session):
    """merge（upsert）模式走的是另一條路徑，同樣不可以掉。"""
    from app.models.device import Device

    ids = await _seed_forward_refs(db_session)
    dump = await exporter.build_export(db_session, ["core"])
    report = await importer.apply_import(db_session, dump, mode="merge", dry_run=False)
    assert report["tables"]["devices"]["errored"] == 0

    dev = (await db_session.execute(
        select(Device).where(Device.id == ids["device"]))).scalar_one()
    assert dev.primary_ip_id == ids["ip"]
