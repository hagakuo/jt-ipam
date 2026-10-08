"""LibreNMS 鏡像表只增不刪（2026-09-26 稽核）。

- LibreNMS 刪掉的裝置永遠留在 librenms_devices（狀態停在最後的值，VLAN 對應、ARP、FDB 也跟著留著）
- 裝置上拿掉的 VLAN，device_vlans 永遠留著
- 排程同步的連接埠匯入沒套偽介面過濾（手動匯入有），Windows 的 ethernet_N 一直累積
- switch_port 找不到候選時不清：IP 換了一台機器，還顯示上一台接的埠
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.device import Device
from app.models.librenms import ARPEntry, FDBEntry, LibreNMSDevice, LibreNMSInstance
from app.models.physical import DevicePort
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.vlan import DeviceVLAN
from app.services import librenms as lib
from sqlalchemy import func, select


async def _inst(db) -> LibreNMSInstance:
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db.add(inst)
    await db.flush()
    return inst


def _api(monkeypatch, routes: dict) -> None:
    async def fake(_inst, path, *, timeout=30.0):
        for prefix, val in routes.items():
            if path.startswith(prefix):
                if isinstance(val, Exception):
                    raise val
                return val
        return {}
    monkeypatch.setattr(lib, "_api_get", fake)


def _devs(*ids: int) -> dict:
    return {"devices": [{"device_id": i, "hostname": f"sw{i}.example.com", "status": 1} for i in ids]}


async def _count(db, model, *where) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def test_a_device_deleted_in_librenms_is_removed_with_its_observations(db_session, monkeypatch) -> None:
    inst = await _inst(db_session)
    _api(monkeypatch, {"/api/v0/devices": _devs(1, 2)})
    await lib.sync_devices(db_session, inst)
    gone = (await db_session.execute(select(LibreNMSDevice).where(
        LibreNMSDevice.legacy_device_id == 2))).scalar_one()
    db_session.add(FDBEntry(mac="00:00:5e:00:53:01", device_id=gone.id, instance_id=inst.id, port_name="ge-0/0/1"))
    db_session.add(ARPEntry(ip="198.51.100.9", mac="00:00:5e:00:53:01", device_id=gone.id, instance_id=inst.id))
    await db_session.flush()

    _api(monkeypatch, {"/api/v0/devices": _devs(1)})
    await lib.sync_devices(db_session, inst)
    await db_session.flush()
    left = set((await db_session.execute(select(LibreNMSDevice.legacy_device_id).where(
        LibreNMSDevice.instance_id == inst.id))).scalars().all())
    assert left == {1}
    assert await _count(db_session, FDBEntry, FDBEntry.mac == "00:00:5e:00:53:01") == 0
    assert await _count(db_session, ARPEntry, ARPEntry.mac == "00:00:5e:00:53:01") == 0


async def test_an_empty_device_list_removes_nothing(db_session, monkeypatch) -> None:
    """讀到 0 台、之前卻有一堆 → 多半是 token 權限被收，不是監控的裝置全刪了。"""
    inst = await _inst(db_session)
    _api(monkeypatch, {"/api/v0/devices": _devs(1, 2, 3, 4, 5, 6)})
    await lib.sync_devices(db_session, inst)
    _api(monkeypatch, {"/api/v0/devices": {"devices": []}})
    await lib.sync_devices(db_session, inst)
    assert await _count(db_session, LibreNMSDevice, LibreNMSDevice.instance_id == inst.id) == 6


async def test_a_vlan_removed_from_a_device_is_unmapped(db_session, monkeypatch) -> None:
    inst = await _inst(db_session)
    _api(monkeypatch, {"/api/v0/devices/1/vlans": {"vlans": [{"vlan_vlan": 10}, {"vlan_vlan": 20}]},
                       "/api/v0/devices": _devs(1)})
    await lib.sync_devices(db_session, inst)
    await lib.sync_vlans(db_session, inst)
    await db_session.flush()
    assert await _count(db_session, DeviceVLAN) == 2

    _api(monkeypatch, {"/api/v0/devices/1/vlans": {"vlans": [{"vlan_vlan": 10}]},
                       "/api/v0/devices": _devs(1)})
    await lib.sync_vlans(db_session, inst)
    await db_session.flush()
    assert await _count(db_session, DeviceVLAN) == 1

    # 讀取失敗：不知道還有哪些 VLAN → 一筆都不動
    _api(monkeypatch, {"/api/v0/devices/1/vlans": lib.LibreNMSError("HTTP 500"),
                       "/api/v0/devices": _devs(1)})
    await lib.sync_vlans(db_session, inst)
    await db_session.flush()
    assert await _count(db_session, DeviceVLAN) == 1


async def test_scheduled_port_sync_skips_and_prunes_pseudo_interfaces(db_session, monkeypatch) -> None:
    """手動匯入早就有過濾與自我修復，排程同步沒有 → 每輪又把 ethernet_N 加回來。"""
    inst = await _inst(db_session)
    dev = Device(name=f"win-{uuid.uuid4().hex[:6]}")
    db_session.add(dev)
    await db_session.flush()
    db_session.add(LibreNMSDevice(instance_id=inst.id, legacy_device_id=7, jt_ipam_device_id=dev.id))
    db_session.add(DevicePort(device_id=dev.id, name="ethernet_32768", type="network"))   # 以前拉進來的
    await db_session.flush()
    _api(monkeypatch, {"/api/v0/devices/7/ports": {"ports": [
        {"ifName": "Ethernet0", "ifType": "ethernetCsmacd"},
        {"ifName": "ethernet_32769", "ifType": "ethernetCsmacd"},
        {"ifName": "WAN Miniport (PPTP)", "ifType": "ppp"}]}})
    await lib.sync_device_ports(db_session, inst)
    await db_session.flush()
    names = set((await db_session.execute(select(DevicePort.name).where(
        DevicePort.device_id == dev.id))).scalars().all())
    assert names == {"Ethernet0"}


async def _switch_setup(db):
    inst = await _inst(db)
    sw = LibreNMSDevice(instance_id=inst.id, legacy_device_id=1, hostname="sw1.example.com")
    db.add(sw)
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    return inst, sw, sub


async def test_switch_port_of_a_replaced_machine_is_cleared(db_session) -> None:
    """IP 換了一台機器（新 MAC 還沒出現在 FDB）：舊機器接的埠不可以繼續掛在這個 IP 上。"""
    inst, sw, sub = await _switch_setup(db_session)
    now = datetime.now(UTC)
    db_session.add(FDBEntry(mac="00:00:5e:00:53:aa", device_id=sw.id, port_name="ge-1", last_seen_at=now))
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.20", mac="00:00:5e:00:53:aa")
    db_session.add(ip)
    await db_session.flush()
    await lib.derive_switch_ports(db_session, inst)
    assert ip.switch_port == "sw1.example.com / ge-1"

    ip.mac = "00:00:5e:00:53:bb"          # 新機器
    await db_session.flush()
    await lib.derive_switch_ports(db_session, inst)
    assert ip.switch_port is None


async def test_switch_port_of_an_offline_machine_is_kept(db_session) -> None:
    """同一台機器只是關機好幾天（FDB 裡是舊的）：它最後接在哪裡仍然有用，保留。"""
    inst, sw, sub = await _switch_setup(db_session)
    now = datetime.now(UTC)
    db_session.add(FDBEntry(mac="00:00:5e:00:53:cc", device_id=sw.id, port_name="ge-2",
                            last_seen_at=now - timedelta(days=5)))
    db_session.add(FDBEntry(mac="00:00:5e:00:53:dd", device_id=sw.id, port_name="ge-3", last_seen_at=now))
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.21", mac="00:00:5e:00:53:cc",
                   switch_port="sw1.example.com / ge-2")
    db_session.add(ip)
    await db_session.flush()
    await lib.derive_switch_ports(db_session, inst)
    assert ip.switch_port == "sw1.example.com / ge-2"
