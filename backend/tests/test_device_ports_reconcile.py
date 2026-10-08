"""裝置連接埠跟著 LibreNMS 走（2026-09-27 使用者回報）。

主機拔掉一張雙埠網卡、USB 網卡拔掉後，LibreNMS 已經把那些埠標成 deleted，裝置的
「連接埠／佈線」卻還列著 —— 同步只新增、從不刪。另外 Docker 主機每起一個容器就多一個
veth 介面，累積了幾十個。

- LibreNMS 匯入的埠記下來源（`librenms:<實例 id>`）；舊資料在 LibreNMS 再回報時認領。
- 那台 LibreNMS 這一輪完整讀到這台裝置的埠清單時，清掉它不再回報、而且是它匯入的埠。
- 已接線、做了穿透對應的埠不動；使用者自己建的埠（沒有來源）不動；別台 LibreNMS 的不動。
- 讀取失敗、或讀到 0 個埠時一律不刪。
- MAC 欄顯示 OUI 廠商。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.device import Device
from app.models.librenms import LibreNMSDevice, LibreNMSInstance
from app.models.physical import DevicePort
from app.services import librenms as lib
from app.services.device_port_filter import is_pseudo_iface
from sqlalchemy import select


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


def _ports(*names: str) -> dict:
    return {"ports": [{"ifName": n, "ifType": "ethernetCsmacd"} for n in names]}


async def _dev(db, inst: LibreNMSInstance, legacy_id: int = 7) -> Device:
    dev = Device(name=f"ws-{uuid.uuid4().hex[:6]}")
    db.add(dev)
    await db.flush()
    db.add(LibreNMSDevice(instance_id=inst.id, legacy_device_id=legacy_id, jt_ipam_device_id=dev.id))
    await db.flush()
    return dev


async def _rows(db, dev: Device) -> dict[str, DevicePort]:
    return {p.name: p for p in (await db.execute(
        select(DevicePort).where(DevicePort.device_id == dev.id))).scalars().all()}


async def test_new_ports_are_marked_and_legacy_ones_claimed(db_session, monkeypatch) -> None:
    inst = await _inst(db_session)
    dev = await _dev(db_session, inst)
    db_session.add_all([DevicePort(device_id=dev.id, name="eno1", type="network"),          # 舊資料
                        DevicePort(device_id=dev.id, name="mgmt-custom", type="network")])  # 使用者建的
    await db_session.flush()
    _api(monkeypatch, {"/api/v0/devices/7/ports": _ports("eno1", "eno2")})
    await lib.sync_device_ports(db_session, inst)
    await db_session.flush()
    rows = await _rows(db_session, dev)
    assert rows["eno1"].source_origin == f"librenms:{inst.id}"
    assert rows["eno2"].source_origin == f"librenms:{inst.id}"
    assert rows["mgmt-custom"].source_origin is None


async def test_ports_librenms_no_longer_reports_are_removed(db_session, monkeypatch) -> None:
    inst = await _inst(db_session)
    other = await _inst(db_session)
    dev = await _dev(db_session, inst)
    _api(monkeypatch, {"/api/v0/devices/7/ports": _ports("eno1", "eno2", "enp2s0f0np0", "enp2s0f1np1")})
    await lib.sync_device_ports(db_session, inst)
    await db_session.flush()
    rows = await _rows(db_session, dev)
    # 其中一個埠已經接線、有穿透對應 → 要保留
    rows["enp2s0f1np1"].peer_port_id = rows["eno1"].id
    db_session.add_all([DevicePort(device_id=dev.id, name="mgmt-custom", type="network"),
                        DevicePort(device_id=dev.id, name="bond9", type="network",
                                   source_origin=f"librenms:{other.id}")])
    await db_session.flush()

    # 拔掉雙埠網卡：LibreNMS 不再回報那兩個埠
    _api(monkeypatch, {"/api/v0/devices/7/ports": _ports("eno1", "eno2")})
    removed = await lib.sync_device_ports(db_session, inst)
    await db_session.flush()
    rows = await _rows(db_session, dev)
    assert "enp2s0f0np0" not in rows
    assert "enp2s0f1np1" in rows, "有穿透對應的埠不可刪"
    assert "mgmt-custom" in rows, "使用者自己建的埠不可刪"
    assert "bond9" in rows, "別台 LibreNMS 匯入的埠不可刪"
    assert removed == 0, "回傳值仍是新增數（相容既有呼叫端）"


@pytest.mark.parametrize("second", [{"ports": []}, lib.LibreNMSError("HTTP 500")])
async def test_an_empty_or_failed_read_removes_nothing(db_session, monkeypatch, second) -> None:
    inst = await _inst(db_session)
    dev = await _dev(db_session, inst)
    _api(monkeypatch, {"/api/v0/devices/7/ports": _ports("eno1", "eno2")})
    await lib.sync_device_ports(db_session, inst)
    await db_session.flush()
    _api(monkeypatch, {"/api/v0/devices/7/ports": second})
    await lib.sync_device_ports(db_session, inst)
    await db_session.flush()
    assert set(await _rows(db_session, dev)) == {"eno1", "eno2"}


async def test_manual_import_marks_and_removes_too(client, auth_headers, db_session, monkeypatch) -> None:
    """「從來源匯入」按鈕與排程同步同一套規則。"""
    inst = await _inst(db_session)
    dev = await _dev(db_session, inst)
    await db_session.commit()
    _api(monkeypatch, {"/api/v0/devices/7/ports": _ports("eno1", "usb-nic0")})
    r = await client.post(f"/api/v1/device-ports/import?device_id={dev.id}", headers=auth_headers)
    assert r.status_code == 200, r.text
    _api(monkeypatch, {"/api/v0/devices/7/ports": _ports("eno1")})
    r = await client.post(f"/api/v1/device-ports/import?device_id={dev.id}", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["removed"] == 1
    dev_id, inst_id = dev.id, inst.id
    db_session.expire_all()
    rows = {p.name: p for p in (await db_session.execute(
        select(DevicePort).where(DevicePort.device_id == dev_id))).scalars().all()}
    assert set(rows) == {"eno1"}
    assert rows["eno1"].source_origin == f"librenms:{inst_id}"


@pytest.mark.parametrize(("name", "pseudo"), [
    ("veth0a7de3d", True), ("vethfb6d8de", True),        # Docker／Podman 容器的 veth
    ("vEthernet (Default Switch)", False),                 # Hyper-V 的虛擬交換器（有意義，保留）
    ("eth0", False), ("docker0", False),
])
def test_container_veth_interfaces_are_pseudo(name: str, pseudo: bool) -> None:
    assert is_pseudo_iface(name) is pseudo


async def test_port_list_shows_the_mac_vendor(client, auth_headers, db_session) -> None:
    from app.models.oui import OUIVendor
    dev = Device(name=f"ws-{uuid.uuid4().hex[:6]}")
    db_session.add(dev)
    await db_session.flush()
    db_session.add_all([
        OUIVendor(prefix="00005E", short_name="IANA", name="ICANN, IANA Department", source="manual"),
        DevicePort(device_id=dev.id, name="eno1", type="network", mac_address="00:00:5e:00:53:01"),
        DevicePort(device_id=dev.id, name="eno2", type="network"),
    ])
    await db_session.commit()
    r = await client.get(f"/api/v1/device-ports?device_id={dev.id}", headers=auth_headers)
    assert r.status_code == 200, r.text
    by = {p["name"]: p for p in r.json()}
    assert by["eno1"]["mac_vendor"] == "IANA"
    assert by["eno2"]["mac_vendor"] is None


async def test_port_sync_does_not_query_per_port(db_session, monkeypatch) -> None:
    """超大規模：以前每個埠各一次 upsert（5,000 台裝置、每台 8 埠 → 一輪 6 萬次查詢、200 秒）。
    查詢數要跟裝置數成正比、不跟埠數成正比；沒變的埠不重寫。"""
    from sqlalchemy import event
    db_session.autoflush = False
    inst = await _inst(db_session)
    for i in range(20):
        await _dev(db_session, inst, legacy_id=100 + i)
    await db_session.commit()
    names = [f"eth{i}" for i in range(40)]
    _api(monkeypatch, {"/api/v0/devices/": {"ports": [
        {"ifName": n, "ifType": "ethernetCsmacd", "ifPhysAddress": f"00005e0053{i:02x}", "ifAlias": f"desk {i}"}
        for i, n in enumerate(names)]}})
    count = {"n": 0}
    conn = await db_session.connection()

    def _c(*_a, **_k):
        count["n"] += 1
    event.listen(conn.sync_connection, "before_cursor_execute", _c)
    try:
        created = await lib.sync_device_ports(db_session, inst)
        await db_session.commit()
        first, count["n"] = count["n"], 0
        again = await lib.sync_device_ports(db_session, inst)
        await db_session.commit()
        second = count["n"]
    finally:
        event.remove(conn.sync_connection, "before_cursor_execute", _c)
    assert (created, again) == (20 * 40, 0)
    assert first < 20 * 8, f"第一輪 {first} 次（20 台 × 40 埠）"
    assert second < 20 * 8, f"第二輪 {second} 次"
    mac = (await db_session.execute(select(DevicePort.mac_address)
                                    .where(DevicePort.name == "eth3").limit(1))).scalar()
    assert mac == "00:00:5e:00:53:03"


async def test_librenms_without_a_value_keeps_what_is_there(db_session, monkeypatch) -> None:
    """LibreNMS 沒給 MAC／說明時不可以把既有的清掉；有給而且不同才覆寫。"""
    db_session.autoflush = False
    inst = await _inst(db_session)
    dev = await _dev(db_session, inst)
    db_session.add(DevicePort(device_id=dev.id, name="ge-0/0/1", mac_address="00:00:5e:00:53:01",
                              description="人資 印表機", source_origin=lib.port_origin(inst.id)))
    await db_session.commit()
    _api(monkeypatch, {"/api/v0/devices/": {"ports": [
        {"ifName": "ge-0/0/1", "ifType": "ethernetCsmacd"}, {"ifName": "ge-0/0/2", "ifType": "ethernetCsmacd"}]}})
    await lib.sync_device_ports(db_session, inst)
    await db_session.commit()
    p = (await _rows(db_session, dev))["ge-0/0/1"]
    assert (p.mac_address, p.description) == ("00:00:5e:00:53:01", "人資 印表機")
    _api(monkeypatch, {"/api/v0/devices/": {"ports": [
        {"ifName": "ge-0/0/1", "ifType": "ethernetCsmacd", "ifPhysAddress": "00005e005309",
         "ifAlias": "財務 3F 影印機"},
        {"ifName": "ge-0/0/2", "ifType": "ethernetCsmacd", "ifAlias": "ge-0/0/2"}]}})
    await lib.sync_device_ports(db_session, inst)
    await db_session.commit()
    got = (await db_session.execute(select(DevicePort.mac_address, DevicePort.description).where(
        DevicePort.device_id == dev.id, DevicePort.name == "ge-0/0/1"))).one()
    assert tuple(got) == ("00:00:5e:00:53:09", "財務 3F 影印機")
