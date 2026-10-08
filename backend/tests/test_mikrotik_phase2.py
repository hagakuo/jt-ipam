"""MikroTik 第二階段：介面、鄰居、FDB（2026-10-01，migration 0170）。

第一階段卡在結構：FDB 表的 device_id 是 LibreNMS 裝置、鄰居表要有 LibreNMS 整合。現在
路由器先對應到一台 jt-ipam 裝置（沒指定就用 API 位址對到的 IP 所屬裝置），介面寫進那台裝置的
連接埠、FDB 記 jt-ipam 裝置、鄰居另存一張表；拓樸兩種都用。沒有對應裝置時略過，**不算失敗**。
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.services import mikrotik as svc
from sqlalchemy import select

from tests.test_mikrotik import _fake_client, _MenuTransport

# ─────────────────── 純解析 ───────────────────

def test_only_real_ports_become_device_ports() -> None:
    ports = svc.interface_ports([
        {"name": "ether1", "type": "ether", "mac-address": "00:00:5E:00:53:01", "comment": "WAN 中華電信"},
        {"name": "sfp-sfpplus1", "type": "ether", "mac-address": "00:00:5E:00:53:02"},
        {"name": "wlan1", "type": "wlan"},
        {"name": "bridge", "type": "bridge"},
        {"name": "vlan10", "type": "vlan"},
        {"name": "pppoe-out1", "type": "pppoe-out"},
        {"name": "wg0", "type": "wg"},
    ])
    assert set(ports) == {"ether1", "sfp-sfpplus1", "wlan1"}
    assert ports["ether1"] == {"mac": "00:00:5e:00:53:01", "description": "WAN 中華電信"}


def test_neighbor_rows_take_the_physical_port_and_dedupe() -> None:
    rows = svc.neighbor_rows([
        {"interface": "ether3,bridge", "address": "198.51.100.2", "mac-address": "00:00:5E:00:53:10",
         "identity": "sw-core", "platform": "MikroTik", "board": "CRS309", "interface-name": "sfp1",
         "discovered-by": "mndp,lldp"},
        {"interface": "ether3", "address": "198.51.100.2", "mac-address": "00:00:5E:00:53:10",
         "identity": "sw-core"},                                      # 同一個鄰居從 bridge 也看到一次
        {"interface": "", "identity": "nowhere"},
    ])
    assert len(rows) == 1
    assert rows[0]["interface"] == "ether3"
    assert rows[0]["remote_interface"] == "sfp1"
    assert rows[0]["address"] == "198.51.100.2"


def test_fdb_rows_skip_the_routers_own_macs() -> None:
    rows = svc.fdb_rows([
        {"mac-address": "00:00:5E:00:53:20", "interface": "ether4", "bridge": "bridge", "vid": "10",
         "local": "false"},
        {"mac-address": "00:00:5E:00:53:21", "interface": "bridge", "bridge": "bridge", "local": "false"},
        {"mac-address": "00:00:5E:00:53:22", "interface": "ether5", "bridge": "bridge", "local": "true"},
        {"mac-address": "bogus", "interface": "ether6"},
    ])
    assert rows == [("00:00:5e:00:53:20", "ether4", 10)]


# ─────────────────── 同步＋拓樸 ───────────────────

async def _site(db) -> dict[str, Any]:
    """一台路由器（裝置 gw-1，管理 IP 192.0.2.9）、一台交換器 sw-core、一台主機 pc-07。"""
    from app.models.address import IPAddress
    from app.models.device import Device
    from app.models.mikrotik import MikroTikRouter
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"mt-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
    sub2 = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add_all([sub, sub2])
    await db.flush()
    gw, sw, pc = Device(name="gw-1", type="router"), Device(name="sw-core", type="other"), \
        Device(name="pc-07", type="other")
    db.add_all([gw, sw, pc])
    await db.flush()
    db.add_all([IPAddress(subnet_id=sub.id, ip="192.0.2.9", device_id=gw.id),
                IPAddress(subnet_id=sub2.id, ip="198.51.100.2", device_id=sw.id),
                IPAddress(subnet_id=sub2.id, ip="198.51.100.77", device_id=pc.id, mac="00:00:5e:00:53:20")])
    router = MikroTikRouter(name=f"ccr-{uuid.uuid4().hex[:4]}", api_url="https://192.0.2.9", api_username="ipam",
                            api_password_enc=b"x", api_password_nonce=b"y", section_delay_ms=0, cpu_load_limit=0,
                            sync_firewall=False, sync_nat=False, sync_dhcp=False, sync_dhcp_ranges=False,
                            sync_vpn=False, sync_address_lists=False, sync_arp=False, sync_fdb=True)
    db.add(router)
    await db.flush()
    return {"gw": gw, "sw": sw, "pc": pc, "router": router}


MENUS: dict[str, Any] = {
    "/interface": [
        {"name": "ether1", "type": "ether", "mac-address": "00:00:5E:00:53:01", "comment": "uplink"},
        {"name": "ether3", "type": "ether", "mac-address": "00:00:5E:00:53:03"},
        {"name": "ether4", "type": "ether", "mac-address": "00:00:5E:00:53:04"},
        {"name": "bridge", "type": "bridge"},
    ],
    "/ip/neighbor": [
        {"interface": "ether3", "address": "198.51.100.2", "mac-address": "00:00:5E:00:53:10",
         "identity": "sw-core", "interface-name": "sfp1", "discovered-by": "lldp"},
    ],
    "/interface/bridge/host": [
        {"mac-address": "00:00:5E:00:53:20", "interface": "ether4", "bridge": "bridge", "local": "false"},
        {"mac-address": "00:00:5E:00:53:04", "interface": "ether4", "bridge": "bridge", "local": "true"},
    ],
}


@pytest.mark.anyio
async def test_a_round_fills_ports_neighbors_and_fdb_and_topology_uses_them(db_session, monkeypatch) -> None:
    from app.models.librenms import FDBEntry
    from app.models.mikrotik import MikroTikNeighbor
    from app.models.physical import DevicePort
    from app.services.topology import build_topology

    s = await _site(db_session)
    router = s["router"]
    _fake_client(monkeypatch, _MenuTransport(MENUS, cpu_seq=[5]))
    counts = await svc.sync_instance(db_session, router)
    await db_session.flush()
    assert router.last_error is None, router.last_error
    assert router.device_id == s["gw"].id                          # API 位址對到的 IP 所屬裝置
    assert (counts["interface_rows"], counts["neighbors"], counts["fdb"]) == (3, 1, 1)

    ports = {p.name: p for p in (await db_session.execute(
        select(DevicePort).where(DevicePort.device_id == s["gw"].id))).scalars().all()}
    assert set(ports) == {"ether1", "ether3", "ether4"}
    assert ports["ether1"].description == "uplink"
    assert ports["ether1"].source_origin == f"mikrotik:{router.id}"
    nb = (await db_session.execute(select(MikroTikNeighbor))).scalars().one()
    assert (nb.interface, nb.identity, nb.remote_interface) == ("ether3", "sw-core", "sfp1")
    fdb = (await db_session.execute(select(FDBEntry).where(FDBEntry.source == "mikrotik"))).scalars().one()
    assert (str(fdb.mac), fdb.port_name, fdb.switch_device_id) == ("00:00:5e:00:53:20", "ether4", s["gw"].id)
    # IP 的交換器位置：沒有 LibreNMS 也填得出來（與 LibreNMS 同一套推導）
    from app.models.address import IPAddress
    pc_ip = (await db_session.execute(select(IPAddress).where(IPAddress.device_id == s["pc"].id))).scalar_one()
    assert (pc_ip.switch_port, pc_ip.switch_port_confident) == ("gw-1 / ether4", True)
    await db_session.commit()

    g = await build_topology(db_session, include_wireless=False, include_l3=False)
    edges = [e["data"] for e in g["edges"]]
    gw, sw, pc = str(s["gw"].id), str(s["sw"].id), str(s["pc"].id)
    assert any(e["kind"] == "l2" and {e["source"], e["target"]} == {pc, gw} and e["port"] == "ether4"
               for e in edges), edges                                # FDB：pc-07 插在 gw-1 的 ether4
    nbe = [e for e in edges if e.get("via") == "neighbor"]
    assert len(nbe) == 1
    assert {nbe[0]["source"], nbe[0]["target"]} == {gw, sw}
    assert (nbe[0]["label"], nbe[0]["evidence"]) == ("ether3 ↔ sfp1", "monitored")


@pytest.mark.anyio
async def test_next_round_removes_what_is_gone_but_keeps_cabled_and_manual_ports(db_session, monkeypatch) -> None:
    from app.models.librenms import FDBEntry
    from app.models.mikrotik import MikroTikNeighbor
    from app.models.physical import DevicePort

    s = await _site(db_session)
    router = s["router"]
    _fake_client(monkeypatch, _MenuTransport(MENUS, cpu_seq=[5]))
    await svc.sync_instance(db_session, router)
    db_session.add(DevicePort(device_id=s["gw"].id, name="console", type="network"))     # 使用者自己建的
    await db_session.flush()

    later = {"/interface": MENUS["/interface"][:2], "/ip/neighbor": [], "/interface/bridge/host": []}
    _fake_client(monkeypatch, _MenuTransport(later, cpu_seq=[5]))
    counts = await svc.sync_instance(db_session, router)
    await db_session.flush()
    names = {p.name for p in (await db_session.execute(
        select(DevicePort).where(DevicePort.device_id == s["gw"].id))).scalars().all()}
    assert names == {"ether1", "ether3", "console"}                 # ether4 沒了；手動的保留
    assert counts["interfaces_removed"] == 1
    assert (await db_session.execute(select(MikroTikNeighbor))).scalars().all() == []
    assert (await db_session.execute(select(FDBEntry).where(FDBEntry.source == "mikrotik"))).scalars().all() == []


@pytest.mark.anyio
async def test_no_device_is_a_pending_setting_not_a_failure(db_session, monkeypatch) -> None:
    s = await _site(db_session)
    router = s["router"]
    router.api_url = "https://203.0.113.250"                          # 對不到任何 IP 記錄
    _fake_client(monkeypatch, _MenuTransport(MENUS, cpu_seq=[5]))
    await svc.sync_instance(db_session, router)
    assert router.last_error is None                                  # 不要每一輪都亮「部分區段失敗」
    assert router.last_cost["interfaces"]["skipped"] == "no_device"
    assert router.last_cost["interfaces"]["code"] == "ros_no_device"
    assert router.device_id is None


@pytest.mark.anyio
async def test_deleting_the_router_takes_its_fdb_and_neighbors(db_session, monkeypatch) -> None:
    from app.models.librenms import FDBEntry
    from app.models.mikrotik import MikroTikNeighbor
    s = await _site(db_session)
    _fake_client(monkeypatch, _MenuTransport(MENUS, cpu_seq=[5]))
    await svc.sync_instance(db_session, s["router"])
    await db_session.commit()
    await db_session.delete(s["router"])
    await db_session.commit()
    assert (await db_session.execute(select(FDBEntry).where(FDBEntry.source == "mikrotik"))).scalars().all() == []
    assert (await db_session.execute(select(MikroTikNeighbor))).scalars().all() == []


async def test_deleting_the_router_through_the_api_releases_its_ports(client, auth_headers, db_session,
                                                                      monkeypatch) -> None:
    """介面寫進的連接埠沒有外鍵跟著走：沒接線的刪掉，已接線的留著、拿掉來源標記。"""
    from app.models.physical import DevicePort
    s = await _site(db_session)
    _fake_client(monkeypatch, _MenuTransport(MENUS, cpu_seq=[5]))
    await svc.sync_instance(db_session, s["router"])
    ports = {p.name: p for p in (await db_session.execute(
        select(DevicePort).where(DevicePort.device_id == s["gw"].id))).scalars().all()}
    far = DevicePort(device_id=s["sw"].id, name="sfp1", type="network")
    db_session.add(far)
    await db_session.flush()
    ports["ether3"].peer_port_id = far.id                       # ether3 接了線
    far.peer_port_id = ports["ether3"].id
    gw_id, rid = s["gw"].id, s["router"].id
    await db_session.commit()

    r = await client.delete(f"/api/v1/mikrotik/{rid}", headers=auth_headers)
    assert r.status_code == 204, r.text
    db_session.expire_all()
    left = {p.name: p.source_origin for p in (await db_session.execute(
        select(DevicePort).where(DevicePort.device_id == gw_id))).scalars().all()}
    assert left == {"ether3": None}


async def test_api_rejects_an_unknown_device_and_lists_neighbors(client, auth_headers, db_session, monkeypatch) -> None:
    s = await _site(db_session)
    await db_session.commit()
    rid = s["router"].id
    bad = await client.patch(f"/api/v1/mikrotik/{rid}", headers=auth_headers,
                             json={"device_id": str(uuid.uuid4())})
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "ros_device_not_found"
    ok = await client.patch(f"/api/v1/mikrotik/{rid}", headers=auth_headers,
                            json={"device_id": str(s["gw"].id), "sync_fdb": True})
    assert ok.status_code == 200, ok.text
    assert ok.json()["device_id"] == str(s["gw"].id)

    from app.models.mikrotik import MikroTikRouter
    router = await db_session.get(MikroTikRouter, rid)
    await db_session.refresh(router)
    _fake_client(monkeypatch, _MenuTransport(MENUS, cpu_seq=[5]))
    await svc.sync_instance(db_session, router)
    await db_session.commit()
    items = (await client.get(f"/api/v1/mikrotik/{rid}/neighbors", headers=auth_headers)).json()["items"]
    assert items[0]["identity"] == "sw-core"
    assert items[0]["device_name"] == "sw-core"                       # 依宣告的位址對到裝置


@pytest.mark.anyio
async def test_mac_lookups_and_vlan_ports_name_the_mikrotik_switch(db_session, admin_user, monkeypatch) -> None:
    """FDB 的其他讀取端：MikroTik 的列 device_id 是空的（那欄是 LibreNMS 裝置），要改看 switch_device_id。"""
    from app.mcp.tools import TOOLS
    s = await _site(db_session)
    menus = dict(MENUS)
    menus["/interface/bridge/host"] = [{**MENUS["/interface/bridge/host"][0], "vid": "30"}]
    _fake_client(monkeypatch, _MenuTransport(menus, cpu_seq=[5]))
    await svc.sync_instance(db_session, s["router"])
    await db_session.commit()

    traced = await TOOLS["trace_mac"]["fn"](db_session, user=admin_user, mac="00:00:5e:00:53:20")
    assert (traced["fdb"]["switch"], traced["fdb"]["port_name"]) == ("gw-1", "ether4")
    assert traced["fdb"]["switch_device_id"] == str(s["gw"].id)
    where = await TOOLS["switch_port_for_ip"]["fn"](db_session, user=admin_user, ip="198.51.100.77")
    assert (where["likely_access_port"]["switch"], where["likely_access_port"]["port"]) == ("gw-1", "ether4")
    assert where["likely_access_port"]["macs_on_port"] == 1


async def test_vlan_members_list_mikrotik_ports(client, auth_headers, db_session, monkeypatch) -> None:
    from app.models.vlan import VLAN, VLANDomain
    s = await _site(db_session)
    menus = dict(MENUS)
    menus["/interface/bridge/host"] = [{**MENUS["/interface/bridge/host"][0], "vid": "30"}]
    _fake_client(monkeypatch, _MenuTransport(menus, cpu_seq=[5]))
    await svc.sync_instance(db_session, s["router"])
    dom = VLANDomain(name=f"d-{uuid.uuid4().hex[:6]}")
    db_session.add(dom)
    await db_session.flush()
    vlan = VLAN(domain_id=dom.id, number=30, name="cams")
    db_session.add(vlan)
    await db_session.commit()
    r = await client.get(f"/api/v1/vlans/{vlan.id}/members", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert {"device": "gw-1", "port": "ether4", "mac": "00:00:5e:00:53:20"} in r.json()["ports"]
