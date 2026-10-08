"""拓樸：用 LibreNMS 回報的 ARP 推「裝置接在哪些網段」（2026-09-30 研究）。

`arp_entries.device_id` 參照的是 **LibreNMS 的裝置**，不是 jt-ipam 的 Device；這段從 v0.4.29
起一直拿它去比 jt-ipam 的裝置，一次都沒對上（正式機 4,109 筆 ARP、0 筆命中）。子網路篩選的
「ARP 鄰居落在這些網段的裝置也要列入」也是同一個錯。修好後透過 LibreNMS 裝置對回 jt-ipam 裝置，
網段取包含那個位址的最精確子網路（依前綴長度查表，不逐一比對所有網段）。
"""
from __future__ import annotations

from sqlalchemy import select

from app.models.librenms import ARPEntry
from app.services.topology import build_topology
from tests.test_topology_fdb import _device, _ln_device, _subnet


def _l3(graph) -> set[tuple[str, str]]:
    return {(e["data"]["source"], e["data"]["target"]) for e in graph["edges"] if e["data"].get("kind") == "l3"}


async def _arp(session, ln, ip: str, mac: str = "00:00:5e:00:53:01") -> None:
    session.add(ARPEntry(ip=ip, mac=mac, device_id=ln.id, instance_id=ln.instance_id, source="librenms"))
    await session.flush()


async def test_arp_links_a_device_to_the_most_specific_subnet_it_sees(db_session) -> None:
    ap = await _device(db_session, "ap-lobby", "ap")
    wide = await _subnet(db_session, "198.51.0.0/16")
    narrow = await _subnet(db_session, "198.51.100.0/24")
    ln = await _ln_device(db_session, ap)
    await _arp(db_session, ln, "198.51.100.23")
    await db_session.commit()
    g = await build_topology(db_session, include_fdb=False, include_vpn=False)
    assert (str(ap.id), f"subnet:{narrow.id}") in _l3(g)
    assert (str(ap.id), f"subnet:{wide.id}") not in _l3(g)
    edge = next(e["data"] for e in g["edges"] if e["data"].get("kind") == "l3" and e["data"]["source"] == str(ap.id))
    assert "arp" in edge.get("via", "") or "arp" in str(edge.get("via"))


async def test_subnet_filter_includes_devices_whose_arp_neighbours_are_in_it(db_session) -> None:
    ap = await _device(db_session, "ap-lobby", "ap")
    other = await _device(db_session, "srv-elsewhere", "server")
    sn = await _subnet(db_session, "198.51.100.0/24")
    ln = await _ln_device(db_session, ap)
    await _arp(db_session, ln, "198.51.100.23")
    await db_session.commit()
    g = await build_topology(db_session, subnet_ids=[sn.id], include_fdb=False, include_vpn=False)
    node_ids = {n["data"]["id"] for n in g["nodes"]}
    assert str(ap.id) in node_ids
    assert str(other.id) not in node_ids


async def test_arp_from_a_librenms_device_not_linked_to_ipam_is_ignored(db_session) -> None:
    ap = await _device(db_session, "ap-lobby", "ap")
    await _subnet(db_session, "198.51.100.0/24")
    ln = await _ln_device(db_session, ap)
    ln.jt_ipam_device_id = None
    await _arp(db_session, ln, "198.51.100.23")
    await db_session.commit()
    g = await build_topology(db_session, include_fdb=False, include_vpn=False)
    assert not any(s == str(ap.id) for s, _t in _l3(g))
    assert (await db_session.execute(select(ARPEntry))).scalars().first() is not None
