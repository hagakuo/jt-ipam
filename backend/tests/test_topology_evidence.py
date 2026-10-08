"""每一條線都要說得出「這是誰說的」。

拓樸圖上同時有兩種東西：**有人登記過的**（實體佈線、無線連線）與**推導出來的**
（FDB 說某個 MAC 在某個埠、ARP 說某台看得到某個網段、名稱剛好是某個 IP）。
把兩者畫成同一種線，等於宣稱我們對它們有一樣的把握 —— 那不是真的。

所以每條邊都帶 `evidence`，對應證據契約的層級（`services/evidence.py`）：

    asserted   人為宣告（IPAM 裡登記的佈線、無線連線、IP↔裝置的連結）
    monitored  第三方監控說的（LibreNMS、虛擬化平台）
    learned    被動學到的（FDB、ARP）
    inferred   我們自己推的（名稱剛好是某個 IP 這種）

`inferred` 不在證據契約裡是刻意的：契約講的是**來源**，而「名稱看起來像」不是來源，
是猜測。它必須看得出來跟其他三種不同。
"""

from __future__ import annotations

from app.models.address import IPAddress
from app.models.device import Device
from app.models.physical import Cable, CableTermination
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.topology import build_topology


def _edges(graph, kind: str) -> list[dict]:
    return [e["data"] for e in graph["edges"] if e["data"].get("kind") == kind]


async def _subnet(session, cidr: str = "198.51.100.0/24") -> Subnet:
    sec = Section(name=f"sec-{cidr}")
    session.add(sec)
    await session.flush()
    sn = Subnet(cidr=cidr, section_id=sec.id)
    session.add(sn)
    await session.flush()
    return sn


async def test_cabling_is_asserted(db_session):
    """實體佈線是人在 IPAM 裡登記的 —— 最高等級的把握。"""
    a = Device(name="sw-a", type="switch")
    b = Device(name="sw-b", type="switch")
    db_session.add_all([a, b])
    await db_session.flush()
    cable = Cable(label="patch-1")
    db_session.add(cable)
    await db_session.flush()
    db_session.add_all([
        CableTermination(cable_id=cable.id, side="A", object_type="device", object_id=a.id),
        CableTermination(cable_id=cable.id, side="B", object_type="device", object_id=b.id),
    ])
    await db_session.flush()

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False)
    assert _edges(g, "cable")[0]["evidence"] == "asserted"


async def test_ip_link_is_asserted_but_name_match_is_only_inferred(db_session):
    """兩條都是 L3 邊，把握程度卻差很多：一條是有人把 IP 連到裝置上，
    另一條只是裝置名稱剛好長得像一個 IP。"""
    sn = await _subnet(db_session)
    linked = Device(name="srv-1", type="server")
    db_session.add(linked)
    await db_session.flush()
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.10", device_id=linked.id))
    # 名稱本身就是網段內的 IP（防火牆常這樣命名）→ 只能算推測
    db_session.add(Device(name="198.51.100.254", type="firewall"))
    await db_session.flush()

    g = await build_topology(db_session, include_vpn=False, include_wireless=False,
                             include_fdb=False)
    by_src = {e["source"]: e for e in _edges(g, "l3")}
    assert by_src[str(linked.id)]["evidence"] == "asserted"
    named = [e for e in _edges(g, "l3") if e["via"] == "name"]
    assert named and named[0]["evidence"] == "inferred"


async def test_fdb_edges_are_learned(db_session):
    """FDB 說的是「曾經在這個埠上學到這個 MAC」—— 被動學到，不是誰宣告的。"""
    from datetime import UTC, datetime

    from app.models.librenms import FDBEntry, LibreNMSDevice, LibreNMSInstance

    sw = Device(name="sw-core", type="switch")
    host = Device(name="srv-1", type="server")
    db_session.add_all([sw, host])
    await db_session.flush()
    sn = await _subnet(db_session)
    mac = "aa:bb:cc:30:00:01"
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.20", mac=mac, device_id=host.id))
    inst = LibreNMSInstance(name="ln", api_url="https://librenms.example.com",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    ln = LibreNMSDevice(instance_id=inst.id, legacy_device_id=1, hostname=sw.name,
                        jt_ipam_device_id=sw.id)
    db_session.add(ln)
    await db_session.flush()
    db_session.add(FDBEntry(mac=mac, port_name="Gi1/0/1", device_id=ln.id,
                            source="librenms", last_seen_at=datetime.now(UTC)))
    await db_session.flush()

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False)
    assert _edges(g, "l2")[0]["evidence"] == "learned"


async def test_vm_placement_comes_from_the_platform(db_session):
    """VM 跑在哪台是虛擬化平台回報的 —— 第三方監控，不是我們登記也不是推測。"""
    from app.models.virt import VirtCluster, VirtualMachine

    host = Device(name="pve-1", type="server")
    db_session.add(host)
    await db_session.flush()
    cl = VirtCluster(name="pve", type="proxmox")
    db_session.add(cl)
    await db_session.flush()
    db_session.add(VirtualMachine(cluster_id=cl.id, name="web-1", node="pve-1",
                                  status="running"))
    await db_session.flush()

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True)
    assert _edges(g, "vm_host")[0]["evidence"] == "monitored"


async def test_every_edge_says_where_it_came_from(db_session):
    """沒有一條邊可以不交代出處 —— 少了就會被當成「確定的」。"""
    sn = await _subnet(db_session)
    d = Device(name="srv-1", type="server")
    db_session.add(d)
    await db_session.flush()
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.30", device_id=d.id))
    await db_session.flush()

    g = await build_topology(db_session, include_vms=True)
    for e in g["edges"]:
        assert e["data"].get("evidence") in {"asserted", "probed", "monitored", "learned",
                                             "inferred"}, e["data"]
