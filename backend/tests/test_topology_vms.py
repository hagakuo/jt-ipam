"""虛擬機與它所在的實體主機。

實機上有 149 台 VM，全部知道自己在哪個節點，卻**一台都沒出現在拓樸圖上** ——
在虛擬化為主的機房裡，那等於圖上少了大半的東西。

對應方式是拿 `virtual_machines.node`（PVE 節點名／ESXi 主機名）比對裝置名稱。
實機上 5 個節點名全部對得上 `devices.name`；`virtual_machines.device_id` 指的是
**VM 自己**對映到的裝置，不是它的實體主機 —— 這兩個很容易搞混。

預設不畫：一次多出上百顆節點會把圖淹掉，要看的人自己開。
"""

from __future__ import annotations

from app.models.device import Device
from app.models.virt import VirtCluster, VirtualMachine
from app.services.topology import build_topology


async def _cluster(session, name: str = "pve") -> VirtCluster:
    c = VirtCluster(name=name, type="proxmox")
    session.add(c)
    await session.flush()
    return c


async def _device(session, name: str, type_: str = "server") -> Device:
    d = Device(name=name, type=type_)
    session.add(d)
    await session.flush()
    return d


async def _vm(session, cluster, name: str, node: str | None, **kw) -> VirtualMachine:
    vm = VirtualMachine(cluster_id=cluster.id, name=name, node=node,
                        status=kw.pop("status", "running"), **kw)
    session.add(vm)
    await session.flush()
    return vm


def _vm_edges(graph) -> list[dict]:
    return [e["data"] for e in graph["edges"] if e["data"].get("kind") == "vm_host"]


def _vm_nodes(graph) -> list[dict]:
    return [n["data"] for n in graph["nodes"] if n["data"].get("type") == "vm"]


async def test_vms_are_not_drawn_unless_asked(db_session):
    """預設不畫 —— 上百顆節點一次冒出來會把圖淹掉。"""
    cl = await _cluster(db_session)
    host = await _device(db_session, "pve-1")
    await _vm(db_session, cl, "web-1", host.name)

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False)
    assert _vm_nodes(g) == [] and _vm_edges(g) == []


async def test_vm_hangs_off_the_host_it_runs_on(db_session):
    cl = await _cluster(db_session)
    host = await _device(db_session, "pve-1")
    vm = await _vm(db_session, cl, "web-1", "pve-1", vcpus=4, memory_mb=8192)

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True)
    nodes = _vm_nodes(g)
    assert len(nodes) == 1
    assert nodes[0]["label"] == "web-1"
    assert nodes[0]["host"] == "pve-1"
    edges = _vm_edges(g)
    assert len(edges) == 1
    assert edges[0]["source"] == f"vm:{vm.id}"
    assert edges[0]["target"] == str(host.id)


async def test_node_name_matches_case_insensitively(db_session):
    cl = await _cluster(db_session)
    host = await _device(db_session, "PVE-1")
    await _vm(db_session, cl, "web-1", "pve-1")

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True)
    assert len(_vm_edges(g)) == 1
    assert _vm_edges(g)[0]["target"] == str(host.id)


async def test_vm_with_no_identifiable_host_is_left_out(db_session):
    """找不到實體主機的 VM 不畫：這個功能畫的是「跑在哪台上面」，
    一顆連不到任何東西的點回答不了那個問題，只會變成雜訊。"""
    cl = await _cluster(db_session)
    await _device(db_session, "pve-1")
    await _vm(db_session, cl, "orphan", "some-other-host")
    await _vm(db_session, cl, "no-node", None)

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True)
    assert _vm_nodes(g) == []


async def test_two_devices_with_the_same_name_are_not_guessed(db_session):
    cl = await _cluster(db_session)
    await _device(db_session, "pve-1")
    await _device(db_session, "pve-1")          # 同名（不同單位各自登記）
    await _vm(db_session, cl, "web-1", "pve-1")

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True)
    assert _vm_nodes(g) == [], "對到多台就不猜"


async def test_vm_already_linked_to_a_device_is_not_drawn_twice(db_session):
    """VM 若已經對映成一台 Device，就用那顆既有節點連到主機，不要再生一顆 VM 節點
    —— 否則同一台機器在圖上出現兩次。"""
    cl = await _cluster(db_session)
    host = await _device(db_session, "pve-1")
    as_device = await _device(db_session, "web-1")
    await _vm(db_session, cl, "web-1", "pve-1", device_id=as_device.id)

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True)
    assert _vm_nodes(g) == []
    edges = _vm_edges(g)
    assert len(edges) == 1
    assert edges[0]["source"] == str(as_device.id)
    assert edges[0]["target"] == str(host.id)


async def test_edge_is_dropped_when_the_host_is_filtered_out(db_session):
    """主機不在圖上時不可以留一條連到不存在節點的邊。"""
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name="s")
    db_session.add(sec)
    await db_session.flush()
    keep = Subnet(cidr="198.51.100.0/24", section_id=sec.id)
    other = Subnet(cidr="203.0.113.0/24", section_id=sec.id)
    db_session.add_all([keep, other])
    await db_session.flush()

    cl = await _cluster(db_session)
    host = await _device(db_session, "pve-1")
    db_session.add(IPAddress(subnet_id=other.id, ip="203.0.113.5", device_id=host.id))
    inside = await _device(db_session, "in-scope")
    db_session.add(IPAddress(subnet_id=keep.id, ip="198.51.100.5", device_id=inside.id))
    await db_session.flush()
    await _vm(db_session, cl, "web-1", "pve-1")

    g = await build_topology(db_session, include_l3=False, include_vpn=False,
                             include_wireless=False, include_fdb=False, include_vms=True,
                             subnet_ids=[keep.id])
    node_ids = {n["data"]["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["data"]["source"] in node_ids and e["data"]["target"] in node_ids
