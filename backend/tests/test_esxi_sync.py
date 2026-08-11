"""ESXi 同步：寫進與 Proxmox **同一組**虛擬化資料表。

共用資料表是刻意的 —— 拓樸、AI 對話、MCP 的 `list_vms` 都不必為了新平台改一行。
但共用也代表「動到那張表就可能弄壞 Proxmox」，所以這裡同時守著兩邊。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.esxi import ESXiInstance
from app.models.virt import VirtCluster, VirtualMachine, VMInterface
from app.services import esxi
from sqlalchemy import select

VMS = [
    {"moid": "vm-101", "name": "web-01", "power_state": "poweredOn", "host": "host-9",
     "vcpus": 4, "memory_mb": 8192, "is_template": False, "hostname": "web-01",
     "ip": "198.51.100.21", "notes": None,
     "nics": [{"mac": "00:50:56:aa:bb:01", "ips": ["198.51.100.21"]}]},
    {"moid": "vm-102", "name": "db-01", "power_state": "poweredOff", "host": None,
     "vcpus": None, "memory_mb": None, "is_template": False, "hostname": None,
     "ip": None, "notes": None, "nics": []},
]


async def _inst(db_session):
    inst = ESXiInstance(name=f"esxi-{uuid.uuid4().hex[:6]}", api_url="https://esx",
                        username="ro", password_enc=b"x", password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    return inst


def _patch(monkeypatch, vms):
    class _S:
        def __init__(self, inst): self.inst = inst
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def list_vms(self): return vms
    monkeypatch.setattr(esxi, "Session", _S)


@pytest.mark.anyio
async def test_vms_are_written_to_the_shared_tables(db_session, monkeypatch):
    inst = await _inst(db_session)
    _patch(monkeypatch, VMS)
    out = await esxi.sync_instance(db_session, inst)
    await db_session.flush()
    assert out["vms"] == 2

    cl = (await db_session.execute(select(VirtCluster).where(
        VirtCluster.id == inst.cluster_id))).scalars().first()
    # 資料表的 CHECK 約束早就允許 vmware（proxmox / vmware / hyper-v / kvm / xenserver / other），
    # 用既有的值就不必為了新平台改約束
    assert cl.type == "vmware"

    rows = {v.name: v for v in (await db_session.execute(select(VirtualMachine).where(
        VirtualMachine.cluster_id == cl.id))).scalars().all()}
    assert rows["web-01"].status == "running"
    assert rows["web-01"].vcpus == 4
    assert rows["web-01"].node == "host-9"
    assert rows["web-01"].kind == "vm", "ESXi 沒有容器，一律 vm"
    assert rows["db-01"].status == "stopped"


@pytest.mark.anyio
async def test_ip_is_matched_not_created(db_session, monkeypatch):
    """只比對既有 IP、不新建 —— VMware Tools 回報的位址不一定在 IPAM 管的範圍內。"""
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sn)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sn.id, ip="198.51.100.21")
    db_session.add(ipa)
    await db_session.flush()

    inst = await _inst(db_session)
    _patch(monkeypatch, VMS)
    out = await esxi.sync_instance(db_session, inst)
    await db_session.flush()
    assert out["matched_ip"] == 1
    vm = (await db_session.execute(select(VirtualMachine).where(
        VirtualMachine.name == "web-01"))).scalars().first()
    assert vm.primary_ip_id == ipa.id
    # 不存在的位址不會被建出來
    assert (await db_session.execute(select(IPAddress).where(
        IPAddress.ip == "198.51.100.99"))).scalars().first() is None


@pytest.mark.anyio
async def test_ambiguous_ip_is_not_guessed(db_session, monkeypatch):
    """重疊網段下同一位址有多筆 → 不猜（與其他整合同一條原則）。"""
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    a = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    b = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add_all([a, b])
    await db_session.flush()
    for sn in (a, b):
        db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.21"))
    await db_session.flush()

    inst = await _inst(db_session)
    _patch(monkeypatch, VMS)
    out = await esxi.sync_instance(db_session, inst)
    assert out["matched_ip"] == 0


@pytest.mark.anyio
async def test_second_sync_is_idempotent_and_removes_deleted_vms(db_session, monkeypatch):
    inst = await _inst(db_session)
    _patch(monkeypatch, VMS)
    await esxi.sync_instance(db_session, inst)
    await db_session.flush()

    _patch(monkeypatch, VMS[:1])          # db-01 在 ESXi 上被刪掉了
    out = await esxi.sync_instance(db_session, inst)
    await db_session.flush()
    assert out["removed"] == 1
    names = [v.name for v in (await db_session.execute(select(VirtualMachine).where(
        VirtualMachine.cluster_id == inst.cluster_id))).scalars().all()]
    assert names == ["web-01"]


@pytest.mark.anyio
async def test_nics_are_mirrored(db_session, monkeypatch):
    inst = await _inst(db_session)
    _patch(monkeypatch, VMS)
    await esxi.sync_instance(db_session, inst)
    await db_session.flush()
    vm = (await db_session.execute(select(VirtualMachine).where(
        VirtualMachine.name == "web-01"))).scalars().first()
    nics = (await db_session.execute(select(VMInterface).where(
        VMInterface.vm_id == vm.id))).scalars().all()
    assert len(nics) == 1
    assert str(nics[0].mac) == "00:50:56:aa:bb:01"


@pytest.mark.anyio
async def test_proxmox_vms_are_untouched(db_session, monkeypatch):
    """**共用資料表的回歸守門**：ESXi 同步只能動自己叢集的列。

    virtual_machines 是 Proxmox 也在用的表，這次還加了 external_id 欄位 ——
    少了這條，「把 PVE 的 VM 清掉」這種事不會有人發現。
    """
    pve = VirtCluster(name=f"pve-{uuid.uuid4().hex[:6]}", type="proxmox")
    db_session.add(pve)
    await db_session.flush()
    keep = VirtualMachine(cluster_id=pve.id, legacy_vmid=101, name="pve-vm", kind="ct",
                          status="running")
    db_session.add(keep)
    await db_session.flush()

    inst = await _inst(db_session)
    _patch(monkeypatch, VMS)
    await esxi.sync_instance(db_session, inst)
    await db_session.flush()

    still = (await db_session.execute(select(VirtualMachine).where(
        VirtualMachine.cluster_id == pve.id))).scalars().all()
    assert [v.name for v in still] == ["pve-vm"]
    assert still[0].legacy_vmid == 101 and still[0].kind == "ct"
