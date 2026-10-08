"""Proxmox 同步（mock _api_get，path 分派）：獨立節點拉一台 qemu VM →
upsert VirtualMachine + 解析 netN 介面；冪等更新。"""

from __future__ import annotations

from app.models.virt import (
    ProxmoxInstance,
    VirtCluster,
    VirtualMachine,
    VMInterface,
)
from app.services import proxmox as px
from sqlalchemy import func, select

_RESP = {
    "/api2/json/version": {"data": {"version": "8.1"}},
    "/api2/json/cluster/status": {"data": [
        {"type": "node", "name": "pve1", "ip": "10.3.0.1"},
    ]},
    "/api2/json/nodes": {"data": [{"node": "pve1"}]},
    "/api2/json/nodes/pve1/network": {"data": []},
    "/api2/json/nodes/pve1/qemu": {"data": [
        {"vmid": 100, "name": "web-vm", "status": "stopped",
         "cpus": 2, "maxmem": 2147483648, "maxdisk": 10737418240},
    ]},
    "/api2/json/nodes/pve1/lxc": {"data": []},
    "/api2/json/nodes/pve1/qemu/100/config": {"data": {
        "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10",
    }},
}


def _patch(monkeypatch, resp=_RESP):
    async def _fake(_session, _instance, path, *, base_url=None, timeout=None):
        return resp.get(path, {"data": []})
    monkeypatch.setattr(px, "_api_get", _fake)


async def _instance(session) -> ProxmoxInstance:
    inst = ProxmoxInstance(
        api_url="https://pve.example.com:8006", auth_username="root@pam",
        auth_token_id="jtipam",
    )
    session.add(inst)
    await session.flush()
    return inst


async def test_sync_standalone_one_vm(db_session, monkeypatch):
    _patch(monkeypatch)
    inst = await _instance(db_session)
    summary = await px.sync_instance(db_session, inst)

    assert summary.cluster == "pve1"
    assert summary.vms_seen == 1
    assert summary.vms_inserted == 1

    cl = (await db_session.execute(
        select(VirtCluster).where(VirtCluster.name == "pve1")
    )).scalar_one()
    assert cl.is_standalone is True

    vm = (await db_session.execute(
        select(VirtualMachine).where(VirtualMachine.legacy_vmid == 100)
    )).scalar_one()
    assert vm.name == "web-vm"
    assert vm.kind == "vm"
    assert vm.status == "stopped"
    assert vm.vcpus == 2
    assert vm.memory_mb == 2048
    assert vm.disk_gb == 10

    itf = (await db_session.execute(
        select(VMInterface).where(VMInterface.vm_id == vm.id)
    )).scalar_one()
    assert itf.name == "net0"
    assert str(itf.mac).lower() == "aa:bb:cc:dd:ee:ff"
    assert itf.bridge == "vmbr0"


async def test_sync_is_idempotent(db_session, monkeypatch):
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)

    # 第二次：狀態變 running → 更新同一筆，不新增
    resp2 = dict(_RESP)
    resp2["/api2/json/nodes/pve1/qemu"] = {"data": [
        {"vmid": 100, "name": "web-vm", "status": "running",
         "cpus": 4, "maxmem": 2147483648, "maxdisk": 10737418240},
    ]}
    # running 會打 agent → 給空 result
    resp2["/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"] = {"data": {"result": []}}
    _patch(monkeypatch, resp2)
    summary = await px.sync_instance(db_session, inst)
    assert summary.vms_updated == 1
    assert summary.vms_inserted == 0

    vms = (await db_session.execute(select(VirtualMachine))).scalars().all()
    assert len(vms) == 1
    assert vms[0].status == "running"
    assert vms[0].vcpus == 4


# ── 客戶回報：VM 沒裝 guest agent → PVE 不知道 IP → 主機名稱一直空白 ──
# 修法：改用 VM 網卡 MAC 比對 IPAM 已知的 IP（scanner/ARP 學到的），只比既有、不新建。
async def _seed_ip(session, ip: str, mac: str | None):
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sect = Section(name=f"s-{ip}")
    session.add(sect)
    await session.flush()
    sub = Subnet(section_id=sect.id, cidr="10.9.0.0/24")
    session.add(sub)
    await session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip=ip, mac=mac)
    session.add(ipa)
    await session.flush()
    return ipa


async def test_no_agent_vm_hostname_via_mac(db_session, monkeypatch):
    """沒有 IP、只有 MAC → 用 MAC 對到既有 IP，並把 PVE 的 VM 名稱記成主機名稱觀測。"""
    ipa = await _seed_ip(db_session, "10.9.0.5", "aa:bb:cc:dd:ee:ff")
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    await db_session.refresh(ipa)
    assert ipa.hostname == "web-vm"
    # 同時回填 VM 主 IP（沒有它，PVE 主控台的 IP→VM 解析也會失敗）
    vm = (await db_session.execute(
        select(VirtualMachine).where(VirtualMachine.legacy_vmid == 100)
    )).scalar_one()
    assert vm.primary_ip_id == ipa.id


async def test_no_agent_vm_mac_unknown_creates_nothing(db_session, monkeypatch):
    """MAC 在 IPAM 找不到 → 什麼都不做（絕不憑空建 IP）。"""
    from app.models.address import IPAddress
    before = await db_session.scalar(select(func.count()).select_from(IPAddress))
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    after = await db_session.scalar(select(func.count()).select_from(IPAddress))
    assert after == before


async def test_no_agent_vm_ambiguous_mac_skipped(db_session, monkeypatch):
    """同一 MAC 對到多筆（重疊網段）→ 視為不明確，不猜、不寫主機名稱。"""
    a = await _seed_ip(db_session, "10.9.0.7", "aa:bb:cc:dd:ee:ff")
    b = await _seed_ip(db_session, "10.9.0.8", "aa:bb:cc:dd:ee:ff")
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    for ipa in (a, b):
        await db_session.refresh(ipa)
        assert ipa.hostname != "web-vm"


# ── 2026-09-26 稽核：鏡像只增不刪、主 IP 只設一次 ──
# VM 在 PVE 刪掉後，清單裡永遠留著最後的狀態（例如 running）；VM 改 IP 或 VMID 被重複使用時，
# 主 IP 停在舊的 → 從舊 IP 開 PVE 主控台會開到錯的（甚至已刪除的）guest。

def _with(resp: dict, **paths) -> dict:
    out = dict(resp)
    for k, v in paths.items():
        out[k.replace("__", "/")] = v
    return out


def _qemu(*vms) -> dict:
    return {"data": [{"vmid": vmid, "name": name, "status": "stopped",
                      "cpus": 1, "maxmem": 1073741824, "maxdisk": 1073741824}
                     for vmid, name in vms]}


async def _vmids(session) -> set[int]:
    return set((await session.execute(select(VirtualMachine.legacy_vmid))).scalars().all())


async def test_a_vm_deleted_in_pve_is_removed(db_session, monkeypatch):
    resp = dict(_RESP)
    resp["/api2/json/nodes/pve1/qemu"] = _qemu((100, "web-vm"), (101, "old-vm"))
    _patch(monkeypatch, resp)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    assert await _vmids(db_session) == {100, 101}

    resp["/api2/json/nodes/pve1/qemu"] = _qemu((100, "web-vm"))
    _patch(monkeypatch, resp)
    summary = await px.sync_instance(db_session, inst)
    assert await _vmids(db_session) == {100}
    assert summary.vms_removed == 1


async def test_nothing_is_removed_when_a_node_listing_fails(db_session, monkeypatch):
    """某個節點的 lxc 清單讀不到 → 不知道那些 CT 還在不在，一台都不可以刪。"""
    resp = dict(_RESP)
    resp["/api2/json/nodes/pve1/qemu"] = _qemu((100, "web-vm"), (101, "old-vm"))
    _patch(monkeypatch, resp)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)

    resp["/api2/json/nodes/pve1/qemu"] = _qemu((100, "web-vm"))

    async def _fake(_s, _i, path, *, base_url=None, timeout=None):
        if path.endswith("/lxc"):
            raise px.ProxmoxError("HTTP 500")
        return resp.get(path, {"data": []})
    monkeypatch.setattr(px, "_api_get", _fake)
    summary = await px.sync_instance(db_session, inst)
    assert summary.errors
    assert await _vmids(db_session) == {100, 101}


async def test_an_empty_listing_removes_nothing(db_session, monkeypatch):
    """讀到 0 台、之前卻有 → 多半是 token 權限被收，不是整個叢集的 VM 都刪了。"""
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    _patch(monkeypatch, _with(_RESP, **{"/api2/json/nodes/pve1/qemu": {"data": []}}))
    await px.sync_instance(db_session, inst)
    assert await _vmids(db_session) == {100}


async def test_another_platforms_vms_are_not_touched(db_session, monkeypatch):
    """同一張表也放 ESXi 的 VM：PVE 的清除只限自己的叢集。"""
    from app.models.virt import VirtCluster as _C
    other = _C(name="esxi-a", type="vmware", is_standalone=True)
    db_session.add(other)
    await db_session.flush()
    db_session.add(VirtualMachine(cluster_id=other.id, legacy_vmid=555, name="esx-vm"))
    await db_session.flush()
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    assert 555 in await _vmids(db_session)


async def test_primary_ip_follows_the_vm_when_its_ip_changes(db_session, monkeypatch):
    """主 IP 每輪重算：網卡改到別的 IP（同 MAC 被搬到另一個位址），主 IP 跟著走。"""
    a = await _seed_ip(db_session, "10.9.0.5", "aa:bb:cc:dd:ee:ff")
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    vm = (await db_session.execute(select(VirtualMachine))).scalar_one()
    assert vm.primary_ip_id == a.id

    a.mac = None
    b = await _seed_ip(db_session, "10.9.0.6", "aa:bb:cc:dd:ee:ff")
    await px.sync_instance(db_session, inst)
    assert vm.primary_ip_id == b.id


async def test_primary_ip_is_cleared_when_nothing_maps_any_more(db_session, monkeypatch):
    a = await _seed_ip(db_session, "10.9.0.5", "aa:bb:cc:dd:ee:ff")
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    vm = (await db_session.execute(select(VirtualMachine))).scalar_one()
    assert vm.primary_ip_id == a.id

    a.mac = None
    await db_session.flush()
    await px.sync_instance(db_session, inst)
    assert vm.primary_ip_id is None


async def test_primary_ip_is_kept_when_the_config_could_not_be_read(db_session, monkeypatch):
    """設定讀不到＝這一輪不知道它的網卡：保留原值，不要清了下一輪又設回來。"""
    a = await _seed_ip(db_session, "10.9.0.5", "aa:bb:cc:dd:ee:ff")
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    vm = (await db_session.execute(select(VirtualMachine))).scalar_one()

    async def _fake(_s, _i, path, *, base_url=None, timeout=None):
        if path.endswith("/config"):
            raise px.ProxmoxError("HTTP 500")
        return _RESP.get(path, {"data": []})
    monkeypatch.setattr(px, "_api_get", _fake)
    await px.sync_instance(db_session, inst)
    assert vm.primary_ip_id == a.id


# ── 叢集以名稱為身分：兩台都叫 pve 的獨立節點會共用同一個叢集 ──
# 以前是 VMID 相同的兩台 VM 合成一筆、來回翻動；有了清除之後會變成每輪互刪對方的 VM。

async def _instance_at(session, host: str) -> ProxmoxInstance:
    inst = ProxmoxInstance(api_url=f"https://{host}:8006", auth_username="root@pam",
                           auth_token_id="jtipam")
    session.add(inst)
    await session.flush()
    return inst


def _patch_per_instance(monkeypatch, by_host: dict[str, dict]):
    async def _fake(_s, inst, path, *, base_url=None, timeout=None):
        from urllib.parse import urlsplit
        return by_host[urlsplit(inst.api_url).hostname].get(path, {"data": []})
    monkeypatch.setattr(px, "_api_get", _fake)


async def test_two_standalone_hosts_with_the_same_node_name_do_not_share_vms(db_session, monkeypatch):
    a_resp = _with(_RESP, **{"/api2/json/nodes/pve1/qemu": _qemu((100, "a-web"), (101, "a-db"))})
    b_resp = _with(_RESP, **{"/api2/json/nodes/pve1/qemu": _qemu((100, "b-web"), (200, "b-app"))})
    _patch_per_instance(monkeypatch, {"pve-a.example.com": a_resp, "pve-b.example.com": b_resp})
    a = await _instance_at(db_session, "pve-a.example.com")
    b = await _instance_at(db_session, "pve-b.example.com")
    for _ in range(2):
        await px.sync_instance(db_session, a)
        await px.sync_instance(db_session, b)
    assert a.cluster_id != b.cluster_id
    names = set((await db_session.execute(select(VirtualMachine.name))).scalars().all())
    assert names == {"a-web", "a-db", "b-web", "b-app"}


async def test_two_instances_of_one_real_cluster_share_it(db_session, monkeypatch):
    """同一個 PVE 叢集設了兩個進入點（備援）→ 同一個叢集、VM 不重複。"""
    resp = _with(_RESP, **{"/api2/json/cluster/status": {"data": [
        {"type": "cluster", "name": "prod-cl"}, {"type": "node", "name": "pve1"}]}})
    _patch_per_instance(monkeypatch, {"pve-a.example.com": resp, "pve-b.example.com": resp})
    a = await _instance_at(db_session, "pve-a.example.com")
    b = await _instance_at(db_session, "pve-b.example.com")
    await px.sync_instance(db_session, a)
    await px.sync_instance(db_session, b)
    assert a.cluster_id == b.cluster_id
    assert await _vmids(db_session) == {100}


async def test_a_pve_node_named_like_an_esxi_cluster_gets_its_own(db_session, monkeypatch):
    from app.models.virt import VirtCluster as _C
    esx = _C(name="pve1", type="vmware", is_standalone=True)
    db_session.add(esx)
    await db_session.flush()
    _patch(monkeypatch)
    inst = await _instance(db_session)
    await px.sync_instance(db_session, inst)
    assert inst.cluster_id != esx.id
    cl = await db_session.get(_C, inst.cluster_id)
    assert cl.type == "proxmox"
