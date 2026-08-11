"""虛擬化頁的 VM 清單：IP 若在 IPAM 裡存在，就要能點過去。

看到一台 VM 的位址、想確認它在 IPAM 裡登記成什麼，目前得自己複製那串數字、
切到 IP 位址頁、貼上搜尋。資料早就在系統裡，連結卻要人用手接。

**重疊網段下不猜**：同一個 IP 字串在不同單位的子網路各有一筆是本專案的設計，
分不出是哪一筆時就不給連結（給錯的連結比沒有連結更糟 —— 使用者會信它）。
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


async def _fixture(db_session, *, duplicate=False):
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface

    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    sub2 = Subnet(section_id=sec.id, cidr="198.51.100.0/24")   # 重疊網段：刻意相同
    cl = VirtCluster(name=f"cl-{uuid.uuid4().hex[:6]}", type="vmware", is_standalone=True)
    db_session.add_all([sub, sub2, cl])
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.50")
    db_session.add(ipa)
    if duplicate:
        db_session.add(IPAddress(subnet_id=sub2.id, ip="198.51.100.50"))
    vm = VirtualMachine(cluster_id=cl.id, external_id=uuid.uuid4().hex[:8],
                        name=f"vm-{uuid.uuid4().hex[:6]}", status="running")
    db_session.add(vm)
    await db_session.flush()
    db_session.add(VMInterface(vm_id=vm.id, name="nic0", primary_ip="198.51.100.50"))
    await db_session.commit()
    return vm, ipa


@pytest.mark.anyio
async def test_an_ip_that_exists_in_ipam_gets_a_link(client: AsyncClient, auth_headers, db_session):
    vm, ipa = await _fixture(db_session)
    r = await client.get("/api/v1/virt/vms", headers=auth_headers,
                         params={"cluster_id": str(vm.cluster_id)})
    assert r.status_code == 200, r.text
    row = next(x for x in r.json()["items"] if x["id"] == str(vm.id))
    assert row["ip_links"]["198.51.100.50"] == str(ipa.id)


@pytest.mark.anyio
async def test_an_ambiguous_ip_gets_no_link(client: AsyncClient, auth_headers, db_session):
    """重疊網段下同一位址有多筆 —— 給錯的連結比沒有連結更糟。"""
    vm, _ = await _fixture(db_session, duplicate=True)
    r = await client.get("/api/v1/virt/vms", headers=auth_headers,
                         params={"cluster_id": str(vm.cluster_id)})
    row = next(x for x in r.json()["items"] if x["id"] == str(vm.id))
    assert "198.51.100.50" not in (row.get("ip_links") or {})


@pytest.mark.anyio
async def test_an_ip_not_in_ipam_gets_no_link(client: AsyncClient, auth_headers, db_session):
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface
    cl = VirtCluster(name=f"cl-{uuid.uuid4().hex[:6]}", type="vmware", is_standalone=True)
    db_session.add(cl)
    await db_session.flush()
    vm = VirtualMachine(cluster_id=cl.id, external_id=uuid.uuid4().hex[:8],
                        name=f"vm-{uuid.uuid4().hex[:6]}", status="running")
    db_session.add(vm)
    await db_session.flush()
    db_session.add(VMInterface(vm_id=vm.id, name="nic0", primary_ip="203.0.113.99"))
    await db_session.commit()
    r = await client.get("/api/v1/virt/vms", headers=auth_headers,
                         params={"cluster_id": str(cl.id)})
    row = next(x for x in r.json()["items"] if x["id"] == str(vm.id))
    assert (row.get("ip_links") or {}) == {}
