"""ESXi／vCenter 同步在超大規模下（2026-09-30 大量資料測試）。

以前每台 VM 各查一次鏡像列、各刪一次網卡、各比對一次 IP（新 VM 還要各 flush 一次）：
vCenter 5,000 台 VM 一輪一萬五千次以上查詢。
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.esxi import ESXiInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.virt import VirtualMachine, VMInterface
from app.services import esxi
from sqlalchemy import event, func, select

N = 300


async def test_vm_sync_does_not_query_per_vm(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    sec = Section(name=f"e-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sn = Subnet(section_id=sec.id, cidr="10.91.0.0/16")
    db_session.add(sn)
    await db_session.flush()
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": sn.id, "ip": f"10.91.{i // 256}.{i % 256}"} for i in range(N)])
    inst = ESXiInstance(name=f"esxi-{uuid.uuid4().hex[:6]}", api_url="https://vc.example",
                        username="ro", password_enc=b"x", password_nonce=b"y")
    db_session.add(inst)
    await db_session.commit()
    vms = [{"moid": f"vm-{i}", "name": f"vm-{i}", "power_state": "poweredOn", "host": "esx-1",
            "vcpus": 2, "memory_mb": 4096, "is_template": False, "notes": None,
            "ip": f"10.91.{i // 256}.{i % 256}",
            "nics": [{"mac": f"00:50:56:00:{i // 256:02x}:{i % 256:02x}", "network": "VM Network",
                      "ips": [f"10.91.{i // 256}.{i % 256}"]}]} for i in range(N)]

    class _S:
        def __init__(self, inst): self.inst = inst
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def list_vms(self): return vms
    monkeypatch.setattr(esxi, "Session", _S)

    counts = []
    for _ in range(2):
        n = {"q": 0}
        conn = await db_session.connection()

        def _c(*_a, _n=n, **_k):
            _n["q"] += 1
        event.listen(conn.sync_connection, "before_cursor_execute", _c)
        try:
            out = await esxi.sync_instance(db_session, inst)
            await db_session.commit()
        finally:
            event.remove(conn.sync_connection, "before_cursor_execute", _c)
        counts.append(n["q"])
        assert out["matched_ip"] == N
    assert counts[0] < 40, f"第一輪查了 {counts[0]} 次（{N} 台 VM）"
    assert counts[1] < 40, f"第二輪查了 {counts[1]} 次（{N} 台 VM）"
    assert (await db_session.execute(select(func.count()).select_from(VirtualMachine))).scalar_one() == N
    assert (await db_session.execute(select(func.count()).select_from(VMInterface))).scalar_one() == N
    vm = (await db_session.execute(select(VirtualMachine).where(VirtualMachine.name == "vm-7"))).scalar_one()
    ip = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "10.91.0.7"))).scalar_one()
    assert vm.primary_ip_id == ip.id
