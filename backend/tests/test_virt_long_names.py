"""issue #25：vCenter 同步因為 portgroup 名稱太長而整批中斷。

回報的實際訊息是
`StringDataRightTruncationError: value too long for type character varying(64)`，
插入的 `bridge` 是 NSX-T 自動產生的網段名稱，裡面嵌了一個 UUID：

    VCD-LoadBalancer-<uuid>-DGC-DR_NSXT-TEST-Edge      （78 字元）

第三方平台的名稱長度不是我們能決定的 —— 給它一個我們自己猜的上限，就是在賭。
這類「純顯示用的外部名稱」欄位一律用不設限的 Text；同理 `node`（ESXi 主機是 FQDN，
最長可到 253 字元）。

`external_id`（MoRef，如 vm-101）與 `name` 維持有界：那兩個有平台自己的規格上限。
"""

from __future__ import annotations

from app.models.virt import VirtCluster, VirtualMachine, VMInterface


async def _vm(session) -> VirtualMachine:
    cluster = VirtCluster(name="vc-1", type="vmware", is_standalone=True)
    session.add(cluster)
    await session.flush()
    vm = VirtualMachine(cluster_id=cluster.id, external_id="vm-101", name="web-1")
    session.add(vm)
    await session.flush()
    return vm


async def test_nsxt_style_portgroup_name_is_accepted(db_session):
    vm = await _vm(db_session)
    bridge = ("VCD-LoadBalancer-c0525187-34a4-46da-9644-ba20d9af542c"
              "-DGC-DR_NSXT-TEST-Edge")
    assert len(bridge) > 64, "這個測試的前提就是它超過原本的欄位長度"
    db_session.add(VMInterface(vm_id=vm.id, name="nic1",
                               mac="00:50:56:91:bd:ab", bridge=bridge))
    await db_session.flush()

    row = (await db_session.execute(
        VMInterface.__table__.select().where(VMInterface.vm_id == vm.id)
    )).first()
    assert row.bridge == bridge, "名稱不可以被截斷 —— 截掉的是識別用的 UUID"


async def test_long_esxi_host_fqdn_is_accepted(db_session):
    vm = await _vm(db_session)
    host = ("esxi-node-" + "a" * 200 + ".example.com")
    vm.node = host
    await db_session.flush()

    row = (await db_session.execute(
        VirtualMachine.__table__.select().where(VirtualMachine.id == vm.id)
    )).first()
    assert row.node == host
