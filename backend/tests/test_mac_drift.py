"""MAC 漂移偵測（2026-09-30 研究：舊規則在多台交換器的網路裡全是誤報）。

舊規則是「同一個 MAC 在 1 小時內出現在 ≥2 個（交換器, 埠）」。可是一台主機的 MAC 本來就會同時
出現在它插的存取埠，以及沿路每一台交換器的上行埠 —— 那是正常的路徑，不是移動。正式機資料：
時間窗放到涵蓋 LibreNMS 最近一次 FDB 探索時，83 筆全部牽涉上行埠、0 筆是真的移動
（平常看起來 0 筆，只是因為 FDB 時間戳是 LibreNMS 每 6 小時刷新一次的 updated_at，
1 小時窗剛好擋掉）。

新規則：**同一台交換器上換了埠**（跨交換器出現是正常的路徑）。分類顯示（使用者選的）：
- 實體設備換埠（device_move）：正式異常、會通知
- 虛擬機遷移（vm_migration）、隨機 MAC 漫遊（random_mac）、上行埠之間的路徑變更（uplink_change）：
  參考，不通知
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.librenms import FDBEntry, LibreNMSDevice, LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.virt import VirtCluster, VirtualMachine, VMInterface
from app.services import anomaly

NOW = datetime.now(UTC)


async def _net(db, *, enabled: bool = True):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sn = Subnet(cidr="198.51.100.0/24", section_id=sec.id, anomaly_enabled=enabled)
    db.add(sn)
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db.add(inst)
    await db.flush()
    sw1 = LibreNMSDevice(instance_id=inst.id, legacy_device_id=1, hostname="sw-core", sysname="sw-core")
    sw2 = LibreNMSDevice(instance_id=inst.id, legacy_device_id=2, hostname="sw-floor3", sysname="sw-floor3")
    db.add_all([sw1, sw2])
    await db.flush()
    return sn, inst, sw1, sw2


def _fdb(inst, sw, port: str, mac: str, *, first: timedelta, last: timedelta) -> FDBEntry:
    return FDBEntry(mac=mac, instance_id=inst.id, device_id=sw.id, port_name=port,
                    first_seen_at=NOW - first, last_seen_at=NOW - last)


def _uplink(inst, sw, port: str, n: int = 12) -> list[FDBEntry]:
    """一個背後有很多 MAC 的埠（上行埠／虛擬化主機）。"""
    return [_fdb(inst, sw, port, f"00:00:5e:00:5{i // 16:x}:{i % 16:02x}", first=timedelta(days=30),
                 last=timedelta(hours=1)) for i in range(n)]


async def test_the_same_mac_on_two_switches_is_a_path_not_a_move(db_session) -> None:
    sn, inst, core, floor = await _net(db_session)
    mac = "00:00:5e:00:53:10"
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.10", mac=mac))
    db_session.add_all([
        # 30 分鐘內：舊規則（1 小時窗、跨交換器也算）一定會把它報出來
        _fdb(inst, floor, "ge-0/0/5", mac, first=timedelta(days=90), last=timedelta(minutes=30)),
        _fdb(inst, core, "xe-0/1/0", mac, first=timedelta(days=90), last=timedelta(minutes=30)),
        *_uplink(inst, core, "xe-0/1/0"),
    ])
    await db_session.commit()
    items = await anomaly.detect_mac_drifts(db_session)
    assert items == []


async def test_a_device_replugged_on_the_same_switch_is_a_move(db_session) -> None:
    sn, inst, _core, floor = await _net(db_session)
    mac = "00:00:5e:00:53:20"
    db_session.add(IPAddress(subnet_id=sn.id, ip="198.51.100.20", mac=mac, hostname="printer-3f"))
    db_session.add_all([
        _fdb(inst, floor, "ge-0/0/18", mac, first=timedelta(days=60), last=timedelta(days=2)),
        _fdb(inst, floor, "ge-0/0/21", mac, first=timedelta(hours=20), last=timedelta(hours=2)),
    ])
    await db_session.commit()
    [item] = await anomaly.detect_mac_drifts(db_session)
    assert item["category"] == "device_move"
    assert (item["device_name"], item["from_port"], item["to_port"]) == ("sw-floor3", "ge-0/0/18", "ge-0/0/21")
    assert item["port"] == "ge-0/0/21"                      # 去重指紋：換到新的埠＝新的一筆
    moved = datetime.fromisoformat(item["moved_at"])
    assert abs((moved - (NOW - timedelta(hours=20))).total_seconds()) < 5   # 首次出現在新埠的時間
    assert item["ips"] == [{"ip": "198.51.100.20", "hostname": "printer-3f"}]
    assert item["ip_id"]                                    # 畫面上的「忽略」按鈕要用
    assert [loc["port"] for loc in item["locations"]] == ["ge-0/0/21", "ge-0/0/18"]


async def test_old_or_long_gone_locations_are_not_moves(db_session) -> None:
    sn, inst, _core, floor = await _net(db_session)
    a, b = "00:00:5e:00:53:30", "00:00:5e:00:53:31"
    db_session.add_all([IPAddress(subnet_id=sn.id, ip="198.51.100.30", mac=a),
                        IPAddress(subnet_id=sn.id, ip="198.51.100.31", mac=b)])
    db_session.add_all([
        # 新位置是三天前的事：不是「最近」的移動
        _fdb(inst, floor, "ge-0/0/1", a, first=timedelta(days=90), last=timedelta(days=10)),
        _fdb(inst, floor, "ge-0/0/2", a, first=timedelta(days=3), last=timedelta(days=3)),
        # 舊位置是一個月前：早就不在那裡了，不算這一次的移動
        _fdb(inst, floor, "ge-0/0/3", b, first=timedelta(days=90), last=timedelta(days=30)),
        _fdb(inst, floor, "ge-0/0/4", b, first=timedelta(hours=5), last=timedelta(hours=1)),
    ])
    await db_session.commit()
    assert await anomaly.detect_mac_drifts(db_session) == []


async def test_categories_vm_random_and_uplink(db_session) -> None:
    sn, inst, core, floor = await _net(db_session)
    cluster = VirtCluster(name=f"pve-{uuid.uuid4().hex[:6]}")
    db_session.add(cluster)
    await db_session.flush()
    vm = VirtualMachine(cluster_id=cluster.id, name="app-01")
    db_session.add(vm)
    await db_session.flush()
    macs = {
        "known_vm": "00:00:5e:00:53:40",            # 整合登記過的 VM 網卡
        "proxmox_oui": "bc:24:11:00:53:41",         # Proxmox 的 VM 位址
        "random": "06:00:5e:00:53:42",              # 本地管理位址（手機隨機 MAC）
        "uplink": "00:00:5e:00:53:43",              # 兩個忙碌的埠之間
    }
    db_session.add(VMInterface(vm_id=vm.id, name="net0", mac=macs["known_vm"]))
    for i, m in enumerate(macs.values()):
        db_session.add(IPAddress(subnet_id=sn.id, ip=f"198.51.100.{40 + i}", mac=m))
    rows = [*_uplink(inst, core, "xe-0/1/0"), *_uplink(inst, core, "xe-0/1/1")]
    for key in ("known_vm", "proxmox_oui", "random"):
        rows += [_fdb(inst, floor, "ge-0/0/10", macs[key], first=timedelta(days=9), last=timedelta(days=1)),
                 _fdb(inst, floor, "ge-0/0/12", macs[key], first=timedelta(hours=6), last=timedelta(hours=1))]
    rows += [_fdb(inst, core, "xe-0/1/0", macs["uplink"], first=timedelta(days=9), last=timedelta(days=1)),
             _fdb(inst, core, "xe-0/1/1", macs["uplink"], first=timedelta(hours=6), last=timedelta(hours=1))]
    db_session.add_all(rows)
    await db_session.commit()
    got = {i["mac"]: i["category"] for i in await anomaly.detect_mac_drifts(db_session)}
    assert got == {macs["known_vm"]: "vm_migration", macs["proxmox_oui"]: "vm_migration",
                   macs["random"]: "random_mac", macs["uplink"]: "uplink_change"}


async def test_only_device_moves_are_formal_anomalies(db_session) -> None:
    """正式異常（會通知、算進總數）只有實體設備換埠；其他在 mac_drift_reference。"""
    sn, inst, _core, floor = await _net(db_session)
    dev, rnd = "00:00:5e:00:53:50", "06:00:5e:00:53:51"
    for i, m in enumerate((dev, rnd)):
        db_session.add(IPAddress(subnet_id=sn.id, ip=f"198.51.100.{50 + i}", mac=m))
        db_session.add_all([
            _fdb(inst, floor, "ge-0/0/30", m, first=timedelta(days=9), last=timedelta(days=1)),
            _fdb(inst, floor, "ge-0/0/31", m, first=timedelta(hours=6), last=timedelta(hours=1))])
    await db_session.commit()
    report = await anomaly.run_detection(db_session, notify_admins=False)
    assert [i["mac"] for i in report.mac_drifts] == [dev]
    assert [i["mac"] for i in report.mac_drift_reference] == [rnd]
    assert report.to_dict()["mac_drift_reference"][0]["category"] == "random_mac"


async def test_scope_and_ignore_list(db_session) -> None:
    """跟其他偵測一樣：只看有開異常偵測的子網路、套用逐 IP 的忽略清單。"""
    sn, inst, _core, floor = await _net(db_session, enabled=False)
    mac = "00:00:5e:00:53:60"
    ip = IPAddress(subnet_id=sn.id, ip="198.51.100.60", mac=mac)
    db_session.add(ip)
    db_session.add_all([
        _fdb(inst, floor, "ge-0/0/40", mac, first=timedelta(days=9), last=timedelta(days=1)),
        _fdb(inst, floor, "ge-0/0/41", mac, first=timedelta(hours=6), last=timedelta(hours=1))])
    await db_session.commit()
    assert await anomaly.detect_mac_drifts(db_session) == []           # 子網路沒開異常偵測
    sn.anomaly_enabled = True
    await db_session.commit()
    assert len(await anomaly.detect_mac_drifts(db_session)) == 1
    ip.anomaly_ignore = ["mac_drifts"]
    await db_session.commit()
    assert await anomaly.detect_mac_drifts(db_session) == []           # 這個 IP 被標成忽略
    assert "mac_drifts" in anomaly.ANOMALY_IGNORABLE
