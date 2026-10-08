"""MAC 歷程：以一個 MAC 為中心，串起它的所有故事（2026-10-01 使用者要求）。

「我有一個 MAC，不確定它用過哪些 IP」：以前只能從 IP 查。資料其實都在，只是散在各處：
IP 異動記錄（MAC 換了幾次、從哪個換成哪個）、ARP 觀測、交換器 MAC 表（FDB）、DHCP 固定分配、
裝置的連接埠、虛擬機網卡。這裡全部以 MAC 為中心收在一起。

隨機（私人）MAC：新版 OS 連 Wi‑Fi 預設用，會換。同一個 IP、主機名稱沒變、換成另一個 MAC，
而其中有隨機位址時，列為「可能是同一台」（只是線索，不合併）。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.device import Device
from app.models.ip_change_log import IPChangeLog
from app.models.librenms import ARPEntry, FDBEntry, LibreNMSDevice, LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.mac_history import mac_history

MAC = "00:00:5e:00:53:01"
NOW = datetime.now(UTC)


async def _story(db) -> dict:
    sec = Section(name=f"mh-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    s1 = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    s2 = Subnet(section_id=sec.id, cidr="203.0.113.0/24")
    db.add_all([s1, s2])
    await db.flush()
    a = IPAddress(subnet_id=s1.id, ip="198.51.100.10", hostname="old-laptop", mac="00:00:5e:00:53:99")
    b = IPAddress(subnet_id=s2.id, ip="203.0.113.20", hostname="laptop-07", mac=MAC,
                  last_seen_scanner=NOW - timedelta(minutes=2))
    db.add_all([a, b])
    await db.flush()
    t1, t2 = NOW - timedelta(days=20), NOW - timedelta(days=5)
    db.add_all([
        IPChangeLog(ip_id=a.id, subnet_id=s1.id, ip_text="198.51.100.10", event_type="mac_changed", field="mac",
                    old_value=None, new_value=MAC, source="scanner", created_at=t1),
        IPChangeLog(ip_id=a.id, subnet_id=s1.id, ip_text="198.51.100.10", event_type="mac_changed", field="mac",
                    old_value=MAC, new_value="00:00:5e:00:53:99", source="scanner", created_at=t2),
        # 手動輸入的寫法不一樣（大寫、破折號）也要對得到
        IPChangeLog(ip_id=b.id, subnet_id=s2.id, ip_text="203.0.113.20", event_type="edited", field="mac",
                    old_value=None, new_value="00-00-5E-00-53-01", source="manual",
                    created_at=t2 + timedelta(hours=1)),
        ARPEntry(ip="203.0.113.20", mac=MAC, source="scanner", subnet_id=s2.id,
                 first_seen_at=t2, last_seen_at=NOW - timedelta(minutes=2)),
    ])
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:4]}", api_url="https://192.0.2.50",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db.add(inst)
    sw = Device(name="sw-floor2", type="switch")
    db.add(sw)
    await db.flush()
    ln = LibreNMSDevice(instance_id=inst.id, legacy_device_id=7, hostname="sw-floor2", jt_ipam_device_id=sw.id)
    db.add(ln)
    await db.flush()
    db.add(FDBEntry(mac=MAC, device_id=ln.id, instance_id=inst.id, port_name="Gi1/0/5", vlan_id_num=10,
                    first_seen_at=t2, last_seen_at=NOW))
    await db.commit()
    return {"a": a, "b": b, "s1": s1, "s2": s2, "sw": sw, "t1": t1, "t2": t2}


async def test_one_mac_one_story(db_session, admin_user) -> None:
    from app.models.dhcp import DHCPReservation
    from app.models.physical import DevicePort
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface
    st = await _story(db_session)
    host = Device(name="nas-01", type="storage")
    db_session.add(host)
    await db_session.flush()
    db_session.add_all([
        DHCPReservation(source_type="kea", source_id=uuid.uuid4(), source_name="kea-1", ip="203.0.113.20",
                        mac="00-00-5E-00-53-01", hostname="laptop-07"),
        DevicePort(device_id=host.id, name="eth0", type="network", mac_address="0000.5E00.5301"),
    ])
    cl = VirtCluster(name=f"pve-{uuid.uuid4().hex[:4]}")
    db_session.add(cl)
    await db_session.flush()
    vm = VirtualMachine(cluster_id=cl.id, name="vm-laptop", status="running")
    db_session.add(vm)
    await db_session.flush()
    db_session.add(VMInterface(vm_id=vm.id, name="net0", mac=MAC))
    await db_session.commit()

    out = await mac_history(db_session, user=admin_user, mac="00-00-5E-00-53-01")
    assert out["mac"] == MAC
    assert out["random"] is False
    assert out["restricted"] is False
    ips = {r["ip"]: r for r in out["ips"]}
    assert set(ips) == {"198.51.100.10", "203.0.113.20"}
    assert ips["203.0.113.20"]["current"] is True
    assert ips["198.51.100.10"]["current"] is False
    assert datetime.fromisoformat(ips["198.51.100.10"]["first_seen"]) == st["t1"]
    assert datetime.fromisoformat(ips["198.51.100.10"]["last_seen"]) == st["t2"]   # 被別的 MAC 取代
    assert ips["203.0.113.20"]["hostname"] == "laptop-07"
    assert out["current"][0]["ip"] == "203.0.113.20"
    kinds = [(e["kind"], e["ip"], e["other_mac"]) for e in out["events"]]
    assert ("released", "198.51.100.10", "00:00:5e:00:53:99") in kinds
    assert ("assigned", "198.51.100.10", None) in kinds
    assert ("assigned", "203.0.113.20", None) in kinds                 # 手動寫法也對得到
    port = out["switch_ports"][0]
    assert (port["switch"], port["port"], port["vlan"]) == ("sw-floor2", "Gi1/0/5", 10)
    assert port["switch_device_id"] == str(st["sw"].id)
    assert out["dhcp_reservations"][0]["ip"] == "203.0.113.20"
    assert out["device_ports"][0]["device_name"] == "nas-01"
    assert out["vms"][0]["vm_name"] == "vm-laptop"


async def test_input_spellings_and_bad_input(client, auth_headers, db_session) -> None:
    await _story(db_session)
    for s in ("00:00:5E:00:53:01", "0000.5e00.5301", "00005e005301"):
        r = await client.get(f"/api/v1/macs/{s}/history", headers=auth_headers)
        assert r.status_code == 200, r.text
        assert r.json()["mac"] == MAC
    bad = await client.get("/api/v1/macs/not-a-mac/history", headers=auth_headers)
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "mac_invalid"


async def test_random_mac_rotation_is_flagged_as_possibly_the_same_device(db_session, admin_user) -> None:
    """同一個 IP、主機名稱沒變、換成另一個 MAC，其中有隨機位址 → 列為「可能是同一台」，不合併。"""
    sec = Section(name="mh-rand")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
    db_session.add(sub)
    await db_session.flush()
    ip = IPAddress(subnet_id=sub.id, ip="192.0.2.30", hostname="iphone-amy", mac="da:00:5e:00:53:31")
    db_session.add(ip)
    await db_session.flush()
    t = NOW - timedelta(days=3)
    db_session.add_all([
        IPChangeLog(ip_id=ip.id, subnet_id=sub.id, ip_text="192.0.2.30", event_type="mac_changed", field="mac",
                    old_value="6e:00:5e:00:53:30", new_value="da:00:5e:00:53:31", source="opnsense", created_at=t),
        # 另一個 IP：主機名稱跟著換了 → 不是同一台
        IPChangeLog(ip_id=ip.id, subnet_id=sub.id, ip_text="192.0.2.30", event_type="mac_changed", field="mac",
                    old_value="7a:00:5e:00:53:29", new_value="6e:00:5e:00:53:30", source="opnsense",
                    created_at=t - timedelta(days=10)),
        IPChangeLog(ip_id=ip.id, subnet_id=sub.id, ip_text="192.0.2.30", event_type="hostname_changed",
                    field="hostname", old_value="pixel-bob", new_value="iphone-amy", source="opnsense",
                    created_at=t - timedelta(days=10, minutes=-5)),
    ])
    await db_session.commit()
    out = await mac_history(db_session, user=admin_user, mac="da:00:5e:00:53:31")
    assert out["random"] is True
    rel = {r["mac"]: r for r in out["related"]}
    assert "6e:00:5e:00:53:30" in rel
    assert rel["6e:00:5e:00:53:30"]["reason"] == "same_ip_same_hostname"
    other = await mac_history(db_session, user=admin_user, mac="6e:00:5e:00:53:30")
    assert "7a:00:5e:00:53:29" not in {r["mac"] for r in other["related"]}   # 那次主機名稱也換了


async def test_limited_user_sees_only_what_they_may_see(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.permission import Permission
    from app.models.user import User
    from app.services.auth import issue_access_token
    st = await _story(db_session)
    u = User(username=f"mh-{uuid.uuid4().hex[:6]}", email=f"mh-{uuid.uuid4().hex[:6]}@test.local",
             display_name="L", password_hash=hash_password("TestPassword2026!"), auth_provider="local",
             is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.flush()
    db_session.add(Permission(object_type="subnet", object_id=st["s2"].id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.get(f"/api/v1/macs/{MAC}/history", headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert {x["ip"] for x in body["ips"]} == {"203.0.113.20"}            # 看不到的網段不出現
    assert all(e["ip"] == "203.0.113.20" for e in body["events"])
    assert body["switch_ports"] == []                                    # 交換器沒授權
    assert body["restricted"] is True                                    # DHCP、虛擬機是全域資料
    assert body["dhcp_reservations"] == [] and body["vms"] == []  # noqa: PT018


@pytest.mark.anyio
async def test_ai_tool_tells_the_same_story(db_session, admin_user) -> None:
    from app.mcp.tools import TOOLS
    await _story(db_session)
    res = await TOOLS["mac_history"]["fn"](db_session, user=admin_user, mac=MAC)
    assert {r["ip"] for r in res["ips"]} == {"198.51.100.10", "203.0.113.20"}
