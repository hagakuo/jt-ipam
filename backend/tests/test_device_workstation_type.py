"""裝置類型「工作站」與自動判斷（使用者 2026-10-06）。

laptop-07（Windows 11 筆電）在 IP 頁是「Windows 主機」，裝置卻是「其他」：裝置類型只在建立時決定一次，
從 IP 頁「建立裝置」還寫死 other。現在依作業系統證據自動判斷工作站／伺服器，人工設定的一律不動。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.models.address import IPAddress
from app.models.device import Device
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.device_type_auto import classify_chassis, classify_os, decide, refresh_auto_types


def test_classify_os() -> None:
    assert classify_os("Microsoft Windows 11 Pro") == "workstation"
    assert classify_os("Windows 11 10.0.26200.9457") == "workstation"
    assert classify_os("Microsoft Windows 10 (92%)") == "workstation"
    assert classify_os("macOS 15.1") == "workstation"
    assert classify_os("Microsoft Windows Server 2022 Standard") == "server"
    # 分不出來的不猜
    assert classify_os("Microsoft Windows 10 1607 - 11 / Server 2016") is None
    assert classify_os("Ubuntu 24.04 LTS") is None
    assert classify_os("windows") is None
    assert classify_os(None) is None


def test_classify_chassis_and_decide() -> None:
    assert classify_chassis("Notebook") == "workstation"
    assert classify_chassis("Desktop") == "workstation"
    assert classify_chassis("Rack Mount Chassis") == "server"
    assert classify_chassis("Tower") is None          # 直立式伺服器也是 tower
    # 代理的作業系統優先；代理之間矛盾就不猜；代理沒說才看 nmap，再看機殼
    assert decide(["Microsoft Windows 11 Pro"], ["Windows Server 2019"], []) == "workstation"
    assert decide(["Windows 11 Pro", "Windows Server 2022"], [], ["Notebook"]) is None
    assert decide([], ["Microsoft Windows 10"], []) == "workstation"
    assert decide(["Ubuntu 24.04"], [], ["Notebook"]) == "workstation"
    assert decide([], [], []) is None


async def _dev_with_ip(db, addr: str, *, os_ocs=None, os_guess=None, chassis=None,
                       dev_type="other", type_source=None) -> tuple[Device, IPAddress]:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    dev = Device(name=f"dev-{uuid.uuid4().hex[:6]}", type=dev_type, type_source=type_source)
    db.add(dev)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip=addr, device_id=dev.id, os_ocs=os_ocs, os_guess=os_guess,
                   ocs_hw={"system": {"chassis": chassis}} if chassis else None)
    db.add(ip)
    await db.flush()
    return dev, ip


async def test_other_device_becomes_workstation_from_agent_os(db_session) -> None:
    dev, _ = await _dev_with_ip(db_session, "198.51.100.71", os_ocs="Microsoft Windows 11 Pro 10.0.26200")
    assert await refresh_auto_types(db_session) >= 1
    await db_session.refresh(dev)
    assert dev.type == "workstation" and dev.type_source == "auto"


async def test_server_edition_and_chassis(db_session) -> None:
    srv, _ = await _dev_with_ip(db_session, "198.51.100.72", os_ocs="Microsoft Windows Server 2022 Standard")
    nb, _ = await _dev_with_ip(db_session, "198.51.100.73", chassis="Notebook")
    await refresh_auto_types(db_session, [srv.id, nb.id])
    await db_session.refresh(srv)
    await db_session.refresh(nb)
    assert srv.type == "server" and nb.type == "workstation"


async def test_manual_and_explicit_types_are_never_touched(db_session) -> None:
    manual, _ = await _dev_with_ip(db_session, "198.51.100.74", os_ocs="Windows 11 Pro",
                                   dev_type="other", type_source="manual")
    lnms, _ = await _dev_with_ip(db_session, "198.51.100.75", os_ocs="Windows 11 Pro",
                                 dev_type="server", type_source="librenms")
    legacy_server, _ = await _dev_with_ip(db_session, "198.51.100.76", os_ocs="Windows 11 Pro",
                                          dev_type="server", type_source=None)
    await refresh_auto_types(db_session, [manual.id, lnms.id, legacy_server.id])
    for d in (manual, lnms, legacy_server):
        await db_session.refresh(d)
    assert manual.type == "other" and lnms.type == "server" and legacy_server.type == "server"


async def test_auto_type_follows_new_evidence(db_session) -> None:
    dev, ip = await _dev_with_ip(db_session, "198.51.100.77", os_ocs="Windows 11 Pro")
    await refresh_auto_types(db_session, [dev.id])
    ip.os_ocs = "Microsoft Windows Server 2025 Datacenter"
    await db_session.flush()
    await refresh_auto_types(db_session, [dev.id])
    await db_session.refresh(dev)
    assert dev.type == "server" and dev.type_source == "auto"


async def test_editing_the_type_by_hand_marks_it_manual(client, auth_headers, db_session) -> None:
    dev, _ = await _dev_with_ip(db_session, "198.51.100.78", os_ocs="Windows 11 Pro")
    await db_session.commit()
    r = await client.patch(f"/api/v1/devices/{dev.id}", headers=auth_headers, json={"type": "storage"})
    assert r.status_code == 200, r.text
    assert r.json()["type_source"] == "manual"
    # 只送了沒變的 type（編輯表單每次都送）不算人改
    dev2, _ = await _dev_with_ip(db_session, "198.51.100.79")
    await db_session.commit()
    r = await client.patch(f"/api/v1/devices/{dev2.id}", headers=auth_headers, json={"type": "other", "vendor": "x"})
    assert r.status_code == 200 and r.json()["type_source"] is None


async def test_workstation_is_a_valid_type_via_api(client, auth_headers) -> None:
    r = await client.post("/api/v1/devices", headers=auth_headers,
                          json={"name": f"ws-{uuid.uuid4().hex[:6]}", "type": "workstation"})
    assert r.status_code == 201, r.text
    assert r.json()["type"] == "workstation" and r.json()["type_source"] == "manual"


async def test_device_created_from_ip_gets_a_type(client, auth_headers, db_session) -> None:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.80", hostname="laptop-07",
                   os_ocs="Microsoft Windows 11 Pro", last_seen_ocs=datetime.now(UTC))
    db_session.add(ip)
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ip.id}/device-suggestion/apply", headers=auth_headers,
                          json={"create_name": "laptop-07"})
    assert r.status_code == 200, r.text
    await db_session.refresh(ip)
    dev = await db_session.get(Device, ip.device_id)
    assert dev is not None and dev.type == "workstation" and dev.type_source == "auto"
