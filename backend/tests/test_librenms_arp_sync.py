"""LibreNMS 的 ARP 同步（先把行為釘住，再改成整批處理）。

超大規模測試：15 萬筆 ARP 一輪同步要 9 分半、29 萬次查詢 —— 每一筆都各查一次 ARP 列、
一次 IP。改成預先載入＋整批寫入，行為要跟以前一樣：
- 新的 ARP 列新增、既有的更新 last_seen_at；同一輪重複回報的只算一次；沒追蹤的裝置略過
- 對得到 IP 的蓋 last_seen_arp；實例設了範圍時只對範圍內的子網路（重疊網段）
- MAC：IP 沒有 MAC 就補上並留異動記錄；同一個 MAC 不重寫；舊資料（來源不明）的 MAC 不覆寫
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.librenms import ARPEntry, LibreNMSDevice, LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import librenms as lib
from sqlalchemy import event, func, select


async def _setup(db, *, scope_second: bool = False):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    a = Subnet(cidr="198.51.100.0/24", section_id=sec.id)
    b = Subnet(cidr="198.51.100.0/24", section_id=sec.id, description="overlap")
    db.add_all([a, b])
    await db.flush()
    inst = LibreNMSInstance(name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y",
                            scope_subnet_ids=[str(b.id)] if scope_second else None)
    db.add(inst)
    await db.flush()
    dev = LibreNMSDevice(instance_id=inst.id, legacy_device_id=7, hostname="sw-01")
    db.add(dev)
    await db.flush()
    return inst, dev, a, b


def _api(monkeypatch, arp: list[dict]) -> None:
    async def fake(_inst, path, *, timeout=30.0):
        return {"arp": arp} if path.startswith("/api/v0/resources/ip/arp") else {}
    monkeypatch.setattr(lib, "_api_get", fake)


async def test_insert_update_dedupe_and_skip_unknown_devices(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, dev, _a, _b = await _setup(db_session)
    db_session.add(ARPEntry(ip="198.51.100.20", mac="00:00:5e:00:53:20", instance_id=inst.id, device_id=dev.id))
    await db_session.commit()
    _api(monkeypatch, [
        {"ipv4_address": "198.51.100.20", "mac_address": "00005e005320", "device_id": 7},   # 既有
        {"ipv4_address": "198.51.100.21", "mac_address": "00005E005321", "device_id": 7},   # 新
        {"ipv4_address": "198.51.100.21", "mac_address": "00005e005321", "device_id": 7},   # 重複
        {"ipv4_address": "198.51.100.22", "mac_address": "00005e005322", "device_id": 99},  # 沒追蹤
        {"ipv4_address": None, "mac_address": "00005e005323", "device_id": 7},              # 缺欄位
    ])
    seen, inserted, updated, _filled = await lib.sync_arp(db_session, inst)
    await db_session.commit()
    assert (seen, inserted, updated) == (2, 1, 1)
    rows = (await db_session.execute(select(func.host(ARPEntry.ip), ARPEntry.mac, ARPEntry.source)
                                     .order_by(ARPEntry.ip))).all()
    assert [(ip, str(mac), src) for ip, mac, src in rows] == [
        ("198.51.100.20", "00:00:5e:00:53:20", "librenms"), ("198.51.100.21", "00:00:5e:00:53:21", "librenms")]


async def test_last_seen_and_mac_fill_respect_scope_and_precedence(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, _dev, a, b = await _setup(db_session, scope_second=True)
    out_scope = IPAddress(subnet_id=a.id, ip="198.51.100.30")
    in_scope = IPAddress(subnet_id=b.id, ip="198.51.100.30")
    same_mac = IPAddress(subnet_id=b.id, ip="198.51.100.31", mac="00:00:5e:00:53:31", mac_source="librenms")
    legacy = IPAddress(subnet_id=b.id, ip="198.51.100.32", mac="00:00:5e:00:53:99")
    db_session.add_all([out_scope, in_scope, same_mac, legacy])
    await db_session.commit()
    _api(monkeypatch, [
        {"ipv4_address": "198.51.100.30", "mac_address": "00005e005330", "device_id": 7},
        {"ipv4_address": "198.51.100.31", "mac_address": "00005e005331", "device_id": 7},
        {"ipv4_address": "198.51.100.32", "mac_address": "00005e005332", "device_id": 7},
    ])
    _seen, _ins, _upd, filled = await lib.sync_arp(db_session, inst)
    await db_session.commit()
    assert filled == 2
    for row in (out_scope, in_scope, same_mac, legacy):
        await db_session.refresh(row)
    assert out_scope.last_seen_arp is None and out_scope.mac is None          # 範圍外：不碰
    assert in_scope.last_seen_arp is not None and str(in_scope.mac) == "00:00:5e:00:53:30"
    assert in_scope.mac_source == "librenms"
    assert same_mac.last_seen_arp is not None and str(same_mac.mac) == "00:00:5e:00:53:31"
    # 來源不明的舊 MAC 優先序最低：ARP 看到別的 MAC 就更新（以前會永遠凍結，2026-10-05）
    assert str(legacy.mac) == "00:00:5e:00:53:32" and legacy.mac_source == "librenms"
    logs = (await db_session.execute(select(IPChangeLog.ip_id, IPChangeLog.field, IPChangeLog.new_value)
                                     .where(IPChangeLog.event_type == "arp_changed"))).all()
    assert sorted((str(i), f) for i, f, _v in logs) == sorted([(str(in_scope.id), "mac"), (str(legacy.id), "mac")])


async def test_tens_of_thousands_of_arp_entries_take_a_handful_of_queries(db_session, monkeypatch) -> None:
    """查詢數不可以跟 ARP 筆數成正比（以前每筆兩次：15 萬筆＝29 萬次查詢、一輪 9 分半）。

    第一輪把兩萬個 IP 的 MAC 補上：每個真的變動都要寫異動記錄（log_change 會先查一次防翻動），
    所以跟「變動數」成正比是對的；第二輪什麼都沒變 —— 這才是每一輪都在付的代價，要是常數。
    """
    db_session.autoflush = False
    inst, _dev, _a, b = await _setup(db_session)
    n = 20_000
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": b.id, "ip": f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"} for i in range(n)])
    await db_session.commit()
    _api(monkeypatch, [{"ipv4_address": f"10.{i // 65536}.{i // 256 % 256}.{i % 256}",
                        "mac_address": f"02{i:010x}", "device_id": 7} for i in range(n)])
    count = {"n": 0}
    conn = await db_session.connection()

    def _c(*_a, **_k):
        count["n"] += 1
    event.listen(conn.sync_connection, "before_cursor_execute", _c)
    try:
        seen, inserted, _u, filled = await lib.sync_arp(db_session, inst)
        await db_session.commit()
        first = count["n"]
        count["n"] = 0
        seen2, inserted2, updated2, filled2 = await lib.sync_arp(db_session, inst)
        await db_session.commit()
        second = count["n"]
    finally:
        event.remove(conn.sync_connection, "before_cursor_execute", _c)
    assert (seen, inserted, filled) == (n, n, n)            # 這些 IP 本來都沒有 MAC
    assert (seen2, inserted2, updated2, filled2) == (n, 0, n, 0)
    assert second < 30, f"沒有任何變動的一輪還是查了 {second} 次"
    assert first < n * 3, f"第一輪 {first} 次"


async def test_device_sync_does_not_query_per_device(db_session, monkeypatch) -> None:
    """超大規模：以前每台裝置各查一次鏡像列、一次主 IP（5,000 台＝1.5 萬次查詢、31 秒）。"""
    db_session.autoflush = False
    inst, _dev, _a, b = await _setup(db_session)
    n = 300
    await db_session.execute(IPAddress.__table__.insert(), [
        {"subnet_id": b.id, "ip": f"10.9.{i // 256}.{i % 256}"} for i in range(n)])
    await db_session.commit()
    devices = [{"device_id": 1000 + i, "hostname": f"sw-{i:03d}", "ip": f"10.9.{i // 256}.{i % 256}",
                "status": 1} for i in range(n)]
    devices.append({"device_id": 9999, "hostname": "odd", "ip": "not-an-ip", "status": 1})

    async def fake(_inst, path, *, timeout=30.0):
        return {"devices": devices} if path.startswith("/api/v0/devices") else {}
    monkeypatch.setattr(lib, "_api_get", fake)
    count = {"n": 0}
    conn = await db_session.connection()

    def _c(*_a, **_k):
        count["n"] += 1
    event.listen(conn.sync_connection, "before_cursor_execute", _c)
    try:
        seen, inserted, updated = await lib.sync_devices(db_session, inst)
        await db_session.commit()
        first, count["n"] = count["n"], 0
        seen2, inserted2, updated2 = await lib.sync_devices(db_session, inst)
        await db_session.commit()
        second = count["n"]
    finally:
        event.remove(conn.sync_connection, "before_cursor_execute", _c)
    # _setup 已經建了一台 legacy 7；這一輪沒報它 → 但只佔極少數，斷路器不會擋、會被清掉
    assert (seen, inserted) == (n + 1, n + 1)
    assert (seen2, inserted2, updated2) == (n + 1, 0, n + 1)
    assert second < 60, f"第二輪 {second} 次"
    seen_ips = (await db_session.execute(select(func.count()).select_from(IPAddress).where(
        IPAddress.last_seen_librenms.is_not(None)))).scalar()
    assert seen_ips == n


async def _devices(db, inst, n: int) -> None:
    for k in range(n):
        db.add(LibreNMSDevice(instance_id=inst.id, legacy_device_id=100 + k, hostname=f"r-{k}"))
    await db.flush()


async def test_several_devices_disagreeing_on_a_mac_decide_once_per_sync(db_session, monkeypatch) -> None:
    """同一個 IP 好幾台設備各回一個 MAC（某台的 ARP 快取沒老化，還留著上一台的 MAC）。

    以前照回報順序一筆一筆套：同一輪 MAC 來回換好幾次、每輪同步都記異動（2026-10-05 正式環境 14 個 IP
    每 16 分鐘來回跳；之前因為來源不明被凍結才沒顯現）。現在一輪只決定一次：取最多台設備回報的 MAC。
    """
    db_session.autoflush = False
    inst, _dev, a, _b = await _setup(db_session)
    await _devices(db_session, inst, 4)
    flap = IPAddress(subnet_id=a.id, ip="198.51.100.40", mac="00:00:5e:00:53:41", mac_source="librenms")
    tie_keep = IPAddress(subnet_id=a.id, ip="198.51.100.41", mac="00:00:5e:00:53:51", mac_source="librenms")
    tie_new = IPAddress(subnet_id=a.id, ip="198.51.100.42")
    db_session.add_all([flap, tie_keep, tie_new])
    await db_session.commit()
    arp = [
        # .40：一台還留著舊的 :41、三台回報 :40 → :40；舊值排在後面也不可以蓋回去
        {"ipv4_address": "198.51.100.40", "mac_address": "00005e005340", "device_id": 100},
        {"ipv4_address": "198.51.100.40", "mac_address": "00005e005340", "device_id": 101},
        {"ipv4_address": "198.51.100.40", "mac_address": "00005e005340", "device_id": 102},
        {"ipv4_address": "198.51.100.40", "mac_address": "00005e005341", "device_id": 103},
        # .41：兩邊一樣多、目前的 MAC 是其中之一 → 不動
        {"ipv4_address": "198.51.100.41", "mac_address": "00005e005350", "device_id": 100},
        {"ipv4_address": "198.51.100.41", "mac_address": "00005e005351", "device_id": 101},
        # .42：兩邊一樣多、還沒有 MAC → 不猜
        {"ipv4_address": "198.51.100.42", "mac_address": "00005e005360", "device_id": 100},
        {"ipv4_address": "198.51.100.42", "mac_address": "00005e005361", "device_id": 101},
    ]
    _api(monkeypatch, arp)
    for _ in range(3):      # 同樣的資料再同步兩輪：不可以再記任何異動
        await lib.sync_arp(db_session, inst)
        await db_session.commit()
    for row in (flap, tie_keep, tie_new):
        await db_session.refresh(row)
    assert str(flap.mac) == "00:00:5e:00:53:40"
    assert str(tie_keep.mac) == "00:00:5e:00:53:51"
    assert tie_new.mac is None
    logs = (await db_session.execute(select(IPChangeLog.ip_id, IPChangeLog.event_type)
                                     .where(IPChangeLog.field == "mac"))).all()
    assert sorted(e for i, e in logs if i == flap.id) == ["arp_changed", "mac_changed"]
    assert [e for i, e in logs if i != flap.id] == []


async def test_sync_arp_uses_global_resources_endpoint(db_session, monkeypatch):
    """Current LibreNMS exposes ARP at /resources/ip/arp/all, not per-device."""
    sec = Section(name="lnms-arp-sec")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="192.83.194.0/24")
    db_session.add(sub)
    inst = LibreNMSInstance(
        name="lnms-arp-test",
        api_url="https://librenms.example",
        api_token_enc=b"x",
        api_token_nonce=b"y",
    )
    db_session.add(inst)
    await db_session.flush()
    dev = LibreNMSDevice(
        instance_id=inst.id,
        legacy_device_id=2,
        hostname="192.83.194.254",
        sysname="nz-c6807_vss.nkmu.edu.tw",
        primary_ip="192.83.194.254",
        status="up",
    )
    db_session.add(dev)
    ip = IPAddress(subnet_id=sub.id, ip="192.83.194.254", state="active")
    db_session.add(ip)
    await db_session.commit()

    async def fake_api_get(_instance, path, *, timeout=30.0):  # noqa: ANN001
        assert path == "/api/v0/resources/ip/arp/all"
        return {
            "status": "ok",
            "arp": [{
                "device_id": 2,
                "port_id": 443,
                "mac_address": "70db98821b00",
                "ipv4_address": "192.83.194.254",
                "context_name": "",
            }, {
                "device_id": 2,
                "port_id": 443,
                "mac_address": "70db98821b00",
                "ipv4_address": "192.83.194.254",
                "context_name": "",
            }],
        }

    monkeypatch.setattr(lib, "_api_get", fake_api_get)

    seen, inserted, updated, filled = await lib.sync_arp(db_session, inst)
    await db_session.commit()

    assert (seen, inserted, updated, filled) == (1, 1, 0, 1)
    arp = (await db_session.execute(select(ARPEntry))).scalar_one()
    assert str(arp.ip) == "192.83.194.254"
    assert str(arp.mac) == "70:db:98:82:1b:00"
    assert arp.device_id == dev.id
    await db_session.refresh(ip)
    row = (await db_session.execute(
        select(IPAddress).where(func.host(IPAddress.ip) == "192.83.194.254")
    )).scalar_one()
    assert str(row.mac) == "70:db:98:82:1b:00"
    assert row.last_seen_arp is not None
