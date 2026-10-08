"""LibreNMS：依 ARP 表自動建立 IP（GitHub #48）。

使用者要求：做成整合設定裡的選項，可以啟用或停用，**預設關**。

以前不做的原因，現在都變成把關：
- **ARP 快取很久才清**（2026-10-01 使用者特別提醒）：LibreNMS 的 ARP 沒有任何時間欄位，
  有些交換器的 ARP 幾小時到幾天才清。只憑 ARP 會把早就離開的設備也建進來 →
  預設要交換器 MAC 表（FDB）24 小時內也看過這個 MAC（MAC 表通常 5 分鐘就老化）
- 重疊網段：沒有子網路資訊 → 唯一且最精確的既有子網路才建，歧義不猜
- 雜訊：代理 ARP（一個 MAC 對應一大串 IP）、廣播／群播 MAC、網路位址與廣播位址
- 管理員剛釋放的位址（冷卻期）不偷偷建回來；DHCP 動態範圍預設略過
- 一輪有上限：第一次打開時可能有幾萬筆，分批建
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.dhcp import DHCPPoolRange
from app.models.ip_cooldown import IPCooldown
from app.models.librenms import FDBEntry, LibreNMSDevice, LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import arp_autocreate
from app.services import librenms as lib
from app.services.ip_autocreate import pick_subnet_for_ip, subnet_index
from sqlalchemy import func, select

NOW = datetime.now(UTC)


async def _setup(db, *, on: bool = True, require_fdb: bool = True, skip_dhcp: bool = True,
                 cidrs=("198.51.100.0/24",), scope: list | None = None):
    sec = Section(name=f"ac-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    subs = [Subnet(cidr=c, section_id=sec.id) for c in cidrs]
    db.add_all(subs)
    await db.flush()
    inst = LibreNMSInstance(
        name=f"lnms-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
        api_token_enc=b"x", api_token_nonce=b"y", auto_create_from_arp=on,
        arp_create_require_fdb=require_fdb, arp_create_skip_dhcp=skip_dhcp,
        scope_subnet_ids=[str(subs[i].id) for i in scope] if scope else None)
    db.add(inst)
    await db.flush()
    dev = LibreNMSDevice(instance_id=inst.id, legacy_device_id=7, hostname="core-01")
    db.add(dev)
    await db.flush()
    return inst, dev, subs


def _api(monkeypatch, pairs: list[tuple[str, str]]) -> None:
    arp = [{"ipv4_address": ip, "mac_address": mac, "device_id": 7} for ip, mac in pairs]

    async def fake(_inst, path, *, timeout=30.0):
        return {"arp": arp} if path.startswith("/api/v0/resources/ip/arp") else {}
    monkeypatch.setattr(lib, "_api_get", fake)


def _fdb(inst, dev, mac: str, *, age: timedelta = timedelta(minutes=10)) -> FDBEntry:
    return FDBEntry(mac=mac, device_id=dev.id, instance_id=inst.id, port_name="Gi1/0/9",
                    first_seen_at=NOW - age, last_seen_at=NOW - age)


async def _sync(db, inst) -> dict:
    stats: dict = {}
    await lib.sync_arp(db, inst, autocreate_stats=stats)
    await db.commit()
    return stats


async def _ips(db) -> dict[str, IPAddress]:
    return {str(r.ip).split("/")[0]: r for r in (await db.execute(select(IPAddress))).scalars().all()}


async def test_off_by_default_creates_nothing(db_session, monkeypatch) -> None:
    assert LibreNMSInstance.__table__.c.auto_create_from_arp.server_default.arg.text == "false"
    db_session.autoflush = False
    inst, dev, _ = await _setup(db_session, on=False)
    db_session.add(_fdb(inst, dev, "00:00:5e:00:53:21"))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.21", "00005e005321")])
    stats = await _sync(db_session, inst)
    assert await _ips(db_session) == {}
    assert stats.get("created", 0) == 0


async def test_creates_with_mac_and_marks_it_as_auto_collected(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, dev, (sub,) = await _setup(db_session)
    db_session.add(_fdb(inst, dev, "00:00:5e:00:53:21"))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.21", "00005e005321")])
    stats = await _sync(db_session, inst)
    ips = await _ips(db_session)
    row = ips["198.51.100.21"]
    assert row.subnet_id == sub.id
    assert row.discovery_source == "librenms_arp"
    assert str(row.mac) == "00:00:5e:00:53:21"
    assert row.mac_source == "librenms"
    assert row.last_seen_arp is not None
    assert "ARP" in (row.note or "")
    assert inst.name in (row.note or "")
    assert stats["created"] == 1


async def test_long_arp_cache_needs_a_recent_mac_table_sighting(db_session, monkeypatch) -> None:
    """ARP 快取很久才清：MAC 表三天沒看過這個 MAC → 設備早就不在了，不建。"""
    db_session.autoflush = False
    inst, dev, _ = await _setup(db_session)
    db_session.add_all([
        _fdb(inst, dev, "00:00:5e:00:53:31", age=timedelta(days=3)),   # 很久以前
        _fdb(inst, dev, "00:00:5e:00:53:32"),                           # 剛剛
    ])
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.31", "00005e005331"), ("198.51.100.32", "00005e005332"),
                       ("198.51.100.33", "00005e005333")])                # 完全沒在 MAC 表
    stats = await _sync(db_session, inst)
    assert set(await _ips(db_session)) == {"198.51.100.32"}
    assert stats["skipped"]["no_recent_fdb"] == 2


async def test_mac_table_check_can_be_turned_off(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, _dev, _ = await _setup(db_session, require_fdb=False)
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.33", "00005e005333")])
    await _sync(db_session, inst)
    assert set(await _ips(db_session)) == {"198.51.100.33"}


async def test_mikrotik_mac_table_counts_too(db_session, monkeypatch) -> None:
    """MikroTik 的 FDB 列沒有 LibreNMS 裝置（device_id 為空）：一樣算佐證。"""
    from app.models.device import Device
    db_session.autoflush = False
    inst, _dev, _ = await _setup(db_session)
    sw = Device(name="mt-sw", type="switch")
    db_session.add(sw)
    await db_session.flush()
    db_session.add(FDBEntry(mac="00:00:5e:00:53:34", switch_device_id=sw.id, port_name="ether3",
                            first_seen_at=NOW, last_seen_at=NOW))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.34", "00005e005334")])
    await _sync(db_session, inst)
    assert set(await _ips(db_session)) == {"198.51.100.34"}


async def test_noise_is_skipped(db_session, monkeypatch) -> None:
    """代理 ARP、廣播／群播 MAC、網路與廣播位址、同一輪一個 IP 兩個 MAC。"""
    db_session.autoflush = False
    inst, _dev, _ = await _setup(db_session, require_fdb=False)
    await db_session.commit()
    proxy = [(f"198.51.100.{i}", "00005e0053aa") for i in range(100, 100 + arp_autocreate.PROXY_ARP_MIN_IPS)]
    _api(monkeypatch, [
        *proxy,
        ("198.51.100.40", "ffffffffffff"),                 # 廣播
        ("198.51.100.41", "01005e000001"),                 # 群播
        ("198.51.100.0", "00005e005342"),                  # 網路位址
        ("198.51.100.255", "00005e005343"),                # 廣播位址
        ("198.51.100.44", "00005e005344"), ("198.51.100.44", "00005e005345"),   # 一個 IP 兩個 MAC
        ("198.51.100.46", "00005e005346"),                 # 正常
    ])
    stats = await _sync(db_session, inst)
    assert set(await _ips(db_session)) == {"198.51.100.46"}
    sk = stats["skipped"]
    assert sk["proxy_arp"] == arp_autocreate.PROXY_ARP_MIN_IPS
    assert sk["bad_mac"] == 2
    assert sk["not_host"] == 2
    assert sk["mac_conflict"] == 1


async def test_overlapping_subnets_are_not_guessed(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, _dev, _ = await _setup(db_session, require_fdb=False, cidrs=("198.51.100.0/24", "198.51.100.0/24"))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.50", "00005e005350"), ("192.0.2.50", "00005e005351")])
    stats = await _sync(db_session, inst)
    assert await _ips(db_session) == {}
    assert stats["skipped"]["no_subnet"] == 2          # 重疊歧義＋不在任何子網路


async def test_scope_resolves_the_overlap(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, _dev, subs = await _setup(db_session, require_fdb=False,
                                    cidrs=("198.51.100.0/24", "198.51.100.0/24"), scope=[1])
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.50", "00005e005350")])
    await _sync(db_session, inst)
    assert (await _ips(db_session))["198.51.100.50"].subnet_id == subs[1].id


async def test_released_addresses_and_dhcp_ranges_are_left_alone(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, _dev, (sub,) = await _setup(db_session, require_fdb=False)
    db_session.add_all([
        IPCooldown(subnet_id=sub.id, ip="198.51.100.60", released_at=NOW - timedelta(days=1),
                   until=NOW + timedelta(days=29)),
        DHCPPoolRange(source_type="kea_dhcp", source_id=uuid.uuid4(), start_ip="198.51.100.150",
                      end_ip="198.51.100.199", family=4),
    ])
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.60", "00005e005360"), ("198.51.100.160", "00005e005361"),
                       ("198.51.100.61", "00005e005362")])
    stats = await _sync(db_session, inst)
    assert set(await _ips(db_session)) == {"198.51.100.61"}
    assert stats["skipped"]["cooldown"] == 1
    assert stats["skipped"]["dhcp_range"] == 1

    inst.arp_create_skip_dhcp = False
    await db_session.commit()
    await _sync(db_session, inst)
    assert "198.51.100.160" in await _ips(db_session)


async def test_one_round_has_a_cap(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    monkeypatch.setattr(arp_autocreate, "MAX_PER_RUN", 2)
    inst, _dev, _ = await _setup(db_session, require_fdb=False)
    await db_session.commit()
    _api(monkeypatch, [(f"198.51.100.{i}", f"00005e0053{i:02x}") for i in range(70, 75)])
    stats = await _sync(db_session, inst)
    assert len(await _ips(db_session)) == 2
    assert stats["skipped"]["cap"] == 3
    await _sync(db_session, inst)
    assert len(await _ips(db_session)) == 4                 # 下一輪接著建


async def test_created_rows_are_not_online_on_arp_alone(db_session, monkeypatch) -> None:
    """建了不代表上線：LibreNMS 的 ARP 不會過期，預設不算上線證據。"""
    from app.services.evidence import default_liveness_sources
    db_session.autoflush = False
    inst, dev, _ = await _setup(db_session)
    db_session.add(_fdb(inst, dev, "00:00:5e:00:53:21"))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.21", "00005e005321")])
    await _sync(db_session, inst)
    assert "arp" not in default_liveness_sources()
    from unittest.mock import patch

    async def _cfg(_s):
        return {"sources": default_liveness_sources(), "minutes": 30}
    with patch("app.services.system_config.get_liveness_config", _cfg):
        await lib.recompute_effective_status(db_session)
    await db_session.commit()
    row = (await _ips(db_session))["198.51.100.21"]
    await db_session.refresh(row)
    assert not (row.effective_status or "").startswith("online")


async def test_summary_reports_created_and_skipped(db_session, monkeypatch) -> None:
    db_session.autoflush = False
    inst, dev, _ = await _setup(db_session)
    db_session.add(_fdb(inst, dev, "00:00:5e:00:53:21"))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.21", "00005e005321"), ("198.51.100.22", "00005e005322")])
    inst.sync_devices = False
    inst.sync_fdb = False
    inst.sync_vlans = False
    inst.sync_links = False
    inst.use_for_status = False
    await db_session.commit()
    out = (await lib.sync_instance(db_session, inst)).to_dict()
    assert out["arp"]["ips_created"] == 1
    assert out["arp"]["create_skipped"] == {"no_recent_fdb": 1}


def test_subnet_index_agrees_with_the_linear_rule() -> None:
    """大站台用索引查落點子網路；規則必須與逐一比對完全相同（最精確優先、同長度多個＝不建）。"""
    a, b, c, d = (uuid.uuid4() for _ in range(4))
    nets = sorted([
        (ipaddress.ip_network("10.0.0.0/8"), a), (ipaddress.ip_network("10.1.1.0/24"), b),
        (ipaddress.ip_network("10.2.0.0/16"), c), (ipaddress.ip_network("10.2.0.0/16"), d),
        (ipaddress.ip_network("2001:db8::/48"), a),
    ], key=lambda x: x[0].prefixlen, reverse=True)
    idx = subnet_index(nets)
    for s in ("10.1.1.9", "10.9.9.9", "10.2.3.4", "192.0.2.1", "2001:db8::5", "2001:db9::1"):
        aip = ipaddress.ip_address(s)
        assert idx.pick(aip) == pick_subnet_for_ip(nets, aip), s


@pytest.mark.parametrize("field", ["auto_create_from_arp", "arp_create_require_fdb", "arp_create_skip_dhcp"])
async def test_api_round_trip(client, auth_headers, db_session, field) -> None:
    inst, _dev, _ = await _setup(db_session, on=False)
    await db_session.commit()
    cur = getattr(inst, field)
    r = await client.patch(f"/api/v1/librenms/instances/{inst.id}", headers=auth_headers, json={field: not cur})
    assert r.status_code == 200, r.text
    assert r.json()[field] is (not cur)
    got = (await client.get("/api/v1/librenms/instances", headers=auth_headers)).json()
    rows = got["items"] if isinstance(got, dict) else got
    assert next(x for x in rows if x["id"] == str(inst.id))[field] is (not cur)
    assert (await db_session.execute(select(func.count()).select_from(IPAddress))).scalar_one() == 0


async def test_skip_reasons_only_count_unregistered_addresses(db_session, monkeypatch) -> None:
    """摘要講的是「IPAM 沒有、卻沒建」的那些：已登記的位址就算一 IP 多 MAC，也不算進略過原因
    （prod 模擬時 48 筆「一 IP 多 MAC」大多是已登記的位址，數字對管理員沒有意義）。"""
    db_session.autoflush = False
    inst, _dev, (sub,) = await _setup(db_session, require_fdb=False)
    db_session.add(IPAddress(subnet_id=sub.id, ip="198.51.100.80"))
    await db_session.commit()
    _api(monkeypatch, [("198.51.100.80", "00005e005380"), ("198.51.100.80", "00005e005381"),
                       ("198.51.100.81", "00005e005382"), ("198.51.100.81", "00005e005383")])
    stats = await _sync(db_session, inst)
    assert stats["skipped"] == {"mac_conflict": 1}          # 只有沒登記的 .81
