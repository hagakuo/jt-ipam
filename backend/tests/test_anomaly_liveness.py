"""異常偵測：每一列 IP 附上「現在」的上線狀態，並保留上次的結果（2026-10-01 使用者要求）。

1. 「異常偵測每一頁有 IP 清單的都要順便顯示其上線狀態」—— 未授權 IP、IP 衝突、失聯 IP…
   狀態要在**顯示當下**算（`attach_liveness`），不是偵測當時的快照：保留下來的結果可能是
   一個小時前跑的，那時離線的機器現在可能回來了。
2. 「點去探測再按返回，結果被清除又要重按一次」—— 結果存起來（手動與排程都存），
   進頁面先拿上次的結果（`GET /anomalies/last`）。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.librenms import ARPEntry
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.anomaly import attach_liveness, detect_unauthorized_ips


async def _subnet(db, cidr: str = "198.51.100.0/24", *, scan: bool = True) -> Subnet:
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr, scan_enabled=scan, anomaly_enabled=True)
    db.add(sub)
    await db.flush()
    return sub


async def test_registered_ip_rows_get_the_records_last_seen(db_session) -> None:
    sub = await _subnet(db_session, scan=False)
    seen = datetime.now(UTC) - timedelta(minutes=3)
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.10", last_seen_scanner=seen,
                   arp_seen={"arp:opnsense": seen.isoformat()})
    db_session.add(ip)
    await db_session.commit()

    out = await attach_liveness(db_session, {
        "ghost_ips": [{"ip": "198.51.100.10", "ip_address_id": str(ip.id)}],
        "ip_conflicts": [{"ip": "198.51.100.10"}],
    })
    live = out["ghost_ips"][0]["live"]
    assert live["registered"] is True
    assert datetime.fromisoformat(live["last_seen_scanner"]) == seen
    assert live["arp_seen"] == {"arp:opnsense": seen.isoformat()}
    assert live["subnet_scan_enabled"] is False          # 沒開掃描的子網路：前端顯示「未知」而不是「離線」
    assert out["ip_conflicts"][0]["live"]["registered"] is True      # 只有 IP 文字也對得到


async def test_unregistered_ip_uses_arp_observations_per_source(db_session) -> None:
    """未授權 IP 在 IPAM 沒有記錄：上線依據是各來源的 ARP 觀測，來源要分開（判定規則才一樣）。"""
    await _subnet(db_session)
    now = datetime.now(UTC)
    t_lnms, t_fw, t_scan = now - timedelta(hours=5), now - timedelta(minutes=8), now - timedelta(minutes=2)
    db_session.add_all([
        ARPEntry(ip="198.51.100.50", mac="00:00:5e:00:53:50", source="librenms", last_seen_at=t_lnms),
        ARPEntry(ip="198.51.100.50", mac="00:00:5e:00:53:50", source="arp:opnsense", last_seen_at=t_fw),
        ARPEntry(ip="198.51.100.50", mac="02:00:5e:00:53:51", source="scanner", last_seen_at=t_scan),
    ])
    await db_session.commit()

    out = await attach_liveness(db_session, {"unauthorized_ips": [{"ip": "198.51.100.50"}],
                                             "rogue_dhcp": [{"server_ip": "203.0.113.99"}]})
    live = out["unauthorized_ips"][0]["live"]
    assert live["registered"] is False
    assert datetime.fromisoformat(live["last_seen_arp"]) == t_lnms
    assert datetime.fromisoformat(live["last_seen_scanner"]) == t_scan
    assert set(live["arp_seen"]) == {"arp:opnsense"}
    assert out["rogue_dhcp"][0]["live"] is None           # 哪裡都沒看過：不猜


async def test_list_rows_and_dns_values(db_session) -> None:
    sub = await _subnet(db_session)
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.20", last_seen_librenms=datetime.now(UTC))
    db_session.add(ip)
    await db_session.commit()
    out = await attach_liveness(db_session, {
        "mac_drifts": [{"mac": "00:00:5e:00:53:20", "ips": [{"ip": "198.51.100.20", "ip_address_id": str(ip.id)}]}],
        "dangling_dns": [{"name": "a.example.com", "value": "198.51.100.20", "type": "A"},
                         {"name": "b.example.com", "value": "target.example.com", "type": "CNAME"}],
    })
    assert out["mac_drifts"][0]["live_ips"]["198.51.100.20"]["registered"] is True
    assert out["dangling_dns"][0]["live"]["registered"] is True
    assert "live" not in out["dangling_dns"][1]            # 不是位址的值不附狀態


async def test_unauthorized_rows_carry_their_macs(db_session) -> None:
    """未授權 IP 只有一個位址看不出是誰：附上 ARP 看到的 MAC（廠商、隨機 MAC、誰看到的、最後時間）。"""
    await _subnet(db_session)
    now = datetime.now(UTC)
    db_session.add_all([
        ARPEntry(ip="198.51.100.60", mac="00:00:5e:00:53:60", source="librenms", last_seen_at=now),
        ARPEntry(ip="198.51.100.60", mac="02:00:5e:00:53:61", source="scanner",
                 last_seen_at=now - timedelta(hours=1)),
    ])
    await db_session.commit()
    rows = await detect_unauthorized_ips(db_session)
    row = next(r for r in rows if r["ip"] == "198.51.100.60")
    macs = {m["mac"]: m for m in row["macs"]}
    assert set(macs) == {"00:00:5e:00:53:60", "02:00:5e:00:53:61"}
    assert macs["02:00:5e:00:53:61"]["local"] is True       # 隨機（本地管理）位址
    assert macs["00:00:5e:00:53:60"]["sources"] == ["librenms"]
    assert row["macs"][0]["mac"] == "00:00:5e:00:53:60"     # 最近看到的排前面
    assert row["last_seen_at"] is not None


async def test_last_report_survives_leaving_the_page(client, auth_headers, db_session) -> None:
    empty = await client.get("/api/v1/anomalies/last", headers=auth_headers)
    assert empty.status_code == 200, empty.text
    assert empty.json()["report"] is None

    sub = await _subnet(db_session)
    db_session.add(ARPEntry(ip="198.51.100.70", mac="00:00:5e:00:53:70", source="scanner",
                            last_seen_at=datetime.now(UTC) - timedelta(minutes=1)))
    await db_session.commit()
    scan = await client.post("/api/v1/anomalies/scan", headers=auth_headers)
    assert scan.status_code == 200, scan.text
    row = next(r for r in scan.json()["unauthorized_ips"] if r["ip"] == "198.51.100.70")
    assert row["live"]["last_seen_scanner"] is not None

    # 之後這個位址登記進 IPAM、並且被掃描看到 —— 上次的結果照舊，狀態是「現在」的
    seen = datetime.now(UTC)
    db_session.add(IPAddress(subnet_id=sub.id, ip="198.51.100.70", last_seen_librenms=seen))
    await db_session.commit()
    last = await client.get("/api/v1/anomalies/last", headers=auth_headers)
    body = last.json()
    assert body["trigger"] == "manual"
    assert body["at"] is not None
    row = next(r for r in body["report"]["unauthorized_ips"] if r["ip"] == "198.51.100.70")
    assert row["live"]["registered"] is True
    assert datetime.fromisoformat(row["live"]["last_seen_librenms"]) == seen


async def test_scheduled_runs_are_kept_too(client, auth_headers, db_session) -> None:
    from app.services.anomaly import run_scheduled
    await run_scheduled(db_session)
    body = (await client.get("/api/v1/anomalies/last", headers=auth_headers)).json()
    assert body["trigger"] == "schedule"
    assert isinstance(body["report"], dict)


async def test_last_report_is_admin_only(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"v-{uuid.uuid4().hex[:6]}", email=f"v-{uuid.uuid4().hex[:6]}@test.local",
             display_name="V", password_hash=hash_password("TestPassword2026!"), auth_provider="local",
             is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.commit()
    r = await client.get("/api/v1/anomalies/last",
                         headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 403
