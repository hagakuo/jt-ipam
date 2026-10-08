"""IP 衝突偵測要看得到掃描代理與防火牆看到的 MAC —— GitHub issue #41。

回報者的網路裡兩台複製出來的 VM 搶同一個固定 IP，`ip_change_log` 裡
那個 IP 五天記了 205 次 MAC 來回切換，IP 衝突偵測卻一次都沒報：偵測器只讀 `arp_entries`，
而那張表**只有 LibreNMS 同步會寫**。沒接 LibreNMS 的站台，偵測器永遠沒有資料，AI 助理
還把「表是空的」講成「沒有任何衝突」。

這裡守四件事：
1. 掃描代理、防火牆 ARP 表看到的 IP／MAC 會存成偵測依據 —— **不管**它能不能依來源優先序
   覆寫 IP 記錄上的 MAC（被擋下的那個 MAC 正是衝突的另一方）。
2. 依據帶子網路：重疊網段（兩個單位各有一個 10.9.0.5）不可以互相判成衝突。
3. 掃描代理每輪只看得到一個 MAC，掃描間隔比 1 小時長就湊不到兩個 → 另外看 MAC 在同樣兩個
   位址之間來回切換（A→B→A→B）。換一次網卡（A→B）不算。
4. AI 工具要講出偵測範圍與有沒有資料，「沒有依據」不能講成「沒有衝突」。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.librenms import ARPEntry
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet

# RFC 7042 的文件用 MAC 範圍（00-00-5E-00-53-00～FF），不是任何一張真的網卡
MAC_A = "00:00:5e:00:53:01"
MAC_B = "00:00:5e:00:53:02"


async def _subnet(session, cidr: str = "198.51.100.0/24", **kw) -> Subnet:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr, **kw)
    session.add(sub)
    await session.flush()
    return sub


async def _ip(session, sub: Subnet, addr: str, **kw) -> IPAddress:
    ip = IPAddress(subnet_id=sub.id, ip=addr, **kw)
    session.add(ip)
    await session.flush()
    return ip


async def _rows(session, ip: str) -> list[ARPEntry]:
    return list((await session.execute(
        select(ARPEntry).where(ARPEntry.ip == ip))).scalars().all())


# ── 1. 寫入 ───────────────────────────────────────────────────────────────

async def test_repeated_observation_refreshes_instead_of_duplicating(db_session) -> None:
    from app.services.arp_evidence import record_arp_observation

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.30")
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    await record_arp_observation(db_session, ip=ipa, mac=MAC_A, source="scanner", seen_at=t0)
    await record_arp_observation(db_session, ip=ipa, mac=MAC_A.replace(":", ""), source="scanner")
    rows = await _rows(db_session, "198.51.100.30")
    assert len(rows) == 1, "同一個 IP／MAC／來源再看到一次要更新時間，不是再加一筆"
    assert rows[0].source == "scanner"
    assert rows[0].subnet_id == sub.id
    assert rows[0].last_seen_at > t0 + timedelta(minutes=29)


async def test_placeholder_macs_are_not_evidence(db_session) -> None:
    """ARP 表裡的未完成項目（全 0）與廣播位址不是任何一台機器。"""
    from app.services.arp_evidence import record_arp_observation

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.31")
    for bad in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "incomplete", ""):
        await record_arp_observation(db_session, ip=ipa, mac=bad, source="scanner")
    assert await _rows(db_session, "198.51.100.31") == []


async def _report(client, monkeypatch, agent, ip: str, mac: str):
    from app.api.v1.endpoints import scan_agents as ep

    async def _fake_agent(session, key):   # noqa: ANN001
        return (await session.execute(
            select(ScanAgent).where(ScanAgent.id == agent.id))).scalar_one()

    monkeypatch.setattr(ep, "_agent_from_key", _fake_agent)
    r = await client.post("/api/v1/scan-agents/report", headers={"X-Agent-Key": "x"},
                          json={"results": [{"ip": ip, "alive": True, "mac": mac}]})
    assert r.status_code == 200, r.text


@pytest.mark.anyio
async def test_scanner_report_feeds_the_conflict_detector(db_session, client, monkeypatch) -> None:
    """回報者的情境：只有掃描代理，兩台機器輪流回應同一個 IP。"""
    from app.services.anomaly import detect_ip_conflicts

    sub = await _subnet(db_session, scan_enabled=True)
    agent = ScanAgent(name=f"a-{uuid.uuid4().hex[:6]}")
    db_session.add(agent)
    await db_session.flush()
    sub.scan_agent_id = agent.id
    await _ip(db_session, sub, "198.51.100.88")
    await db_session.commit()

    await _report(client, monkeypatch, agent, "198.51.100.88", MAC_A)
    await _report(client, monkeypatch, agent, "198.51.100.88", MAC_B)

    rows = [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.88"]
    assert len(rows) == 1, "兩個 MAC 都是掃描代理在一小時內看到的，應該判成衝突"
    macs = {m["mac"]: m for m in rows[0]["macs"]}
    assert set(macs) == {MAC_A, MAC_B}
    assert macs[MAC_A]["sources"] == ["scanner"], "要看得出是誰看到的"
    assert "arp" in rows[0]["evidence"]
    assert rows[0]["subnet_id"] == str(sub.id)


@pytest.mark.anyio
async def test_evidence_is_kept_when_source_priority_rejects_the_mac(
    db_session, client, monkeypatch,
) -> None:
    """IP 記錄上的 MAC 是手動填的（優先序最高），掃描代理看到的另一個 MAC 不會覆寫它 ——
    但那個被擋下來的 MAC 正是衝突的另一方，偵測依據一定要留下來。"""
    sub = await _subnet(db_session, scan_enabled=True)
    agent = ScanAgent(name=f"a-{uuid.uuid4().hex[:6]}")
    db_session.add(agent)
    await db_session.flush()
    sub.scan_agent_id = agent.id
    ipa = await _ip(db_session, sub, "198.51.100.189", mac=MAC_A, mac_source="manual")
    await db_session.commit()

    await _report(client, monkeypatch, agent, "198.51.100.189", MAC_B)

    await db_session.refresh(ipa)
    assert str(ipa.mac) == MAC_A, "手動填的 MAC 不該被掃描結果蓋掉（前提）"
    got = {str(r.mac) for r in await _rows(db_session, "198.51.100.189")}
    assert MAC_B in got


async def test_firewall_arp_is_evidence_but_leases_and_static_entries_are_not(db_session) -> None:
    """ARP 表的動態項目＝有機器在用這個 IP；DHCP 租約只是「曾經發給誰」、靜態 ARP 是設定值，
    拿來判衝突會把換過網卡、租約重發的正常情況報成衝突。"""
    from app.services.fw_sightings import SightingBatch

    sub = await _subnet(db_session)
    await _ip(db_session, sub, "198.51.100.40")
    batch = SightingBatch(db_session, source="opnsense")
    batch.add("198.51.100.40", evidence="arp:opnsense", mac=MAC_A)
    batch.add("198.51.100.40", evidence="lease:opnsense", mac=MAC_B)
    batch.add("198.51.100.40", evidence="arp:opnsense", mac="02:00:00:00:00:99", permanent=True)
    await batch.flush()
    rows = await _rows(db_session, "198.51.100.40")
    assert [(str(r.mac), r.source) for r in rows] == [(MAC_A, "arp:opnsense")]


# ── 2. 範圍 ───────────────────────────────────────────────────────────────

async def test_overlapping_subnets_do_not_conflict_with_each_other(db_session) -> None:
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    s1 = await _subnet(db_session, "10.9.0.0/24")
    s2 = await _subnet(db_session, "10.9.0.0/24")      # 另一個單位的同一段
    a = await _ip(db_session, s1, "10.9.0.5")
    b = await _ip(db_session, s2, "10.9.0.5")
    await record_arp_observation(db_session, ip=a, mac=MAC_A, source="scanner")
    await record_arp_observation(db_session, ip=b, mac=MAC_B, source="scanner")
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "10.9.0.5"], \
        "兩個網路各自一台，不是衝突"

    await record_arp_observation(db_session, ip=a, mac=MAC_B, source="scanner")
    rows = [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "10.9.0.5"]
    assert len(rows) == 1 and rows[0]["subnet_id"] == str(s1.id)


async def test_librenms_and_scanner_evidence_are_compared_when_the_ip_is_unambiguous(
    db_session,
) -> None:
    """LibreNMS 的 ARP 沒有子網路。IP 只落在一個子網路時就能跟掃描代理看到的比。"""
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    sub = await _subnet(db_session, "203.0.113.0/24")
    ipa = await _ip(db_session, sub, "203.0.113.9")
    db_session.add(ARPEntry(ip="203.0.113.9", mac=MAC_A, source="librenms",
                            last_seen_at=datetime.now(UTC)))
    await db_session.flush()
    await record_arp_observation(db_session, ip=ipa, mac=MAC_B, source="scanner")
    rows = [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "203.0.113.9"]
    assert len(rows) == 1
    assert {s for m in rows[0]["macs"] for s in m["sources"]} == {"librenms", "scanner"}


async def test_an_observation_older_than_the_window_is_not_a_current_conflict(db_session) -> None:
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.50")
    await record_arp_observation(db_session, ip=ipa, mac=MAC_A, source="scanner",
                                 seen_at=datetime.now(UTC) - timedelta(hours=3))
    await record_arp_observation(db_session, ip=ipa, mac=MAC_B, source="scanner")
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.50"]


# ── 2b. 同一台機器的兩張網卡（ARP flux）────────────────────────────────────
# Linux 預設會用任何一張網卡回答本機任何一個 IP 的 ARP（arp_ignore=0）。兩個網段在同一個廣播
# 網域時，一台雙網卡主機的同一個位址會同時被兩張網卡回答 —— 看起來像兩個 MAC 在搶一個 IP，
# 其實是同一台機器（正式環境 2026-10-04：SuperMicro 主機板網卡與 HP 擴充網卡）。兩個 MAC 都
# 屬於同一個裝置（登記在它的其他 IP 上、或是它的埠）時不算衝突；多出第三台才算。

async def _device(session, name: str = "dual-nic-host", port_macs: tuple[str, ...] = ()):
    from app.models.device import Device
    from app.models.physical import DevicePort

    dev = Device(name=f"{name}-{uuid.uuid4().hex[:6]}")
    session.add(dev)
    await session.flush()
    for i, mac in enumerate(port_macs):
        session.add(DevicePort(device_id=dev.id, name=f"eth{i}", mac_address=mac))
    await session.flush()
    return dev


async def test_one_machine_answering_on_two_nics_is_not_a_conflict(db_session) -> None:
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    dev = await _device(db_session)
    s1 = await _subnet(db_session, "198.51.100.0/24")
    s2 = await _subnet(db_session, "203.0.113.0/24")
    a = await _ip(db_session, s1, "198.51.100.111", mac=MAC_A, device_id=dev.id)
    await _ip(db_session, s2, "203.0.113.111", mac=MAC_B, device_id=dev.id)
    await record_arp_observation(db_session, ip=a, mac=MAC_A, source="scanner")
    await record_arp_observation(db_session, ip=a, mac=MAC_B, source="arp:opnsense")
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.111"], \
        "兩個 MAC 都是同一個裝置的網卡，不是兩台機器在搶"


async def test_a_port_mac_of_the_same_device_is_the_same_machine(db_session) -> None:
    """另一張網卡不一定登記成 IP；從 LibreNMS 匯入的裝置埠也帶 MAC。"""
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    dev = await _device(db_session, port_macs=(MAC_B.upper(),))
    sub = await _subnet(db_session)
    a = await _ip(db_session, sub, "198.51.100.112", mac=MAC_A, device_id=dev.id)
    await record_arp_observation(db_session, ip=a, mac=MAC_A, source="scanner")
    await record_arp_observation(db_session, ip=a, mac=MAC_B, source="scanner")
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.112"]


async def test_a_mac_of_another_device_is_still_a_conflict(db_session) -> None:
    """另一個 MAC 登記在別台裝置上：那正是搶走這個 IP 的機器，要報。"""
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    d1, d2 = await _device(db_session, "one"), await _device(db_session, "two")
    s1 = await _subnet(db_session, "198.51.100.0/24")
    s2 = await _subnet(db_session, "203.0.113.0/24")
    a = await _ip(db_session, s1, "198.51.100.113", mac=MAC_A, device_id=d1.id)
    await _ip(db_session, s2, "203.0.113.113", mac=MAC_B, device_id=d2.id)
    await record_arp_observation(db_session, ip=a, mac=MAC_A, source="scanner")
    await record_arp_observation(db_session, ip=a, mac=MAC_B, source="scanner")
    assert len([r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.113"]) == 1


async def test_a_third_machine_besides_the_two_nics_is_still_a_conflict(db_session) -> None:
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    dev = await _device(db_session, port_macs=(MAC_B,))
    sub = await _subnet(db_session)
    a = await _ip(db_session, sub, "198.51.100.114", mac=MAC_A, device_id=dev.id)
    for mac in (MAC_A, MAC_B, "00:00:5e:00:53:03"):
        await record_arp_observation(db_session, ip=a, mac=mac, source="scanner")
    rows = [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.114"]
    assert len(rows) == 1
    assert len(rows[0]["macs"]) == 3


async def test_an_ip_without_a_device_keeps_the_old_rule(db_session) -> None:
    from app.services.anomaly import detect_ip_conflicts
    from app.services.arp_evidence import record_arp_observation

    sub = await _subnet(db_session)
    a = await _ip(db_session, sub, "198.51.100.115", mac=MAC_A)
    await record_arp_observation(db_session, ip=a, mac=MAC_A, source="scanner")
    await record_arp_observation(db_session, ip=a, mac=MAC_B, source="scanner")
    assert len([r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.115"]) == 1


# ── 3. MAC 來回切換 ───────────────────────────────────────────────────────

async def _changes(session, ipa: IPAddress, seq: list[tuple[str, str]], *, hours_ago: float) -> None:
    now = datetime.now(UTC)
    step = hours_ago / max(len(seq), 1)
    for i, (old, new) in enumerate(seq):
        session.add(IPChangeLog(
            ip_id=ipa.id, subnet_id=ipa.subnet_id, ip_text=str(ipa.ip).split("/")[0],
            event_type="mac_changed", field="mac", old_value=old, new_value=new,
            source="scanner", created_at=now - timedelta(hours=hours_ago - i * step)))
    await session.flush()


async def test_mac_flipping_between_two_addresses_is_a_conflict(db_session) -> None:
    """掃描間隔兩小時：ARP 的一小時窗永遠只湊得到一個 MAC，但異動記錄看得出來回切換。"""
    from app.services.anomaly import detect_ip_conflicts

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.60")
    await _changes(db_session, ipa, [(MAC_A, MAC_B), (MAC_B, MAC_A), (MAC_A, MAC_B)], hours_ago=6)
    rows = [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.60"]
    assert len(rows) == 1
    assert rows[0]["evidence"] == ["mac_flip"]
    assert rows[0]["changes"] == 3
    assert {m["mac"] for m in rows[0]["macs"]} == {MAC_A, MAC_B}


async def test_flipping_between_two_nics_of_one_device_is_not_a_conflict(db_session) -> None:
    """ARP flux 也會讓 IP 記錄上的 MAC 在兩張網卡之間來回換（沒有手動釘住 MAC 時）。"""
    from app.services.anomaly import detect_ip_conflicts

    dev = await _device(db_session, port_macs=(MAC_A, MAC_B))
    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.61", device_id=dev.id)
    await _changes(db_session, ipa, [(MAC_A, MAC_B), (MAC_B, MAC_A), (MAC_A, MAC_B)], hours_ago=6)
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.61"]


@pytest.mark.parametrize("seq", [
    [(MAC_A, MAC_B)],                                        # 換了一次網卡
    [(MAC_A, MAC_B), (MAC_B, "02:00:00:00:00:03")],          # 連換兩次，沒有換回來
    [(MAC_A, MAC_B), (MAC_B, MAC_A)],                        # DHCP 租約重發回原主（只來回一次）
])
async def test_ordinary_mac_changes_are_not_flipping(db_session, seq) -> None:
    from app.services.anomaly import detect_ip_conflicts

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.61")
    await _changes(db_session, ipa, seq, hours_ago=6)
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.61"]


async def test_flipping_outside_the_window_is_history_not_a_current_conflict(db_session) -> None:
    from app.services.anomaly import detect_ip_conflicts

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.62")
    await _changes(db_session, ipa, [(MAC_A, MAC_B), (MAC_B, MAC_A), (MAC_A, MAC_B)], hours_ago=60)
    now = datetime.now(UTC)
    for row in (await db_session.execute(
            select(IPChangeLog).where(IPChangeLog.ip_id == ipa.id))).scalars():
        row.created_at = now - timedelta(hours=50)
    await db_session.flush()
    assert not [r for r in await detect_ip_conflicts(db_session) if r["ip"] == "198.51.100.62"]


# ── 4. AI 工具的措辭 ──────────────────────────────────────────────────────

async def test_ai_tool_says_when_there_was_no_evidence_to_judge(db_session) -> None:
    """表是空的 ≠ 沒有衝突。回報者的 AI 助理回「系統中沒有任何已記錄的 IP 衝突」，
    實際上是偵測器根本沒有資料可看。"""
    from app.mcp.tools import list_anomalies
    from app.models.user import User

    await db_session.execute(ARPEntry.__table__.delete())
    await db_session.execute(IPChangeLog.__table__.delete().where(
        IPChangeLog.event_type == "mac_changed"))
    await db_session.flush()
    admin = User(username=f"u-{uuid.uuid4().hex[:6]}", is_admin=True)
    out = await list_anomalies(db_session, admin, kind="ip_conflicts")
    assert out["total"] == 0
    cov = out["coverage"]["ip_conflicts"]
    assert cov["observations"] == 0
    assert cov["window_minutes"] == 60
    assert "no arp" in out["note"].lower() or "no evidence" in out["note"].lower()
    assert "cannot" in out["note"].lower(), "要叫模型說「無法判定」，不是「沒有衝突」"


async def test_ai_tool_reports_coverage_by_source(db_session) -> None:
    from app.mcp.tools import list_anomalies
    from app.models.user import User
    from app.services.arp_evidence import record_arp_observation

    sub = await _subnet(db_session)
    ipa = await _ip(db_session, sub, "198.51.100.70")
    await record_arp_observation(db_session, ip=ipa, mac=MAC_A, source="scanner")
    admin = User(username=f"u-{uuid.uuid4().hex[:6]}", is_admin=True)
    out = await list_anomalies(db_session, admin, kind="ip_conflicts")
    cov = out["coverage"]["ip_conflicts"]
    assert cov["observations"] >= 1
    assert cov["by_source"].get("scanner", 0) >= 1
