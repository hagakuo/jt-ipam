"""主機名稱的逐來源實例目擊與清除（2026-09-26 稽核）。

使用者回報：198.51.100.139 換了主機，DNS 記錄已在 DNS 伺服器刪除、手動同步過，仍顯示舊名
old-host。查下去是整類問題 —— 16 個來源的主機名稱**沒有一個會在上游不再回報時清掉**。
這裡驗核心元件 HostnameRun 的每一條規則：完整才清、多台不互刪、改名要生效、斷路器、舊資料的認領。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.ip_hostname import IPHostnameObservation, IPHostnameReport
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import hostname_reports as hr
from app.services.hostname import apply_observation
from sqlalchemy import select


async def _ips(db, n: int = 1) -> list[IPAddress]:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    out = []
    for i in range(n):
        ip = IPAddress(subnet_id=sub.id, ip=f"198.51.100.{i + 1}")
        db.add(ip)
        out.append(ip)
    await db.flush()
    return out


async def _obs(db, ip: IPAddress, source: str) -> str | None:
    return (await db.execute(select(IPHostnameObservation.hostname).where(
        IPHostnameObservation.ip_id == ip.id, IPHostnameObservation.source == source))).scalar_one_or_none()


async def _run(db, source, origin, reports: dict, *, complete=True, peers=1):
    run = hr.HostnameRun(db, source=source, origin=origin, peers=peers)
    for ip, name in reports.items():
        run.report(ip, name)
    return run, await run.finish(complete=complete)


async def test_reported_names_become_the_observation_and_the_hostname(db_session) -> None:
    (ip,) = await _ips(db_session)
    await _run(db_session, "dns", "dns:a", {ip: "web01.example.com"})
    assert await _obs(db_session, ip, "dns") == "web01.example.com"
    assert ip.hostname == "web01.example.com"


async def test_a_name_the_upstream_stopped_reporting_is_removed_on_a_complete_run(db_session) -> None:
    """就是 .139 那一筆：DNS 記錄刪掉、完整同步一輪 → 舊名要消失，改回其他來源的名字。"""
    (ip,) = await _ips(db_session)
    await apply_observation(db_session, ip=ip, source="manual", hostname="new-host")
    await _run(db_session, "dns", "dns:a", {ip: "old-host.example.com"})
    await _run(db_session, "dns", "dns:a", {})
    assert await _obs(db_session, ip, "dns") is None
    assert ip.hostname == "new-host"


async def test_an_incomplete_run_removes_nothing(db_session) -> None:
    """某個 zone／端點失敗時沒看到，不代表上游刪了 —— 不可以清。"""
    (ip,) = await _ips(db_session)
    await _run(db_session, "opnsense", "opnsense:a", {ip: "host-a"})
    await _run(db_session, "opnsense", "opnsense:a", {}, complete=False)
    assert await _obs(db_session, ip, "opnsense") == "host-a"


async def test_one_instance_does_not_remove_what_another_still_reports(db_session) -> None:
    """兩台同類整合共用一個來源：A 不再回報，B 還在 → 名稱改用 B 的，不可以整筆刪掉。"""
    (ip,) = await _ips(db_session)
    await _run(db_session, "opnsense", "opnsense:a", {ip: "alpha"}, peers=2)
    await _run(db_session, "opnsense", "opnsense:b", {ip: "bravo"}, peers=2)
    await _run(db_session, "opnsense", "opnsense:a", {}, peers=2)
    assert await _obs(db_session, ip, "opnsense") == "bravo"
    await _run(db_session, "opnsense", "opnsense:b", {}, peers=2)
    assert await _obs(db_session, ip, "opnsense") is None


async def test_a_rename_to_a_later_name_takes_effect(db_session) -> None:
    """以前的 tiebreak_min：同一個實體改名成字典序較大的名字，永遠不會生效。"""
    (ip,) = await _ips(db_session)
    await _run(db_session, "proxmox", "proxmox:c1", {ip: "aaa-old"})
    await _run(db_session, "proxmox", "proxmox:c1", {ip: "web01"})
    assert await _obs(db_session, ip, "proxmox") == "web01"


async def test_several_names_in_one_run_pick_the_same_one_every_time(db_session) -> None:
    """同一輪有兩個實體報同一個 IP（兩台 guest 報同一個位址）：取固定的一個，不要每輪翻來翻去。"""
    (ip,) = await _ips(db_session)
    for _ in range(3):
        run = hr.HostnameRun(db_session, source="proxmox", origin="proxmox:c1")
        run.report(ip, "zeta")
        run.report(ip, "alpha")
        await run.finish(complete=True)
        assert await _obs(db_session, ip, "proxmox") == "alpha"


async def test_the_breaker_stops_a_mass_removal(db_session) -> None:
    """一次要清掉一大半：多半是 API 權限被收、回傳不完整，而不是真的刪了那麼多 —— 不清並講出來。"""
    ips = await _ips(db_session, 30)
    await _run(db_session, "wazuh", "wazuh:a", {ip: f"h{i}" for i, ip in enumerate(ips)})
    run, summary = await _run(db_session, "wazuh", "wazuh:a", {ips[0]: "h0"})
    assert summary["breaker"], "應該被斷路器擋下"
    assert await _obs(db_session, ips[29], "wazuh") == "h29"


async def test_an_empty_complete_read_does_not_wipe_a_source(db_session) -> None:
    ips = await _ips(db_session, 6)
    await _run(db_session, "zabbix", "zabbix:a", {ip: f"z{i}" for i, ip in enumerate(ips)})
    _, summary = await _run(db_session, "zabbix", "zabbix:a", {})
    assert summary["breaker"]
    assert await _obs(db_session, ips[0], "zabbix") == "z0"


async def test_an_explicit_empty_name_clears_this_instance_even_when_incomplete(db_session) -> None:
    """上游還回報這個 IP、只是名稱變成空的（例如 pfSense ARP 顯示 ?）→ 這台的那一筆要清。"""
    (ip,) = await _ips(db_session)
    await _run(db_session, "pfsense", "pfsense:a:arp", {ip: "old.example.com"})
    await _run(db_session, "pfsense", "pfsense:a:arp", {ip: None}, complete=False)
    assert await _obs(db_session, ip, "pfsense") is None


async def test_manual_names_are_never_touched(db_session) -> None:
    (ip,) = await _ips(db_session)
    await apply_observation(db_session, ip=ip, source="manual", hostname="my-name")
    await _run(db_session, "dns", "dns:a", {})
    assert await _obs(db_session, ip, "manual") == "my-name"


async def _legacy(db, ip, source, name, *, age=timedelta(0)):
    await apply_observation(db, ip=ip, source=source, hostname=name)
    db.add(IPHostnameReport(ip_id=ip.id, source=source, origin=hr.LEGACY_ORIGIN, hostname=name,
                            last_seen_at=datetime.now(UTC) - age))
    await db.flush()


async def test_legacy_rows_are_claimed_by_a_real_instance(db_session) -> None:
    """升級前的舊觀測：真實同步看到就認領，之後照一般規則處理。"""
    (ip,) = await _ips(db_session)
    await _legacy(db_session, ip, "dns", "old.example.com")
    await _run(db_session, "dns", "dns:a", {ip: "new.example.com"}, peers=2)
    assert await _obs(db_session, ip, "dns") == "new.example.com"
    left = (await db_session.execute(select(IPHostnameReport.origin).where(
        IPHostnameReport.ip_id == ip.id))).scalars().all()
    assert left == ["dns:a"], "認領後舊的那筆要刪掉"


async def test_unclaimed_legacy_rows_go_at_once_when_there_is_only_one_instance(db_session) -> None:
    """只有一台 DNS：它完整同步一輪卻沒看到 → 沒有別台可能還在回報，舊資料可以立刻清（.139 的情況）。"""
    (ip,) = await _ips(db_session)
    await _legacy(db_session, ip, "dns", "old-host.example.com")
    await _run(db_session, "dns", "dns:a", {}, peers=1)
    assert await _obs(db_session, ip, "dns") is None


async def test_unclaimed_legacy_rows_wait_for_other_instances(db_session) -> None:
    """有兩台：沒被這台認領，可能是另一台的 —— 等寬限期（24 小時）過了、仍沒人認領才清。"""
    (ip,) = await _ips(db_session)
    await _legacy(db_session, ip, "opnsense", "lease-name")
    await _run(db_session, "opnsense", "opnsense:a", {}, peers=2)
    assert await _obs(db_session, ip, "opnsense") == "lease-name"
    (ip2,) = await _ips(db_session)
    await _legacy(db_session, ip2, "opnsense", "stale-name", age=hr.LEGACY_GRACE + timedelta(minutes=1))
    await _run(db_session, "opnsense", "opnsense:a", {}, peers=2)
    assert await _obs(db_session, ip2, "opnsense") is None


@pytest.mark.parametrize("source", ["mikrotik"])
async def test_new_sources_are_recorded_as_themselves_not_as_manual(db_session, source) -> None:
    """MikroTik 以前不在來源清單裡，被當成「手動」寫入，蓋過使用者真正填的值。"""
    (ip,) = await _ips(db_session)
    await apply_observation(db_session, ip=ip, source="manual", hostname="typed-by-user")
    await _run(db_session, source, f"{source}:a", {ip: "lease-name"})
    assert await _obs(db_session, ip, "manual") == "typed-by-user"
    assert await _obs(db_session, ip, source) == "lease-name"


async def test_an_unknown_source_is_refused_not_turned_into_manual(db_session) -> None:
    (ip,) = await _ips(db_session)
    await apply_observation(db_session, ip=ip, source="manual", hostname="typed-by-user")
    await apply_observation(db_session, ip=ip, source="not-a-source", hostname="junk")
    assert await _obs(db_session, ip, "manual") == "typed-by-user"


async def test_a_held_name_survives_a_complete_run(db_session) -> None:
    """PVE：VM 還在、只是這一輪 guest agent 沒回應（不知道 IP）→ 它的名稱不可以被清；
    被刪掉的 VM 不在清單裡、不會被 hold，名稱照常清掉。"""
    a, b = await _ips(db_session, 2)
    await _run(db_session, "proxmox", "proxmox:c1", {a: "vm-alive", b: "vm-deleted"})
    run = hr.HostnameRun(db_session, source="proxmox", origin="proxmox:c1")
    run.hold("vm-alive")
    await run.finish(complete=True)
    assert await _obs(db_session, a, "proxmox") == "vm-alive"
    assert await _obs(db_session, b, "proxmox") is None
