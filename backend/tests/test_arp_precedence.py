"""ARP/MAC 來源順序：停用的來源不得覆寫 MAC。"""

from __future__ import annotations

from typing import Any

from app.models.address import IPAddress
from app.services.arp_precedence import (
    consider_mac,
    get_arp_disabled,
    set_arp_precedence,
)


async def test_disabled_arp_source_does_not_overwrite(db_session):
    await set_arp_precedence(
        db_session,
        order=["manual", "scanner", "opnsense", "librenms"],
        disabled=["scanner"],
    )
    assert "scanner" in await get_arp_disabled(db_session)

    ip = IPAddress(ip="10.9.9.9")
    # 停用的來源（scanner）→ 不寫入
    changed = await consider_mac(db_session, ip=ip, mac="aa:bb:cc:dd:ee:01", source="scanner")
    assert changed is False
    assert ip.mac is None

    # 啟用的來源（opnsense）→ 可寫入
    changed2 = await consider_mac(db_session, ip=ip, mac="aa:bb:cc:dd:ee:02", source="opnsense")
    assert changed2 is True
    assert ip.mac == "aa:bb:cc:dd:ee:02"


async def test_manual_cannot_be_disabled(db_session):
    _, disabled = await set_arp_precedence(
        db_session, order=["manual", "scanner"], disabled=["manual", "scanner"],
    )
    assert "manual" not in disabled   # manual 永遠不可停用
    assert "scanner" in disabled


# ── 來源不明的舊 MAC 不可以永遠凍結（2026-10-05 正式環境：DHCP 位址換成另一台筆電，掃描代理、防火牆 ARP、
#    租約都看到新的 MAC，IP 記錄卻一直停在上一台的 Apple MAC，也沒有任何異動記錄；同樣卡住的有 30 個）──

def test_unknown_source_mac_is_the_lowest_priority() -> None:
    from app.services.arp_precedence import DEFAULT_ARP_ORDER, would_take
    for src in ("scanner", "opnsense", "librenms", "windows_dhcp"):
        assert would_take(DEFAULT_ARP_ORDER, [], cur_mac="00:00:5e:00:53:46", cur_source=None,
                          mac="00:00:5e:00:53:f8", source=src), src
    # 人工編輯的照樣最優先，不會被自動來源蓋掉
    assert not would_take(DEFAULT_ARP_ORDER, [], cur_mac="00:00:5e:00:53:46", cur_source="manual",
                          mac="00:00:5e:00:53:f8", source="scanner")
    # 停用的來源還是不參與
    assert not would_take(DEFAULT_ARP_ORDER, ["scanner"], cur_mac="00:00:5e:00:53:46", cur_source=None,
                          mac="00:00:5e:00:53:f8", source="scanner")


async def test_scanner_replaces_a_legacy_mac_and_logs_the_change(db_session):
    from unittest.mock import AsyncMock, patch
    ip = IPAddress(ip="10.9.9.10", mac="00:00:5e:00:53:46", mac_source=None)
    with patch("app.services.ip_history.log_change", new=AsyncMock()) as log:
        changed = await consider_mac(db_session, ip=ip, mac="00:00:5e:00:53:f8", source="scanner")
    assert changed is True
    assert ip.mac == "00:00:5e:00:53:f8"
    assert ip.mac_source == "scanner"
    assert log.await_count == 1
    assert log.await_args.kwargs["event_type"] == "mac_changed"


async def test_same_mac_from_a_source_adopts_the_source_without_a_log(db_session):
    """MAC 本來就對、只是來源不明：記下來源（之後就照正常優先序），不寫異動記錄。"""
    from unittest.mock import AsyncMock, patch
    ip = IPAddress(ip="10.9.9.11", mac="00:00:5e:00:53:f8", mac_source=None)
    with patch("app.services.ip_history.log_change", new=AsyncMock()) as log:
        await consider_mac(db_session, ip=ip, mac="00:00:5E:00:53:F8", source="opnsense")
    assert ip.mac_source == "opnsense"
    assert log.await_count == 0


# ── 換了一台設備（MAC 變了）：上一台自己報的名稱（NetBIOS、mDNS、代理）要清掉（2026-10-05：DHCP 位址換給
#    Windows 筆電之後，NetBIOS 還掛著一個月前那台 Mac 的名稱；新筆電擋了 NetBIOS，舊值永遠不會被蓋掉）──

async def test_mac_change_forgets_names_reported_by_the_previous_device(db_session):
    import uuid
    from datetime import UTC, datetime, timedelta

    from app.models.ip_hostname import IPHostnameObservation
    from app.models.section import Section
    from app.models.subnet import Subnet
    from sqlalchemy import select
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.175", mac="00:00:5e:00:53:46", mac_source="opnsense",
                   hostname="laptop-07")
    db_session.add(ip)
    await db_session.flush()
    old = datetime.now(UTC) - timedelta(days=40)
    for src, name in (("netbios", "OLD-MAC-NB"), ("mdns", "old-mac.local"), ("wazuh", "old-mac"),
                      ("manual", "laptop-old"), ("opnsense", "laptop-07"), ("dns", "laptop-07.example.net")):
        db_session.add(IPHostnameObservation(ip_id=ip.id, source=src, hostname=name, observed_at=old))
    await db_session.commit()

    changed = await consider_mac(db_session, ip=ip, mac="00:00:5e:00:53:f8", source="opnsense")
    await db_session.commit()
    assert changed is True
    left = {s for (s,) in (await db_session.execute(
        select(IPHostnameObservation.source).where(IPHostnameObservation.ip_id == ip.id))).all()}
    # 跟著設備走的清掉；人填的、DNS、防火牆租約（會跟著新租約重報）留著
    assert left == {"manual", "opnsense", "dns"}, left

    # 同一個 MAC 再看到一次（或第一次填 MAC）不清
    db_session.add(IPHostnameObservation(ip_id=ip.id, source="netbios", hostname="LAPTOP-07"))
    await db_session.commit()
    await consider_mac(db_session, ip=ip, mac="00:00:5e:00:53:f8", source="opnsense")
    await db_session.commit()
    assert "netbios" in {s for (s,) in (await db_session.execute(
        select(IPHostnameObservation.source).where(IPHostnameObservation.ip_id == ip.id))).all()}

    # 換回 24 小時內這個 IP 用過的 MAC＝同一批設備輪流出現，不是換設備：名稱不清。
    # 正式環境的樣子（2026-10-05 .110／.127）：雙網卡主機的 ARP flux，掃描每隔幾小時看到另一張網卡、10 分多鐘後又換回來
    from app.models.ip_change_log import IPChangeLog
    from sqlalchemy import update

    async def _age(minutes: int) -> None:
        await db_session.execute(update(IPChangeLog).where(IPChangeLog.ip_id == ip.id)
                                 .values(created_at=datetime.now(UTC) - timedelta(minutes=minutes)))
        await db_session.commit()

    def _names() -> Any:
        return db_session.execute(
            select(IPHostnameObservation.source).where(IPHostnameObservation.ip_id == ip.id))

    for mac, age in (("00:00:5e:00:53:46", 11), ("00:00:5e:00:53:f8", 120)):
        await _age(age)
        await consider_mac(db_session, ip=ip, mac=mac, source="opnsense")
        await db_session.commit()
        assert str(ip.mac) == mac
        assert "netbios" in {s for (s,) in (await _names()).all()}, mac


# ── 同一個來源、同一輪對同一個 IP 報了好幾個 MAC（兩台 VM 設了同一個 IP、某台設備的 ARP 快取沒老化）：
#    以前照回報順序一筆一筆套，同一輪、每一輪都來回換（2026-10-05 正式環境 15 個 IP），
#    加上換設備會清名稱，名稱也跟著每輪被清 ──

def test_pick_mac_keeps_the_current_one_and_never_guesses() -> None:
    from app.services.arp_precedence import pick_mac
    assert pick_mac("00:00:5e:00:53:01", {"00005e005301": 1, "00005e005302": 1}) == "00005e005301"
    assert pick_mac(None, {"00005e005301": 1, "00005e005302": 1}) is None
    assert pick_mac("00:00:5e:00:53:09", {"00005e005301": 1, "00005e005302": 1}) is None
    assert pick_mac("00:00:5e:00:53:09", {"00005e005302": 1}) == "00005e005302"
    assert pick_mac("00:00:5e:00:53:01", {"00005e005301": 1, "00005e005302": 3}) == "00005e005302"
    assert pick_mac("00:00:5e:00:53:09", {}) is None


async def test_mac_run_decides_once_whatever_the_report_order(db_session):
    from unittest.mock import AsyncMock, patch

    from app.services.arp_precedence import MacRun
    ip = IPAddress(ip="10.9.9.12", mac="00:00:5e:00:53:02", mac_source="proxmox")
    with patch("app.services.ip_history.log_change", new=AsyncMock()) as log:
        for order in (("00:00:5e:00:53:01", "00:00:5e:00:53:02"), ("00:00:5e:00:53:02", "00:00:5e:00:53:01")):
            run = MacRun(db_session, source="proxmox")
            for mac in order:
                run.report(ip, mac)
            assert await run.finish() == 0
        assert str(ip.mac) == "00:00:5e:00:53:02"
        assert log.await_count == 0
        # 只剩另一個在報 → 換過去
        run = MacRun(db_session, source="proxmox")
        run.report(ip, "00:00:5E:00:53:01")
        assert await run.finish() == 1
    assert str(ip.mac) == "00:00:5e:00:53:01"
