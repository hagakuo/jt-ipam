"""異常規則：一個 IP 頻繁更換 MAC。

現有的「MAC 變動」判的是**同一個 MAC 出現在兩個交換器埠**（FDB）——那是找接錯線／
偽裝。這一條問的是反過來的事：**同一個 IP 一直換 MAC**，通常是 DHCP 池被反覆重用、
有人手動搶用固定 IP，或某台機器在做位址隨機化。

⚠️ 隨機化是常態不是異常：Windows 11 / macOS / iOS / Android 開啟隱私功能後每次
連線都會換一個「本地管理位址」。所以這條規則必須能**逐 IP 忽略**，否則裝置一多
就會把整個異常偵測頁洗掉，真正該看的東西被埋在下面。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.librenms import ARPEntry
from app.models.section import Section
from app.models.subnet import Subnet


async def _ip(session, addr: str) -> IPAddress:
    sec = (await session.execute(__import__("sqlalchemy").select(Section))).scalars().first()
    if sec is None:
        sec = Section(name="flap-sec")
        session.add(sec)
        await session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", anomaly_enabled=True)
    session.add(sub)
    await session.flush()
    ip = IPAddress(subnet_id=sub.id, ip=addr)
    session.add(ip)
    await session.flush()
    return ip


async def _arp(session, ip: str, macs: list[str], *, days_ago: int = 1) -> None:
    now = datetime.now(UTC)
    for i, m in enumerate(macs):
        session.add(ARPEntry(ip=ip, mac=m, first_seen_at=now - timedelta(days=days_ago),
                             last_seen_at=now - timedelta(hours=i)))
    await session.flush()


async def test_flapping_ip_is_reported(db_session):
    from app.services.anomaly import detect_mac_flapping

    ip = await _ip(db_session, "198.51.100.40")
    await _arp(db_session, "198.51.100.40",
               ["00005e005301", "00005e005302", "00005e005303", "00005e005304"])
    out = await detect_mac_flapping(db_session, days=7, min_macs=4)
    assert len(out) == 1
    row = out[0]
    assert row["ip"] == "198.51.100.40"
    assert row["mac_count"] == 4
    assert len(row["macs"]) == 4, "要列出是哪幾個 MAC，否則沒辦法判斷是不是隨機化"
    assert row["ip_id"] == str(ip.id)


async def test_below_the_threshold_is_not_reported(db_session):
    from app.services.anomaly import detect_mac_flapping

    await _ip(db_session, "198.51.100.41")
    await _arp(db_session, "198.51.100.41", ["00005e005311", "00005e005312"])
    assert await detect_mac_flapping(db_session, days=7, min_macs=4) == []


async def test_randomized_macs_are_flagged_as_such(db_session):
    """本地管理位址佔多數時要講出來 —— 但**不是**自動忽略：
    那也可能是有人在做 MAC 偽裝，該由人看過再決定。"""
    from app.services.anomaly import detect_mac_flapping

    await _ip(db_session, "198.51.100.42")
    # 第二個十六進位字元是 2/6/a/e → 本地管理位址（隱私隨機化）
    await _arp(db_session, "198.51.100.42",
               ["0a005e005301", "0a005e005302", "0e005e005303", "02005e005304"])
    out = await detect_mac_flapping(db_session, days=7, min_macs=4)
    assert out[0]["randomized"] is True


async def test_ignored_ip_is_skipped(db_session):
    """管理員把這個 IP 標成忽略之後，這條規則就不該再報它。"""
    from app.services.anomaly import detect_mac_flapping

    ip = await _ip(db_session, "198.51.100.43")
    await _arp(db_session, "198.51.100.43",
               ["00005e005321", "00005e005322", "00005e005323", "00005e005324"])
    assert len(await detect_mac_flapping(db_session, days=7, min_macs=4)) == 1

    ip.anomaly_ignore = ["mac_flapping"]
    await db_session.flush()
    assert await detect_mac_flapping(db_session, days=7, min_macs=4) == []


async def test_ignoring_one_category_does_not_silence_the_rest(db_session):
    """忽略是逐類別的 —— 標了「這台會自己換 MAC」不代表它失聯也不用報。"""
    ip = await _ip(db_session, "198.51.100.44")
    ip.anomaly_ignore = ["mac_flapping"]
    await db_session.flush()
    from app.services.anomaly import is_ignored

    assert is_ignored(ip, "mac_flapping") is True
    assert is_ignored(ip, "ghost_ips") is False


async def test_ignore_endpoint_only_accepts_known_categories(client, db_session, auth_headers):
    """亂塞字串進忽略清單，之後沒有人查得出那是什麼。"""
    ip = await _ip(db_session, "198.51.100.45")
    await db_session.commit()

    r = await client.put(f"/api/v1/anomalies/ignore/{ip.id}", headers=auth_headers,
                         json={"categories": ["mac_flapping", "not-a-real-category"]})
    assert r.status_code == 200, r.text
    assert r.json()["categories"] == ["mac_flapping"]


async def test_rogue_dhcp_cannot_be_ignored_per_ip():
    """「非法 DHCP 伺服器」不該讓人用『這台就是這樣』關掉 —— 那正是要立刻處理的事。"""
    from app.services.anomaly import ANOMALY_IGNORABLE

    assert "rogue_dhcp" not in ANOMALY_IGNORABLE
    assert "ip_conflicts" not in ANOMALY_IGNORABLE
