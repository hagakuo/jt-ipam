"""主機名稱以外的欄位改變，也要留下異動記錄。

使用者從 IP 詳細資料頁的「異動記錄」時間軸看到的只有主機名稱變更 —— 因為
`hostname.py` 每次有效值改變都會寫一筆，而同樣走來源優先序的 `arp_precedence`
（MAC）**一筆都沒寫**。結果是「這個 IP 什麼時候換了 MAC」在畫面上完全查不到，
即使 ARP 表裡其實看得出來。
"""
from __future__ import annotations

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet
from sqlalchemy import select


async def _ip(session, addr: str = "198.51.100.5") -> IPAddress:
    sec = Section(name=f"prec-{addr}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    session.add(sub)
    await session.flush()
    ip = IPAddress(subnet_id=sub.id, ip=addr)
    session.add(ip)
    await session.flush()
    return ip


async def _log_rows(session, ip, field: str) -> list[IPChangeLog]:
    return list((await session.execute(
        select(IPChangeLog).where(IPChangeLog.ip_id == ip.id, IPChangeLog.field == field)
    )).scalars().all())


async def test_mac_change_is_recorded(db_session):
    from app.services.arp_precedence import consider_mac

    ip = await _ip(db_session, "198.51.100.5")
    await consider_mac(db_session, ip=ip, mac="00:00:5e:00:53:01", source="librenms")
    await db_session.flush()
    first = await _log_rows(db_session, ip, "mac")
    assert len(first) == 1, "第一次填入 MAC 也要留記錄（否則時間軸上沒有起點）"
    assert first[0].new_value.replace(":", "") == "00005e005301"
    assert first[0].source == "librenms"

    # 換成另一個 MAC（同來源）→ 要再留一筆，而且舊值要對
    await consider_mac(db_session, ip=ip, mac="00:00:5e:00:53:02", source="librenms")
    await db_session.flush()
    rows = await _log_rows(db_session, ip, "mac")
    assert len(rows) == 2
    changed = [r for r in rows if r.old_value][0]
    assert changed.old_value.replace(":", "") == "00005e005301"
    assert changed.new_value.replace(":", "") == "00005e005302"


async def test_same_mac_again_records_nothing(db_session):
    """每輪同步都看到同一個 MAC —— 不能每輪都寫一筆，那會把時間軸洗掉。"""
    from app.services.arp_precedence import consider_mac

    ip = await _ip(db_session, "198.51.100.6")
    for _ in range(3):
        await consider_mac(db_session, ip=ip, mac="00:00:5e:00:53:0a", source="librenms")
    await db_session.flush()
    assert len(await _log_rows(db_session, ip, "mac")) == 1


# ── 其餘三個欄位為什麼不在這裡 ────────────────────────────────────────────
# 一開始以為 MAC／作業系統／裝置名稱／型號四個都該寫進 `ip_change_log`，實際看過才知道
# 形狀不同：
#   * **作業系統**（`os_precedence.effective_os`）是**讀取時才推導**的，沒有「被覆寫」
#     那個時刻可以掛記錄。要留歷程得先改成寫入式，那是另一件事。
#   * **裝置名稱／型號**（`device_name_precedence` / `model_precedence`）掛在**裝置**上，
#     不是 IP —— 而這個專案**沒有裝置的異動記錄表**，塞進 IP 的時間軸只會張冠李戴。
# 所以這一版只補 MAC。上面兩點是真的缺口，但要各自的設計，不是順手加一行。
