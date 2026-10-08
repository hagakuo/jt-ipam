"""IP 掛著某台裝置，但那個位址後來換了 MAC → 關聯多半已經過期。

由來（使用者提問，2026-08-30）：「日後 IP 如果被別的主機用，這邊還是會掛在這個裝置上嗎？」
會 —— 關聯一旦寫下去就不再重新評估，位址被別台機器拿去用（DHCP 尤其常見）之後，
關聯會**安靜地變成錯的**：畫面看起來一切正常，只是指到了另一台機器。

刻意做成事後偵測而不是在寫入端多加判斷：寫入端再聰明也只是猜，而這裡有真正的證據 ——
**異動記錄裡，MAC 的變更發生在關聯之後**。也刻意不自動解除關聯：那同樣是猜。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.address import IPAddress
from app.models.device import Device
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.anomaly import detect_stale_device_links


async def _seed(session, *, cidr: str, ip: str, mac_after_link: bool) -> IPAddress:
    sec = Section(name=f"sdl-{ip}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr)
    session.add(sub)
    await session.flush()
    dev = Device(name=f"dev-{ip}", type="server")
    session.add(dev)
    await session.flush()
    addr = IPAddress(subnet_id=sub.id, ip=ip, device_id=dev.id, mac="aa:bb:cc:dd:ee:01")
    session.add(addr)
    await session.flush()

    now = datetime.now(UTC)
    linked_at = now - timedelta(days=2)
    mac_at = now - timedelta(days=1) if mac_after_link else now - timedelta(days=3)
    # ip_text / subnet_id 是刪除後仍要保留歷史用的快照欄位，非空
    session.add(IPChangeLog(
        ip_id=addr.id, subnet_id=sub.id, ip_text=ip,
        event_type="edited", field="device_id",
        old_value=None, new_value=str(dev.id), source="user", created_at=linked_at,
    ))
    session.add(IPChangeLog(
        ip_id=addr.id, subnet_id=sub.id, ip_text=ip,
        event_type="edited", field="mac",
        old_value="aa:bb:cc:dd:ee:00", new_value="aa:bb:cc:dd:ee:01",
        source="system", created_at=mac_at,
    ))
    await session.commit()
    return addr


async def test_mac_changed_after_linking_is_flagged(db_session):
    addr = await _seed(db_session, cidr="10.90.0.0/24", ip="10.90.0.5", mac_after_link=True)
    hits = await detect_stale_device_links(db_session)
    assert any(h["ip_id"] == str(addr.id) for h in hits), (
        "MAC 在關聯之後才變 —— 這正是「位址換了主人」的證據，應該提出來"
    )
    hit = next(h for h in hits if h["ip_id"] == str(addr.id))
    assert hit["device"], "沒有講出掛在哪一台裝置，使用者無從判斷"
    assert hit["linked_at"] and hit["mac_changed_at"], (
        "沒有附上兩個時間點，看的人無法自己確認先後"
    )


async def test_mac_changed_before_linking_is_not_flagged(db_session):
    """關聯之前的 MAC 變更不算數 —— 那是掛上去的人當時就看得到的狀態。"""
    addr = await _seed(db_session, cidr="10.91.0.0/24", ip="10.91.0.5", mac_after_link=False)
    hits = await detect_stale_device_links(db_session)
    assert all(h["ip_id"] != str(addr.id) for h in hits), "把關聯之前的變更也報出來了"


async def test_detector_does_not_change_anything(db_session):
    """偵測就是偵測 —— 不可以順手解除關聯。要不要拆是人的決定。"""
    addr = await _seed(db_session, cidr="10.92.0.0/24", ip="10.92.0.5", mac_after_link=True)
    before = addr.device_id
    await detect_stale_device_links(db_session)
    await db_session.refresh(addr)
    assert addr.device_id == before, "偵測規則動到了資料"
