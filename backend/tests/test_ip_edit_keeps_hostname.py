"""IP 編輯表單沒改主機名稱就存檔，不可以把主機名稱清掉（2026-10-04 e2e 抓到）。

表單每次都會送 hostname 與 hostname_source_pin（就算沒改）。以前只要請求裡有 hostname_source_pin 就重算
有效主機名稱；這個 IP 沒有任何來源觀測（舊資料、匯入、種子資料直接寫 ip.hostname）時，重算結果是空的
→ 存一次表單名字就不見了，異動記錄還寫成「手動改成空白」。
"""
from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.section import Section
from app.models.subnet import Subnet


async def test_saving_the_form_unchanged_keeps_a_hostname_without_observations(client, auth_headers, db_session):
    sec = Section(name=f"keep-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.40", hostname="legacy-host-40")   # 沒有任何觀測
    db_session.add(ip)
    await db_session.commit()

    for pin in (None, ""):
        r = await client.patch(f"/api/v1/addresses/{ip.id}", headers=auth_headers,
                               json={"hostname": "legacy-host-40", "hostname_source_pin": pin,
                                     "description": f"just a note {pin!r}"})
        assert r.status_code == 200, r.text
        assert r.json()["hostname"] == "legacy-host-40", f"沒改主機名稱就存檔不可以清掉（pin={pin!r}）"
    logs = (await db_session.execute(select(IPChangeLog).where(
        IPChangeLog.ip_id == ip.id, IPChangeLog.event_type == "hostname_changed"))).scalars().all()
    assert not logs, "沒改就不該有主機名稱異動記錄"
