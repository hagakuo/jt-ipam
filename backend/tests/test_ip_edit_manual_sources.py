"""IP 編輯表單：沒改的主機名稱與 MAC 不可以被當成「手動輸入」（2026-09-26）。

表單每次存檔都會把目前顯示的主機名稱與 MAC 一起送出。以前後端照單全收：
- 只改了說明、按儲存，畫面上當時的 DNS 名稱就被凍結成「手動」，之後 DNS 怎麼改都蓋不過；
- MAC 來源被標成手動（MAC 優先序裡最高）→ 機器換掉後 ARP／掃描的新 MAC 永遠寫不進去。
另外：使用者明確輸入新名稱、而全域順序會讓它被別的來源蓋掉時（正式機的手動排在 DNS 之後），
以前存完馬上被蓋回去、畫面沒有任何提示 —— 使用者回報手動輸入了名稱，畫面還是顯示 DNS 的舊名
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.ip_hostname import IPHostnameObservation
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.hostname import apply_observation, set_precedence
from sqlalchemy import select


async def _ip(db) -> IPAddress:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.139", mac="00:00:5e:00:53:01", mac_source="scanner")
    db.add(ip)
    await db.flush()
    await apply_observation(db, ip=ip, source="dns", hostname="old-host.example.com")
    await db.commit()
    return ip


def _form(ip: IPAddress, **over) -> dict:
    body = {"hostname": ip.hostname, "description": "x", "state": "active", "mac": ip.mac,
            "hostname_source_pin": None}
    body.update(over)
    return body


async def _manual(db, ip) -> str | None:
    return (await db.execute(select(IPHostnameObservation.hostname).where(
        IPHostnameObservation.ip_id == ip.id, IPHostnameObservation.source == "manual"))).scalar_one_or_none()


async def test_saving_the_form_without_touching_the_hostname_does_not_freeze_it(client, auth_headers, db_session):
    ip = await _ip(db_session)
    r = await client.patch(f"/api/v1/addresses/{ip.id}", headers=auth_headers, json=_form(ip, description="just a note"))
    assert r.status_code == 200, r.text
    assert await _manual(db_session, ip) is None, "沒改主機名稱卻被存成手動"
    assert r.json()["hostname_source_pin"] is None


async def test_saving_the_form_without_touching_the_mac_keeps_its_source(client, auth_headers, db_session):
    ip = await _ip(db_session)
    r = await client.patch(f"/api/v1/addresses/{ip.id}", headers=auth_headers,
                           json=_form(ip, mac=ip.mac.upper()))     # 大小寫不同也算同一個
    assert r.status_code == 200, r.text
    await db_session.refresh(ip)
    assert ip.mac_source == "scanner", "沒改 MAC 卻被標成手動 → 之後換機器的新 MAC 永遠寫不進來"
    r = await client.patch(f"/api/v1/addresses/{ip.id}", headers=auth_headers,
                           json=_form(ip, mac="00:00:5e:00:53:99"))
    await db_session.refresh(ip)
    assert ip.mac_source == "manual"


async def test_a_typed_name_takes_effect_even_when_manual_ranks_below_dns(client, auth_headers, db_session):
    ip = await _ip(db_session)
    await set_precedence(db_session, order=["dns", "manual"])
    await db_session.commit()
    r = await client.patch(f"/api/v1/addresses/{ip.id}", headers=auth_headers, json=_form(ip, hostname="new-host"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hostname"] == "new-host", "輸入的名稱被 DNS 蓋回去了"
    assert body["hostname_source_pin"] == "manual", "要看得出為什麼：固定成用手動"


async def test_an_explicit_pin_choice_is_respected(client, auth_headers, db_session):
    """使用者同時明確選了別的固定來源 → 照他選的，不自作主張改成手動。"""
    ip = await _ip(db_session)
    await set_precedence(db_session, order=["dns", "manual"])
    await db_session.commit()
    r = await client.patch(f"/api/v1/addresses/{ip.id}", headers=auth_headers,
                           json=_form(ip, hostname="new-host", hostname_source_pin="dns"))
    assert r.json()["hostname"] == "old-host.example.com"
    assert r.json()["hostname_source_pin"] == "dns"
