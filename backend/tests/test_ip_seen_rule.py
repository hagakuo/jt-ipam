"""IP 詳細資料帶「上線判定規則」：畫面的「各來源最後出現」要逐列說出這個來源算不算上線證據、是否還在時限內。

規則來自系統設定（採信的來源＋時限），與 services/librenms.recompute_effective_status 用的是同一份；
畫面自己猜會跟實際判定不一致。只放在單筆讀取（清單不需要）。
"""
from __future__ import annotations

import uuid


async def _ip(db_session):
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db_session.add(sub)
    await db_session.flush()
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.61", state="used")
    db_session.add(ipa)
    await db_session.commit()
    return ipa


async def test_detail_carries_the_liveness_rule(client, auth_headers, db_session) -> None:
    from app.services.system_config import get_liveness_config
    ipa = await _ip(db_session)
    cfg = await get_liveness_config(db_session)
    r = await client.get(f"/api/v1/addresses/{ipa.id}", headers=auth_headers)
    assert r.status_code == 200, r.text
    rule = r.json()["liveness_rule"]
    assert rule["minutes"] == cfg["minutes"]
    assert sorted(rule["sources"]) == sorted(cfg["sources"])
    assert "scanner" in rule["sources"]                 # 預設採信掃描代理
    assert "arp" not in rule["sources"]                 # ARP 快取不會過期 → 預設不採信


async def test_list_does_not_carry_it(client, auth_headers, db_session) -> None:
    ipa = await _ip(db_session)
    r = await client.get("/api/v1/addresses", headers=auth_headers, params={"subnet_id": str(ipa.subnet_id)})
    assert r.status_code == 200
    assert all(it.get("liveness_rule") is None for it in r.json()["items"])
