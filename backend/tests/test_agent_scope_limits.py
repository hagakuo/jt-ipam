"""整合的「限定子網路範圍」也決定「未裝 Agent 的 IP」要列哪些（使用者要求，2026-09-25）。

Wazuh 已經有「限定子網路範圍」（重疊網段時只在這些子網路內比對 IP），但「未裝 Agent 的 IP」
仍然列全站 —— 使用者限定了三個子網路，清單卻還是一堆教材示範網段的 10.10.x。限定了範圍，
就表示範圍外的機器本來就不歸這套 Wazuh／OCS 管，不該算成缺口。

規則（兩個整合共用）：
- 指定某個整合 → 用它的範圍；
- 看全部 → 所有啟用中的整合範圍的聯集；只要有一個整合沒設範圍（＝全域），就不限。
OCS 也要有同樣的「限定子網路範圍」，同步時只跟範圍內 IP 的 MAC 比對。
"""
from __future__ import annotations

import uuid

import pytest

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet


async def _two_subnets(session):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    a = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    b = Subnet(section_id=sec.id, cidr="203.0.113.0/24")
    session.add_all([a, b])
    await session.flush()
    ia = IPAddress(subnet_id=a.id, ip="198.51.100.20", hostname="pc-in-scope",
                   mac="00:00:5e:00:53:20")
    ib = IPAddress(subnet_id=b.id, ip="203.0.113.20", hostname="pc-out-of-scope",
                   mac="00:00:5e:00:53:21")
    session.add_all([ia, ib])
    await session.flush()
    return a, b, ia, ib


async def _wazuh(session, scope):
    from app.models.wazuh import WazuhInstance
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.5:55000",
                         api_user="ro", api_password_enc=b"x", api_password_nonce=b"y",
                         scope_subnet_ids=scope)
    session.add(inst)
    await session.flush()
    return inst


def _ips(rows) -> set[str]:
    return {r["ip"] for r in rows}


@pytest.mark.anyio
async def test_wazuh_missing_agents_follow_the_integration_scope(
    db_session, client, auth_headers,
) -> None:
    a, _b, _ia, _ib = await _two_subnets(db_session)
    await _wazuh(db_session, [str(a.id)])
    await db_session.commit()
    r = await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers)
    assert r.status_code == 200, r.text
    got = _ips(r.json())
    assert "198.51.100.20" in got
    assert "203.0.113.20" not in got, "範圍外的機器不歸這套 Wazuh 管，不是缺口"


@pytest.mark.anyio
async def test_an_unscoped_integration_means_everywhere(db_session, client, auth_headers) -> None:
    a, _b, _ia, _ib = await _two_subnets(db_session)
    await _wazuh(db_session, [str(a.id)])
    await _wazuh(db_session, None)                   # 另一套沒設範圍＝全域
    await db_session.commit()
    got = _ips((await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers)).json())
    assert {"198.51.100.20", "203.0.113.20"} <= got


@pytest.mark.anyio
async def test_ocs_has_a_scope_and_its_missing_list_follows_it(
    db_session, client, auth_headers,
) -> None:
    a, _b, _ia, _ib = await _two_subnets(db_session)
    await db_session.commit()
    r = await client.post("/api/v1/ocs", headers=auth_headers, json={
        "name": f"ocs-{uuid.uuid4().hex[:6]}", "base_url": "https://ocs.example.com",
        "scope_subnet_ids": [str(a.id)]})
    assert r.status_code == 201, r.text
    assert r.json()["scope_subnet_ids"] == [str(a.id)]
    got = _ips((await client.get("/api/v1/ocs/missing-agents", headers=auth_headers)).json())
    assert "198.51.100.20" in got and "203.0.113.20" not in got

    # 清成空＝全域
    r = await client.patch(f"/api/v1/ocs/{r.json()['id']}", headers=auth_headers,
                           json={"scope_subnet_ids": []})
    assert r.status_code == 200, r.text
    got = _ips((await client.get("/api/v1/ocs/missing-agents", headers=auth_headers)).json())
    assert {"198.51.100.20", "203.0.113.20"} <= got


async def test_ocs_sync_only_matches_macs_inside_its_scope(db_session) -> None:
    """重疊網段的另一個單位剛好有同一個 MAC 的記錄時，不能被這套 OCS 寫到。"""
    from app.models.ocs import OcsServer
    from app.services import ocs as svc

    a, _b, ia, ib = await _two_subnets(db_session)
    ib.mac = ia.mac                                  # 兩邊同一個 MAC（例如複製出來的 VM）
    server = OcsServer(name=f"ocs-{uuid.uuid4().hex[:6]}", source_type="rest",
                       base_url="https://ocs.example.com", scope_subnet_ids=[str(a.id)])
    db_session.add(server)
    await db_session.flush()
    index = await svc.mac_index(db_session, server)
    assert index[svc.normalize_mac(ia.mac)] == [ia.id], "只有範圍內那一筆"

    server.scope_subnet_ids = None
    index = await svc.mac_index(db_session, server)
    assert set(index[svc.normalize_mac(ia.mac)]) == {ia.id, ib.id}
