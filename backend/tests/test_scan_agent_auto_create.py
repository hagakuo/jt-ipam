"""掃描代理掃到「IPAM 沒登錄」的位址時，收不收錄由開關決定，且預設關閉。

掃描代理原本是三類來源裡最後一個還在**無條件自動建立**的（0115 已收 OPNsense/pfSense、
0116 收 Proxmox/VMware）。改成開關的理由跟那兩次一樣：位址一旦被建進 IPAM，就**不會再
出現在「未授權 IP」異常偵測裡** —— 那道偵測的判定正是「掃得到、IPAM 沒有」。也就是說
自動收錄會把「有人私接了一台機器」這件事，安靜地變成一筆看起來很正常的紀錄。

所以這裡守的是**不該建的時候有沒有忍住**，以及**沒建的時候有沒有講出來**（靜靜丟掉
資料是這個專案吃過虧的老問題：客戶得自己讀原始碼才知道資料去哪了）。
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.address import IPAddress
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet


@pytest.mark.anyio
async def test_default_is_off(db_session) -> None:
    """預設關閉 —— 升級後不該有人突然發現 IPAM 多出一批沒登記過的機器。"""
    agent = ScanAgent(name=f"a-{uuid.uuid4().hex[:6]}")
    db_session.add(agent)
    await db_session.flush()
    assert agent.auto_create_ips is False


async def _fixture(db_session, *, auto: bool):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", scan_enabled=True)
    agent = ScanAgent(name=f"a-{uuid.uuid4().hex[:6]}", auto_create_ips=auto)
    db_session.add_all([sub, agent])
    await db_session.flush()
    sub.scan_agent_id = agent.id
    await db_session.flush()
    return sub, agent


async def _count_ips(db_session, subnet_id) -> int:
    rows = (await db_session.execute(
        select(IPAddress).where(IPAddress.subnet_id == subnet_id))).scalars().all()
    return len(rows)


@pytest.mark.anyio
async def test_scanning_an_unknown_address_creates_nothing_when_off(
    db_session, client, monkeypatch,
) -> None:
    """關閉時：掃到未登錄的位址不建立紀錄，而且回應要說有幾筆被略過。"""
    sub, agent = await _fixture(db_session, auto=False)
    await db_session.commit()

    from app.api.v1.endpoints import scan_agents as ep

    async def _fake_agent(session, key):   # noqa: ANN001
        return (await session.execute(
            select(ScanAgent).where(ScanAgent.id == agent.id))).scalar_one()

    monkeypatch.setattr(ep, "_agent_from_key", _fake_agent)

    r = await client.post("/api/v1/scan-agents/report",
                          headers={"X-Agent-Key": "x"},
                          json={"results": [{"ip": "198.51.100.77", "alive": True}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["skipped_not_in_ipam"] == 1, "略過了卻沒說 —— 使用者會以為掃描器什麼都沒找到"
    assert body.get("created", 0) == 0
    assert await _count_ips(db_session, sub.id) == 0


@pytest.mark.anyio
async def test_scanning_an_unknown_address_records_it_when_on(
    db_session, client, monkeypatch,
) -> None:
    """開啟時：建立紀錄並標成 scanner（前端靠這個來源打「自動收錄」標記）。"""
    sub, agent = await _fixture(db_session, auto=True)
    await db_session.commit()

    from app.api.v1.endpoints import scan_agents as ep

    async def _fake_agent(session, key):   # noqa: ANN001
        return (await session.execute(
            select(ScanAgent).where(ScanAgent.id == agent.id))).scalar_one()

    monkeypatch.setattr(ep, "_agent_from_key", _fake_agent)

    r = await client.post("/api/v1/scan-agents/report",
                          headers={"X-Agent-Key": "x"},
                          json={"results": [{"ip": "198.51.100.77", "alive": True}]})
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 1

    row = (await db_session.execute(
        select(IPAddress).where(IPAddress.subnet_id == sub.id))).scalars().one()
    assert str(row.ip) == "198.51.100.77"
    assert row.discovery_source == "scanner", "來源標錯 → 前端不會顯示「自動收錄」標記"
