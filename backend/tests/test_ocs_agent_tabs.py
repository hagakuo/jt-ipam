"""OCS 整合頁的「代理數」與「未裝 Agent 的 IP」（比照 Wazuh 整合頁）。

OCS 沒有每台電腦的記錄表：盤點資料是依網卡 MAC 補進 IP（ocs_id／last_seen_ocs…）。
一台電腦常有好幾個 IP —— 實機上一輪同步是「14 台電腦、比對到 60 個 IP」。
所以「代理數」要**依 OCS 電腦 ID 彙整，一台一筆**，不能直接數 IP，否則數字大好幾倍。

「未裝 Agent 的 IP」比照 Wazuh：有主機名稱、卻從來沒被 OCS 盤點過的 IP。
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.services import ocs as svc


async def _net(session):
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name="t")
    session.add(sec)
    await session.flush()
    net = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    session.add(net)
    await session.flush()
    return net


async def _ip(session, net, ip: str, hostname: str | None = None, **kw):
    from app.models.address import IPAddress
    obj = IPAddress(subnet_id=net.id, ip=ip, hostname=hostname, **kw)
    session.add(obj)
    await session.flush()
    return obj


@pytest.mark.anyio
async def test_agents_are_counted_per_computer_not_per_ip(db_session) -> None:
    net = await _net(db_session)
    t1 = datetime(2026, 9, 24, 7, 0, tzinfo=UTC)
    t2 = datetime(2026, 9, 24, 8, 0, tzinfo=UTC)
    # 同一台電腦（OCS id 5）有兩個 IP
    await _ip(db_session, net, "198.51.100.10", "host-a", ocs_id=5, last_seen_ocs=t1,
              os_ocs="Ubuntu 24.04", ocs_agent="unix_agent_v2.10", ocs_tag="LAB")
    await _ip(db_session, net, "198.51.100.11", "host-a", ocs_id=5, last_seen_ocs=t2,
              os_ocs="Ubuntu 24.04", ocs_agent="unix_agent_v2.10", ocs_tag="LAB")
    await _ip(db_session, net, "198.51.100.20", "host-b", ocs_id=7, last_seen_ocs=t1,
              os_ocs="Debian 12", ocs_agent="unix_agent_v2.8")
    await _ip(db_session, net, "198.51.100.30", "no-agent")

    agents = await svc.list_agents(db_session)
    assert len(agents) == 2, "代理數要一台電腦一筆，不是一個 IP 一筆"
    a = next(x for x in agents if x["ocs_id"] == 5)
    assert a["ips"] == ["198.51.100.10", "198.51.100.11"]
    assert a["name"] == "host-a"
    assert a["last_inventory"] == t2, "取這台電腦最新的一次盤點"
    assert (a["os"], a["agent_version"], a["tag"]) == ("Ubuntu 24.04", "unix_agent_v2.10", "LAB")
    assert agents[0]["ocs_id"] == 5, "依最後盤點時間由新到舊"


@pytest.mark.anyio
async def test_missing_agents_are_named_ips_never_inventoried(db_session) -> None:
    net = await _net(db_session)
    await _ip(db_session, net, "198.51.100.10", "host-a", ocs_id=5,
              last_seen_ocs=datetime(2026, 9, 24, tzinfo=UTC))
    miss = await _ip(db_session, net, "198.51.100.30", "no-agent")
    await _ip(db_session, net, "198.51.100.40")                    # 沒有主機名稱

    rows = await svc.find_missing_agents(db_session)
    assert [r["ip"] for r in rows] == ["198.51.100.30"]
    assert rows[0]["ip_address_id"] == str(miss.id)
    assert rows[0]["hostname"] == "no-agent"
    every = await svc.find_missing_agents(db_session, hostnamed_only=False)
    assert {r["ip"] for r in every} == {"198.51.100.30", "198.51.100.40"}


@pytest.mark.anyio
async def test_endpoints_are_admin_only_and_shaped_like_wazuh(client, auth_headers, db_session) -> None:
    net = await _net(db_session)
    await _ip(db_session, net, "198.51.100.10", "host-a", ocs_id=5,
              last_seen_ocs=datetime(2026, 9, 24, tzinfo=UTC))
    await _ip(db_session, net, "198.51.100.30", "no-agent")
    await db_session.commit()

    r = await client.get("/api/v1/ocs/agents", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1 and body["items"][0]["ips"] == ["198.51.100.10"]
    r = await client.get("/api/v1/ocs/missing-agents", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert [x["ip"] for x in r.json()] == ["198.51.100.30"]
    r = await client.get("/api/v1/ocs/agents")
    assert r.status_code == 401
