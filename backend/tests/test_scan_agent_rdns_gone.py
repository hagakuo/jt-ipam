"""掃描代理反解查不到名稱時，它先前回報的名字要清掉（2026-09-26 稽核）。

以前代理只回報「有名字」的，查不到就什麼都不說 → 伺服器分不出「這輪沒查」與「查了、DNS 說
沒有這筆 PTR」，舊名永遠留著。代理 1.8.1 起在 DNS 明確回答「沒有」（NXDOMAIN／NO_DATA）時送
空字串；逾時、DNS 連不上仍然什麼都不送 —— 那種時候清掉會讓全部名稱跟著 DNS 故障一起消失。
"""
from __future__ import annotations

import socket
import sys
import uuid
from pathlib import Path

import pytest
from app.models.address import IPAddress
from app.models.ip_hostname import IPHostnameObservation
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet
from sqlalchemy import select


async def _setup(db, monkeypatch):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", scan_enabled=True)
    agent = ScanAgent(name=f"a-{uuid.uuid4().hex[:6]}")
    db.add_all([sub, agent])
    await db.flush()
    sub.scan_agent_id = agent.id
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.40")
    db.add(ip)
    await db.flush()
    ip_id, agent_id = ip.id, agent.id
    await db.commit()
    from app.api.v1.endpoints import scan_agents as ep

    async def _fake_agent(session, key):   # noqa: ANN001
        return (await session.execute(select(ScanAgent).where(ScanAgent.id == agent_id))).scalar_one()
    monkeypatch.setattr(ep, "_agent_from_key", _fake_agent)
    return ip_id


async def _report(client, item: dict) -> None:
    r = await client.post("/api/v1/scan-agents/report", headers={"X-Agent-Key": "x"},
                          json={"results": [{"ip": "198.51.100.40", "alive": True, **item}]})
    assert r.status_code == 200, r.text


async def _scanner_name(db, ip_id) -> str | None:
    db.expire_all()
    return (await db.execute(select(IPHostnameObservation.hostname).where(
        IPHostnameObservation.ip_id == ip_id, IPHostnameObservation.source == "scanner"))).scalar_one_or_none()


@pytest.mark.anyio
async def test_an_explicit_no_ptr_clears_the_old_name(db_session, client, monkeypatch) -> None:
    ip = await _setup(db_session, monkeypatch)
    await _report(client, {"rdns": "old-host.example.com", "probes_run": ["icmp", "rdns"]})
    assert await _scanner_name(db_session, ip) == "old-host.example.com"
    await _report(client, {"rdns": "", "probes_run": ["icmp", "rdns"]})
    assert await _scanner_name(db_session, ip) is None


@pytest.mark.anyio
async def test_silence_keeps_the_name(db_session, client, monkeypatch) -> None:
    """沒有送 rdns（舊代理、這輪沒查、DNS 逾時）→ 不清。"""
    ip = await _setup(db_session, monkeypatch)
    await _report(client, {"rdns": "host.example.com", "probes_run": ["icmp", "rdns"]})
    await _report(client, {"probes_run": ["icmp", "rdns"]})
    assert await _scanner_name(db_session, ip) == "host.example.com"
    # 空字串但 rdns 探測沒跑 → 也不清（不是這個探測說的）
    await _report(client, {"rdns": "", "probes_run": ["icmp"]})
    assert await _scanner_name(db_session, ip) == "host.example.com"


def _agent_module():
    root = Path(__file__).resolve().parents[2] / "agent"
    sys.path.insert(0, str(root))
    try:
        import jt_ipam_agent
        return jt_ipam_agent
    finally:
        sys.path.remove(str(root))


def test_agent_tells_no_ptr_apart_from_a_dns_failure(monkeypatch) -> None:
    agent = _agent_module()

    def nxdomain(_ip):
        raise socket.herror(1, "Unknown host")

    def try_again(_ip):
        raise socket.herror(2, "Host name lookup failure")

    def timeout(_ip):
        raise TimeoutError

    monkeypatch.setattr(agent.socket, "gethostbyaddr", nxdomain)
    assert agent._rdns("198.51.100.1") == (None, True)
    monkeypatch.setattr(agent.socket, "gethostbyaddr", try_again)
    assert agent._rdns("198.51.100.1") == (None, False)
    monkeypatch.setattr(agent.socket, "gethostbyaddr", timeout)
    assert agent._rdns("198.51.100.1") == (None, False)
    monkeypatch.setattr(agent.socket, "gethostbyaddr", lambda _ip: ("pc.example.com", [], []))
    assert agent._rdns("198.51.100.1") == ("pc.example.com", False)


def test_the_rdns_tool_job_still_returns_plain_names(monkeypatch) -> None:
    """_rdns 改回傳 (名稱, 是否確定沒有) 之後，網路工具的反解工作也要跟著拆開 —— 不然回傳 tuple。"""
    agent = _agent_module()
    monkeypatch.setattr(agent.socket, "gethostbyaddr", lambda _ip: ("pc.example.com", [], []))
    result, err = agent._job_execute("rdns", {"targets": ["198.51.100.1"]})
    assert err is None
    assert result == [{"target": "198.51.100.1", "hostname": "pc.example.com"}]
