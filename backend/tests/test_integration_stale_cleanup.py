"""整合同步：上游不再回報的資料要清、讀取失敗時不可以誤清（2026-09-26 稽核）。

核心規則在 test_hostname_reports.py；這裡驗各整合把「是否完整」接對了。
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.wazuh import WazuhAgent, WazuhInstance
from app.models.windows_dhcp import WindowsDhcpServer
from app.services import wazuh as wz
from app.services import windows_dhcp as wd
from sqlalchemy import select


async def _ips(db, *addrs):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    out = [IPAddress(subnet_id=sub.id, ip=a) for a in addrs]
    db.add_all(out)
    await db.flush()
    return sub, out


# ── Windows DHCP ──
class _FakeWin:
    def __init__(self, scopes: dict):
        self.scopes = scopes       # scope id -> list[lease] | Exception

    def get_scopes(self):
        return [{"ScopeId": k} for k in self.scopes]

    def get_leases(self, sid):
        v = self.scopes[sid]
        if isinstance(v, Exception):
            raise v
        return v


async def _win(db, monkeypatch, scopes, sub):
    inst = (await db.execute(select(WindowsDhcpServer))).scalars().first()
    if inst is None:
        inst = WindowsDhcpServer(name="dhcp-a", host="192.0.2.5", username="u",
                                 password_enc=b"x", password_nonce=b"x", scope_subnet_ids=[str(sub.id)])
        db.add(inst)
        await db.flush()
    monkeypatch.setattr(wd, "_client", lambda _i: _FakeWin(scopes))
    await wd.sync_leases(db, inst)
    await db.flush()


async def test_windows_dhcp_failed_scope_keeps_flags_and_names(db_session, monkeypatch):
    """以前：某個 scope 讀取失敗 → 那個 scope 每一筆 IP 的「有 DHCP 租約」都被清掉。"""
    sub, (a, b) = await _ips(db_session, "198.51.100.10", "198.51.100.11")
    leases = {"198.51.100.0": [
        {"IPAddress": "198.51.100.10", "HostName": "pc-a.corp"},
        {"IPAddress": "198.51.100.11", "HostName": "pc-b.corp"}]}
    await _win(db_session, monkeypatch, leases, sub)
    assert a.in_dhcp_lease and a.hostname == "pc-a"

    await _win(db_session, monkeypatch, {"198.51.100.0": wd.WindowsDhcpError("WinRM timeout")}, sub)
    await db_session.refresh(a)
    assert a.in_dhcp_lease, "讀取失敗不代表租約過期"
    assert a.hostname == "pc-a"

    # 讀取成功、租約真的沒了 → 才清
    await _win(db_session, monkeypatch, {"198.51.100.0": [
        {"IPAddress": "198.51.100.11", "HostName": "pc-b.corp"}]}, sub)
    await db_session.refresh(a)
    assert not a.in_dhcp_lease
    assert a.hostname is None


# ── Wazuh ──
def _agents(monkeypatch, agents):
    async def _fake(_inst, *, batch=500):
        return agents
    monkeypatch.setattr(wz, "fetch_agents", _fake)


async def test_wazuh_agents_deleted_upstream_disappear_with_their_names(db_session, monkeypatch):
    inst = WazuhInstance(name="wz-a", api_url="https://wz.example.com", api_user="u",
                         api_password_enc=b"x", api_password_nonce=b"x")
    db_session.add(inst)
    await db_session.flush()
    _, (ip,) = await _ips(db_session, "198.51.100.20")
    _agents(monkeypatch, [{"id": "001", "name": "old-host", "ip": "198.51.100.20", "status": "active"},
                          {"id": "002", "name": "other", "ip": "198.51.100.99", "status": "active"}])
    await wz.sync_agents(db_session, inst)
    await db_session.flush()
    assert ip.hostname == "old-host"

    _agents(monkeypatch, [{"id": "002", "name": "other", "ip": "198.51.100.99", "status": "active"}])
    res = await wz.sync_agents(db_session, inst)
    await db_session.flush()
    left = set((await db_session.execute(select(WazuhAgent.agent_id).where(
        WazuhAgent.instance_id == inst.id))).scalars().all())
    assert left == {"002"}, "已刪除的代理還留在鏡像裡（它的 OS 會被當成這個 IP 的有效 OS）"
    assert res["removed"] == 1
    await db_session.refresh(ip)
    assert ip.hostname is None


async def test_wazuh_name_is_not_taken_from_an_agent_that_no_longer_owns_the_ip(db_session, monkeypatch):
    """DHCP 位址被回收再配給別台：舊代理失聯、這個 IP 之後又被偵測到活著 → 不採用它的名字。"""
    from datetime import UTC, datetime, timedelta
    inst = WazuhInstance(name="wz-b", api_url="https://wz.example.com", api_user="u",
                         api_password_enc=b"x", api_password_nonce=b"x")
    db_session.add(inst)
    await db_session.flush()
    _, (ip,) = await _ips(db_session, "198.51.100.30")
    ip.last_seen_scanner = datetime.now(UTC)
    old = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _agents(monkeypatch, [{"id": "015", "name": "laptop-a1", "ip": "198.51.100.30",
                           "status": "disconnected", "lastKeepAlive": old}])
    await wz.sync_agents(db_session, inst)
    await db_session.flush()
    assert ip.hostname is None


# ── OPNsense ──
async def _opn(db):
    from app.models.firewall import OPNsenseFirewall
    fw = OPNsenseFirewall(name=f"opn-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.1",
                          api_key_enc=b"x", api_key_nonce=b"x", api_secret_enc=b"x", api_secret_nonce=b"x")
    db.add(fw)
    await db.flush()
    return fw


async def test_opnsense_unreachable_keeps_nat_and_says_so(db_session, monkeypatch):
    """以前：連不上時每一支 NAT 端點都失敗 → 「這次沒看到的都刪掉」把整台的 NAT 清空，同步還顯示成功。"""
    from app.models.nat import NATTranslation
    from app.services import opnsense_firewall as opn
    fw = await _opn(db_session)
    db_session.add(NATTranslation(name="web-dnat", type="port_forward",
                                  source_origin=f"opnsense:{fw.id}", external_id="u-1"))
    await db_session.flush()

    async def _down(*_a, **_k):
        raise opn.OPNsenseError("connect timeout")
    monkeypatch.setattr(opn, "_api_post", _down)
    monkeypatch.setattr(opn, "_api_get", _down)
    out = await opn.sync_nat_rules(db_session, fw)
    left = (await db_session.execute(select(NATTranslation.name).where(
        NATTranslation.source_origin == f"opnsense:{fw.id}"))).scalars().all()
    assert left == ["web-dnat"]
    assert out.get("error"), "失敗要讓整批同步的 last_error 看得到"
