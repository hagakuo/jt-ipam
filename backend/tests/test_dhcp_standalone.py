"""issue #45：獨立的 Kea 與 ISC DHCP 伺服器（端到端：設定 → 拉取／回報 → 範圍、保留、租約寫進 IPAM）。

Kea 用模擬的控制 API 回應（控制代理與 Kea 3.0 直連兩種形狀都要會）；ISC DHCP 用真的代理金鑰打回報端點。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.dhcp import DHCPPoolRange, DHCPReservation
from app.models.dhcp_standalone import IscDhcpServer, KeaDhcpServer
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import kea_dhcp as kea
from sqlalchemy import select


async def _net(db) -> dict[str, IPAddress]:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="192.0.2.0/24")
    db.add(sub)
    await db.flush()
    ips = {}
    for last in (5, 101, 102):
        ip = IPAddress(subnet_id=sub.id, ip=f"192.0.2.{last}", state="active")
        db.add(ip)
        ips[str(last)] = ip
    await db.commit()
    return ips


DHCP4 = {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24",
                      "pools": [{"pool": "192.0.2.100 - 192.0.2.150"}],
                      "reservations": [{"hw-address": "00:00:5e:00:53:05", "ip-address": "192.0.2.5",
                                        "hostname": "printer-5"}]}]}


def _lease(ip: str, mac: str, name: str | None = None) -> dict:
    return {"ip-address": ip, "hw-address": mac, "hostname": name, "state": 0,
            "cltt": int(datetime.now(UTC).timestamp()) - 60, "valid-lft": 3600, "subnet-id": 1}


def _fake_kea(monkeypatch, *, mode: str = "agent", leases: list | None = None, lease_cmds: bool = True,
              status: int = 200, calls: list | None = None):
    async def fake_post(self, body):  # noqa: ANN001
        if calls is not None:
            calls.append(body)
        if status == 401:
            raise kea.KeaError("401 Unauthorized — check the username/password (Kea HTTP basic auth)")
        cmd = body["command"]
        wrap = (lambda x: [x]) if mode == "agent" else (lambda x: x)
        if mode == "agent" and "service" not in body:
            # 控制代理：不帶 service 時回的是它自己的設定
            return [{"result": 0, "arguments": {"Control-agent": {}}}] if cmd == "config-get" else \
                [{"result": 2, "text": f"'{cmd}' command not supported."}]
        if cmd == "config-get":
            return wrap({"result": 0, "arguments": {"Dhcp4": DHCP4}})
        if cmd == "version-get":
            return wrap({"result": 0, "text": "2.6.1", "arguments": {"extended": "2.6.1\nlinked with ..."}})
        if cmd == "reservation-get-all":
            return wrap({"result": 2, "text": "'reservation-get-all' command not supported."})
        if cmd == "lease4-get-page":
            if not lease_cmds:
                return wrap({"result": 2, "text": "'lease4-get-page' command not supported."})
            rows = leases or []
            return wrap({"result": 0 if rows else 3, "arguments": {"leases": rows, "count": len(rows)}})
        return wrap({"result": 2, "text": "unsupported"})
    monkeypatch.setattr(kea.KeaClient, "_post", fake_post)


async def _kea_inst(db, **kw) -> KeaDhcpServer:
    inst = KeaDhcpServer(name=f"kea-{uuid.uuid4().hex[:6]}", api_url="http://192.0.2.53:8000/", **kw)
    db.add(inst)
    await db.commit()
    return inst


@pytest.mark.parametrize("mode", ["agent", "direct"])
async def test_kea_sync_writes_pools_reservations_and_leases(db_session, monkeypatch, mode) -> None:
    ips = await _net(db_session)
    calls: list = []
    _fake_kea(monkeypatch, mode=mode, calls=calls,
              leases=[_lease("192.0.2.101", "00:00:5e:00:53:65", "laptop-101.example.test")])
    inst = await _kea_inst(db_session)
    summary = await kea.sync_instance(db_session, inst)
    await db_session.commit()
    assert summary["pools"] == 1 and summary["reservations"] == 1 and summary["leases"] == 1
    assert summary["mode"] == mode
    if mode == "agent":
        assert all(c.get("service") == ["dhcp4"] for c in calls[1:]), "控制代理：之後的指令都要帶 service"
    else:
        assert all("service" not in c for c in calls), "直連：不帶 service"

    pool = (await db_session.execute(select(DHCPPoolRange).where(
        DHCPPoolRange.source_id == inst.id))).scalar_one()
    assert (pool.source_type, pool.source, pool.start_ip, pool.end_ip) == ("kea_dhcp", "kea", "192.0.2.100", "192.0.2.150")
    res = (await db_session.execute(select(DHCPReservation).where(
        DHCPReservation.source_id == inst.id))).scalar_one()
    assert (res.ip, res.mac, res.hostname) == ("192.0.2.5", "00:00:5e:00:53:05", "printer-5")
    ip101 = await db_session.get(IPAddress, ips["101"].id)
    await db_session.refresh(ip101)
    assert ip101.in_dhcp_lease is True
    assert str(ip101.mac).lower() == "00:00:5e:00:53:65"
    await db_session.refresh(inst)
    assert inst.last_error is None and inst.last_sync_at is not None
    assert inst.last_summary["version"] == "2.6.1"


async def test_kea_without_lease_cmds_still_syncs_ranges_and_says_so(db_session, monkeypatch) -> None:
    await _net(db_session)
    _fake_kea(monkeypatch, lease_cmds=False)
    inst = await _kea_inst(db_session)
    summary = await kea.sync_instance(db_session, inst)
    assert summary["pools"] == 1 and "leases" not in summary
    assert summary["leases_unsupported"] is True
    assert inst.last_summary["leases_unsupported"] is True, "畫面要能提示「租約要開 lease_cmds」"
    assert inst.last_error is None, "範圍與保留都同步成功，不算失敗"


async def test_kea_unauthorised_is_a_failure_with_the_reason(db_session, monkeypatch) -> None:
    _fake_kea(monkeypatch, status=401)
    inst = await _kea_inst(db_session)
    with pytest.raises(kea.KeaError):
        await kea.sync_instance(db_session, inst)
    await db_session.refresh(inst)
    assert "401" in (inst.last_error or "")


async def test_kea_api_create_hides_the_password_and_test_reports_errors(client, auth_headers, db_session,
                                                                         monkeypatch) -> None:
    r = await client.post("/api/v1/kea-dhcp/servers", headers=auth_headers, json={
        "name": f"kea-api-{uuid.uuid4().hex[:6]}", "api_url": "https://192.0.2.54:8000/",
        "username": "jtipam", "password": "s3cret-pass"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_password"] is True
    assert "password" not in body and "password_enc" not in body
    inst = await db_session.get(KeaDhcpServer, uuid.UUID(body["id"]))
    assert inst.password_enc and b"s3cret-pass" not in inst.password_enc
    assert kea._password(inst) == "s3cret-pass"

    _fake_kea(monkeypatch, status=401)
    t = await client.post(f"/api/v1/kea-dhcp/servers/{body['id']}/test", headers=auth_headers)
    assert t.status_code == 502
    assert t.json()["detail"]["code"] == "kea_dhcp_error"
    assert "401" in t.json()["detail"]["params"]["reason"]

    bad = await client.post("/api/v1/kea-dhcp/servers", headers=auth_headers, json={
        "name": "kea-bad", "api_url": "file:///etc/kea/kea-dhcp4.conf"})
    assert bad.status_code == 422, "只接受 http(s) 網址"


async def test_deleting_a_kea_server_takes_its_rows_with_it(client, auth_headers, db_session, monkeypatch) -> None:
    await _net(db_session)
    _fake_kea(monkeypatch, leases=[_lease("192.0.2.101", "00:00:5e:00:53:65")])
    inst = await _kea_inst(db_session)
    await kea.sync_instance(db_session, inst)
    await db_session.commit()
    r = await client.delete(f"/api/v1/kea-dhcp/servers/{inst.id}", headers=auth_headers)
    assert r.status_code == 204, r.text
    left = (await db_session.execute(select(DHCPPoolRange).where(DHCPPoolRange.source_id == inst.id))).all()
    assert left == []


# ── ISC DHCP ─────────────────────────────────────────────────────────────────

async def _agent(db, raw: str) -> ScanAgent:
    from app.api.v1.endpoints.scan_agents import _key_hash
    agent = ScanAgent(name=f"dhcp-host-{uuid.uuid4().hex[:6]}", enroll_key_hash=_key_hash(raw), enabled=True)
    db.add(agent)
    await db.commit()
    return agent


def _report(source_id, *, conf_ok=True, leases_ok=True) -> dict:
    return {
        "source_id": str(source_id),
        "pools": [{"subnet": "192.0.2.0/24", "start": "192.0.2.100", "end": "192.0.2.150"}],
        "reservations": [{"ip": "192.0.2.5", "mac": "00:00:5e:00:53:05", "hostname": "printer-5"}],
        "leases": [{"ip": "192.0.2.101", "mac": "00:00:5e:00:53:65", "hostname": "laptop-101",
                    "ends": "2026-09-30T00:00:00+00:00"}],
        "files": {"conf": {"path": "/etc/dhcp/dhcpd.conf", "ok": conf_ok,
                           "error": None if conf_ok else "PermissionError: Permission denied"},
                  "leases": {"path": "/var/lib/dhcp/dhcpd.leases", "ok": leases_ok,
                             "error": None if leases_ok else "FileNotFoundError: No such file or directory"}},
    }


async def test_isc_source_is_handed_to_its_agent_and_the_report_lands(client, auth_headers, db_session) -> None:
    ips = await _net(db_session)
    raw = "d" * 40
    agent = await _agent(db_session, raw)
    r = await client.post("/api/v1/isc-dhcp/servers", headers=auth_headers, json={
        "name": f"isc-{uuid.uuid4().hex[:6]}", "agent_id": str(agent.id), "report_interval_seconds": 120})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert r.json()["agent_name"] == agent.name

    poll = await client.get("/api/v1/scan-agents/poll", headers={"X-Agent-Key": raw})
    assert poll.json()["dhcpd"] == {"source_id": sid, "interval_seconds": 120}

    rep = await client.post("/api/v1/scan-agents/dhcpd-report", headers={"X-Agent-Key": raw},
                            json=_report(sid))
    assert rep.status_code == 200, rep.text
    assert rep.json()["pools"] == 1 and rep.json()["reservations"] == 1 and rep.json()["leases"] == 1
    ip101 = await db_session.get(IPAddress, ips["101"].id)
    await db_session.refresh(ip101)
    assert ip101.in_dhcp_lease is True
    src = await db_session.get(IscDhcpServer, uuid.UUID(sid))
    await db_session.refresh(src)
    assert src.last_error is None and src.file_status["conf"]["ok"] is True


async def test_an_agent_cannot_report_for_a_source_that_is_not_its_own(client, auth_headers, db_session) -> None:
    mine, other = "e" * 40, "f" * 40
    a1 = await _agent(db_session, mine)
    await _agent(db_session, other)
    src = IscDhcpServer(name=f"isc-{uuid.uuid4().hex[:6]}", agent_id=a1.id)
    db_session.add(src)
    await db_session.commit()
    r = await client.post("/api/v1/scan-agents/dhcpd-report", headers={"X-Agent-Key": other},
                          json=_report(src.id))
    assert r.status_code == 404
    poll = await client.get("/api/v1/scan-agents/poll", headers={"X-Agent-Key": other})
    assert poll.json()["dhcpd"] is None, "沒有指派的代理不該被要求讀 dhcpd 檔"


async def test_unreadable_files_do_not_wipe_what_was_there(client, auth_headers, db_session) -> None:
    await _net(db_session)
    raw = "g" * 40
    agent = await _agent(db_session, raw)
    src = IscDhcpServer(name=f"isc-{uuid.uuid4().hex[:6]}", agent_id=agent.id)
    db_session.add(src)
    await db_session.commit()
    await client.post("/api/v1/scan-agents/dhcpd-report", headers={"X-Agent-Key": raw}, json=_report(src.id))
    # 權限被改掉、讀不到設定檔：範圍與固定分配不可以被清掉，錯誤要講清楚
    bad = _report(src.id, conf_ok=False, leases_ok=False)
    bad["pools"], bad["reservations"], bad["leases"] = [], [], []
    r = await client.post("/api/v1/scan-agents/dhcpd-report", headers={"X-Agent-Key": raw}, json=bad)
    assert r.status_code == 200
    pools = (await db_session.execute(select(DHCPPoolRange).where(DHCPPoolRange.source_id == src.id))).all()
    assert len(pools) == 1
    await db_session.refresh(src)
    assert "Permission denied" in (src.last_error or "")
    assert "/var/lib/dhcp/dhcpd.leases" in (src.last_error or "")


async def test_one_agent_one_isc_source(client, auth_headers, db_session) -> None:
    agent = await _agent(db_session, "h" * 40)
    ok = await client.post("/api/v1/isc-dhcp/servers", headers=auth_headers,
                           json={"name": f"isc-a-{uuid.uuid4().hex[:6]}", "agent_id": str(agent.id)})
    assert ok.status_code == 201
    dup = await client.post("/api/v1/isc-dhcp/servers", headers=auth_headers,
                            json={"name": f"isc-b-{uuid.uuid4().hex[:6]}", "agent_id": str(agent.id)})
    assert dup.status_code == 409
    assert dup.json()["detail"]["code"] == "isc_dhcp_agent_taken"


async def test_a_silent_agent_marks_the_source_as_failing(db_session) -> None:
    from app.services.dhcp_standalone import mark_stale_isc
    agent = await _agent(db_session, "i" * 40)
    src = IscDhcpServer(name=f"isc-{uuid.uuid4().hex[:6]}", agent_id=agent.id, report_interval_seconds=300,
                        last_sync_at=datetime.now(UTC) - timedelta(minutes=30))
    db_session.add(src)
    await db_session.commit()
    assert await mark_stale_isc(db_session) >= 1
    assert "no report from the scan agent" in (src.last_error or "")
