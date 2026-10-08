"""IP 詳細頁的「探測」：由負責該子網路的掃描代理對單一 IP 做非侵入式的識別
（服務版本、OS 指紋、banner／TLS 憑證、名稱查詢），推出這是什麼主機（2026-09-28 使用者要求）。

- 只有管理員能用；每次都寫稽核
- 目標只能是 jt-ipam 裡已有的單一 IP（不接受主機名稱、不接受多個目標）—— 後端與代理各驗一次
- 由那個子網路的掃描代理執行；沒有代理負責時講清楚
- 同一個 IP 同時只能跑一個探測
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.models.address import IPAddress
from app.models.agent_probe_job import STATUS_DONE, STATUS_PENDING, AgentProbeJob
from app.models.scan_agent import ScanAgent
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.agent_probe import ProbeJobError, validate_params
from sqlalchemy import select

# ─────────────────── 參數驗證（後端） ───────────────────

def test_identify_takes_one_ip() -> None:
    assert validate_params("identify", {"targets": "198.51.100.7"}) == {"targets": ["198.51.100.7"]}


@pytest.mark.parametrize("targets", ["host.example.net", "198.51.100.7 198.51.100.8", "198.51.100.0/24", ""])
def test_identify_rejects_anything_but_a_single_ip(targets: str) -> None:
    with pytest.raises(ProbeJobError):
        validate_params("identify", {"targets": targets})


# ─────────────────── 端點 ───────────────────

async def _setup(db, *, with_agent: bool = True):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    agent = None
    if with_agent:
        agent = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}", enroll_key_hash="x" * 64, enabled=True)
        db.add(agent)
        await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", scan_agent_id=agent.id if agent else None)
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.7", state="active")
    db.add(ip)
    await db.commit()
    return ip, agent


async def test_identify_creates_a_job_for_the_subnets_agent(client, auth_headers, db_session) -> None:
    ip, agent = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["agent_name"] == agent.name
    job = await db_session.get(AgentProbeJob, uuid.UUID(body["job_id"]))
    assert job.kind == "identify"
    assert job.params == {"targets": ["198.51.100.7"]}
    assert job.agent_id == agent.id
    assert job.status == STATUS_PENDING

    from app.models.audit import AuditLog
    audit = (await db_session.execute(select(AuditLog).where(
        AuditLog.action == "identify", AuditLog.object_id == ip.id))).scalars().first()
    assert audit is not None


async def test_only_one_probe_per_ip_at_a_time(client, auth_headers, db_session) -> None:
    ip, _ = await _setup(db_session)
    r1 = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    assert r1.status_code == 202, r1.text
    r2 = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    assert r2.status_code == 409, r2.text
    assert r2.json()["detail"]["code"] == "identify_in_progress"


async def test_a_subnet_without_a_scan_agent_says_so(client, auth_headers, db_session) -> None:
    ip, _ = await _setup(db_session, with_agent=False)
    r = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "identify_no_agent"


async def test_non_admins_cannot_probe(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    ip, _ = await _setup(db_session)
    u = User(username=f"viewer-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=False, is_active=True)
    db_session.add(u)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    r = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=h)
    assert r.status_code == 403, r.text


async def test_result_comes_back_with_a_summary(client, auth_headers, db_session) -> None:
    ip, _ = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    job_id = r.json()["job_id"]
    job = await db_session.get(AgentProbeJob, uuid.UUID(job_id))
    job.status = STATUS_DONE
    job.result = SAMPLE_RESULT
    await db_session.commit()

    got = await client.get(f"/api/v1/addresses/{ip.id}/identify/{job_id}", headers=auth_headers)
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["status"] == STATUS_DONE
    assert body["summary"]["device_type"] == "server"
    assert body["summary"]["os"] == "Ubuntu Linux", "指紋只給核心範圍時，改顯示 SSH 講出的發行版"
    assert "22/tcp ssh OpenSSH 9.6p1" in body["summary"]["services"]

    # 最近一次的結果：重新打開畫面時看得到
    latest = await client.get(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    assert latest.status_code == 200
    assert latest.json()["job_id"] == job_id


async def test_a_job_of_another_ip_is_not_returned(client, auth_headers, db_session) -> None:
    ip, agent = await _setup(db_session)
    other = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.99"]},
                          status=STATUS_DONE, result=SAMPLE_RESULT,
                          expires_at=datetime.now(UTC))
    db_session.add(other)
    await db_session.commit()
    got = await client.get(f"/api/v1/addresses/{ip.id}/identify/{other.id}", headers=auth_headers)
    assert got.status_code == 404


# ─────────────────── 摘要（由證據推出類型／廠牌） ───────────────────

SAMPLE_RESULT = {
    "target": "198.51.100.7",
    "names": {"rdns": "srv-01.example.net", "netbios": None, "mdns": None},
    "nmap": {
        "available": True,
        "mac": "00:00:5E:00:53:01", "mac_vendor": "ICANN, IANA Department",
        "os": [{"name": "Linux 5.0 - 6.2", "accuracy": 96, "type": "general purpose",
                "vendor": "Linux", "family": "Linux"}],
        "ports": [
            {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH",
             "version": "9.6p1", "extrainfo": "Ubuntu Linux; protocol 2.0", "scripts": {}},
            {"port": 443, "proto": "tcp", "state": "open", "service": "https", "product": "nginx",
             "version": "1.24.0", "extrainfo": "", "tunnel": "ssl",
             "scripts": {"http-title": "Welcome", "ssl-cert": "Subject: commonName=srv-01.example.net"}},
        ],
    },
}


def test_summary_of_a_linux_server() -> None:
    from app.services import ip_identify
    s = ip_identify.summarize(SAMPLE_RESULT, mac_vendor="IANA")
    assert s["device_type"] == "server"
    assert s["os"] == "Ubuntu Linux", "指紋只給核心範圍（Linux 5.0 - 6.2）時，改顯示 SSH 講出的發行版"
    assert s["nic_vendor"] == "IANA"
    assert s["vendor"] is None, "指紋的「廠牌」是作業系統作者（Linux），不是硬體廠牌"
    assert {"srv-01.example.net"} <= set(s["names"])
    assert s["services"] == ["22/tcp ssh OpenSSH 9.6p1", "443/tcp https nginx 1.24.0"]


@pytest.mark.parametrize(("ports", "osclass", "expected"), [
    ([{"port": 9100, "service": "jetdirect"}], None, "printer"),
    ([{"port": 631, "service": "ipp"}], None, "printer"),
    ([{"port": 554, "service": "rtsp"}], None, "camera"),
    ([{"port": 5060, "service": "sip"}], None, "voip"),
    ([{"port": 3389, "service": "ms-wbt-server"}], None, "windows"),
    ([{"port": 8006, "service": "https", "product": "Proxmox Virtual Environment REST API"}], None, "hypervisor"),
    ([], "router", "router"),
    ([], "switch", "switch"),
    ([], "WAP", "wireless_ap"),
    ([], "printer", "printer"),
    ([], None, "unknown"),
])
def test_device_type_rules(ports, osclass, expected) -> None:
    from app.services import ip_identify
    # closed：主機有回應（其餘埠回 RST）—— 這裡測的是「有回應但比對不到」，不是「沒有回應」
    res = {"nmap": {"available": True, "os": [{"name": "x", "accuracy": 90, "type": osclass}] if osclass else [],
                    "ports": [{"proto": "tcp", "state": "open", **p} for p in ports], "closed": 3}}
    assert ip_identify.summarize(res)["device_type"] == expected


def test_summary_when_the_agent_has_no_nmap() -> None:
    from app.services import ip_identify
    s = ip_identify.summarize({"names": {"rdns": "a.example.net"}, "nmap": {"available": False}})
    assert s["device_type"] == "unknown"
    assert s["nmap_available"] is False
    assert s["names"] == ["a.example.net"]


def test_names_from_a_cert_skip_the_issuer_and_wildcards() -> None:
    """正式環境實測：Let's Encrypt 簽發者的 CN（YR2）與萬用憑證 *.example.net 都被當成主機名稱。"""
    from app.services import ip_identify
    cert = ("Subject: commonName=*.example.net\n"
            "Subject Alternative Name: DNS:*.example.net, DNS:pve-01.example.net\n"
            "Issuer: commonName=YR2/organizationName=Let's Encrypt/countryName=US\n"
            "Public Key type: ec")
    res = {"nmap": {"available": True, "ports": [
        {"port": 8006, "proto": "tcp", "state": "open", "service": "https", "scripts": {"ssl-cert": cert}}]}}
    assert ip_identify.summarize(res)["names"] == ["pve-01.example.net"]


def test_a_cert_with_many_names_does_not_flood_the_list() -> None:
    from app.services import ip_identify
    sans = ", ".join(f"DNS:site{i}.example.net" for i in range(20))
    cert = f"Subject: commonName=site0.example.net\nSubject Alternative Name: {sans}\nIssuer: commonName=CA"
    res = {"nmap": {"available": True, "ports": [
        {"port": 443, "proto": "tcp", "state": "open", "service": "https", "scripts": {"ssl-cert": cert}}]}}
    assert len(ip_identify.summarize(res)["names"]) <= 3


# ─────────────────── 代理端（後端被入侵時的最後一道閘） ───────────────────

def _agent_module():
    import importlib.util
    import pathlib
    path = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"
    spec = importlib.util.spec_from_file_location("jt_agent_identify_test", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("targets", [["host.example.net"], ["198.51.100.7", "198.51.100.8"], ["-oX=/tmp/x"]])
def test_agent_refuses_identify_on_anything_but_one_ip(targets) -> None:
    mod = _agent_module()
    result, error = mod._job_execute("identify", {"targets": targets})
    assert result is None
    assert error


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sV" start="1790560000" version="7.94">
<host starttime="1790560000" endtime="1790560030"><status state="up" reason="user-set"/>
<address addr="198.51.100.7" addrtype="ipv4"/>
<address addr="00:00:5E:00:53:01" addrtype="mac" vendor="ICANN, IANA Department"/>
<hostnames><hostname name="srv-01.example.net" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service>
<script id="ssh-hostkey" output="&#xa;  256 aa:bb (ECDSA)&#xa;"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/>
<script id="http-title" output="Welcome"/>
<script id="ssl-cert" output="Subject: commonName=srv-01.example.net"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/><service name="http" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 5.0 - 6.2" accuracy="96" line="1">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/></osmatch></os>
</host></nmaprun>"""


def test_agent_parses_nmap_xml() -> None:
    mod = _agent_module()
    out = mod._parse_nmap_xml(NMAP_XML)
    assert out["mac"] == "00:00:5E:00:53:01"
    assert out["mac_vendor"] == "ICANN, IANA Department"
    assert out["hostnames"] == ["srv-01.example.net"]
    assert [p["port"] for p in out["ports"]] == [22, 443]      # 只列開著的
    ssh = out["ports"][0]
    assert (ssh["service"], ssh["product"], ssh["version"]) == ("ssh", "OpenSSH", "9.6p1")
    assert out["ports"][1]["tunnel"] == "ssl"
    assert out["ports"][1]["scripts"]["http-title"] == "Welcome"
    assert out["os"][0] == {"name": "Linux 5.0 - 6.2", "accuracy": 96, "type": "general purpose",
                            "vendor": "Linux", "family": "Linux"}


def test_agent_reports_how_nmap_identified_each_service() -> None:
    """代理 1.17.2：每個埠帶 nmap 的 method／conf／devicetype。method="table" ＝沒有探針比中、名稱只是照埠號表寫的
    （9100 寫 jetdirect），伺服器據此不把它當成認出了服務；devicetype 是 nmap-service-probes 的 d/ 欄位。"""
    mod = _agent_module()
    assert tuple(int(x) for x in mod.AGENT_VERSION.split(".")) >= (1, 17, 2)
    xml = """<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/>
<address addr="198.51.100.20" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Hikvision IP camera httpd" devicetype="webcam" method="probed" conf="10"/></port>
<port protocol="tcp" portid="9100"><state state="open" reason="syn-ack"/>
<service name="jetdirect" method="table" conf="3"/></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>
</ports></host></nmaprun>"""
    ports = {p["port"]: p for p in mod._parse_nmap_xml(xml)["ports"]}
    assert (ports[80]["method"], ports[80]["conf"], ports[80]["devicetype"]) == ("probed", "10", "webcam")
    assert (ports[9100]["method"], ports[9100]["conf"], ports[9100]["devicetype"]) == ("table", "3", "")
    assert (ports[22]["method"], ports[22]["devicetype"]) == ("", "")          # 沒有 <service> 也不出錯
    # 定期 OS 偵測送回伺服器的精簡版也帶著
    assert mod._compact_nmap({"ports": list(ports.values())})["ports"][0]["method"] == "probed"


def test_agent_parse_survives_garbage() -> None:
    mod = _agent_module()
    assert mod._parse_nmap_xml("not xml")["ports"] == []


async def test_the_tools_page_cannot_start_an_identify_on_any_address(client, auth_headers, db_session) -> None:
    """工具頁的代理探測可以打任意位址；identify 只能從 IP 詳細頁對 jt-ipam 裡的 IP 發起。"""
    agent = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}", enroll_key_hash="y" * 64, enabled=True)
    db_session.add(agent)
    await db_session.commit()
    r = await client.post("/api/v1/tools/net/agent-probe", headers=auth_headers,
                          json={"agent_id": str(agent.id), "kind": "identify", "targets": "203.0.113.9"})
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["code"] == "identify_use_ip_page"
    assert (await db_session.execute(select(AgentProbeJob))).scalars().first() is None


NMAP_SERVICES = """# comment line
tcpmux\t1/tcp\t0.001995
ssh\t22/tcp\t0.182286\t# Secure Shell
domain\t53/udp\t0.213496
http\t80/tcp\t0.484143
https\t443/tcp\t0.208669
telnet\t23/tcp\t0.221265
broken line
"""


def test_agent_port_list_is_top_ports_plus_infrastructure_ports(tmp_path) -> None:
    """nmap 的前 N 個常用埠不含 8006（PVE）這類基礎設施埠，而 -p 與 --top-ports 併用時是取交集，
    所以代理自己從 nmap-services 算前 N 個再併上補充清單。"""
    mod = _agent_module()
    f = tmp_path / "nmap-services"
    f.write_text(NMAP_SERVICES)
    ports = [int(x) for x in mod._identify_port_list(str(f), top=3).split(",")]
    assert {80, 23, 443} <= set(ports)                     # 依頻率取前 3 個（只算 TCP）
    assert not {22, 53, 1} & set(ports)
    assert {8006, 5985} <= set(ports)                      # 補充的基礎設施埠
    assert ports == sorted(set(ports))


def test_agent_port_list_falls_back_when_nmap_services_is_missing(tmp_path) -> None:
    mod = _agent_module()
    assert mod._identify_port_list(str(tmp_path / "nope")) is None


# ─────────────────── 第二版：深度、進度、歷次結果、應用程式（2026-09-28 使用者回饋） ───────────────────

async def _agent_with_key(db, raw_key: str):
    from app.api.v1.endpoints.scan_agents import _key_hash
    ip, agent = await _setup(db)
    agent.enroll_key_hash = _key_hash(raw_key)
    await db.commit()
    return ip, agent


async def test_agent_reports_progress_and_the_page_sees_it(client, auth_headers, db_session) -> None:
    raw = "p" * 40
    ip, _ = await _agent_with_key(db_session, raw)
    job_id = (await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)).json()["job_id"]
    got = await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw})
    assert [j["id"] for j in got.json()["jobs"]] == [job_id]

    prog = {"stage": "tcp", "elapsed": 12}
    r = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/progress", json={"progress": prog},
                          headers={"X-Agent-Key": raw})
    assert r.status_code == 200, r.text
    body = (await client.get(f"/api/v1/addresses/{ip.id}/identify/{job_id}", headers=auth_headers)).json()
    assert body["status"] == "running"
    assert body["progress"]["stage"] == "tcp"


async def test_progress_is_only_accepted_from_the_agent_running_the_job(client, auth_headers, db_session) -> None:
    raw = "q" * 40
    ip, _ = await _agent_with_key(db_session, raw)
    job_id = (await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)).json()["job_id"]
    # 還沒被領走（不是 running）→ 拒絕
    r = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/progress", json={"progress": {"stage": "tcp"}},
                          headers={"X-Agent-Key": raw})
    assert r.status_code == 404
    await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw})
    # 別的代理 → 拒絕
    from app.api.v1.endpoints.scan_agents import _key_hash
    other = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}", enroll_key_hash=_key_hash("o" * 40), enabled=True)
    db_session.add(other)
    await db_session.commit()
    r = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/progress", json={"progress": {"stage": "tcp"}},
                          headers={"X-Agent-Key": "o" * 40})
    assert r.status_code == 404
    # 太大 → 拒絕（進度只是幾行狀態，不是結果）
    r = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/progress",
                          json={"progress": {"log": ["x" * 1000] * 40}}, headers={"X-Agent-Key": raw})
    assert r.status_code == 413


async def test_history_lists_this_ips_probes_newest_first(client, auth_headers, db_session) -> None:
    ip, agent = await _setup(db_session)
    base = datetime.now(UTC)
    from datetime import timedelta
    for i in range(3):
        db_session.add(AgentProbeJob(
            agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.7"]},
            status=STATUS_DONE, result=SAMPLE_RESULT, expires_at=base,
            created_at=base - timedelta(hours=3 - i)))
    db_session.add(AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.99"]},
                                 status=STATUS_DONE, result=SAMPLE_RESULT, expires_at=base))
    await db_session.commit()
    r = await client.get(f"/api/v1/addresses/{ip.id}/identify/history", headers=auth_headers)
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 3
    assert items[0]["created_at"] > items[1]["created_at"] > items[2]["created_at"]
    assert items[0]["summary"]["device_type"] == "server"      # 清單上就看得出是什麼
    assert "result" not in items[0]                             # 清單不帶整包原始結果


def test_a_cert_name_that_is_not_a_host_name_is_not_a_name() -> None:
    """實測：7070 埠的憑證 CN 是「AnyDesk Client」，被當成主機名稱「AnyDesk」。"""
    from app.services import ip_identify
    cert = "Subject: commonName=AnyDesk Client\nIssuer: commonName=AnyDesk Client\nPublic Key type: rsa"
    res = {"nmap": {"available": True, "ports": [
        {"port": 7070, "proto": "tcp", "state": "open", "service": "realserver", "tunnel": "ssl",
         "scripts": {"ssl-cert": cert}}]}}
    s = ip_identify.summarize(res)
    assert s["names"] == []
    assert "AnyDesk" in s["applications"]          # 但它說明了這一埠跑的是什麼軟體


def test_applications_come_from_products_and_cert_hints() -> None:
    from app.services import ip_identify
    res = {"nmap": {"available": True, "ports": [
        {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9p1"},
        {"port": 80, "proto": "tcp", "state": "open", "service": "http", "product": "Apache httpd", "version": "2.4.52"},
        {"port": 4000, "proto": "tcp", "state": "open", "service": "nomachine-nx",
         "product": "NoMachine NX Server remote desktop", "version": "7.9.2"},
        {"port": 443, "proto": "tcp", "state": "open", "service": "https", "product": "nginx"},
        {"port": 8443, "proto": "tcp", "state": "open", "service": "https", "product": "nginx"},
    ]}}
    apps = ip_identify.summarize(res)["applications"]
    assert apps[:3] == ["OpenSSH 8.9p1", "Apache httpd 2.4.52", "NoMachine NX Server remote desktop 7.9.2"]
    assert apps.count("nginx") == 1                  # 同一個軟體開兩個埠只列一次




async def test_a_result_shows_what_changed_since_the_previous_probe(client, auth_headers, db_session) -> None:
    """歷次結果都留著，所以每一筆都能跟上一筆比：新開、關掉、版本變了的服務。"""
    ip, agent = await _setup(db_session)
    from datetime import timedelta
    base = datetime.now(UTC)
    old = {"nmap": {"available": True, "ports": [
        {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9p1"},
        {"port": 80, "proto": "tcp", "state": "open", "service": "http", "product": "Apache httpd"}]}}
    new = {"nmap": {"available": True, "ports": [
        {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6p1"},
        {"port": 443, "proto": "tcp", "state": "open", "service": "https", "product": "nginx"}]}}
    j1 = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.7"]},
                       status=STATUS_DONE, result=old, expires_at=base, created_at=base - timedelta(days=1))
    j2 = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.7"]},
                       status=STATUS_DONE, result=new, expires_at=base, created_at=base)
    db_session.add_all([j1, j2])
    await db_session.commit()
    body = (await client.get(f"/api/v1/addresses/{ip.id}/identify/{j2.id}", headers=auth_headers)).json()
    ch = body["changes"]
    assert ch["previous_job_id"] == str(j1.id)
    assert ch["opened"] == ["443/tcp"]
    assert ch["closed"] == ["80/tcp"]
    assert ch["changed"] == [{"port": "22/tcp", "before": "OpenSSH 8.9p1", "after": "OpenSSH 9.6p1"}]
    first = (await client.get(f"/api/v1/addresses/{ip.id}/identify/{j1.id}", headers=auth_headers)).json()
    assert first["changes"] is None           # 第一次探測沒有可以比的


def test_agent_reports_which_stage_the_probe_is_in(monkeypatch) -> None:
    """探測要跑幾分鐘，畫面要看得到現在在做什麼：代理在每個階段開始時回報。"""
    mod = _agent_module()
    monkeypatch.setattr(mod, "_rdns", lambda ip: ("h.example.net", None))
    monkeypatch.setattr(mod, "_netbios", lambda ip: None)
    monkeypatch.setattr(mod, "_mdns", lambda ip: None)
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)       # 沒有 nmap：只查名稱
    seen: list[str] = []
    result, error = mod._job_execute("identify", {"targets": ["198.51.100.7"]},
                                     progress=lambda p: seen.append(p["stage"]))
    assert error is None
    assert seen == ["names"]
    assert result["names"]["rdns"] == "h.example.net"


def test_agent_runs_identify_off_the_job_queue_thread() -> None:
    """探測要跑好幾分鐘；在工作佇列的執行緒上跑，這段期間別的工具探測會排不到而作廢。"""
    mod = _agent_module()
    assert mod._job_runs_in_background("identify") is True
    assert mod._job_runs_in_background("ping") is False


def test_a_linux_host_running_cups_is_not_a_printer() -> None:
    """實測：一台 Ubuntu 開發機開了 631/ipp（CUPS）被判成印表機。CUPS 是 Linux 的列印服務。"""
    from app.services import ip_identify
    res = {"nmap": {"available": True,
                    "os": [{"name": "Linux 5.0 - 5.4", "accuracy": 100, "type": "general purpose"}],
                    "ports": [
                        {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH"},
                        {"port": 631, "proto": "tcp", "state": "open", "service": "ipp", "product": "CUPS",
                         "version": "2.4"}]}}
    assert ip_identify.summarize(res)["device_type"] == "server"


def test_a_real_printer_is_still_a_printer() -> None:
    from app.services import ip_identify
    res = {"nmap": {"available": True, "ports": [
        {"port": 631, "proto": "tcp", "state": "open", "service": "ipp", "product": "HP LaserJet ipp"},
    ]}}
    assert ip_identify.summarize(res)["device_type"] == "printer"


# ─────────────────── 探測出現在「作業」頁，完成時通知發起人（2026-09-28 使用者要求） ───────────────────

async def _task_of(db, job_id):
    from app.models.background_task import BackgroundTask
    return (await db.execute(select(BackgroundTask).where(
        BackgroundTask.kind == "ip.identify",
        BackgroundTask.summary["job_id"].astext == str(job_id)))).scalars().first()


async def test_a_probe_shows_up_as_a_task_and_notifies_when_done(client, auth_headers, db_session, admin_user) -> None:
    from app.models.notification import Notification
    raw = "t" * 40
    ip, agent = await _agent_with_key(db_session, raw)
    job_id = (await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)).json()["job_id"]
    task = await _task_of(db_session, job_id)
    assert task is not None
    assert (task.status, task.target_id, task.actor_user_id) == ("pending", ip.id, admin_user.id)
    assert "198.51.100.7" in task.target_label

    await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw})
    await db_session.refresh(task)
    assert task.status == "running"
    await client.post(f"/api/v1/scan-agents/jobs/{job_id}/progress", json={"progress": {"stage": "scan"}},
                      headers={"X-Agent-Key": raw})
    await db_session.refresh(task)
    assert task.progress == 60

    r = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/result", json={"result": SAMPLE_RESULT},
                          headers={"X-Agent-Key": raw})
    assert r.status_code == 200, r.text
    await db_session.refresh(task)
    assert (task.status, task.progress) == ("succeeded", 100)
    assert task.summary["device_type"] == "server"
    note = (await db_session.execute(select(Notification).where(
        Notification.user_id == admin_user.id, Notification.title_key == "notif.identify_done"))).scalars().first()
    assert note is not None
    assert note.link == f"/addresses/{ip.id}/identify?job={job_id}"
    assert note.params["ip"] == "198.51.100.7"
    assert note.params["type_key"] == "identify.type.server"


async def test_a_failed_probe_fails_the_task_and_says_so(client, auth_headers, db_session, admin_user) -> None:
    from app.models.notification import Notification
    raw = "u" * 40
    ip, _ = await _agent_with_key(db_session, raw)
    job_id = (await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)).json()["job_id"]
    await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw})
    await client.post(f"/api/v1/scan-agents/jobs/{job_id}/result", json={"result": None, "error": "nmap crashed"},
                      headers={"X-Agent-Key": raw})
    task = await _task_of(db_session, job_id)
    assert task.status == "failed"
    assert task.error == "nmap crashed"
    assert (await db_session.execute(select(Notification).where(
        Notification.user_id == admin_user.id, Notification.title_key == "notif.identify_failed"))).scalars().first()


async def test_a_probe_nobody_picked_up_fails_its_task(client, auth_headers, db_session) -> None:
    from datetime import timedelta
    ip, _ = await _setup(db_session)
    job_id = (await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)).json()["job_id"]
    job = await db_session.get(AgentProbeJob, uuid.UUID(job_id))
    job.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    await client.get(f"/api/v1/addresses/{ip.id}/identify/history", headers=auth_headers)   # 會順手收掉過期的
    task = await _task_of(db_session, job_id)
    await db_session.refresh(task)
    assert task.status == "failed"


# ─────────────────── 以位址探測（IPAM 沒有記錄的位址，例如異常偵測的「未授權 IP」） ───────────────────
# 2026-09-29 使用者要求異常偵測清單也能按「探測」。未授權 IP 按定義就是 IPAM 沒有記錄的位址，
# 所以目標從「IPAM 裡那筆 IP」放寬成「IPAM 管理的子網路裡的位址」：仍然不能拿來掃外面的主機、
# 也不能掃沒有代理負責的網段；由那個子網路的代理執行。

async def _subnet_only(db, *, cidr: str = "198.51.100.0/24", with_agent: bool = True):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    agent = None
    if with_agent:
        agent = ScanAgent(name=f"agent-{uuid.uuid4().hex[:6]}", enroll_key_hash=uuid.uuid4().hex * 2, enabled=True)
        db.add(agent)
        await db.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr, scan_agent_id=agent.id if agent else None)
    db.add(sub)
    await db.commit()
    return sub, agent


async def test_an_unregistered_address_in_a_managed_subnet_can_be_probed(client, auth_headers, db_session) -> None:
    sub, agent = await _subnet_only(db_session)
    info = await client.get("/api/v1/identify/ip/198.51.100.50", headers=auth_headers)
    assert info.status_code == 200, info.text
    assert info.json()["ip"] == "198.51.100.50"
    assert info.json()["subnet_cidr"] == "198.51.100.0/24"
    assert info.json()["agent_name"] == agent.name
    assert info.json()["address_id"] is None
    assert info.json()["record_count"] == 0

    r = await client.post("/api/v1/identify/ip/198.51.100.50", headers=auth_headers)
    assert r.status_code == 202, r.text
    job = await db_session.get(AgentProbeJob, uuid.UUID(r.json()["job_id"]))
    assert job.params == {"targets": ["198.51.100.50"]}
    assert job.agent_id == agent.id

    from app.models.audit import AuditLog
    audit = (await db_session.execute(select(AuditLog).where(
        AuditLog.action == "identify", AuditLog.diff["ip"].astext == "198.51.100.50"))).scalars().first()
    assert audit is not None, "以位址探測也要寫稽核"

    hist = await client.get("/api/v1/identify/ip/198.51.100.50/history", headers=auth_headers)
    assert [x["job_id"] for x in hist.json()["items"]] == [str(job.id)]
    job.status, job.result = STATUS_DONE, SAMPLE_RESULT
    await db_session.commit()
    got = await client.get(f"/api/v1/identify/ip/198.51.100.50/{job.id}", headers=auth_headers)
    assert got.status_code == 200, got.text
    assert got.json()["summary"]["device_type"] == "server"


@pytest.mark.parametrize("target", ["203.0.113.5", "8.8.8.8"])
async def test_an_address_outside_every_managed_subnet_is_refused(client, auth_headers, db_session, target) -> None:
    await _subnet_only(db_session)
    for r in (await client.get(f"/api/v1/identify/ip/{target}", headers=auth_headers),
              await client.post(f"/api/v1/identify/ip/{target}", headers=auth_headers)):
        assert r.status_code == 404, r.text
        assert r.json()["detail"]["code"] == "identify_not_managed"


@pytest.mark.parametrize("target", ["198.51.100.0", "198.51.100.255", "host.example.net", "198.51.100.0-24"])
async def test_network_broadcast_and_non_addresses_are_refused(client, auth_headers, db_session, target) -> None:
    await _subnet_only(db_session)
    r = await client.post(f"/api/v1/identify/ip/{target}", headers=auth_headers)
    assert r.status_code in (400, 404), r.text
    assert not (await db_session.execute(select(AgentProbeJob).where(
        AgentProbeJob.kind == "identify"))).scalars().first()


async def test_a_subnet_without_an_agent_says_so_by_address(client, auth_headers, db_session) -> None:
    await _subnet_only(db_session, with_agent=False)
    r = await client.post("/api/v1/identify/ip/198.51.100.50", headers=auth_headers)
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "identify_no_agent"


async def test_overlapping_subnets_with_different_agents_are_not_guessed(client, auth_headers, db_session) -> None:
    """兩個單位共用同一個 CIDR、各有自己的代理：不知道是哪一邊的主機，不可以挑一個就掃。"""
    await _subnet_only(db_session)
    await _subnet_only(db_session)
    r = await client.post("/api/v1/identify/ip/198.51.100.50", headers=auth_headers)
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "identify_ambiguous"


async def test_the_most_specific_subnet_decides_the_agent(client, auth_headers, db_session) -> None:
    await _subnet_only(db_session, cidr="198.51.0.0/16")
    _, inner_agent = await _subnet_only(db_session, cidr="198.51.100.0/24")
    r = await client.post("/api/v1/identify/ip/198.51.100.50", headers=auth_headers)
    assert r.status_code == 202, r.text
    assert r.json()["agent_name"] == inner_agent.name


async def test_by_address_uses_the_record_when_there_is_one(client, auth_headers, db_session) -> None:
    """已經登記的位址：資訊裡帶出那筆記錄（畫面轉到記錄的探測頁），作業也掛在那筆記錄上。"""
    ip, _ = await _setup(db_session)
    info = await client.get("/api/v1/identify/ip/198.51.100.7", headers=auth_headers)
    assert info.json()["address_id"] == str(ip.id)
    job_id = (await client.post("/api/v1/identify/ip/198.51.100.7", headers=auth_headers)).json()["job_id"]
    task = await _task_of(db_session, job_id)
    assert task.target_id == ip.id


async def test_a_probe_by_address_notifies_with_a_link_back_to_it(client, auth_headers, db_session, admin_user) -> None:
    from app.api.v1.endpoints.scan_agents import _key_hash
    from app.models.notification import Notification
    raw = "v" * 40
    _, agent = await _subnet_only(db_session)
    agent.enroll_key_hash = _key_hash(raw)
    await db_session.commit()
    job_id = (await client.post("/api/v1/identify/ip/198.51.100.50", headers=auth_headers)).json()["job_id"]
    task = await _task_of(db_session, job_id)
    assert task.target_id is None and "198.51.100.50" in task.target_label
    await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw})
    await client.post(f"/api/v1/scan-agents/jobs/{job_id}/result", json={"result": SAMPLE_RESULT},
                      headers={"X-Agent-Key": raw})
    note = (await db_session.execute(select(Notification).where(
        Notification.user_id == admin_user.id, Notification.title_key == "notif.identify_done"))).scalars().first()
    assert note.link == f"/identify/ip/198.51.100.50?job={job_id}"


async def test_non_admins_cannot_probe_by_address(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    await _subnet_only(db_session)
    u = User(username=f"viewer-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=False, is_active=True)
    db_session.add(u)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    assert (await client.post("/api/v1/identify/ip/198.51.100.50", headers=h)).status_code == 403
    assert (await client.get("/api/v1/identify/ip/198.51.100.50/history", headers=h)).status_code == 403


# ─────────────────── 探測時沒有回應 ───────────────────
# 2026-09-29 使用者問「無法判斷 正常嗎」：那台主機探測時已經關機（ping 不通、代理主機的 ARP 是 INCOMPLETE），
# 只從 ARP 的 MAC 查到廠牌。畫面寫「無法判斷」看起來像探測壞掉 —— 要講清楚是「沒有回應」。

def test_a_host_that_did_not_answer_is_no_response_not_unknown() -> None:
    from app.services.ip_identify import summarize
    silent = {"target": "198.51.100.61", "names": {"rdns": None, "netbios": None, "mdns": None},
              "nmap": {"available": True, "exit": 0, "ports": [], "os": [], "mac": None, "closed": 0}}
    s = summarize(silent, mac_vendor="ProxmoxServe")
    assert s["device_type"] == "no_response" and s["no_response"] is True
    assert s["nic_vendor"] == "ProxmoxServe", "網卡廠牌照樣列出（來自先前記錄的 MAC）"

    # 有回 RST（關著的埠）＝主機活著，只是認不出來
    alive = {**silent, "nmap": {**silent["nmap"], "closed": 998}}
    s2 = summarize(alive)
    assert s2["device_type"] == "unknown" and s2["no_response"] is False
    # 區網內有 MAC 回應也算活著
    assert summarize({**silent, "nmap": {**silent["nmap"], "mac": "00:00:5E:00:53:61"}})["no_response"] is False
    # 反解是 DNS 回的，不算主機回應
    assert summarize({**silent, "names": {"rdns": "vm-61.example.net"}})["no_response"] is True
    # 代理沒有 nmap：不能說沒回應
    assert summarize({"names": {}, "nmap": {"available": False}})["no_response"] is False


def test_agent_counts_closed_ports_from_nmap_xml() -> None:
    import importlib.util
    import pathlib
    path = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"
    spec = importlib.util.spec_from_file_location(f"jt_agent_closed_{uuid.uuid4().hex[:6]}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    xml = """<nmaprun><host><status state="up" reason="user-set"/>
      <address addr="198.51.100.62" addrtype="ipv4"/>
      <ports><extraports state="closed" count="997"/>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
        <port protocol="tcp" portid="25"><state state="closed"/></port>
      </ports></host></nmaprun>"""
    got = mod._parse_nmap_xml(xml)
    assert got["closed"] == 998
    silent = mod._parse_nmap_xml("""<nmaprun><host><status state="up" reason="user-set"/>
      <ports><extraports state="filtered" count="1000"/></ports></host></nmaprun>""")
    assert silent["closed"] == 0 and silent["ports"] == [] and silent["mac"] is None


async def test_by_address_info_says_when_arp_last_saw_it(client, auth_headers, db_session) -> None:
    from app.models.librenms import ARPEntry
    await _subnet_only(db_session)
    db_session.add(ARPEntry(ip="198.51.100.61", mac="00:00:5e:00:53:61", source="librenms",
                            first_seen_at=datetime(2026, 9, 29, 1, 0, tzinfo=UTC),
                            last_seen_at=datetime(2026, 9, 29, 6, 29, tzinfo=UTC)))
    await db_session.commit()
    info = (await client.get("/api/v1/identify/ip/198.51.100.61", headers=auth_headers)).json()
    assert info["arp_source"] == "librenms"
    assert info["arp_last_seen"].startswith("2026-09-29T06:29")


# ─────────────────── 類型推測：NAS 不可以因為開了 RTSP 就被判成攝影機 ───────────────────
# 2026-09-29 實例：Synology NAS 開 554/rtsp（DSM 的影音服務），nmap 猜那個服務像某款網路攝影機 →
# 舊規則「有 RTSP 就是攝影機」直接命中。但同一台還有 Synology 的網卡廠牌、DSM 產品字樣、SMB、iSCSI。

def _nas_ports() -> list[dict]:
    return [
        {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.2"},
        {"port": 139, "service": "netbios-ssn", "product": "Samba smbd", "version": "3.X - 4.X"},
        {"port": 445, "service": "netbios-ssn", "product": "Samba smbd", "version": "3.X - 4.X"},
        {"port": 554, "service": "rtsp", "product": "D-Link DCS-2130 or Pelco IDE10DN webcam rtspd"},
        {"port": 3260, "service": "iscsi", "product": "Synology DSM Snapshot Replication iSCSI LUN"},
    ]


def _res(ports: list[dict], os_type: str | None = "general purpose") -> dict:
    return {"nmap": {"available": True, "closed": 900,
                     "os": [{"name": "Linux 3.10 - 4.11", "accuracy": 100, "type": os_type}] if os_type else [],
                     "ports": [{"proto": "tcp", "state": "open", **p} for p in ports]}}


def test_a_synology_nas_with_rtsp_is_storage_not_a_camera() -> None:
    from app.services.ip_identify import summarize
    s = summarize(_res(_nas_ports()), mac_vendor="Synology")
    assert s["device_type"] == "storage", s["evidence"]
    # 只靠產品字樣也要認得（例如 IP 記錄沒有 MAC）
    assert summarize(_res(_nas_ports()))["device_type"] == "storage"
    # 只靠網卡廠牌＋檔案分享也要認得
    plain = [p for p in _nas_ports() if p["port"] != 3260]
    assert summarize(_res(plain), mac_vendor="Synology")["device_type"] == "storage"


def test_rtsp_alone_on_a_small_device_is_still_a_camera() -> None:
    from app.services.ip_identify import summarize
    cam = [{"port": 80, "service": "http", "product": "lighttpd"}, {"port": 554, "service": "rtsp"}]
    assert summarize(_res(cam, os_type=None))["device_type"] == "camera"
    named = [{"port": 80, "service": "http", "product": "Hikvision IP camera httpd"}]
    assert summarize(_res(named, os_type=None))["device_type"] == "camera"


def _mac_airplay(os_name: str = "Apple macOS 11 (Big Sur) (Darwin 20.6.0)") -> dict:
    """2026-10-05 正式環境的 MacBook（192.0.2.200）：macOS 的 AirPlay 接收器在 5000／7000 用 RTSP，
    nmap 正確認出 rtsp，以前一律判成攝影機；網卡是 CalDigit 擴充座的。"""
    ports = [{"port": 3000, "service": "websocket", "product": "Ogar agar.io server"},
             {"port": 5000, "service": "rtsp"}, {"port": 7000, "service": "rtsp"},
             {"port": 7070, "service": "realserver"}, {"port": 8084, "service": "websnp"}]
    return {"nmap": {"available": True, "closed": 900,
                     "os": [{"name": os_name, "accuracy": 96, "type": "general purpose", "vendor": "Apple"}],
                     "ports": [{"proto": "tcp", "state": "open", **p} for p in ports]}}


def test_airplay_rtsp_on_a_mac_is_not_a_camera() -> None:
    from app.services.ip_identify import summarize
    s = summarize(_mac_airplay(), mac_vendor="CalDigit")
    assert s["device_type"] == "server", s["evidence"]
    assert not any(e.startswith("service:") and "rtsp" in e for e in s["evidence"])
    # Windows、iOS 也是一般電腦／手機：單憑 RTSP 不算攝影機
    assert summarize(_mac_airplay("Microsoft Windows 10 1607"))["device_type"] != "camera"
    assert summarize(_mac_airplay("Apple iOS 15.0 - 16.1 (Darwin 21.0.0 - 22.1.0)"))["device_type"] != "camera"
    # 明確認出攝影機產品的照算（例如 Windows 上的錄影軟體不算，但這裡是產品字樣直接寫攝影機）
    named = _mac_airplay()
    named["nmap"]["ports"].append({"proto": "tcp", "state": "open", "port": 80, "service": "http",
                                   "product": "Hikvision IP camera httpd"})
    assert summarize(named)["device_type"] == "camera"
    # Linux 上的 RTSP 照舊算攝影機（IP 攝影機幾乎都是 Linux）
    cam = [{"port": 80, "service": "http", "product": "lighttpd"}, {"port": 554, "service": "rtsp"}]
    assert summarize(_res(cam))["device_type"] == "camera"


def _nm(ports: list[dict], os: list[tuple] | None = None) -> dict:
    """os: (name, accuracy, type, vendor)"""
    return {"nmap": {"available": True, "closed": 900,
                     "os": [{"name": n, "accuracy": a, "type": t, "vendor": v} for n, a, t, v in (os or [])],
                     "ports": [{"proto": "tcp", "state": "open", **p} for p in ports]}}


FREEBSD = [("FreeBSD 11.2-RELEASE", 94, "general purpose", "FreeBSD")]


def test_opnsense_is_a_firewall_and_its_node_exporter_is_not_a_printer() -> None:
    """2026-10-05 正式環境 fw-01：OPNsense 開著 9100（Prometheus node_exporter 外掛），nmap 只照埠號表
    寫 jetdirect、沒有產品 → 以前判成印表機。http 明明寫著 OPNsense。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "10.2"},
             {"port": 80, "service": "http", "product": "OPNsense"},
             {"port": 443, "service": "https", "product": "OPNsense"},
             {"port": 3493, "service": "nut", "product": "Network UPS Tools upsd"},
             {"port": 9100, "service": "jetdirect"}]
    assert summarize(_nm(ports, FREEBSD))["device_type"] == "firewall"
    # 沒有 OPNsense 字樣、一般作業系統上只有埠號猜的 9100 → 也不是印表機（多半是 node_exporter）
    plain = [{"port": 22, "service": "ssh", "product": "OpenSSH"}, {"port": 9100, "service": "jetdirect"}]
    assert summarize(_nm(plain, [("Linux 5.0 - 5.4", 100, "general purpose", "Linux")]))["device_type"] == "server"
    # 真的印表機：沒有一般作業系統的指紋、或 9100 有認出產品 → 照算
    assert summarize(_nm([{"port": 9100, "service": "jetdirect"}]))["device_type"] == "printer"
    assert summarize(_nm([{"port": 9100, "service": "jetdirect", "product": "HP JetDirect"}],
                         [("Linux 3.2 - 4.9", 95, "general purpose", "Linux")]))["device_type"] == "printer"


def test_router_and_firewall_products() -> None:
    from app.services.ip_identify import summarize
    for prod, kind in (("pfSense", "firewall"), ("FortiGate", "firewall"), ("MikroTik RouterOS", "router"),
                       ("OpenWrt LuCI", "router"), ("DrayTek Vigor2927", "router")):
        assert summarize(_nm([{"port": 443, "service": "https", "product": prod}]))["device_type"] == kind, prod


def test_pve_port_on_a_container_or_mail_gateway_is_not_a_hypervisor() -> None:
    """pmg-01（Proxmox Mail Gateway，PVE 上的 LXC）：管理頁同樣在 8006 → 以前判成虛擬化主機。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1 Debian 2+deb12u10"},
             {"port": 25, "service": "smtp", "product": "Postfix smtpd"}, {"port": 8006, "service": "wpl-analytics"}]
    linux = [("Linux 5.3 - 5.4", 94, "general purpose", "Linux")]
    assert summarize(_nm(ports, linux), virtual_guest=True)["device_type"] == "server"
    pmg = [{"port": 8006, "service": "https", "product": "Proxmox Mail Gateway"}]
    assert summarize(_nm(pmg, linux))["device_type"] != "hypervisor"
    # 實體主機上的 8006 照舊是 Proxmox VE
    assert summarize(_nm([{"port": 8006, "service": "wpl-analytics"}], linux))["device_type"] == "hypervisor"


def test_ambiguous_fingerprint_does_not_pick_a_device_class() -> None:
    """192.0.2.185（網卡是 Dyson）：前四名都是 90%，交換器／影音設備／影音設備／手機 → 以前判成 HP 交換器。"""
    from app.services.ip_identify import summarize
    os = [("HP ProCurve E2910al switch", 90, "switch", "HP"),
          ("Slingbox Pro-HD TV over IP gateway", 90, "media device", "Sling"),
          ("Denon AVR-2113 audio receiver", 90, "media device", "Denon"),
          ("Nokia 5800 mobile phone (Symbian OS 9.4)", 90, "phone", "Nokia")]
    s = summarize(_nm([], os), mac_vendor="Dyson")
    assert s["device_type"] == "specialized", "指紋不採用；Dyson 只做家電 → 網卡廠牌當最後的線索"
    assert not any(e.startswith("osclass:") for e in s["evidence"]) and "oui-kind:Dyson" in s["evidence"]
    assert s["os"] is None, "猜不出來的指紋也不該寫成作業系統"
    assert summarize(_nm([], os), mac_vendor="SomeOtherCo")["device_type"] == "unknown"


def test_fingerprint_class_must_agree_with_the_nic_vendor() -> None:
    """atomcam-01（網卡 ATOMtech，ATOM Cam 攝影機）：指紋是 Linux 2.4 的 OpenWrt（WAP）→ 以前判成無線 AP。
    指紋的類別只是「這個 TCP/IP 指紋常見於哪種機器」；廠牌對不上就不採信。"""
    from app.services.ip_identify import summarize
    os = [("OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34)", 97, "WAP", "Linux"),
          ("OpenWrt White Russian 0.9 (Linux 2.4.30)", 97, "WAP", "Linux"),
          ("Asus RT-AC66U router (Linux 2.6)", 95, "broadband router", "Asus")]
    assert summarize(_nm([{"port": 9999, "service": "abyss"}], os), mac_vendor="ATOMtech")["device_type"] != "wireless_ap"
    # D-Link 交換器：指紋廠牌與網卡廠牌一致 → 照算
    sw = [("D-Link DGS-1510 switch", 98, "switch", "D-Link")]
    assert summarize(_nm([], sw), mac_vendor="DLinkInterna")["device_type"] == "switch"
    # 不知道網卡廠牌（沒有 MAC）時照舊採信
    assert summarize(_nm([], sw))["device_type"] == "switch"


def test_mobile_phone_fingerprint_is_not_a_voip_phone() -> None:
    from app.services.ip_identify import summarize
    os = [("Apple iOS 14.0 - 15.6 (Darwin 20.0.0 - 21.6.0)", 98, "phone", "Apple")]
    assert summarize(_nm([], os))["device_type"] != "voip"


def test_nic_vendor_is_reported_separately_from_the_device_vendor() -> None:
    """網卡廠牌（MAC 的 OUI）不等於設備廠牌：Mac 接 CalDigit 擴充座，以前畫面寫「廠牌 CalDigit」。"""
    from app.services.ip_identify import summarize
    s = summarize(_mac_airplay(), mac_vendor="CalDigit")
    assert s["nic_vendor"] == "CalDigit"
    assert s["vendor"] != "CalDigit"
    hp = summarize(_nm([], [("HP LaserJet M476dw printer", 98, "printer", "HP")]), mac_vendor="HP")
    assert hp["vendor"] == "HP" and hp["nic_vendor"] == "HP"


def test_xrdp_on_linux_is_not_a_windows_host() -> None:
    """ws-ud24（Ubuntu，裝了 xrdp）：3389 開著 → 以前判成 Windows 主機。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13"},
             {"port": 3389, "service": "ms-wbt-server", "product": "xrdp"}]
    assert summarize(_nm(ports, [("Linux 5.0 - 5.14", 98, "general purpose", "Linux")]))["device_type"] == "server"
    assert summarize(_nm(ports))["device_type"] == "server", "xrdp 本身就說明不是 Windows"
    # 作業系統確定是 Linux 時，沒有產品字樣的 3389 也不算 Windows
    bare = [{"port": 3389, "service": "ms-wbt-server"}]
    assert summarize(_nm(bare, [("Linux 5.0 - 5.14", 98, "general purpose", "Linux")]))["device_type"] == "server"
    assert summarize(_nm(bare))["device_type"] == "windows"


def test_phones_and_tablets_are_mobile() -> None:
    """192.0.2.166（iPhone，隨機 MAC）被判成 Windows 主機；ipad 以前是「影音設備」。"""
    from app.services.ip_identify import summarize
    iphone = [{"port": 62078, "service": "iphone-sync"}]
    assert summarize(_nm(iphone))["device_type"] == "mobile"
    ipad = [{"port": 49152, "service": "tcpwrapped"}, {"port": 62078, "service": "tcpwrapped"}]
    os = [("Apple macOS 10.13 (High Sierra) - 10.15 (Catalina) or iOS 11.0 - 13.4 (Darwin 17.0.0 - 19.6.0)", 90,
           "phone", "Apple"), ("Apple macOS 11 (Big Sur) (Darwin 20.6.0)", 90, "general purpose", "Apple")]
    s = summarize(_nm(ipad, os))
    assert s["device_type"] == "mobile", "62078 只有 iOS 會開"
    assert "iOS" in (s["os"] or ""), "iPhone 與 Mac 的指紋幾乎一樣；62078 說明是 iOS，作業系統取 iOS 那個候選"
    android = [("Android 10 - 12 (Linux 4.14 - 4.19)", 96, "phone", "Google")]
    assert summarize(_nm([], android))["device_type"] == "mobile"


LINUX100 = [("Linux 5.0 - 5.4", 100, "general purpose", "Linux")]


def test_samba_ad_dc_msrpc_on_linux_is_not_windows() -> None:
    """samba-dc-01／samba-dc-02（Debian 上的 Samba AD DC）：nmap 把 Samba 的 135 認成「Microsoft Windows RPC」→ 知識表的產品樣式
    判成 Windows（2026-10-05 正式環境）。作業系統確定不是 Windows 時，任何一條路講 Windows 都不採信。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1 Debian 2+deb12u7"},
             {"port": 53, "service": "domain"}, {"port": 88, "service": "kerberos-sec"},
             {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC", "method": "probed"},
             {"port": 139, "service": "netbios-ssn", "product": "Samba smbd", "version": "4"},
             {"port": 445, "service": "netbios-ssn", "product": "Samba smbd", "version": "4"}]
    s = summarize(_nm(ports, LINUX100))
    assert s["device_type"] == "server", s["evidence"]
    # 虛擬機（samba-dc-01 是 KVM）同樣不可以是 Windows
    assert summarize(_nm(ports, LINUX100), virtual_guest="vm")["device_type"] != "windows"
    # 反向代理轉出 IIS 的 Server 標頭、主機本身是 Linux：也不是 Windows
    iis = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13"},
           {"port": 443, "service": "https", "scripts": {"http-server-header": "Microsoft-IIS/10.0"}}]
    assert summarize(_nm(iis, LINUX100))["device_type"] != "windows"
    # 不知道作業系統時，msrpc 的產品字樣照舊算 Windows
    assert summarize(_nm([{"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC",
                           "method": "probed"}]))["device_type"] == "windows"


def test_port_8006_on_ubuntu_is_not_proxmox() -> None:
    """gpu-node-01（NVIDIA DGX，Ubuntu）：8006 是別的服務。Proxmox VE 一定是 Debian。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13.18"},
             {"port": 8006, "service": "wpl-analytics"}]
    assert summarize(_nm(ports, LINUX100), mac_vendor="NVIDIA")["device_type"] == "server"
    pve = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1 Debian 2+deb12u3"},
           {"port": 8006, "service": "wpl-analytics"}]
    assert summarize(_nm(pve, LINUX100))["device_type"] == "hypervisor"


def test_nfs_on_a_samba_domain_controller_is_not_storage() -> None:
    """samba-dc-01（Debian 上的 Samba AD DC）開了 NFS → 以前判成儲存設備。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1 Debian 2+deb12u7"},
             {"port": 88, "service": "kerberos-sec"}, {"port": 445, "service": "netbios-ssn", "product": "Samba smbd"},
             {"port": 2049, "service": "rpcbind"}]
    assert summarize(_nm(ports, LINUX100))["device_type"] == "server"
    # 沒有一般作業系統的指紋、只有 iSCSI → 照舊是儲存設備
    assert summarize(_nm([{"port": 3260, "service": "iscsi"}]))["device_type"] == "storage"


def test_rtsp_misdetected_on_web_ports_is_not_a_camera() -> None:
    """sso-01（Keycloak）：nmap 把 8080／8443 的網頁認成 rtsp → 以前判成攝影機。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13.19"},
             {"port": 8080, "service": "rtsp"}, {"port": 8443, "service": "rtsp"}]
    assert summarize(_nm(ports, LINUX100))["device_type"] == "server"
    # 攝影機（Linux）的 554 照舊算
    assert summarize(_nm([{"port": 554, "service": "rtsp"}], LINUX100))["device_type"] == "camera"


def test_supermicro_bmc_is_specialized() -> None:
    """192.0.2.63：SuperMicro 網卡、Dropbear、UPnP、VNC（iKVM）→ BMC。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "Dropbear sshd", "version": "2019.78"},
             {"port": 80, "service": "http"}, {"port": 443, "service": "https"},
             {"port": 5900, "service": "vnc"}]
    os = [("OpenWrt Kamikaze 7.09 (Linux 2.6.22)", 94, "WAP", "Linux"), ("Linux 3.12 - 4.10", 94, "general purpose", "Linux")]
    assert summarize(_nm(ports, os), mac_vendor="SuperMicroCo")["device_type"] == "specialized"
    assert summarize(_nm([{"port": 623, "service": "asf-rmcp"}]))["device_type"] == "specialized"


def test_single_purpose_nic_vendors_hint_the_kind_when_nothing_else_does() -> None:
    from app.services.ip_identify import summarize
    silent = {"nmap": {"available": True, "closed": 999, "ports": [], "os": []}}
    assert summarize(silent, mac_vendor="Nintendo")["device_type"] == "media"
    assert summarize(silent, mac_vendor="ATOMtech")["device_type"] == "camera"
    assert summarize(silent, mac_vendor="Dyson")["device_type"] == "specialized"
    # 2026-10-05 改成廠牌名稱完全相等才算：IPAM 拿到的是 Wireshark manuf 的短名稱，Brother 的是「BrotherIndus」。
    # 以前這裡寫 "Brother"，是靠子字串比對才過的 —— 同一個比對也讓「McKayBrother」變成印表機
    assert summarize(silent, mac_vendor="BrotherIndus")["device_type"] == "printer"
    assert summarize(silent, mac_vendor="McKayBrother")["device_type"] == "unknown"
    assert summarize(silent, mac_vendor="SomeOtherCo")["device_type"] == "unknown"
    # 服務證據講出別的時，網卡廠牌不蓋過它
    assert summarize(_nm([{"port": 9100, "service": "jetdirect", "product": "HP JetDirect"}]),
                     mac_vendor="Nintendo")["device_type"] == "printer"


def test_consistent_embedded_fingerprint_is_specialized_even_if_vendor_differs() -> None:
    """ps-001（TP-Link 網卡）：指紋前幾名都是 lwIP 的嵌入式設備（Philips Hue、Enlogic PDU…）→ 專用設備。"""
    from app.services.ip_identify import summarize
    os = [("Philips Hue Bridge (lwIP stack)", 94, "specialized", "Philips"),
          ("Enlogic PDU (FreeRTOS/lwIP)", 91, "specialized", "Enlogic")]
    assert summarize(_nm([{"port": 9999, "service": "abyss"}], os), mac_vendor="TPLink")["device_type"] == "specialized"


def test_guest_fallback_only_for_containers() -> None:
    """沒有任何服務講出角色時：LXC 容器＝Linux 主機；KVM 虛擬機不知道（可能是防火牆或 Windows）。"""
    from app.services.ip_identify import summarize
    tw = {"nmap": {"available": True, "closed": 5, "ports": [{"port": 22, "proto": "tcp", "state": "open",
                                                             "service": "tcpwrapped"}], "os": []}}
    assert summarize(tw, virtual_guest="ct")["device_type"] == "server"
    assert summarize(tw, virtual_guest="vm")["device_type"] == "unknown"


def test_device_fingerprint_name_is_not_an_os_when_the_vendor_disagrees() -> None:
    """CyberPower UPS 與 TP-Link 插座的作業系統都寫成「Philips Hue Bridge」（對抗式驗證 2026-10-05）。"""
    from app.services.ip_identify import summarize
    os = [("Philips Hue Bridge (lwIP stack)", 94, "specialized", "Philips"),
          ("Enlogic PDU (FreeRTOS/lwIP)", 91, "specialized", "Enlogic")]
    s = summarize(_nm([], os), mac_vendor="CyberPower")
    assert s["device_type"] == "specialized" and s["os"] is None


def test_consistent_wap_fingerprint_on_an_ap_vendor_nic() -> None:
    """ap-hall-01（Ubiquiti 網卡、Dropbear、指紋前幾名都是 WAP）以前判不出來。"""
    from app.services.ip_identify import summarize
    os = [("OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34)", 97, "WAP", "Linux"),
          ("OpenWrt White Russian 0.9 (Linux 2.4.30)", 97, "WAP", "Linux")]
    ports = [{"port": 22, "service": "ssh", "product": "Dropbear sshd"}]
    assert summarize(_nm(ports, os), mac_vendor="Ubiquiti")["device_type"] == "wireless_ap"
    assert summarize(_nm(ports, os), mac_vendor="ATOMtech")["device_type"] != "wireless_ap"


def test_lpd_on_routers_and_nas_is_not_a_printer() -> None:
    """198.51.100.2 VigorAP903、198.51.100.6 Synology RT1900ac：分享 USB 印表機開著 515（LPD）→ 以前判成印表機。"""
    from app.services.ip_identify import summarize
    ap = [{"port": 23, "service": "telnet", "product": "BusyBox telnetd"},
          {"port": 80, "service": "http", "product": "GoAhead WebServer"}, {"port": 515, "service": "printer"}]
    assert summarize(_nm(ap, [("Linux 3.2 - 3.8", 100, "general purpose", "Linux")]))["device_type"] != "printer"
    # Recog 認出 DrayTek（作業系統家族＝網通設備）時也一樣
    assert summarize(_nm(ap, [("DrayTek Vigor 2910 router", 95, "broadband router", "DrayTek")]),
                     mac_vendor="DrayTek")["device_type"] == "router"
    # 真的印表機：認出產品
    assert summarize(_nm([{"port": 515, "service": "printer", "product": "Brother printer lpd"}]))["device_type"] == "printer"


def test_samba_on_linux_is_not_a_windows_host() -> None:
    from app.services.ip_identify import summarize
    linux_smb = [{"port": 22, "service": "ssh", "product": "OpenSSH"},
                 {"port": 445, "service": "microsoft-ds", "product": "Samba smbd"}]
    assert summarize(_res(linux_smb))["device_type"] == "server"
    win = [{"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows Server 2019 microsoft-ds"},
           {"port": 3389, "service": "ms-wbt-server"}]
    assert summarize(_res(win, os_type=None))["device_type"] == "windows"


# ─────────────────── 代理：憑證完整欄位與主機層腳本（給 Recog 比對用） ───────────────────

def test_agent_reports_full_certificate_names_and_host_scripts() -> None:
    mod = _agent_module()
    xml = """<?xml version="1.0"?><nmaprun><host><status state="up" reason="user-set"/>
<address addr="198.51.100.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="https" method="table" conf="3"/>
<script id="ssl-cert" output="Subject: commonName=ExampleGate/organizationName=Example Networks"><table key="subject">
<elem key="commonName">ExampleGate</elem><elem key="countryName">US</elem>
<elem key="organizationalUnitName">ExampleGate</elem><elem key="localityName">Springfield</elem>
</table><table key="issuer"><elem key="commonName">ExampleGate CA</elem></table>
<table key="pubkey"><elem key="bits">2048</elem></table></script></port></ports>
<hostscript><script id="smb-os-discovery" output="&#xa;  OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)&#xa;"/></hostscript>
</host></nmaprun>"""
    out = mod._parse_nmap_xml(xml)
    cert = out["ports"][0]["script_data"]["ssl-cert"]
    # 文字輸出沒有 OU／L；Recog 的設備預設憑證常常要靠這兩個欄位
    assert cert["subject"] == {"commonName": "ExampleGate", "countryName": "US",
                               "organizationalUnitName": "ExampleGate", "localityName": "Springfield"}
    assert cert["issuer"] == {"commonName": "ExampleGate CA"}
    # smb-os-discovery 是主機層腳本：以前整段被丟掉
    assert out["host_scripts"]["smb-os-discovery"].startswith("OS: Windows 10 Pro 19045")


async def test_the_probe_page_judges_a_container_like_the_periodic_probe(client, auth_headers, db_session) -> None:
    """同一台、不同入口要同一個判讀：PVE 回報這個位址是容器 → 手動「探測」的摘要也不拿 nmap 指紋的類別與廠牌
    （定期 OS 偵測已經這樣做；探測頁沒帶「是虛擬機／容器」時，同一台在兩個畫面一個伺服器、一個 HP 儲存設備）。"""
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface
    ip, _ = await _setup(db_session)
    cl = VirtCluster(name=f"pve-{uuid.uuid4().hex[:4]}", type="proxmox")
    db_session.add(cl)
    await db_session.flush()
    ct = VirtualMachine(cluster_id=cl.id, name="ct-app-01", kind="ct")
    db_session.add(ct)
    await db_session.flush()
    db_session.add(VMInterface(vm_id=ct.id, name="eth0", primary_ip="198.51.100.7"))
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ip.id}/identify", headers=auth_headers)
    job = await db_session.get(AgentProbeJob, uuid.UUID(r.json()["job_id"]))
    job.status = STATUS_DONE
    job.result = {"nmap": {"available": True, "ports": [], "closed": 5,
                           "os": [{"name": "HP P2000 G3 NAS device", "accuracy": 93,
                                   "type": "storage-misc", "vendor": "HP"}]}}
    await db_session.commit()
    body = (await client.get(f"/api/v1/addresses/{ip.id}/identify/{job.id}", headers=auth_headers)).json()
    assert body["summary"]["device_type"] == "server"
    assert body["summary"]["vendor"] != "HP"
    items = (await client.get(f"/api/v1/addresses/{ip.id}/identify/history", headers=auth_headers)).json()["items"]
    assert items[0]["summary"]["device_type"] == "server"


# ── 對抗式驗證第二輪（2026-10-05）：規則要在任何網路都成立 ───────────────────────────────────────────

def test_a_linux_fingerprint_alone_does_not_make_a_server() -> None:
    """TCP/IP 指紋的「general purpose」只代表 Linux 核心：路由器、AP、IoT 閘道全是 Linux（198.51.100.53
    只開 80、198.51.100.130 只開 443／8800，都被判成伺服器）。要看得到一般主機的正面證據才算。"""
    from app.services.ip_identify import summarize
    old = [("Linux 3.2 - 3.8", 90, "general purpose", "Linux")]
    assert summarize(_nm([{"port": 80, "service": "http"}], old))["device_type"] == "unknown"
    gw = [{"port": 443, "service": "https"}, {"port": 8800, "service": "sunwebadmin"}]
    assert summarize(_nm(gw, [("Linux 2.6.30", 90, "general purpose", "Linux")]))["device_type"] == "unknown"
    # BusyBox 是嵌入式設備：同一台另外開著 OpenSSH 也不算一般主機
    bb = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.0"},
          {"port": 23, "service": "telnet", "product": "BusyBox telnetd"}]
    assert summarize(_nm(bb, old))["device_type"] != "server"
    # 正面證據：OpenSSH（RHEL 系的 banner 不帶發行版）、發行版字樣、資料庫、Samba
    for ports in ([{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.7"}],
                  [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13"}],
                  [{"port": 5432, "service": "postgresql", "product": "PostgreSQL DB"}],
                  [{"port": 445, "service": "netbios-ssn", "product": "Samba smbd"}]):
        assert summarize(_nm(ports, LINUX100))["device_type"] == "server", ports
    # Windows／macOS 的指紋本身就說明是一般電腦
    win = {"nmap": {"available": True, "closed": 900, "ports": [], "os": [
        {"name": "Microsoft Windows 10 1607", "accuracy": 96, "type": "general purpose", "vendor": "Microsoft",
         "family": "Windows"}]}}
    assert summarize(win)["device_type"] == "windows"
    mac = {"nmap": {"available": True, "closed": 900, "ports": [], "os": [
        {"name": "Apple macOS 13 (Ventura)", "accuracy": 95, "type": "general purpose", "vendor": "Apple",
         "family": "macOS"}]}}
    assert summarize(mac)["device_type"] == "server"


def test_iapp_on_an_embedded_device_is_an_access_point() -> None:
    """3517/tcp（802.11 IAPP，AP 之間的漫遊協定）：嵌入式 Linux 上開著 → AP（198.51.100.3 VigorAP903 以前是伺服器）。"""
    from app.services.ip_identify import summarize
    ap = [{"port": 22, "service": "ssh"}, {"port": 23, "service": "telnet", "product": "BusyBox telnetd"},
          {"port": 80, "service": "http"}, {"port": 515, "service": "printer"},
          {"port": 3517, "service": "802-11-iapp", "method": "table"}]
    old = [("Linux 3.2 - 3.8", 100, "general purpose", "Linux")]
    assert summarize(_nm(ap, old), mac_vendor="DrayTek")["device_type"] == "wireless_ap"
    # 一般主機上剛好開著 3517 不算
    srv = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1 Debian 2+deb12u7"},
           {"port": 3517, "service": "802-11-iapp", "method": "table"}]
    assert summarize(_nm(srv, LINUX100))["device_type"] == "server"


def test_a_multi_line_vendor_without_a_model_is_not_a_router() -> None:
    """DrayTek 同時做 Vigor 路由器、VigorAP、VigorSwitch，網頁標題都是 Vigor：只有網卡廠牌或沒有型號的
    「DrayTek Vigor」說不出是哪一種（198.51.100.2 VigorAP903 被判成路由器）。有型號才算。"""
    from app.services.ip_identify import summarize
    ap = [{"port": 23, "service": "telnet", "product": "BusyBox telnetd"},
          {"port": 80, "service": "http", "product": "GoAhead WebServer"}, {"port": 515, "service": "printer"}]
    old = [("Linux 3.2 - 3.8", 100, "general purpose", "Linux")]
    assert summarize(_nm(ap, old), mac_vendor="DrayTek")["device_type"] not in ("router", "server")
    assert summarize(_nm([{"port": 443, "service": "https", "product": "DrayTek Vigor"}]))["device_type"] != "router"
    for prod, kind in (("Vigor2927", "router"), ("DrayTek Vigor ADSL router httpd", "router"),
                       ("VigorAP 903", "wireless_ap"), ("VigorSwitch G1282", "switch")):
        assert summarize(_nm([{"port": 443, "service": "https", "product": prod}]))["device_type"] == kind, prod


def test_port_8006_with_mail_or_datacenter_manager_ports_is_not_proxmox_ve() -> None:
    """Proxmox Mail Gateway 的管理頁也在 8006（同時開 25／26），Proxmox Datacenter Manager 在 8443：
    實體主機上只認得埠號時，這兩種都不是虛擬化主機。只開 8006／8007（PVE＋PBS）照舊是。"""
    from app.services.ip_identify import summarize
    deb = {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "10.0p2 Debian 7+deb13u4"}
    pve = {"port": 8006, "service": "wpl-analytics", "method": "table"}
    pmg = [deb, {"port": 25, "service": "smtp", "product": "Postfix smtpd"}, {"port": 26, "service": "smtp"}, pve]
    assert summarize(_nm(pmg, LINUX100))["device_type"] == "server"
    pdm = [deb, pve, {"port": 8443, "service": "https-alt"}]
    assert summarize(_nm(pdm, LINUX100))["device_type"] == "server"
    node = [deb, pve, {"port": 8007, "service": "ajp12", "method": "table"}]
    assert summarize(_nm(node, LINUX100))["device_type"] == "hypervisor"


def test_tapo_ship_header_is_a_smart_home_device() -> None:
    """TP-Link Tapo／Kasa 新款的網頁 Server 標頭是「SHIP 2.0」（一個 P105 插座只剩主機名稱可判）。
    同一台串流 RTSP（554）就是攝影機。"""
    from app.services.ip_identify import summarize
    plug = [{"port": 80, "service": "http", "product": "SHIP 2.0"}]
    assert summarize(_nm(plug), mac_vendor="TPLink")["device_type"] == "specialized"
    cam = [*plug, {"port": 554, "service": "rtsp"}, {"port": 2020, "service": "xinupageserver"}]
    assert summarize(_nm(cam), mac_vendor="TPLink")["device_type"] == "camera"


def test_lockdownd_with_airplay_is_apple_tv_not_a_phone() -> None:
    """62078 只有 Apple 的行動裝置會開，但 Apple TV／HomePod 也會；它們同時是 AirPlay 接收器（7000）。"""
    from app.services.ip_identify import summarize
    assert summarize(_nm([{"port": 62078, "service": "iphone-sync"}]))["device_type"] == "mobile"
    atv = [{"port": 7000, "service": "rtsp", "product": "AirTunes rtspd"}, {"port": 62078, "service": "iphone-sync"}]
    assert summarize(_nm(atv))["device_type"] == "media"


def test_windows_stack_fingerprint_beats_a_container_banner() -> None:
    """Windows 桌機用 Docker Desktop 把 Ubuntu 底的容器發布在本機 IP：SSH 寫著 Ubuntu，但 TCP/IP 堆疊是 Windows
    ——「作業系統不是 Windows」要看堆疊指紋，應用程式的 banner 不算。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13.5"},
             {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC"},
             {"port": 445, "service": "microsoft-ds"}, {"port": 3389, "service": "ms-wbt-server"}]
    ports[0]["scripts"] = {"banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"}
    win = [("Microsoft Windows 10 1709 - 21H2", 97, "general purpose", "Microsoft")]
    from app.services import recog
    db = recog.parse_database(b"""<fingerprints matches="ssh.banner" preference="0.9">
  <fingerprint pattern="^OpenSSH_([\\w.]+) Ubuntu-\\S+$">
    <description>OpenSSH running on Ubuntu</description>
    <example>OpenSSH_9.6p1 Ubuntu-3ubuntu13.5</example>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="0" name="os.vendor" value="Ubuntu"/>
    <param pos="0" name="os.family" value="Linux"/>
    <param pos="0" name="os.product" value="Linux"/>
  </fingerprint>
</fingerprints>""", "ssh_banners.xml")
    matcher = recog.Matcher("9.9.9", {db.key: (db.preference, db.fingerprints)})
    s = summarize(_nm(ports, win), recog=matcher)
    assert any(e.startswith("recog:") for e in s["evidence"]), "測試本身要讓 Recog 比中 Ubuntu"
    assert s["device_type"] == "windows", s["evidence"]
    assert "windows" in (s["os"] or "").lower(), s["os"]


def test_debian_release_from_the_ssh_banner_replaces_a_vague_kernel_range() -> None:
    """Debian 11／13 的虛擬機顯示「Linux 2.6.32」：SSH banner 的 debNNuM 講得出是哪一版 Debian。"""
    from app.core.os_fingerprint import normalize_os
    from app.services.ip_identify import summarize
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.4p1 Debian 5+deb11u3"}]
    s = summarize(_nm(ports, [("Linux 2.6.32", 93, "general purpose", "Linux")]))
    assert "Debian" in (s["os"] or "") and "11" in (s["os"] or ""), s["os"]
    assert normalize_os(s["os"]) == "linux"
    # 堆疊指紋是 Windows 時不改（banner 可能來自容器）
    win = [("Microsoft Windows Server 2019", 96, "general purpose", "Microsoft")]
    assert "windows" in (summarize(_nm(ports, win))["os"] or "").lower()


def test_mobile_evidence_names_the_os_that_was_chosen() -> None:
    """192.0.2.166 iPhone：作業系統已改取 iOS 的候選，依據卻還寫 Big Sur。"""
    from app.services.ip_identify import summarize
    ports = [{"port": 49152, "service": "tcpwrapped"}, {"port": 62078, "service": "iphone-sync"}]
    os = [("Apple macOS 10.13 (High Sierra) - 10.15 (Catalina) or iOS 11.0 - 13.4 (Darwin 17.0.0 - 19.6.0)", 90,
           "phone", "Apple"), ("Apple macOS 11 (Big Sur) (Darwin 20.6.0)", 90, "general purpose", "Apple")]
    s = summarize(_nm(ports, os))
    line = next(e for e in s["evidence"] if e.startswith("os:"))
    assert "iOS" in line and "Big Sur" not in line, s["evidence"]


async def test_a_running_probe_can_be_cancelled_and_a_late_result_is_ignored(client, auth_headers, db_session) -> None:
    """探測卡住（例如部署重啟時代理的回報掉了）要能取消，不必等滿 9 分鐘（使用者 2026-10-07）。"""
    from app.models.background_task import BackgroundTask
    raw = "c" * 40
    ip, _ = await _agent_with_key(db_session, raw)
    ip_id = ip.id
    job_id = (await client.post(f"/api/v1/addresses/{ip_id}/identify", headers=auth_headers)).json()["job_id"]
    await client.get("/api/v1/scan-agents/jobs", headers={"X-Agent-Key": raw})      # 代理領走 → running

    r = await client.post(f"/api/v1/addresses/{ip_id}/identify/{job_id}/cancel", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = (await client.get(f"/api/v1/addresses/{ip_id}/identify/{job_id}", headers=auth_headers)).json()
    assert body["status"] == "failed" and "取消" in (body.get("error") or "")
    db_session.expire_all()
    task = (await db_session.execute(select(BackgroundTask).where(
        BackgroundTask.kind == "ip.identify"))).scalars().all()[-1]
    assert task.status == "cancelled"

    # 代理之後才回報：不可以把取消掉的工作改回完成
    r = await client.post(f"/api/v1/scan-agents/jobs/{job_id}/result", json={"result": {"names": {}}},
                          headers={"X-Agent-Key": raw})
    body = (await client.get(f"/api/v1/addresses/{ip_id}/identify/{job_id}", headers=auth_headers)).json()
    assert body["status"] == "failed"
    # 取消後可以馬上再探測一次（同一個位址同時只能一個，取消的不算進行中）
    again = await client.post(f"/api/v1/addresses/{ip_id}/identify", headers=auth_headers)
    assert again.status_code == 202, again.text
    # 稽核
    from app.models.audit import AuditLog
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "identify_cancel"))).scalars().all()
    assert rows


async def test_finished_probes_cannot_be_cancelled(client, auth_headers, db_session) -> None:
    ip, agent = await _setup(db_session)
    job = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.7"]},
                        status="done", result={}, expires_at=datetime.now(UTC))
    db_session.add(job)
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ip.id}/identify/{job.id}/cancel", headers=auth_headers)
    assert r.status_code == 409
