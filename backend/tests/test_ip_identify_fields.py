"""IP「探測」：把已經抓到的資料正確顯示出來、修掉判讀錯誤（使用者 2026-10-07「要做」）。

不多送任何封包、不擴大掃描範圍（腳本清單與連接埠不變）。分兩類：
- 已經抓到、但畫面沒顯示：Windows 電腦名稱／網域、TLS 憑證的簽發者／到期日／指紋、SSH 主機金鑰、
  關閉與過濾的埠數、耗時與有沒有做 OS 指紋、名稱的來源、判斷的理由、跟上一次比的範圍
- 有資料卻顯示錯：nmap 失敗被當成「沒有回應」、IPv6 一定失敗、作業系統空白（SMB／RDP 有講）、
  MAC 與廠牌對不上、照埠號猜的服務看起來像認出來、上一次沒回應時全部埠都算「新開」、截斷沒有標記
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import pathlib
import uuid
from datetime import UTC, datetime, timedelta

from app.services.ip_identify import changes_between, summarize


def _agent_module():  # type: ignore[no-untyped-def]
    path = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"
    spec = importlib.util.spec_from_file_location(f"jt_agent_fields_{uuid.uuid4().hex[:6]}", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _self_signed_pem() -> tuple[str, str, str]:
    """(PEM, SHA-256 hex, SHA-1 hex)"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nas-07.example.net")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem, cert.fingerprint(hashes.SHA256()).hex(), cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303


def _ed25519_blob() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return pub.decode().split()[1]


def _sha256_fp(blob: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")


# ─────────────────── 代理 1.17.4：從既有輸出多解析幾個欄位 ───────────────────

def test_agent_version_is_at_least_1_17_4() -> None:
    assert tuple(int(x) for x in _agent_module().AGENT_VERSION.split(".")) >= (1, 17, 4)


def test_agent_reports_filtered_ports_distance_uptime_and_whether_the_host_was_in_the_output() -> None:
    mod = _agent_module()
    xml = """<nmaprun><host><status state="up" reason="user-set"/>
      <address addr="198.51.100.71" addrtype="ipv4"/>
      <ports><extraports state="filtered" count="990"/><extraports state="closed" count="7"/>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
        <port protocol="tcp" portid="23"><state state="filtered"/></port>
      </ports>
      <uptime seconds="1036800" lastboot="Mon Sep 26 08:00:00 2026"/>
      <distance value="2"/>
    </host></nmaprun>"""
    out = mod._parse_nmap_xml(xml)
    assert out["filtered"] == 991
    assert out["closed"] == 7
    assert out["distance"] == 2
    assert out["uptime"] == {"seconds": 1036800, "lastboot": "Mon Sep 26 08:00:00 2026"}
    assert out["host_found"] is True and out["timedout"] is False
    # nmap 跑完但輸出裡沒有這台（失敗、被略過）：跟「這台沒回應」是兩回事
    assert mod._parse_nmap_xml("<nmaprun></nmaprun>")["host_found"] is False
    timed = mod._parse_nmap_xml("""<nmaprun><host timedout="true"><status state="up" reason="user-set"/>
      <address addr="198.51.100.71" addrtype="ipv4"/></host></nmaprun>""")
    assert timed["host_found"] is True and timed["timedout"] is True


def test_agent_reports_certificate_validity_and_fingerprints_without_the_pem() -> None:
    mod = _agent_module()
    pem, sha256, sha1 = _self_signed_pem()
    xml = f"""<nmaprun><host><status state="up" reason="user-set"/>
<address addr="198.51.100.72" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" method="probed" conf="10"/>
<script id="ssl-cert" output="Subject: commonName=nas-07.example.net"><table key="subject">
<elem key="commonName">nas-07.example.net</elem></table>
<table key="issuer"><elem key="commonName">nas-07.example.net</elem></table>
<table key="pubkey"><elem key="type">ec</elem><elem key="bits">256</elem></table>
<table key="extensions"><table><elem key="name">X509v3 Subject Alternative Name</elem>
<elem key="value">DNS:nas-07.example.net, DNS:nas-07, IP Address:198.51.100.72</elem></table></table>
<elem key="sig_algo">ecdsa-with-SHA256</elem>
<table key="validity"><elem key="notBefore">2026-09-15T23:40:01</elem><elem key="notAfter">2026-12-14T23:40:00</elem></table>
<elem key="md5">f0fcdfd580b7392be505891472edfe0d</elem><elem key="sha1">{sha1}</elem>
<elem key="pem">{pem}</elem></script></port></ports></host></nmaprun>"""
    cert = mod._parse_nmap_xml(xml)["ports"][0]["script_data"]["ssl-cert"]
    assert cert["not_before"] == "2026-09-15T23:40:01"
    assert cert["not_after"] == "2026-12-14T23:40:00"
    assert cert["sha1"] == sha1
    assert cert["sha256"] == sha256, "nmap 7.94 不給 SHA-256：代理自己從 PEM 算"
    assert (cert["key_type"], cert["key_bits"]) == ("ec", 256)
    assert cert["san"] == ["DNS:nas-07.example.net", "DNS:nas-07", "IP Address:198.51.100.72"]
    assert "pem" not in cert and "-----BEGIN" not in str(cert), "整張憑證不送回伺服器"


def test_agent_reports_ssh_host_keys_as_sha256_fingerprints() -> None:
    mod = _agent_module()
    blob = _ed25519_blob()
    xml = f"""<nmaprun><host><status state="up" reason="user-set"/>
<address addr="198.51.100.73" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="probed" conf="10"/>
<script id="ssh-hostkey" output="&#xa;  256 2d:9e (ED25519)"><table>
<elem key="bits">256</elem><elem key="fingerprint">2d9eddc05b22c965011da7725b6ff75c</elem>
<elem key="key">{blob}</elem><elem key="type">ssh-ed25519</elem></table></script></port></ports></host></nmaprun>"""
    keys = mod._parse_nmap_xml(xml)["ports"][0]["script_data"]["ssh-hostkey"]
    assert keys == [{"type": "ssh-ed25519", "bits": 256, "sha256": _sha256_fp(blob)}]


def test_agent_marks_script_output_that_was_cut() -> None:
    mod = _agent_module()
    long = "x" * (mod._IDENTIFY_MAX_TEXT + 50)
    xml = f"""<nmaprun><host><status state="up" reason="user-set"/>
<address addr="198.51.100.74" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
<script id="ssl-cert" output="{long}"/><script id="http-title" output="short"/></port></ports>
<hostscript><script id="smb-os-discovery" output="{long}"/></hostscript></host></nmaprun>"""
    out = mod._parse_nmap_xml(xml)
    assert out["ports"][0]["truncated"] == ["ssl-cert"]
    assert out["host_scripts_truncated"] == ["smb-os-discovery"]


def test_agent_probes_ipv6_with_dash_6_and_says_whether_it_did_os_detection(monkeypatch) -> None:
    mod = _agent_module()
    seen: list[list[str]] = []

    class _R:
        returncode, stdout, stderr = 0, "<nmaprun></nmaprun>", ""

    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(mod.subprocess, "run", lambda argv, **kw: (seen.append(argv), _R())[1])
    for fn in ("_rdns",):
        monkeypatch.setattr(mod, fn, lambda ip: (None, None))
    monkeypatch.setattr(mod, "_netbios", lambda ip: None)
    monkeypatch.setattr(mod, "_mdns", lambda ip: None)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1000, raising=False)
    out = mod._job_run_identify("2001:db8::7")
    assert "-6" in seen[-1]
    assert out["nmap"]["os_scan"] is False, "不是 root 時 nmap 不做 OS 指紋，畫面要講原因"
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0, raising=False)
    out = mod._job_run_identify("198.51.100.75")
    assert "-6" not in seen[-1]
    assert out["nmap"]["os_scan"] is True


# ─────────────────── 摘要：nmap 失敗不是「沒有回應」 ───────────────────

_NAMES = {"rdns": None, "netbios": None, "mdns": None}


def test_a_failed_nmap_run_is_not_reported_as_no_response() -> None:
    failed = {"names": _NAMES, "nmap": {"available": True, "exit": 1, "ports": [], "os": [], "closed": 0,
                                        "host_found": False, "stderr": "Failed to resolve given hostname/IP"}}
    s = summarize(failed)
    assert s["no_response"] is False and s["device_type"] == "unknown"
    assert s["scan_failed"] is True and "Failed to resolve" in (s["scan_error"] or "")
    # 結束碼 0 但輸出裡沒有這台
    missing = {"names": _NAMES, "nmap": {"available": True, "exit": 0, "ports": [], "os": [], "closed": 0,
                                         "host_found": False}}
    assert summarize(missing)["scan_failed"] is True
    # 逾時、例外
    assert summarize({"names": _NAMES, "nmap": {"available": True, "error": "nmap timed out after 300s"}})["scan_failed"]
    # 單台時限到了：nmap 丟掉這台的結果
    timed = {"names": _NAMES, "nmap": {"available": True, "exit": 0, "ports": [], "os": [], "closed": 0,
                                       "host_found": True, "timedout": True}}
    assert summarize(timed)["scan_failed"] is True and summarize(timed)["no_response"] is False
    # 舊代理（沒有 host_found）、真的沒回應：照舊是沒有回應
    silent = {"names": _NAMES, "nmap": {"available": True, "exit": 0, "ports": [], "os": [], "closed": 0}}
    s2 = summarize(silent)
    assert s2["no_response"] is True and s2["scan_failed"] is False


# ─────────────────── 摘要：已經抓到的資料 ───────────────────

_RDP = ("\n  Target_Name: CORP\n  NetBIOS_Domain_Name: CORP\n  NetBIOS_Computer_Name: LAPTOP-07\n"
        "  DNS_Domain_Name: corp.example.net\n  DNS_Computer_Name: laptop-07.corp.example.net\n"
        "  DNS_Tree_Name: corp.example.net\n  Product_Version: 10.0.26100\n  System_Time: 2026-10-07T01:02:03+00:00")
_SMB = ("\n  OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)\n  OS CPE: cpe:/o:microsoft:windows_10::-\n"
        "  Computer name: laptop-07\n  NetBIOS computer name: LAPTOP-07\\x00\n  Domain name: corp.example.net\n"
        "  Forest name: corp.example.net\n  FQDN: laptop-07.corp.example.net\n  System time: 2026-10-07T09:02:03+08:00")


def _host(ports=None, **nmap):  # type: ignore[no-untyped-def]
    return {"names": dict(_NAMES), "nmap": {"available": True, "exit": 0, "host_found": True, "os": [],
                                            "closed": 0, "ports": ports or [], **nmap}}


def test_windows_computer_name_and_domain_from_rdp_and_smb() -> None:
    rdp_port = {"port": 3389, "proto": "tcp", "state": "open", "service": "ms-wbt-server",
                "product": "Microsoft Terminal Services", "scripts": {"rdp-ntlm-info": _RDP}}
    s = summarize(_host([rdp_port]))
    assert s["windows"] == {"computer": "LAPTOP-07", "domain": "CORP", "dns_domain": "corp.example.net",
                            "fqdn": "laptop-07.corp.example.net", "workgroup": None, "product_version": "10.0.26100"}
    s2 = summarize(_host([], host_scripts={"smb-os-discovery": _SMB}))
    assert s2["windows"]["computer"] == "LAPTOP-07"
    assert s2["windows"]["fqdn"] == "laptop-07.corp.example.net"
    assert s2["windows"]["dns_domain"] == "corp.example.net"
    wg = summarize(_host([], host_scripts={"smb-os-discovery":
                                           "\n  OS: Windows 10 Home 19045\n  NetBIOS computer name: PC-07\\x00\n"
                                           "  Workgroup: WORKGROUP\\x00\n"}))
    assert wg["windows"]["workgroup"] == "WORKGROUP" and wg["windows"]["computer"] == "PC-07"
    # 名稱清單也有這些，並標出來源
    by = {n["name"]: n["sources"] for n in s["name_sources"]}
    assert by["laptop-07.corp.example.net"] == ["rdp"]
    assert "LAPTOP-07" in s["names"]


def test_os_falls_back_to_what_smb_or_rdp_said() -> None:
    s = summarize(_host([], host_scripts={"smb-os-discovery": _SMB}))
    assert s["os"] == "Windows 10 Pro 19045"
    # Samba 會自稱 Windows 6.1：不採信
    samba = summarize(_host([], host_scripts={"smb-os-discovery": "\n  OS: Windows 6.1 (Samba 4.9.5-Debian)\n"}))
    assert samba["os"] is None
    # 只有 RDP：版本號不分用戶端或伺服器版，照實寫 build
    rdp_port = {"port": 3389, "proto": "tcp", "state": "open", "service": "ms-wbt-server", "scripts": {"rdp-ntlm-info": _RDP}}
    assert summarize(_host([rdp_port]))["os"] == "Windows (build 26100)"
    # 有可信的 OS 指紋時不蓋掉
    fp = summarize(_host([rdp_port], os=[{"name": "Microsoft Windows 11 21H2", "accuracy": 97,
                                          "type": "general purpose", "vendor": "Microsoft", "family": "Windows"}]))
    assert fp["os"] == "Microsoft Windows 11 21H2"


def test_names_say_where_they_came_from() -> None:
    r = _host([], hostnames=["srv-07.example.net"])
    r["names"] = {"rdns": "srv-07.example.net", "netbios": "SRV-07", "mdns": "srv-07.local"}
    s = summarize(r)
    by = {n["name"]: n["sources"] for n in s["name_sources"]}
    assert by == {"srv-07.example.net": ["rdns", "nmap"], "SRV-07": ["netbios"], "srv-07.local": ["mdns"]}
    assert s["names"] == ["srv-07.example.net", "SRV-07", "srv-07.local"]


def test_certificates_and_ssh_keys_are_in_the_summary() -> None:
    blob_fp = "SHA256:AAAAexampleexampleexampleexampleexampleexam"
    ports = [
        {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH",
         "scripts": {"ssh-hostkey": "\n  256 2d:9e (ED25519)"},
         "script_data": {"ssh-hostkey": [{"type": "ssh-ed25519", "bits": 256, "sha256": blob_fp}]}},
        {"port": 443, "proto": "tcp", "state": "open", "service": "https", "scripts": {"ssl-cert": "Subject: commonName=a"},
         "script_data": {"ssl-cert": {"subject": {"commonName": "nas-07.example.net"},
                                      "issuer": {"commonName": "nas-07.example.net"},
                                      "not_before": "2026-09-15T23:40:01", "not_after": "2026-12-14T23:40:00",
                                      "sha1": "aa" * 20, "sha256": "bb" * 32, "key_type": "ec", "key_bits": 256,
                                      "san": ["DNS:nas-07.example.net"]}}},
    ]
    s = summarize(_host(ports))
    assert s["ssh_keys"] == [{"port": "22/tcp", "type": "ssh-ed25519", "bits": 256, "fingerprint": blob_fp}]
    c = s["certs"][0]
    assert c["port"] == "443/tcp" and c["subject"] == "CN=nas-07.example.net"
    assert c["not_after"] == "2026-12-14T23:40:00" and c["sha256"] == "bb" * 32
    assert c["self_signed"] is True and c["key"] == "ec 256" and c["san"] == ["DNS:nas-07.example.net"]


def test_old_agents_text_output_still_gives_expiry_and_key_fingerprints() -> None:
    ports = [
        {"port": 22, "proto": "tcp", "state": "open", "service": "ssh",
         "scripts": {"ssh-hostkey": "\n  256 3d:e7:e6:8b (ECDSA)\n  256 2d:9e:dd:c0 (ED25519)"}},
        {"port": 443, "proto": "tcp", "state": "open", "service": "https",
         "scripts": {"ssl-cert": "Subject: commonName=www.example.net\nIssuer: commonName=Example CA/organizationName=Example\n"
                                 "Public Key type: rsa\nPublic Key bits: 2048\nNot valid before: 2026-09-15T23:40:01\n"
                                 "Not valid after:  2026-12-14T23:40:00\nMD5:   f0fc:dfd5\nSHA-1: e20d:4328:427b"}},
    ]
    s = summarize(_host(ports))
    assert [k["type"] for k in s["ssh_keys"]] == ["ECDSA", "ED25519"]
    assert s["ssh_keys"][1]["fingerprint"] == "MD5:2d:9e:dd:c0"
    c = s["certs"][0]
    assert c["subject"] == "CN=www.example.net" and c["issuer"] == "CN=Example CA, O=Example"
    assert c["not_after"] == "2026-12-14T23:40:00" and c["sha1"] == "e20d4328427b" and c["self_signed"] is False


def test_port_counts_distance_uptime_elapsed_and_os_detection() -> None:
    r = _host([{"port": 22, "proto": "tcp", "state": "open", "service": "ssh"}], closed=990, filtered=9,
              distance=2, uptime={"seconds": 1036800, "lastboot": "x"}, os_scan=False)
    r["elapsed"] = 83.4
    s = summarize(r)
    assert s["port_counts"] == {"open": 1, "closed": 990, "filtered": 9}
    assert s["distance"] == 2 and s["uptime_seconds"] == 1036800 and s["elapsed"] == 83.4
    assert s["os_scan"] is False
    assert {"code": "no_os_scan", "params": {}} in s["notes"]
    # 舊代理沒有過濾數：不寫 0（不知道就是不知道）
    assert summarize(_host([], closed=3))["port_counts"] == {"open": 0, "closed": 3, "filtered": None}


def test_the_reasons_behind_the_conclusion_are_listed() -> None:
    low = summarize(_host([], closed=5, os=[{"name": "Linux 4.15", "accuracy": 80, "type": "general purpose",
                                             "vendor": "Linux", "family": "Linux"}]))
    assert {"code": "os_low_accuracy", "params": {"acc": 80, "min": 85}} in low["notes"]
    amb = summarize(_host([], closed=5, os=[
        {"name": "HP switch", "accuracy": 90, "type": "switch", "vendor": "HP", "family": "embedded"},
        {"name": "Sony media", "accuracy": 90, "type": "media device", "vendor": "Sony", "family": "embedded"}]))
    assert any(n["code"] == "os_ambiguous" for n in amb["notes"])
    guest = summarize(_host([], closed=5, os=[{"name": "Linux 5.X", "accuracy": 95, "type": "general purpose",
                                               "vendor": "Linux", "family": "Linux"}]), virtual_guest="vm")
    assert any(n["code"] == "guest_fp_ignored" for n in guest["notes"])
    guessed = summarize(_host([{"port": 9100, "proto": "tcp", "state": "open", "service": "jetdirect", "method": "table"}]))
    assert {"code": "port_table_guess", "params": {"ports": "9100/tcp"}} in guessed["notes"]
    rnd = summarize(_host([], closed=5), mac="02:00:5e:00:53:07", mac_vendor=None)
    assert any(n["code"] == "mac_random" for n in rnd["notes"])


def test_the_mac_shown_is_the_one_the_vendor_came_from_and_a_different_one_is_flagged() -> None:
    r = _host([], closed=5, mac="00:00:5E:00:53:99", mac_vendor="ICANN")
    s = summarize(r, mac="00:00:5e:00:53:07", mac_vendor="Example Corp")
    assert s["mac"] == "00:00:5e:00:53:07" and s["mac_seen"] == "00:00:5E:00:53:99"
    assert {"code": "mac_differs", "params": {"seen": "00:00:5E:00:53:99"}} in s["notes"]
    same = summarize(r, mac="00:00:5E:00:53:99", mac_vendor="ICANN")
    assert not any(n["code"] == "mac_differs" for n in same["notes"]), "大小寫不同不算不同"
    # 沒給 MAC（未登記、ARP 也沒有）：用 nmap 看到的
    assert summarize(r)["mac"] == "00:00:5E:00:53:99"


# ─────────────────── 跟上一次比 ───────────────────

_SSH = {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6p1"}


def test_a_silent_previous_probe_does_not_make_every_port_new() -> None:
    prev = _host([])
    cur = _host([_SSH, {"port": 443, "proto": "tcp", "state": "open", "service": "https"}])
    ch = changes_between(prev, cur)
    assert ch["opened"] == [] and ch["baseline"] == "no_response"
    # 反過來：這次沒回應，不是全部關掉了
    ch2 = changes_between(cur, prev)
    assert ch2["closed"] == [] and ch2["current"] == "no_response"
    # 失敗的那次也不能拿來比
    failed = _host([], exit=1, host_found=False, stderr="boom")
    assert changes_between(failed, cur)["baseline"] == "scan_failed"


def test_changes_cover_mac_os_type_names_keys_and_certificates() -> None:
    a = _host([{**_SSH, "script_data": {"ssh-hostkey": [{"type": "ssh-ed25519", "bits": 256, "sha256": "SHA256:old"}]}},
               {"port": 443, "proto": "tcp", "state": "open", "service": "https",
                "script_data": {"ssl-cert": {"subject": {"commonName": "a.example.net"}, "issuer": {"commonName": "CA"},
                                             "not_after": "2026-10-30T00:00:00", "sha256": "11" * 32}}}],
              mac="00:00:5E:00:53:01")
    b = _host([{**_SSH, "script_data": {"ssh-hostkey": [{"type": "ssh-ed25519", "bits": 256, "sha256": "SHA256:new"}]}},
               {"port": 443, "proto": "tcp", "state": "open", "service": "https",
                "script_data": {"ssl-cert": {"subject": {"commonName": "a.example.net"}, "issuer": {"commonName": "CA"},
                                             "not_after": "2027-01-30T00:00:00", "sha256": "22" * 32}}}],
              mac="00:00:5E:00:53:02")
    b["names"] = {"rdns": "b.example.net", "netbios": None, "mdns": None}
    sa, sb = summarize(a), summarize(b)
    ch = changes_between(a, b, sa, sb)
    fields = {f["field"]: (f["before"], f["after"]) for f in ch["fields"]}
    assert fields["mac"] == ("00:00:5E:00:53:01", "00:00:5E:00:53:02")
    assert ch["names_added"] == ["b.example.net"] and ch["names_removed"] == []
    assert ch["ssh_keys"] == [{"port": "22/tcp", "type": "ssh-ed25519", "before": "SHA256:old", "after": "SHA256:new"}]
    assert ch["certs"] == [{"port": "443/tcp", "before": {"sha256": "11" * 32, "not_after": "2026-10-30T00:00:00"},
                            "after": {"sha256": "22" * 32, "not_after": "2027-01-30T00:00:00"}}]
    # 沒傳摘要也能比連接埠（舊的呼叫方式）
    assert changes_between(a, b)["opened"] == []


async def test_the_probe_page_compares_keys_and_mac_with_the_previous_probe(client, auth_headers, db_session) -> None:
    from app.models.agent_probe_job import STATUS_DONE, AgentProbeJob
    from tests.test_ip_identify import _setup
    ip, agent = await _setup(db_session)
    base = datetime.now(UTC)

    def res(fp: str, mac: str) -> dict:
        return _host([{**_SSH, "script_data": {"ssh-hostkey": [{"type": "ssh-ed25519", "bits": 256, "sha256": fp}]}}],
                     mac=mac)
    j1 = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.7"]}, status=STATUS_DONE,
                       result=res("SHA256:old", "00:00:5E:00:53:01"), expires_at=base, created_at=base - timedelta(days=1))
    j2 = AgentProbeJob(agent_id=agent.id, kind="identify", params={"targets": ["198.51.100.7"]}, status=STATUS_DONE,
                       result=res("SHA256:new", "00:00:5E:00:53:02"), expires_at=base, created_at=base)
    db_session.add_all([j1, j2])
    await db_session.commit()
    body = (await client.get(f"/api/v1/addresses/{ip.id}/identify/{j2.id}", headers=auth_headers)).json()
    ch = body["changes"]
    assert ch["ssh_keys"] == [{"port": "22/tcp", "type": "ssh-ed25519", "before": "SHA256:old", "after": "SHA256:new"}]
    assert {"field": "mac", "before": "00:00:5E:00:53:01", "after": "00:00:5E:00:53:02"} in ch["fields"]
    assert body["summary"]["ssh_keys"][0]["fingerprint"] == "SHA256:new"
