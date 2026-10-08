"""Recog 指紋資料庫（rapid7/recog）：探測用它認出 nmap 認不出的設備與更精確的 OS。

- Ruby 正規式要轉成 Python：轉不過去、或轉完比不中自己附的範例的規則一律剔除（不可以默默比錯）
- 下載的檔案不可信任：只讀 xml/*.xml、大小有上限、XML 走 defusedxml
- 選用元件：沒裝時探測照常；更新失敗不可以動到現有的一版
"""
from __future__ import annotations

import io
import re
import zipfile

import pytest
from app.services import recog
from app.services.ip_identify import recog_observations, summarize

# ─────────────────── Ruby → Python ───────────────────


@pytest.mark.parametrize(("ruby", "python"), [
    (r"^foo\z", r"^foo\Z"),
    (r"^foo\Z", r"^foo(?=\n?\Z)"),
    (r"^v(\h+)$", r"^v([0-9a-fA-F]+)$"),
    (r"^[\h:]+$", r"^[0-9a-fA-F:]+$"),
    (r"^[[:alpha:]][[:digit:]]$", r"^[a-zA-Z][0-9]$"),
    (r"^(?<ver>\d+)-\k<ver>$", r"^(?P<ver>\d+)-(?P=ver)$"),
    (r"(?m)^a.b$", r"(?s)^a.b$"),
    (r"(?i)^foo$", r"(?i)^foo$"),
    # 寫在中間的 (?i)：Ruby 管到所屬群組結束；Python 3.11 起不接受 → 包成 (?i:…)
    (r"^(?i)Cisco (\d+)$", r"^(?i:Cisco (\d+)$)"),
    (r"^a((?i)b)c$", r"^a((?i:b))c$"),
    (r"^(?<=x)y(?<!z)$", r"^(?<=x)y(?<!z)$"),
    (r"^[\]a]$", r"^[\]a]$"),
])
def test_translate(ruby: str, python: str) -> None:
    assert recog.translate(ruby) == python
    re.compile(python)


@pytest.mark.parametrize("ruby", [r"\Gfoo", r"^\p{Alpha}$", r"^(foo$", r"^foo)$", "^[abc$"])
def test_translate_refuses_what_python_cannot_do(ruby: str) -> None:
    with pytest.raises(ValueError, match=r"unsupported|unbalanced|unterminated"):
        recog.translate(ruby)


def test_ruby_line_anchors_and_flags() -> None:
    # Ruby 的 ^ $ 一律逐行；REG_DOT_NEWLINE ＝ . 也比對換行
    assert recog.compile_pattern(r"^login:$", None).search("Welcome\nlogin:")
    rx = recog.compile_pattern(r"^a.b$", "REG_DOT_NEWLINE,REG_ICASE")
    assert rx.search("A\nB")


@pytest.mark.parametrize("pattern", [r"^(.+)* http", r"^(\d+)+$", r"^([a-z]*)*x", r"^(?:\S+)+$"])
def test_catastrophic_backtracking_shapes_are_refused(pattern: str) -> None:
    # banner 是被掃的主機給的：(.+)* 這種寫法遇到惡意字串會回溯到指數時間
    with pytest.raises(ValueError, match="nested quantifier"):
        recog.compile_pattern(pattern, None)


@pytest.mark.parametrize("pattern", [r"^(\d+(?:\.\d+)*)$", r"^OpenSSH_(\S+) (\w+)$", r"^v((?:\d+\.)*\d+)$"])
def test_separated_repetition_is_fine(pattern: str) -> None:
    recog.compile_pattern(pattern, None)


# ─────────────────── 解析指紋檔 ───────────────────

FTP_XML = b"""<?xml version='1.0' encoding='UTF-8'?>
<fingerprints matches="ftp.banner" protocol="ftp" database_type="service" preference="0.90">
  <fingerprint pattern="^(\\S+) ExampleFTP (\\d+\\.\\d+) ready$">
    <description>ExampleFTP</description>
    <example host.name="ftp.example.net" service.version="2.1">ftp.example.net ExampleFTP 2.1 ready</example>
    <param pos="1" name="host.name"/>
    <param pos="0" name="service.product" value="ExampleFTP"/>
    <param pos="2" name="service.version"/>
    <param pos="0" name="service.cpe23" value="cpe:/a:example:exampleftp:{service.version}"/>
  </fingerprint>
  <fingerprint pattern="^BrokenExample (\\d+)$">
    <description>its own example does not match -- must be dropped</description>
    <example>Something else entirely</example>
    <param pos="0" name="service.product" value="Broken"/>
  </fingerprint>
  <fingerprint pattern="^WrongParam (\\d+)$">
    <description>captures the wrong value -- must be dropped</description>
    <example service.version="9">WrongParam 7</example>
    <param pos="1" name="service.version"/>
  </fingerprint>
  <fingerprint pattern="^B64 (\\w+)$">
    <description>base64 example</description>
    <example _encoding="base64" service.version="ok">QjY0IG9r</example>
    <param pos="1" name="service.version"/>
  </fingerprint>
  <fingerprint pattern="^(?i)Generic FTP$" certainty="0.8">
    <description>mid-pattern inline flag</description>
    <example>GENERIC ftp</example>
    <param pos="0" name="service.product" value="Generic"/>
  </fingerprint>
</fingerprints>
"""


def test_parse_database_keeps_only_fingerprints_that_pass_their_examples() -> None:
    db = recog.parse_database(FTP_XML, "xml/ftp_banners.xml")
    assert (db.key, db.protocol, db.preference) == ("ftp.banner", "ftp", 0.9)
    assert db.total == 5
    assert db.skipped == 2
    assert [fp["d"] for fp in db.fingerprints] == ["ExampleFTP", "base64 example", "mid-pattern inline flag"]
    assert db.fingerprints[2]["c"] == "0.8"


def test_database_without_matches_attribute_uses_the_file_name() -> None:
    xml = b"""<fingerprints protocol="telnet"><fingerprint pattern="^login:$">
      <description>login prompt</description><example>login:</example></fingerprint></fingerprints>"""
    assert recog.parse_database(xml, "xml/telnet_banners.xml").key == "telnet_banners"


def test_parse_database_blocks_xml_entities() -> None:
    evil = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>
      <fingerprints matches="x"><fingerprint pattern="&e;"><description>x</description></fingerprint></fingerprints>"""
    from defusedxml import DefusedXmlException
    with pytest.raises(DefusedXmlException):
        recog.parse_database(evil, "xml/evil.xml")


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_parse_bundle_reads_only_xml_files_under_xml() -> None:
    data = _zip({
        "xml/ftp_banners.xml": FTP_XML,
        "xml/fingerprints.xsd": b"<schema/>",
        "../evil.xml": FTP_XML,
        "xml/../../evil2.xml": FTP_XML,
        "README.md": b"hello",
    })
    dbs = recog.parse_bundle(data)
    assert [d.key for d in dbs] == ["ftp.banner"]


def test_parse_bundle_rejects_bad_input(monkeypatch) -> None:
    with pytest.raises(recog.RecogError):
        recog.parse_bundle(b"not a zip")
    with pytest.raises(recog.RecogError):
        recog.parse_bundle(_zip({"README.md": b"no fingerprints here"}))
    monkeypatch.setattr(recog, "MAX_TOTAL_XML_BYTES", 100)
    with pytest.raises(recog.RecogError):
        recog.parse_bundle(_zip({"xml/ftp_banners.xml": FTP_XML}))


# ─────────────────── 比對 ───────────────────

def _matcher(*xmls: tuple[str, bytes]) -> recog.Matcher:
    dbs = [recog.parse_database(x, name) for name, x in xmls]
    return recog.Matcher("9.9.9", {d.key: (d.preference, d.fingerprints) for d in dbs})


def test_matcher_first_match_wins_and_interpolates() -> None:
    m = _matcher(("xml/ftp_banners.xml", FTP_XML))
    got = m.match("ftp.banner", "ftp.example.net ExampleFTP 2.1 ready")
    assert got["description"] == "ExampleFTP"
    assert got["params"]["service.cpe23"] == "cpe:/a:example:exampleftp:2.1"
    assert m.match("ftp.banner", "nothing like it") is None
    assert m.match("no.such.db", "x") is None
    assert m.match("ftp.banner", "") is None


def test_matcher_input_is_capped() -> None:
    m = _matcher(("xml/ftp_banners.xml", FTP_XML))
    # 超過上限的部分不看：比對時間的最壞情況有上限
    assert m.match("ftp.banner", "x" * 10_000) is None


# ─────────────────── 探測摘要整合 ───────────────────

SSH_XML = b"""<fingerprints matches="ssh.banner" preference="0.90">
  <fingerprint pattern="^OpenSSH_([\\w.]+) Ubuntu-\\S+$">
    <description>OpenSSH running on Ubuntu</description>
    <example service.version="9.6p1">OpenSSH_9.6p1 Ubuntu-3ubuntu13.4</example>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="os.vendor" value="Ubuntu"/>
    <param pos="0" name="os.product" value="Linux"/>
    <param pos="0" name="os.certainty" value="0.75"/>
  </fingerprint>
</fingerprints>"""

X509_XML = b"""<fingerprints matches="x509.subject">
  <fingerprint pattern="^CN=ExampleGate,OU=ExampleGate,O=Example Networks,L=Springfield,C=US$">
    <description>Example Networks firewall default certificate</description>
    <example>CN=ExampleGate,OU=ExampleGate,O=Example Networks,L=Springfield,C=US</example>
    <param pos="0" name="hw.vendor" value="Example Networks"/>
    <param pos="0" name="hw.device" value="Firewall"/>
    <param pos="0" name="hw.product" value="EG-100"/>
    <param pos="0" name="os.product" value="ExampleOS"/>
  </fingerprint>
</fingerprints>"""

ISSUER_XML = b"""<fingerprints matches="x509.issuer">
  <fingerprint pattern="^CN=R3,O=Let's Encrypt,C=US$">
    <description>Lets Encrypt R3 - generic -- assert nothing.</description>
    <example>CN=R3,O=Let's Encrypt,C=US</example>
    <param pos="0" name="hw.certainty" value="0.0"/>
    <param pos="0" name="os.certainty" value="0.0"/>
    <param pos="0" name="service.certainty" value="0.0"/>
  </fingerprint>
</fingerprints>"""

HTTP_XML = b"""<fingerprints matches="http_header.server" preference="0.9">
  <fingerprint pattern="^ExampleCam-httpd/([\\d.]+)$">
    <description>Example camera web server</description>
    <example service.version="1.2">ExampleCam-httpd/1.2</example>
    <param pos="0" name="service.product" value="ExampleCam httpd"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="hw.device" value="IP Camera"/>
    <param pos="0" name="hw.vendor" value="ExampleCam"/>
  </fingerprint>
</fingerprints>"""

SMB_XML = b"""<fingerprints matches="smb.native_os">
  <fingerprint pattern="^Windows 10 (Pro|Enterprise) (\\d+)$">
    <description>Windows 10</description>
    <example os.edition="Pro" os.build="19045">Windows 10 Pro 19045</example>
    <param pos="0" name="os.vendor" value="Microsoft"/>
    <param pos="0" name="os.product" value="Windows 10"/>
    <param pos="1" name="os.edition"/>
    <param pos="2" name="os.build"/>
  </fingerprint>
</fingerprints>"""


def _all() -> recog.Matcher:
    return _matcher(("xml/ssh_banners.xml", SSH_XML), ("xml/x509_subjects.xml", X509_XML),
                    ("xml/x509_issuers.xml", ISSUER_XML), ("xml/http_servers.xml", HTTP_XML),
                    ("xml/smb_native_os.xml", SMB_XML))


def _res(ports, **nmap):
    return {"nmap": {"available": True, "ports": [{"proto": "tcp", "state": "open", **p} for p in ports],
                     "os": nmap.pop("os", []), **nmap}}


def test_ssh_comment_gives_a_more_precise_os_than_the_tcp_fingerprint() -> None:
    res = _res([{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1",
                 "scripts": {"banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4"}}],
               os=[{"name": "Linux 4.15 - 5.8", "accuracy": 96, "type": "general purpose"}])
    assert summarize(res)["os"] == "Linux 4.15 - 5.8"
    s = summarize(res, recog=_all())
    assert s["os"] == "Ubuntu Linux"
    assert "os:Linux 4.15 - 5.8 (96%)" in s["evidence"]            # nmap 的依據照樣列著
    assert "recog:OpenSSH running on Ubuntu (22/tcp ssh.banner)" in s["evidence"]


def test_default_certificate_identifies_the_device() -> None:
    # 新版代理回報完整的 Subject 欄位（文字輸出只有 CN／O／ST／C）
    res = _res([{"port": 443, "service": "https", "scripts": {"ssl-cert": "Subject: commonName=ExampleGate"},
                 "script_data": {"ssl-cert": {
                     "subject": {"commonName": "ExampleGate", "countryName": "US", "localityName": "Springfield",
                                 "organizationName": "Example Networks", "organizationalUnitName": "ExampleGate"},
                     "issuer": {"commonName": "R3", "organizationName": "Let's Encrypt", "countryName": "US"}}}}])
    s = summarize(res, recog=_all())
    assert s["device_type"] == "firewall"
    assert s["vendor"] == "Example Networks"
    assert s["model"] == "EG-100"
    assert s["os"] == "ExampleOS"
    # Let's Encrypt 那條是「不下結論」：比中了也不列進依據
    assert not any("Lets Encrypt" in e for e in s["evidence"])


def test_recog_device_beats_the_port_heuristics_and_vendors_stay_apart() -> None:
    # 開了 RTSP 的 NAS 以前被判成攝影機；反過來，Recog 認得的攝影機網頁伺服器要判成攝影機
    res = _res([{"port": 80, "service": "http", "scripts": {"http-server-header": "ExampleCam-httpd/1.2"}},
                {"port": 5060, "service": "sip"}])
    assert summarize(res)["device_type"] == "voip"
    s = summarize(res, recog=_all(), mac_vendor="Some NIC Maker")
    assert s["device_type"] == "camera"
    # 網卡廠牌（OUI）與設備廠牌（服務自己講的）分開：網卡的品牌不等於設備的品牌（2026-10-05）
    assert s["nic_vendor"] == "Some NIC Maker"
    assert s["vendor"] == "ExampleCam"
    assert "ExampleCam httpd 1.2" in s["applications"]            # nmap 沒認出產品 → 用 Recog 的


def test_recog_does_not_add_noise_for_ports_nmap_already_knows() -> None:
    res = _res([{"port": 80, "service": "http", "product": "ExampleCam httpd", "version": "1.2",
                 "scripts": {"http-server-header": "ExampleCam-httpd/1.2"}}])
    s = summarize(res, recog=_all())
    assert s["applications"] == ["ExampleCam httpd 1.2"]


def test_smb_host_script_gives_the_windows_edition() -> None:
    res = _res([{"port": 445, "service": "microsoft-ds"}],
               host_scripts={"smb-os-discovery": "\n  OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)\n  Computer name: pc1"})
    s = summarize(res, recog=_all())
    assert s["os"] == "Microsoft Windows 10 Pro"
    assert s["device_type"] == "windows"


def test_without_recog_the_summary_is_unchanged() -> None:
    res = _res([{"port": 22, "service": "ssh", "scripts": {"banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4"}}])
    s = summarize(res)
    assert s["model"] is None
    assert not any(e.startswith("recog:") for e in s["evidence"])


def test_observations_from_nmap_output() -> None:
    nmap = {"ports": [
        {"port": 21, "service": "ftp", "state": "open",
         "scripts": {"banner": "220 ftp.example.net ExampleFTP 2.1 ready\\x0D\\x0A"}},
        {"port": 25, "service": "smtp", "state": "open", "scripts": {"banner": "220 mx.example.net ESMTP"}},
        {"port": 110, "service": "pop3", "state": "open", "scripts": {"banner": "+OK Dovecot ready."}},
        {"port": 143, "service": "imap", "state": "open",
         "scripts": {"banner": "* OK [CAPABILITY IMAP4rev1 LITERAL+] Dovecot ready."}},
        {"port": 23, "service": "telnet", "state": "open",
         "scripts": {"banner": "\\xFF\\xFD\\x18\\xFF\\xFD\\x20\\x0D\\x0Alogin:"}},
        {"port": 80, "service": "http", "state": "open",
         "scripts": {"http-title": "Site doesn't have a title (text/html).", "http-server-header": "nginx"}},
        {"port": 8080, "service": "http", "state": "open",
         "scripts": {"http-title": "\\xE7\\xAE\\xA1\\xE7\\x90\\x86\\xE4\\xBB\\x8B\\xE9\\x9D\\xA2\nRequested resource was /login"}},
        {"port": 8443, "service": "https", "state": "open",
         "scripts": {"ssl-cert": "Subject: commonName=a.example.net/organizationName=Acme, Inc./countryName=US\n"
                                 "Issuer: commonName=Acme CA/organizationName=Acme, Inc."}},
    ]}
    obs = recog_observations(nmap)
    assert ("ftp.banner", "21/tcp", "ftp.example.net ExampleFTP 2.1 ready") in obs
    assert ("smtp.banner", "25/tcp", "mx.example.net ESMTP") in obs
    assert ("pop3.banner", "110/tcp", "Dovecot ready.") in obs
    assert ("imap4.banner", "143/tcp", "Dovecot ready.") in obs
    assert ("telnet_banners", "23/tcp", "login:") in obs                  # 去掉 telnet 協商位元組
    assert ("http_header.server", "80/tcp", "nginx") in obs
    assert not any(k == "html_title" and w == "80/tcp" for k, w, _ in obs)   # 「沒有標題」不是標題
    assert ("html_title", "8080/tcp", "管理介面") in obs                  # nmap 的 \\xHH 解回中文
    # 舊版代理只有文字：值裡的逗號要跳脫
    assert ("x509.subject", "8443/tcp", "CN=a.example.net,O=Acme\\, Inc.,C=US") in obs
    assert ("x509.issuer", "8443/tcp", "CN=Acme CA,O=Acme\\, Inc.") in obs


# ─────────────────── 資料表：安裝、檢查、更新 ───────────────────

def _bundle() -> bytes:
    return _zip({"xml/ftp_banners.xml": FTP_XML, "xml/ssh_banners.xml": SSH_XML,
                 "xml/x509_subjects.xml": X509_XML})


@pytest.fixture
def small_bundles_ok(monkeypatch):
    monkeypatch.setattr(recog, "MIN_FINGERPRINTS", 1)
    recog.reset_cache()
    yield
    recog.reset_cache()


async def test_install_then_match_through_the_database(db_session, small_bundles_ok) -> None:
    assert await recog.installed(db_session) is None
    assert await recog.get_matcher(db_session) is None
    res = await recog.install_bundle(db_session, _bundle(), version="3.2.0", source="test")
    await db_session.commit()
    assert res == {"release": "3.2.0", "databases": 3, "fingerprints": 5, "skipped": 2}
    st = await recog.status(db_session)
    assert (st["installed"], st["release"], st["fingerprints"], st["skipped"]) == (True, "3.2.0", 5, 2)
    m = await recog.get_matcher(db_session)
    assert m is not None
    assert m.release == "3.2.0"
    assert m.match("ssh.banner", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.4")["params"]["os.vendor"] == "Ubuntu"


async def test_a_suspiciously_small_bundle_never_replaces_the_installed_one(db_session, small_bundles_ok,
                                                                        monkeypatch) -> None:
    await recog.install_bundle(db_session, _bundle(), version="3.2.0", source="test")
    await db_session.commit()
    monkeypatch.setattr(recog, "MIN_FINGERPRINTS", 1000)
    with pytest.raises(recog.RecogError):
        await recog.install_bundle(db_session, _bundle(), version="3.3.0", source="test")
    await db_session.rollback()
    assert (await recog.installed(db_session))["release"] == "3.2.0"


async def test_check_and_update(db_session, small_bundles_ok, monkeypatch) -> None:
    downloads: list[str] = []

    async def latest():
        return recog.Release(version=state["latest"], url="https://example.net/recog.zip")

    async def download(rel):
        downloads.append(rel.version)
        return _bundle()

    state = {"latest": "3.2.0"}
    monkeypatch.setattr(recog, "latest_release", latest)
    monkeypatch.setattr(recog, "download", download)

    r = await recog.check_and_update(db_session)
    await db_session.commit()
    assert (r["status"], r["release"], r["previous"]) == ("updated", "3.2.0", None)

    # 同一版：只記錄檢查時間，不重新下載
    r = await recog.check_and_update(db_session)
    await db_session.commit()
    assert r["status"] == "up_to_date"
    assert downloads == ["3.2.0"]

    # 轉換規則改了：同一版也要重新匯入
    monkeypatch.setattr(recog, "TRANSLATOR_VERSION", recog.TRANSLATOR_VERSION + 1)
    r = await recog.check_and_update(db_session)
    await db_session.commit()
    assert r["status"] == "updated"
    assert downloads == ["3.2.0", "3.2.0"]

    state["latest"] = "3.3.0"
    r = await recog.check_and_update(db_session)
    await db_session.commit()
    assert (r["status"], r["previous"], r["release"]) == ("updated", "3.2.0", "3.3.0")
    st = await recog.status(db_session)
    assert (st["release"], st["latest"], st["error"]) == ("3.3.0", "3.3.0", None)


async def test_a_failed_check_is_recorded_and_keeps_the_installed_version(db_session, small_bundles_ok,
                                                                        monkeypatch) -> None:
    await recog.install_bundle(db_session, _bundle(), version="3.2.0", source="test")
    await db_session.commit()

    async def latest():
        raise recog.RecogError("cannot reach GitHub (test)")

    monkeypatch.setattr(recog, "latest_release", latest)
    r = await recog.check_and_update(db_session)
    await db_session.commit()
    assert (r["status"], r["release"]) == ("error", "3.2.0")
    st = await recog.status(db_session)
    assert st["installed"]
    assert st["release"] == "3.2.0"
    assert "cannot reach GitHub" in st["error"]


def test_version_from_filename() -> None:
    assert recog.version_from_filename("downloads/recog-content-3.2.0.zip") == "3.2.0"
    assert recog.version_from_filename("recog.zip") is None


# ─────────────────── 版本頁與「立即檢查更新」 ───────────────────

async def test_version_page_lists_recog_as_an_optional_database(client, auth_headers, db_session,
                                                              small_bundles_ok) -> None:
    r = await client.get("/api/v1/system/version", headers=auth_headers)
    assert r.status_code == 200, r.text
    entry = r.json()["host"]["optional_tools"]["recog"]
    assert entry["present"] is False
    assert "rapid7/recog" in entry["package"]

    await recog.install_bundle(db_session, _bundle(), version="3.2.0", source="test")
    await db_session.commit()
    body = (await client.get("/api/v1/system/version", headers=auth_headers)).json()
    assert body["host"]["optional_tools"]["recog"]["present"] is True
    assert body["recog"]["release"] == "3.2.0"
    assert body["recog"]["license"] == "BSD-2-Clause"


async def test_update_now_is_audited(client, auth_headers, db_session, small_bundles_ok, monkeypatch) -> None:
    from app.models.audit import AuditLog
    from sqlalchemy import select

    async def latest():
        return recog.Release(version="3.2.0", url="https://example.net/recog.zip")

    async def download(rel):
        return _bundle()

    monkeypatch.setattr(recog, "latest_release", latest)
    monkeypatch.setattr(recog, "download", download)
    r = await client.post("/api/v1/system/recog/update", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["result"]["status"] == "updated"
    assert r.json()["status"]["release"] == "3.2.0"
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.object_type == "system"))).scalars().all()
    assert any((a.diff or {}).get("target") == "recog_db_update" for a in rows)


async def test_recog_page_status_lists_each_database(client, auth_headers, db_session, small_bundles_ok) -> None:
    """Recog 獨立頁（比照 MAC 製造商資料庫頁）：狀態＋每個指紋檔的筆數，詳細資訊不再放在版本頁。"""
    empty = await client.get("/api/v1/system/recog/status", headers=auth_headers)
    assert empty.status_code == 200, empty.text
    assert empty.json()["installed"] is False
    assert empty.json()["database_list"] == []

    await recog.install_bundle(db_session, _bundle(), version="3.2.0", source="test")
    await db_session.commit()
    body = (await client.get("/api/v1/system/recog/status", headers=auth_headers)).json()
    assert body["release"] == "3.2.0"
    dbs = body["database_list"]
    assert dbs
    assert all({"key", "protocol", "fingerprints"} <= set(d) for d in dbs)
    assert sum(d["fingerprints"] for d in dbs) == body["fingerprints"]
    assert (await client.get("/api/v1/system/recog/status")).status_code in (401, 403)


async def test_update_now_is_admin_only(client, db_session) -> None:
    r = await client.post("/api/v1/system/recog/update")
    assert r.status_code in (401, 403)


# ─────────────────── 系統診斷 ───────────────────

async def test_doctor_reports_recog(db_session, small_bundles_ok) -> None:
    from datetime import UTC, datetime, timedelta

    from app.services.self_check import _recog_check

    c = await _recog_check(db_session)
    assert (c.status, c.detail_key) == ("warn", "doctor.d_recog_missing")
    assert "app.cli.recog update" in c.fix                    # 沒裝：要講怎麼裝

    await recog.install_bundle(db_session, _bundle(), version="3.2.0", source="test")
    await db_session.commit()
    c = await _recog_check(db_session)
    assert (c.status, c.params["release"]) == ("ok", "3.2.0")

    # 每週檢查連續失敗三週以上：不是偶爾連不到，要講出來
    await recog._put_state(db_session, last_ok_at=(datetime.now(UTC) - timedelta(days=30)).isoformat(),
                           error="cannot reach GitHub (test)")
    await db_session.commit()
    c = await _recog_check(db_session)
    assert (c.status, c.detail_key) == ("warn", "doctor.d_recog_stale")
    assert c.params["days"] >= 29


def test_a_vendor_default_certificate_name_is_not_a_host_name() -> None:
    """Synology 的出廠憑證 CN 是 synology.com：Recog 認出是預設憑證，就不要列成這台的名稱。"""
    res = _res([{"port": 443, "service": "https",
                 "scripts": {"ssl-cert": "Subject: commonName=gate.example.net"},
                 "script_data": {"ssl-cert": {"subject": {
                     "commonName": "ExampleGate", "organizationalUnitName": "ExampleGate",
                     "organizationName": "Example Networks", "localityName": "Springfield", "countryName": "US"}}}},
                {"port": 8443, "service": "https",
                 "scripts": {"ssl-cert": "Subject: commonName=real-host.example.net"}}])
    s = summarize(res, recog=_all())
    # 寫成集合運算：`"主機名稱" in x` 會被 CodeQL 當成網址子字串檢查（#41／#42），這裡的 names 是清單
    assert not {"gate.example.net"} & set(s["names"])              # 預設憑證那個埠的名稱不算
    assert {"real-host.example.net"} <= set(s["names"])            # 其他憑證照常
    assert {"gate.example.net"} <= set(summarize(res)["names"])    # 沒有 Recog 時維持原本行為


async def test_two_updates_at_once_do_not_collide(db_session, session_factory, small_bundles_ok,
                                                  monkeypatch) -> None:
    """安裝腳本自己的下載與排程同時跑（2026-09-29 全新安裝關卡抓到：timer 的 Requires= 讓
    `enable --now` 順便啟動了 service，兩邊一起寫 → pk_recog_databases 撞鍵）。要排隊，後到的看到已是最新。"""
    import asyncio

    async def latest():
        return recog.Release(version="3.2.0", url="https://example.net/recog.zip")

    async def download(rel):
        await asyncio.sleep(0.3)          # 讓兩邊都走到寫入那一步
        return _bundle()

    monkeypatch.setattr(recog, "latest_release", latest)
    monkeypatch.setattr(recog, "download", download)

    async def run() -> str:
        async with session_factory() as s:
            r = await recog.check_and_update(s)
            await s.commit()
            return r["status"]

    assert sorted(await asyncio.gather(run(), run())) == ["up_to_date", "updated"]


def test_a_wrong_tcp_fingerprint_does_not_decide_the_device_type() -> None:
    """PVE 的 LXC 容器（2026-10-02 使用者回報被判成「儲存設備 · HP」）：容器跟宿主共用核心，
    nmap 的 TCP/IP 指紋第一名是「HP P2000 G3 NAS（93%）」；OpenSSH 的註解卻明講是 Ubuntu。
    OS 已經採信 Recog（Ubuntu），設備類型就不可以再拿被推翻的那個指紋的類別（storage）—— 自相矛盾。"""
    res = _res([{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1",
                 "scripts": {"banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4"}}],
               os=[{"name": "HP P2000 G3 NAS device", "accuracy": 93, "type": "storage-misc", "vendor": "HP"}])
    s = summarize(res, recog=_all())
    assert s["os"] == "Ubuntu Linux"
    assert s["device_type"] == "server"
    assert "osclass:storage-misc" not in s["evidence"]
    assert s["vendor"] != "HP"                                   # 被推翻的指紋的廠牌也不採信
    # 沒有 Recog 時維持原本行為（只能信 nmap）
    assert summarize(res)["device_type"] == "storage"


def test_known_virtual_guests_ignore_the_tcp_fingerprint_class() -> None:
    """已由 Proxmox／VMware 確認是虛擬機或容器：虛擬化讓 TCP/IP 指紋失準，不拿它的類別判斷；
    但服務本身的證據照常（TrueNAS 的 VM 仍然是儲存設備）。"""
    fp = [{"name": "HP P2000 G3 NAS device", "accuracy": 93, "type": "storage-misc", "vendor": "HP"}]
    bare = _res([], os=fp)
    assert summarize(bare)["device_type"] == "storage"
    # 指紋的類別不採信之後就沒有別的證據了：一台虛擬機／容器沒有特定角色的服務，就是一般主機。
    # 不可以停在「不明」—— 不明不會覆寫 IP 上舊的（錯的）「儲存設備」，畫面永遠改不過來
    assert summarize(bare, virtual_guest=True)["device_type"] == "server"
    assert summarize(bare, virtual_guest=True)["vendor"] != "HP"
    win = _res([], os=[{"name": "Microsoft Windows 10 1809", "accuracy": 96, "type": "general purpose",
                        "vendor": "Microsoft"}])
    assert summarize(win, virtual_guest=True)["device_type"] == "windows"
    nas = _res([{"port": 445, "service": "microsoft-ds"}, {"port": 2049, "service": "nfs"},
                {"port": 80, "service": "http", "product": "nginx", "scripts": {"http-title": "TrueNAS"}}], os=fp)
    assert summarize(nas, virtual_guest=True)["device_type"] == "storage"


def test_an_ambiguous_fingerprint_is_not_a_device() -> None:
    """nmap 的積極猜測常把新版 Linux 核心認成「HP P2000 G3 NAS」，與 Linux 的猜測只差 0~1 個百分點（2026-10-04 正式環境，
    兩台同款 SuperMicro 一台判成儲存設備、一台判成伺服器，只看哪一筆剛好排第一）。差距這麼小＝分不出來，不可以當成設備。"""
    hp = {"name": "HP P2000 G3 NAS device", "accuracy": 93, "type": "storage-misc", "vendor": "HP"}
    lin = {"name": "Linux 5.3 - 5.4", "accuracy": 93, "type": "general purpose", "vendor": "Linux"}
    s = summarize(_res([], os=[hp, lin]))
    assert s["device_type"] in ("server", "unknown"), "不可以是儲存設備（只有 Linux 指紋時是不明）"
    assert s["os"] == "Linux 5.3 - 5.4"
    assert s["vendor"] != "HP"
    # 差距夠大才是真的設備
    printer = {"name": "HP LaserJet printer", "accuracy": 98, "type": "printer", "vendor": "HP"}
    assert summarize(_res([], os=[printer, {**lin, "accuracy": 88}]))["device_type"] == "printer"


def test_proxmox_web_port_means_a_hypervisor() -> None:
    """8006 是 Proxmox VE 的網頁介面；版本偵測常認不出它（tcpwrapped），但開著這個埠本身就足以判斷。"""
    res = _res([{"port": 22, "service": "ssh", "product": "OpenSSH"}, {"port": 8006, "service": "tcpwrapped"}],
               os=[{"name": "Linux 5.3 - 5.4", "accuracy": 94, "type": "general purpose", "vendor": "Linux"}])
    assert summarize(res)["device_type"] == "hypervisor"
