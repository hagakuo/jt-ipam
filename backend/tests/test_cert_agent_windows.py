"""Windows / IIS 憑證派送代理：Windows 相容 PKCS#12、agent.ps1 下載、版本比對。

重點在「Windows 匯得進去」這件事 —— PBESv1 是 Windows CryptoAPI 全版本都吃的形式，
所以要斷言真的產出 PBESv1 而不是預設的 PBESv2/AES-256（後者失敗時訊息是誤導的
「密碼不正確」，會讓人往密碼方向查）。理由詳見 `cert_service.export_cert_file`。
"""

from __future__ import annotations

import hashlib
import uuid

from app.api.v1.endpoints import cert_agents as ca
from app.services.cert_service import export_cert_file
from cryptography.hazmat.primitives.serialization import pkcs12

from tests.test_cert_agents_api import _cert_with_version, _make_agent, _make_cert

# DER 編碼的演算法 OID。直接在位元組裡找,才是真的在驗「產出用了哪種加密」,
# 而不是只驗「解得開」（兩種都解得開,但只有一種 Windows 匯得進去）。
_OID_PBES1_SHA1_3DES = bytes.fromhex("060A2A864886F70D010C0103")  # 1.2.840.113549.1.12.1.3
_OID_PBES2 = bytes.fromhex("06092A864886F70D01050D")              # 1.2.840.113549.1.5.13


def test_legacy_pfx_uses_pbesv1_and_default_does_not():
    cert_pem, key_pem = _make_cert("iis.example.com")
    legacy, _, _ = export_cert_file(cert_pem, key_pem, None, "pfx",
                                    name="iis", pfx_password="pw", pfx_legacy=True)
    modern, _, _ = export_cert_file(cert_pem, key_pem, None, "pfx",
                                    name="iis", pfx_password="pw", pfx_legacy=False)

    assert _OID_PBES1_SHA1_3DES in legacy, "legacy PFX 必須是 PBESv1-SHA1-3DES（Windows 匯得進去的那種）"
    assert _OID_PBES2 not in legacy
    # 反向：預設那條確實是 PBESv2 —— 證明這個測試分得出兩者,不是恆真
    assert _OID_PBES2 in modern
    assert _OID_PBES1_SHA1_3DES not in modern

    # 兩種都要能用同一個密碼解開（legacy 不是壞掉的檔）
    for blob in (legacy, modern):
        key, cert, _ = pkcs12.load_key_and_certificates(blob, b"pw")
        assert key is not None and cert is not None


def test_legacy_without_password_is_unencrypted():
    """沒帶密碼時不會誤走 legacy 分支（PBESv1 沒有「空密碼」這種用法）。"""
    cert_pem, key_pem = _make_cert()
    blob, _, _ = export_cert_file(cert_pem, key_pem, None, "pfx", pfx_password="", pfx_legacy=True)
    assert _OID_PBES1_SHA1_3DES not in blob
    key, cert, _ = pkcs12.load_key_and_certificates(blob, None)
    assert key is not None and cert is not None


async def test_bundle_raw_pkcs12_password_header(client, auth_headers):
    cid, name, _ = await _cert_with_version(client, auth_headers)
    key = await _make_agent(client, auth_headers, [cid])

    r = await client.get(f"/api/v1/cert-agents/bundle/raw?cert={name}&part=pkcs12",
                         headers={"X-Agent-Key": key, "X-Pfx-Password": "s3cret"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/x-pkcs12")
    assert _OID_PBES1_SHA1_3DES in r.content, "帶 X-Pfx-Password 時要回 Windows 相容的 PFX"
    pkey, cert, _ = pkcs12.load_key_and_certificates(r.content, b"s3cret")
    assert pkey is not None and cert is not None

    # 不帶 header 維持原本行為（無密碼），既有 jetty 用法不受影響
    r2 = await client.get(f"/api/v1/cert-agents/bundle/raw?cert={name}&part=pkcs12",
                          headers={"X-Agent-Key": key})
    assert r2.status_code == 200
    pkey2, _, _ = pkcs12.load_key_and_certificates(r2.content, None)
    assert pkey2 is not None


async def test_agent_ps1_and_installer_download(client):
    """代理程式本體公開可取（無密鑰，同 agent.sh）。"""
    r = await client.get("/api/v1/cert-agents/agent.ps1")
    assert r.status_code == 200, r.text
    assert "jt-ipam certificate distribution agent for Windows" in r.text
    assert "charset=utf-8" in r.headers["content-type"]

    ri = await client.get("/api/v1/cert-agents/installer.ps1")
    assert ri.status_code == 200
    assert "jt-ipam-cert-agent" in ri.text


async def test_check_json_carries_ps1_sha_and_text_does_not(client, auth_headers):
    cid, _, _ = await _cert_with_version(client, auth_headers)
    key = await _make_agent(client, auth_headers, [cid])

    rj = await client.get("/api/v1/cert-agents/check", headers={"X-Agent-Key": key})
    assert rj.status_code == 200
    expected = hashlib.sha256(ca._AGENT_PS1.read_bytes()).hexdigest()
    assert rj.json()["agent_ps1_sha"] == expected
    assert rj.json()["agent_sha"] != expected, "兩支代理是不同檔案,sha 不該相同"

    # text 格式是純 bash 代理在解析的 —— 新欄位不可以漏進去
    rt = await client.get("/api/v1/cert-agents/check?format=text", headers={"X-Agent-Key": key})
    assert rt.status_code == 200
    assert "agent_ps1_sha" not in rt.text
    assert rt.text.splitlines()[0].startswith("agent_sha=")


def test_server_version_picks_the_matching_agent():
    """Windows 代理要拿 agent.ps1 的版本比,否則永遠被標成「版本落後」。"""
    linux = ca._server_agent_version("0.4.173")
    win = ca._server_agent_version("1.0.0-win")
    assert linux and win
    assert win.endswith("-win")
    assert not linux.endswith("-win")

    # 關鍵性質：代理自報的版本若就是 server 上那支的版本,兩邊必須相等（＝不會誤報落後）
    import re
    ps1_ver = re.search(r'^\$AGENT_VERSION\s*=\s*"([^"]+)"',
                        ca._AGENT_PS1.read_text(), re.M).group(1)
    assert ca._server_agent_version(f"{ps1_ver}-win") == f"{ps1_ver}-win"


async def test_windows_agent_version_reported_and_not_flagged_stale(client, auth_headers):
    """端到端：Windows 代理帶 -win 版本回報後，list 回的 server_agent_version 要對得上。"""
    cid, _, _ = await _cert_with_version(client, auth_headers)
    key = await _make_agent(client, auth_headers, [cid])
    import re
    ps1_ver = re.search(r'^\$AGENT_VERSION\s*=\s*"([^"]+)"',
                        ca._AGENT_PS1.read_text(), re.M).group(1)

    r = await client.get("/api/v1/cert-agents/check",
                         headers={"X-Agent-Key": key, "X-Agent-Version": f"{ps1_ver}-win"})
    assert r.status_code == 200

    rl = await client.get("/api/v1/cert-agents", headers=auth_headers)
    row = next(a for a in rl.json()["items"] if a["agent_version"] == f"{ps1_ver}-win")
    assert row["server_agent_version"] == row["agent_version"], "不該被誤判為版本落後"


def test_agent_sha_distinguishes_platforms():
    assert ca._agent_sha() == hashlib.sha256(ca._AGENT_SH.read_bytes()).hexdigest()
    assert ca._agent_sha(windows=True) == hashlib.sha256(ca._AGENT_PS1.read_bytes()).hexdigest()


async def test_pkcs12_download_is_audited(client, auth_headers, db_session):
    """取 PFX ＝ 取私鑰，一定要留稽核。"""
    from app.models.audit import AuditLog
    from sqlalchemy import func, select

    cid, name, _ = await _cert_with_version(client, auth_headers)
    key = await _make_agent(client, auth_headers, [cid])
    before = (await db_session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    r = await client.get(f"/api/v1/cert-agents/bundle/raw?cert={name}&part=pkcs12",
                         headers={"X-Agent-Key": key, "X-Pfx-Password": uuid.uuid4().hex})
    assert r.status_code == 200
    after = (await db_session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    assert after > before
