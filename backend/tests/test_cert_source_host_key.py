"""憑證派送的 SFTP 來源要釘選主機金鑰（2026-10-06，CodeQL 判讀時發現）。

以前每一次連線都是 `known_hosts=None`：完全不驗主機金鑰、又用密碼登入 —— 網路中間的人冒充 SFTP 主機，
就拿得到密碼。現在第一次連線記下主機金鑰（TOFU），之後每次都要相同，不同就拒絕並列出兩個指紋；
改了主機或埠會重新釘選；主機真的換了金鑰時，管理員確認後可以「重新信任」。

用 asyncssh 在本機起一台真的 SFTP 伺服器，換一把主機金鑰就是「被冒充」。
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import asyncssh
import pytest
from app.models.certificate import Certificate
from app.services import cert_fetch
from tests.test_cert_fetch import _cert


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "certs" and password == "pw-2026"


@asynccontextmanager
async def _sftp_server(root, host_key):
    server = await asyncssh.listen(
        "127.0.0.1", 0, server_factory=_Server, server_host_keys=[host_key],
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(root)))
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def allow_loopback(monkeypatch):
    # 正式環境擋迴路位址（SSRF）；測試的 SFTP 伺服器在本機
    monkeypatch.setattr(cert_fetch, "_check_host_safe", lambda host: None)


async def _source_cert(db_session, port: int) -> Certificate:
    from app.services.cert_fetch import save_cert_secret
    c = Certificate(name=f"c-{uuid.uuid4().hex[:6]}", source_type="sftp",
                    source_config={"host": "127.0.0.1", "port": port, "username": "certs",
                                   "cert_path": "/cert.pem", "key_path": "/key.pem"})
    db_session.add(c)
    await db_session.flush()
    await save_cert_secret(db_session, c.id, "source_password", "pw-2026")
    await db_session.commit()
    return c


def _write_bundle(root) -> None:
    cert_pem, key_pem, _ = _cert(cn=f"svc-{uuid.uuid4().hex[:6]}.example.com")
    (root / "cert.pem").write_text(cert_pem)
    (root / "key.pem").write_text(key_pem)


async def test_first_fetch_pins_the_host_key_and_a_different_key_is_refused(
        db_session, tmp_path, allow_loopback) -> None:
    _write_bundle(tmp_path)
    real = asyncssh.generate_private_key("ssh-ed25519")
    async with _sftp_server(tmp_path, real) as port:
        cert = await _source_cert(db_session, port)
        res = await cert_fetch.fetch_certificate(db_session, cert, actor_user_id=None)
        assert res["status"] == "updated", res
        await db_session.refresh(cert)
        pin = cert.source_config.get("host_key_fingerprint")
        assert pin and pin.startswith("SHA256:")
        assert cert.source_config.get("host_key_for") == f"127.0.0.1:{port}"

    # 同一個位址換了一台（主機金鑰不同）＝被冒充或主機重灌：拒絕，不送出密碼
    _write_bundle(tmp_path)
    impostor = asyncssh.generate_private_key("ssh-ed25519")
    async with _sftp_server(tmp_path, impostor) as port2:
        cfg = dict(cert.source_config)
        cfg["port"] = port2
        cfg["host_key_for"] = f"127.0.0.1:{port2}"     # 模擬同一個目標
        cert.source_config = cfg
        await db_session.commit()
        res = await cert_fetch.fetch_certificate(db_session, cert, actor_user_id=None)
        assert res["status"] == "error", res
        assert res.get("code") == "cert_src_host_key_mismatch", res
        assert pin in str(res.get("params") or res)


async def test_connection_test_reports_the_fingerprint_and_honours_the_pin(
        client, auth_headers, db_session, tmp_path, allow_loopback) -> None:
    _write_bundle(tmp_path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    async with _sftp_server(tmp_path, key) as port:
        cert = await _source_cert(db_session, port)
        cid = cert.id
        body = {"source_type": "sftp", "source_config": dict(cert.source_config)}
        r = await client.post(f"/api/v1/certificates/{cid}/source/test", headers=auth_headers, json=body)
        assert r.status_code == 200 and r.json()["ok"], r.text
        fp = r.json()["host_key_fingerprint"]
        assert fp.startswith("SHA256:")
        db_session.expire_all()
        saved = await db_session.get(Certificate, cid)
        assert saved.source_config["host_key_fingerprint"] == fp, "測試成功就記住（目標跟已存的設定相同時）"


async def test_saving_the_source_keeps_or_drops_the_pin_and_ignores_client_values(
        client, auth_headers, db_session) -> None:
    c = Certificate(name=f"c-{uuid.uuid4().hex[:6]}", source_type="sftp",
                    source_config={"host": "192.0.2.40", "port": 22, "username": "certs", "cert_path": "/c.pem",
                                   "host_key": "ssh-ed25519 AAAA", "host_key_fingerprint": "SHA256:old",
                                   "host_key_for": "192.0.2.40:22"})
    db_session.add(c)
    await db_session.commit()
    cid = c.id
    form = {"host": "192.0.2.40", "port": 22, "username": "certs", "cert_path": "/new.pem",
            "host_key_fingerprint": "SHA256:forged", "host_key": "ssh-ed25519 FORGED"}
    r = await client.put(f"/api/v1/certificates/{cid}/source", headers=auth_headers,
                         json={"source_type": "sftp", "source_config": form})
    assert r.status_code == 200, r.text
    db_session.expire_all()
    cfg = (await db_session.get(Certificate, cid)).source_config
    assert cfg["cert_path"] == "/new.pem"
    assert cfg["host_key_fingerprint"] == "SHA256:old", "表單送來的指紋不可以蓋掉伺服器記住的"
    # 換主機 → 釘選作廢，下一次連線重新記住
    form = {**form, "host": "192.0.2.41"}
    r = await client.put(f"/api/v1/certificates/{cid}/source", headers=auth_headers,
                         json={"source_type": "sftp", "source_config": form})
    db_session.expire_all()
    cfg = (await db_session.get(Certificate, cid)).source_config
    assert "host_key_fingerprint" not in cfg and "host_key" not in cfg


async def test_forgetting_the_host_key_is_audited(client, auth_headers, db_session) -> None:
    from app.models.audit import AuditLog
    from sqlalchemy import select
    c = Certificate(name=f"c-{uuid.uuid4().hex[:6]}", source_type="sftp",
                    source_config={"host": "192.0.2.42", "port": 22, "username": "certs", "cert_path": "/c.pem",
                                   "host_key": "ssh-ed25519 AAAA", "host_key_fingerprint": "SHA256:old",
                                   "host_key_for": "192.0.2.42:22"})
    db_session.add(c)
    await db_session.commit()
    cid = c.id
    r = await client.post(f"/api/v1/certificates/{cid}/source/forget-host-key", headers=auth_headers)
    assert r.status_code == 200, r.text
    db_session.expire_all()
    cfg = (await db_session.get(Certificate, cid)).source_config
    assert "host_key_fingerprint" not in cfg
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "cert_source_forget_host_key"))).scalars().all()
    assert rows and rows[-1].diff.get("fingerprint") == "SHA256:old"
