"""相容 RustDesk 的網頁連線：記住密碼（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 D）。

- D.2 金庫：protocol=rustdesk 只有密碼、帳號可以空白、一律綁定 IP；同一個人同一個 IP 只留一筆
- D.3 login_assist：五項檢查依序做，任何一項不過都回失敗而且**不關連線**；通過才回 h2（7.2）
- D.1 回覆、稽核、日誌裡沒有密碼明文，也沒有 h1（h1 對同一台受控端等同密碼）

假的 hbbs／hbbr 與假的瀏覽器沿用 test_rustdesk_web_console。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid

import pytest
from sqlalchemy import select

from app.api.v1.endpoints.ssh_credentials import cred_aad
from app.core.security import envelope_encrypt
from app.models.address import IPAddress
from app.models.permission import Permission
from app.models.ssh_credential import SSHCredential
from app.services import rustdesk_web as W
from app.services import rustdesk_web_proto as proto
from tests.test_rustdesk_web_console import (  # noqa: F401（fake_redis、_fast 是 fixture）
    PEER,
    FakeBrowser,
    _audits,
    _env,
    _fast,
    _run,
    _setup,
    _ticket,
    _user,
    fake_redis,
)

PASSWORD = "Pa55-word"
SALT = "aB3dE9"
CHALLENGE = "x7Kq2Z"
# 7.2 的測試向量
H1_HEX = "785d9695403b00957cd9fa07b849b520b62d407a8a4acce6d34220aa04af4c32"
H2_HEX = "78b83fce809b76e7359978565022d729350f6e725f68f65e85448190884bb03f"
H2_ZH_HEX = "a000b7305dbdbd8e350228a7c62ee7e1d65c56efe365cb60bad82ec7f56b2925"


# ── 7.2 雜湊 ──

def test_h2_matches_the_spec_test_vectors() -> None:
    assert proto.password_h2(PASSWORD, SALT, CHALLENGE).hex() == H2_HEX
    assert proto.password_h2("密碼123", SALT, CHALLENGE).hex() == H2_ZH_HEX
    # 兩步驟的中間值（只拿來確認向量本身；函式不回 h1）
    assert hashlib.sha256(PASSWORD.encode() + SALT.encode()).hexdigest() == H1_HEX


# ── 資料 ──

async def _saved(db, *, owner, ip_id, password: str = PASSWORD, protocol: str = "rustdesk",
                 aad_owner=None) -> SSHCredential:
    """直接寫進金庫（與 POST /ssh-credentials 存的格式相同）。aad_owner 給別人＝解不開的密文。"""
    cred = SSHCredential(
        owner_user_id=owner.id, label=f"RustDesk {PEER}", username="", auth_type="password",
        protocol=protocol, target_ip_id=ip_id,
        secrets_enc={"password": envelope_encrypt(password, aad=cred_aad(aad_owner or owner.id, "password"))},
    )
    db.add(cred)
    await db.commit()
    return cred


def _assist(cred_id, salt=SALT, challenge=CHALLENGE) -> dict:
    return {"t": "login_assist", "credential_id": str(cred_id), "salt": salt, "challenge": challenge}


def _replies(b: FakeBrowser) -> list[dict]:
    return [x for x in b.texts if x.get("t") == "login_assist"]


async def _next_reply(b: FakeBrowser, n: int) -> dict:
    """等到第 n 則（從 1 起算）login_assist 回覆。"""
    await b.wait_for(lambda: len(_replies(b)) >= n)
    return _replies(b)[n - 1]


async def _still_open(b: FakeBrowser, rd, payload: bytes) -> None:
    """連線沒有被關：瀏覽器送的訊息照樣轉到受控端。"""
    b.send_bin(payload)
    for _ in range(100):
        if payload in rd.hbbr_got:
            break
        await asyncio.sleep(0.02)
    assert payload in rd.hbbr_got, "失敗之後連線要保持（附錄 D.3）"
    assert b.closed_code is None
    assert "error" not in b.kinds()


async def _paired(db_session, admin_user, fake_redis, ip, srv) -> tuple[FakeBrowser, asyncio.Task]:
    t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
    b = FakeBrowser()
    task = await _run(ip.id, t, b)
    await b.wait_for(lambda: b.binaries)        # 已配對，受控端第一則已轉給瀏覽器
    b.send_bin(b"P" * 90)                       # PublicKey（明文那一則，不算登入嘗試）
    return b, task


async def _close(b: FakeBrowser, task: asyncio.Task) -> None:
    b.send_json({"t": "close", "reason": "user"})
    await asyncio.wait_for(task, 3)


# ── D.5 票證 ──

async def test_ticket_says_whether_a_saved_password_exists(client, auth_headers, admin_user, db_session,
                                                           fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["has_saved_password"] is False
    # 別的用途、別人的都不算
    other = await _user(db_session)
    await _saved(db_session, owner=admin_user, ip_id=ip.id, protocol="vnc")
    await _saved(db_session, owner=other, ip_id=ip.id)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.json()["has_saved_password"] is False
    await _saved(db_session, owner=admin_user, ip_id=ip.id)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.json()["has_saved_password"] is True
    assert PASSWORD not in r.text


# ── D.3 login_assist：成功 ──

async def test_login_assist_returns_h2_only(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        b.send_json(_assist(cred.id))
        reply = await _next_reply(b, 1)
        assert reply == {"t": "login_assist", "ok": True, "hash": base64.b64encode(bytes.fromhex(H2_HEX)).decode()}
        dumped = json.dumps(b.texts)
        assert PASSWORD not in dumped
        assert H1_HEX not in dumped and base64.b64encode(bytes.fromhex(H1_HEX)).decode() not in dumped
        await _still_open(b, rd, b"after-assist")
        b.send_bin(b"L" * 150)                       # 瀏覽器拿 h2 送 LoginRequest（密文）
        b.send_json({"t": "login_result", "ok": True, "error": ""})
        await _close(b, task)

    await db_session.refresh(cred)
    assert cred.last_used_at is not None
    audits = await _audits(db_session, ip.id)
    actions = [a for a, _ in audits]
    assert actions == ["rustdesk.web_session_open", "rustdesk.saved_password_used", "rustdesk.web_session_close"]
    used = audits[1][1]
    assert used == {"peer_id": PEER, "server_id": str(srv.id), "credential_id": str(cred.id)}
    assert audits[2][1]["saved_password_used"] is True
    dumped = json.dumps(audits)
    assert PASSWORD not in dumped and H1_HEX not in dumped and H2_HEX not in dumped


async def test_non_ascii_password_uses_utf8(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id, password="密碼123")
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        b.send_json(_assist(cred.id))
        reply = await _next_reply(b, 1)
        assert base64.b64decode(reply["hash"]).hex() == H2_ZH_HEX
        await _close(b, task)


# ── D.3 login_assist：每一項檢查 ──

@pytest.mark.parametrize("case", ["not_owner", "other_ip", "other_protocol", "missing", "bad_id"])
async def test_unusable_credential_is_refused_without_closing(db_session, admin_user, fake_redis, case) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        good = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        if case == "not_owner":
            cred_id = (await _saved(db_session, owner=await _user(db_session), ip_id=ip.id)).id
        elif case == "other_ip":
            other_ip = IPAddress(subnet_id=ip.subnet_id, ip="198.51.100.21", rustdesk_enabled=True)
            db_session.add(other_ip)
            await db_session.commit()
            cred_id = (await _saved(db_session, owner=admin_user, ip_id=other_ip.id)).id
        elif case == "other_protocol":
            cred_id = (await _saved(db_session, owner=admin_user, ip_id=ip.id, protocol="vnc")).id
        elif case == "missing":
            cred_id = uuid.uuid4()
        else:
            cred_id = "not-a-uuid"
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        b.send_json(_assist(cred_id))
        assert await _next_reply(b, 1) == {"t": "login_assist", "ok": False, "code": "rd_saved_password_unavailable"}
        await _still_open(b, rd, b"still-open")
        # 同一條連線之後用自己的憑證照樣可以
        b.send_json(_assist(good.id))
        assert (await _next_reply(b, 2))["ok"] is True
        await _close(b, task)
    actions = [a for a, _ in await _audits(db_session, ip.id)]
    assert actions.count("rustdesk.saved_password_used") == 1, "失敗的不寫「已使用」"


async def test_decrypt_failure_is_its_own_code(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        other = await _user(db_session)
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id, aad_owner=other.id)   # AAD 不同＝解不開
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        b.send_json(_assist(cred.id))
        assert await _next_reply(b, 1) == {"t": "login_assist", "ok": False, "code": "rd_saved_password_decrypt"}
        await _still_open(b, rd, b"still-open")
        await _close(b, task)
    await db_session.refresh(cred)
    assert cred.last_used_at is None


async def test_before_pairing_is_refused_without_closing(db_session, admin_user, fake_redis, monkeypatch) -> None:
    monkeypatch.setattr(W, "RESTART_AFTER", 0.5)
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        rd.silent_hbbr_connections = 1               # 第一次的中繼不配對 → 會合重來一次，中間有空檔
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: any(x.get("stage") == "relay" for x in b.texts))
        b.send_json(_assist(cred.id))
        assert await _next_reply(b, 1) == {"t": "login_assist", "ok": False, "code": "rd_saved_password_unavailable"}
        assert not b.binaries, "這時候還沒配對"
        await b.wait_for(lambda: b.binaries, timeout=5)       # 照樣配對成功
        b.send_bin(b"P" * 90)
        b.send_json(_assist(cred.id))
        assert (await _next_reply(b, 2))["ok"] is True, "配對前那一次不算進 3 次的上限"
        await _close(b, task)


async def test_after_login_is_refused_without_closing(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        b.send_bin(b"L" * 150)
        b.send_json({"t": "login_result", "ok": True, "error": ""})
        b.send_json(_assist(cred.id))
        assert await _next_reply(b, 1) == {"t": "login_assist", "ok": False, "code": "rd_saved_password_unavailable"}
        await _still_open(b, rd, b"still-open")
        await _close(b, task)


async def test_at_most_three_per_connection(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        for i in range(1, 4):
            b.send_json(_assist(cred.id, challenge=f"chal{i}"))
            assert (await _next_reply(b, i))["ok"] is True
        b.send_json(_assist(cred.id))
        assert await _next_reply(b, 4) == {"t": "login_assist", "ok": False, "code": "rd_login_assist_limit"}
        await _still_open(b, rd, b"still-open")
        await _close(b, task)


@pytest.mark.parametrize("bad", [
    [("", CHALLENGE), (SALT, ""), ("x" * 65, CHALLENGE)],
    [("密碼", CHALLENGE), (SALT, "a\nb"), (123, CHALLENGE)],
    [(None, CHALLENGE), (SALT, ["x"]), (SALT, "\x7f")],
])
async def test_bad_salt_or_challenge_is_refused(db_session, admin_user, fake_redis, bad) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        for i, (salt, challenge) in enumerate(bad, start=1):
            b.send_json(_assist(cred.id, salt=salt, challenge=challenge))
            assert await _next_reply(b, i) == {"t": "login_assist", "ok": False,
                                               "code": "rd_saved_password_unavailable"}, (salt, challenge)
        await _still_open(b, rd, b"still-open")
        await _close(b, task)
    await db_session.refresh(cred)
    assert cred.last_used_at is None


async def test_longest_allowed_salt_and_challenge(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id)
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        salt, challenge = "~" * 64, " " * 64
        b.send_json(_assist(cred.id, salt=salt, challenge=challenge))
        reply = await _next_reply(b, 1)
        assert base64.b64decode(reply["hash"]) == proto.password_h2(PASSWORD, salt, challenge)
        await _close(b, task)


async def test_wrong_saved_password_counts_as_a_failure(db_session, admin_user, fake_redis) -> None:
    """D.4：用已存密碼登入失敗，和手動輸入一樣計入 7.8 的失敗次數。"""
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        cred = await _saved(db_session, owner=admin_user, ip_id=ip.id, password="old-password")
        b, task = await _paired(db_session, admin_user, fake_redis, ip, srv)
        b.send_json(_assist(cred.id))
        assert (await _next_reply(b, 1))["ok"] is True
        b.send_bin(b"L" * 150)
        b.send_json({"t": "login_result", "ok": False, "error": "Wrong Password"})
        await _close(b, task)
    counts = await W.failure_counts(fake_redis, admin_user.id, srv.id, PEER)
    assert counts["password"]["m"] == 1


# ── D.2 金庫 ──

async def test_vault_stores_rustdesk_passwords_per_ip(client, auth_headers, admin_user, db_session,
                                                      fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session)
    body = {"label": f"RustDesk {PEER}", "username": "", "auth_type": "password", "protocol": "rustdesk",
            "target_ip_id": str(ip.id), "password": "first"}
    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json=body)
    assert r.status_code == 201, r.text
    first = r.json()
    assert first["protocol"] == "rustdesk" and first["username"] == "" and first["has_password"] is True
    assert "first" not in r.text

    # 同一個 IP 再存一次（對方改了密碼）：取代舊的，不留兩筆
    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json={**body, "password": "second"})
    assert r.status_code == 201, r.text
    second = r.json()
    r = await client.get("/api/v1/ssh-credentials", headers=auth_headers,
                         params={"protocol": "rustdesk", "target_ip_id": str(ip.id)})
    assert r.status_code == 200
    assert [c["id"] for c in r.json()] == [second["id"]]
    rows = (await db_session.execute(select(SSHCredential).where(SSHCredential.protocol == "rustdesk"))).scalars().all()
    assert [str(c.id) for c in rows] == [second["id"]]

    from app.models.audit import AuditLog
    logs = (await db_session.execute(select(AuditLog).where(AuditLog.object_type == "rustdesk_credential")
                                     .order_by(AuditLog.id))).scalars().all()
    assert [(str(a.object_id), a.action) for a in logs] == [
        (first["id"], "create"), (first["id"], "delete"), (second["id"], "create")]
    assert logs[1].diff["replaced_by"] == second["id"]
    assert "first" not in json.dumps([a.diff for a in logs]) and "second" not in json.dumps([a.diff for a in logs])

    # protocol 篩選：別的用途不會混進來
    r = await client.get("/api/v1/ssh-credentials", headers=auth_headers, params={"protocol": "vnc"})
    assert r.json() == []


@pytest.mark.parametrize("change,code", [
    ({"target_ip_id": None}, "cred_target_required"),
    ({"auth_type": "key", "private_key": "x", "password": None}, None),
])
async def test_vault_rules_for_rustdesk(client, auth_headers, db_session, fake_redis, change, code) -> None:
    ip, _srv, _peer = await _setup(db_session)
    body = {"label": "rd", "username": "", "auth_type": "password", "protocol": "rustdesk",
            "target_ip_id": str(ip.id), "password": "pw", **change}
    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json=body)
    assert r.status_code == 400, r.text
    if code:
        assert r.json()["detail"]["code"] == code


async def test_vault_needs_rustdesk_rights_on_the_ip(client, auth_headers, db_session, fake_redis) -> None:
    from app.services.auth import issue_access_token
    ip, _srv, _peer = await _setup(db_session, rustdesk_enabled=False)
    body = {"label": "rd", "username": "", "auth_type": "password", "protocol": "rustdesk",
            "target_ip_id": str(ip.id), "password": "pw"}
    r = await client.post("/api/v1/ssh-credentials", headers=auth_headers, json=body)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "console_target_forbidden"

    ip2, _srv2, _peer2 = await _setup(db_session)
    u = await _user(db_session)
    db_session.add(Permission(object_type="subnet", object_id=ip2.subnet_id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.post("/api/v1/ssh-credentials", headers={"Authorization": f"Bearer {issue_access_token(u)}"},
                          json={**body, "target_ip_id": str(ip2.id)})
    assert r.status_code == 403
