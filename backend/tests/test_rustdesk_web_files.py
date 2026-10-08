"""相容 RustDesk 的網頁連線：檔案傳輸（規格附錄 J.6、J.7 的後端部分）。

- 伺服器設定「允許網頁檔案傳輸」（預設關）與上傳上限（0183）
- 票證 kind = "file"：伺服器開關沒開就拒絕；權限照舊是 can_use_rustdesk
- WebSocket 照舊只轉送密文；新的控制訊息 file_audit（瀏覽器自報）寫稽核 rustdesk.file_<op>：
  op 只收固定的幾種、路徑截到 512 字元、size 要是整數、每條連線限流
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import uuid
from pathlib import Path

import pytest
from app.models.permission import Permission
from app.services import rustdesk_web
from sqlalchemy import text

from tests.test_rustdesk_web_console import (
    PEER,
    FakeBrowser,
    FakeRedis,
    FakeRustDesk,
    _audits,
    _run,
    _server_keys,
    _setup,
    _ticket,
    _user,
)

MB = 1024 * 1024


# 與 test_rustdesk_web_console.py 相同的兩個 fixture（假 Redis、縮短時限、讓假伺服器可以在 127.0.0.1）
@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr("app.api.v1.endpoints.rustdesk_console._redis_client", lambda: fake)
    monkeypatch.setattr("app.core.rate_limit._redis_client", lambda: fake)
    return fake


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(rustdesk_web, "ATTEMPT_WAIT_UNIT", 0.2)
    monkeypatch.setattr(rustdesk_web, "PAIR_TIMEOUT", 1.0)
    monkeypatch.setattr(rustdesk_web, "RELAY_CONNECT_DELAY", 0.0)
    monkeypatch.setattr(rustdesk_web, "CONNECT_TIMEOUT", 1.0)
    monkeypatch.setattr(rustdesk_web, "check_addrs", lambda host, addrs: None)
    from app.api.v1.endpoints import rustdesk_console as console
    console._active_total = 0
    console._active_by_user.clear()


async def _enable_files(db, srv, on: bool = True, max_file_mb: int | None = None,
                        max_total_mb: int | None = None) -> None:
    srv.web_file_transfer = on
    if max_file_mb is not None:
        srv.web_file_max_file_mb = max_file_mb
    if max_total_mb is not None:
        srv.web_file_max_total_mb = max_total_mb
    db.add(srv)
    await db.commit()


async def _file_ticket(fake_redis, *, user_id, ip_id, server_id, peer_id=PEER) -> str:
    t = uuid.uuid4().hex
    await fake_redis.set(f"rdweb:tk:{t}", json.dumps(
        {"user_id": str(user_id), "ip_id": str(ip_id), "server_id": str(server_id), "peer_id": peer_id,
         "kind": "file"}), ex=30)
    return t


@contextlib.asynccontextmanager
async def _file_env(db_session, *, files_on: bool = True):
    sk, pub = _server_keys()
    rd = FakeRustDesk(sk)
    hbbs_port, hbbr_port = await rd.start()
    ip, srv, _peer = await _setup(db_session, public_key=pub, hbbs_port=hbbs_port, relay_port=hbbr_port)
    await _enable_files(db_session, srv, files_on)
    try:
        yield ip, srv, rd
    finally:
        await rd.stop()


async def _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv):
    t = await _file_ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
    b = FakeBrowser()
    task = await _run(ip.id, t, b)
    await b.wait_for(lambda: b.binaries)
    b.send_bin(b"P" * 90)                      # PublicKey
    b.send_bin(b"L" * 150)                     # LoginRequest（union file_transfer，密文）
    b.send_json({"t": "login_result", "ok": True, "error": ""})
    return b, task


async def _close(b: FakeBrowser, task: asyncio.Task) -> None:
    b.send_json({"t": "close", "reason": "user"})
    await asyncio.wait_for(task, 5)


def _file_audits(audits: list[tuple[str, dict]]) -> list[tuple[str, dict]]:
    return [(a, d) for a, d in audits if a.startswith("rustdesk.file_")]


# ── 遷移 ──

def _migration():
    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0183_rustdesk_web_files.py"
    spec = importlib.util.spec_from_file_location("m0183", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_migration_follows_0182() -> None:
    mod = _migration()
    assert mod.revision == "0183_rustdesk_web_files"
    assert mod.down_revision == "0182_rustdesk_peer_delete"


async def test_the_columns_default_to_off_and_two_gigabytes(db_session) -> None:
    rows = (await db_session.execute(text(
        "SELECT column_name, is_nullable, column_default FROM information_schema.columns "
        "WHERE table_name = 'rustdesk_servers' AND column_name LIKE 'web_file_%' ORDER BY column_name"))).all()
    cols = {r[0]: (r[1], r[2]) for r in rows}
    assert set(cols) == {"web_file_transfer", "web_file_max_file_mb", "web_file_max_total_mb"}, \
        "測試資料庫可能不是最新結構（先跑 alembic upgrade head）"
    assert all(nullable == "NO" for nullable, _ in cols.values())
    assert cols["web_file_transfer"][1] == "false"
    assert cols["web_file_max_file_mb"][1] == "2048"
    assert cols["web_file_max_total_mb"][1] == "10240"


# ── 伺服器設定 ──

async def test_server_setting_defaults_off_and_round_trips(client, auth_headers) -> None:
    r = await client.post("/api/v1/rustdesk/servers", headers=auth_headers, json={"name": "rd-files"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["web_file_transfer"] is False, "升級或新增都不會自己打開"
    assert body["web_file_max_file_mb"] == 2048
    assert body["web_file_max_total_mb"] == 10240
    r = await client.patch(f"/api/v1/rustdesk/servers/{body['id']}", headers=auth_headers, json={
        "web_file_transfer": True, "web_file_max_file_mb": 100, "web_file_max_total_mb": 500})
    assert r.status_code == 200, r.text
    assert r.json()["web_file_transfer"] is True
    assert r.json()["web_file_max_file_mb"] == 100
    assert r.json()["web_file_max_total_mb"] == 500
    for bad in ({"web_file_max_file_mb": 0}, {"web_file_max_total_mb": -1}, {"web_file_max_file_mb": 10**9}):
        r = await client.patch(f"/api/v1/rustdesk/servers/{body['id']}", headers=auth_headers, json=bad)
        assert r.status_code == 422, bad


# ── 票證 ──

async def test_file_ticket_is_refused_while_the_server_switch_is_off(client, auth_headers, db_session,
                                                                     fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers, json={"kind": "file"})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "rd_file_disabled"
    assert not fake_redis.store, "沒有發出票證"
    # 遠端桌面的票證不受影響
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["kind"] == "desktop"


async def test_file_ticket_carries_kind_and_the_upload_limits(client, auth_headers, db_session, fake_redis) -> None:
    ip, srv, _peer = await _setup(db_session)
    await _enable_files(db_session, srv, max_file_mb=100, max_total_mb=300)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers, json={"kind": "file"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "file"
    assert body["file_limits"] == {"max_file_bytes": 100 * MB, "max_total_bytes": 300 * MB}
    assert body["ws_path"] == f"/api/v1/addresses/{ip.id}/rustdesk/ws"
    stored = json.loads(fake_redis.store[f"rdweb:tk:{body['ticket']}"])
    assert stored["kind"] == "file"


async def test_file_ticket_needs_the_same_rustdesk_rights(client, db_session, fake_redis) -> None:
    from app.services.auth import issue_access_token
    ip, srv, _peer = await _setup(db_session)
    await _enable_files(db_session, srv)
    u = await _user(db_session)
    db_session.add(Permission(object_type="subnet", object_id=ip.subnet_id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", json={"kind": "file"},
                          headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "rd_not_permitted"


async def test_unknown_ticket_kind_is_rejected(client, auth_headers, db_session, fake_redis) -> None:
    ip, _srv, _peer = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/ticket", headers=auth_headers,
                          json={"kind": "port_forward"})
    assert r.status_code == 422


async def test_ip_detail_says_whether_file_transfer_is_available(client, auth_headers, db_session,
                                                                 fake_redis) -> None:
    from app.services.auth import issue_access_token
    ip, srv, _peer = await _setup(db_session)
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers=auth_headers)
    assert r.json()["rustdesk"]["file_available"] is False
    await _enable_files(db_session, srv)
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers=auth_headers)
    assert r.json()["rustdesk"]["file_available"] is True
    # 沒有權限的人一律 false
    u = await _user(db_session)
    db_session.add(Permission(object_type="subnet", object_id=ip.subnet_id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.json()["rustdesk"]["file_available"] is False
    # 網頁連線整個關掉時也是 false（同一條中繼）
    srv.web_enabled = False
    db_session.add(srv)
    await db_session.commit()
    r = await client.get(f"/api/v1/addresses/{ip.id}", headers=auth_headers)
    assert r.json()["rustdesk"]["file_available"] is False


# ── WebSocket ──

async def test_file_ticket_is_rechecked_when_the_websocket_opens(db_session, admin_user, fake_redis) -> None:
    """拿到票證之後管理員關掉開關：WebSocket 那一端再查一次，連 hbbs 都不碰。"""
    async with _file_env(db_session) as (ip, srv, rd):
        t = await _file_ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        await _enable_files(db_session, srv, False)
        b = FakeBrowser()
        await asyncio.wait_for(await _run(ip.id, t, b), 3)
        assert b.texts[-1]["t"] == "error"
        assert b.texts[-1]["code"] == "rd_file_disabled"
        assert rd.hbbs_got == []


async def test_file_session_relays_ciphertext_like_the_desktop(db_session, admin_user, fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, rd):
        b, task = await _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv)
        b.send_bin(b"B" * 4096)                    # 上傳的資料塊（密文）
        for _ in range(100):
            if b"B" * 4096 in rd.hbbr_got:
                break
            await asyncio.sleep(0.02)
        assert b"B" * 4096 in rd.hbbr_got, "原封不動轉給受控端"
        await rd.peer_send(b"DIR")
        await b.wait_for(lambda: b"DIR" in b.binaries)
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    assert audits[0][0] == "rustdesk.web_session_open"
    assert audits[0][1]["kind"] == "file"
    assert audits[-1][0] == "rustdesk.web_session_close"
    assert audits[-1][1]["kind"] == "file"


async def test_file_audit_is_written_and_marked_as_browser_reported(db_session, admin_user, fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, _rd):
        b, task = await _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv)
        b.send_json({"t": "file_audit", "op": "download", "path": "/home/a/report.pdf", "size": 12345,
                     "result": "ok"})
        b.send_json({"t": "file_audit", "op": "rename", "path": "/home/a/old", "to": "/home/a/new",
                     "result": "error"})
        b.send_json({"t": "file_audit", "op": "mkdir", "path": "/home/a/dir", "result": "ok"})
        await _close(b, task)
    found = _file_audits(await _audits(db_session, ip.id))
    assert [a for a, _ in found] == ["rustdesk.file_download", "rustdesk.file_rename", "rustdesk.file_mkdir"]
    d = found[0][1]
    assert d["path"] == "/home/a/report.pdf"
    assert d["size"] == 12345
    assert d["result"] == "ok"
    assert d["peer_id"] == PEER
    assert d["source"] == "browser"
    assert "reported by the browser" in d["description"]
    assert found[1][1]["to"] == "/home/a/new"
    assert found[1][1]["result"] == "error"
    assert "size" not in found[2][1] or found[2][1]["size"] is None


async def test_file_audit_caps_the_path_at_512_characters(db_session, admin_user, fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, _rd):
        b, task = await _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv)
        # （FakeBrowser 送的 JSON 會把中文跳脫成 \uXXXX，900 個中文字會超過控制訊息 4096 字元的上限，所以用英文字母）
        b.send_json({"t": "file_audit", "op": "upload", "path": "/" + "x" * 900, "size": 1, "result": "ok"})
        b.send_json({"t": "file_audit", "op": "delete", "path": "/a\u0000b\u001fc", "size": 0, "result": "ok"})
        await _close(b, task)
    found = _file_audits(await _audits(db_session, ip.id))
    assert len(found[0][1]["path"]) == 512
    assert found[1][1]["path"] == "/abc", "控制字元拿掉（JSONB 也存不了 \\u0000）"


async def test_file_audit_rejects_bad_messages(db_session, admin_user, fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, _rd):
        b, task = await _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv)
        for bad in (
            {"op": "chmod", "path": "/x", "result": "ok"},                 # 不在固定清單的 op
            {"op": "file_download", "path": "/x", "result": "ok"},
            {"op": "download", "path": "/x", "result": "maybe"},          # 不合法的 result
            {"op": "download", "path": "/x", "size": "12", "result": "ok"},   # size 不是整數
            {"op": "download", "path": "/x", "size": True, "result": "ok"},
            {"op": "download", "path": "/x", "size": -1, "result": "ok"},
            {"op": "download", "path": "/x", "size": 1.5, "result": "ok"},
            {"op": "download", "path": 42, "result": "ok"},                # path 不是字串
            {"op": "download", "result": "ok"},
        ):
            b.send_json({"t": "file_audit", **bad})
        b.send_json({"t": "file_audit", "op": "download", "path": "/fine", "size": 1, "result": "ok"})
        await _close(b, task)
    found = _file_audits(await _audits(db_session, ip.id))
    assert [d["path"] for _, d in found] == ["/fine"]


async def test_file_audit_is_ignored_before_login_and_on_desktop_sessions(db_session, admin_user,
                                                                          fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, _rd):
        # 檔案傳輸的連線，但還沒登入
        t = await _file_ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_json({"t": "file_audit", "op": "download", "path": "/early", "size": 1, "result": "ok"})
        await _close(b, task)
        # 遠端桌面的連線：沒有檔案傳輸，不收
        t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
        b = FakeBrowser()
        task = await _run(ip.id, t, b)
        await b.wait_for(lambda: b.binaries)
        b.send_bin(b"P" * 90)
        b.send_bin(b"L" * 150)
        b.send_json({"t": "login_result", "ok": True, "error": ""})
        b.send_json({"t": "file_audit", "op": "download", "path": "/desktop", "size": 1, "result": "ok"})
        await _close(b, task)
    assert _file_audits(await _audits(db_session, ip.id)) == []


async def test_file_audit_is_rate_limited_per_connection(db_session, admin_user, fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, _rd):
        b, task = await _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv)
        for i in range(200):
            b.send_json({"t": "file_audit", "op": "upload", "path": f"/f{i}", "size": i, "result": "ok"})
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    found = _file_audits(audits)
    assert 0 < len(found) < 200
    closed = audits[-1][1]
    assert closed["file_audits"] == len(found)
    assert closed["file_audits_dropped"] == 200 - len(found)
