"""相容 RustDesk 的網頁連線：Windows 免安裝受控端的請求提權稽核（規格附錄 K.2、K.3 的後端部分）。

提權是對受控端取得系統管理員權限，要記稽核。後端只轉送密文、看不到提權的請求與回覆，所以由瀏覽器在送出請求時、
以及得到結果時各送一則控制訊息（沿用附錄 J 的 file_audit 機制，這次在一般遠端桌面連線上）：
`{"t": "elevation_audit", "method": "direct|logon", "result": "requested|ok|error|timeout", "detail": …}`

- 只在一般遠端桌面連線、而且已經登入時接受（檔案傳輸的連線上收到不處理）
- 寫入 rustdesk.elevation_request（誰、哪台、方式、結果、錯誤原文），標明是瀏覽器自報的
- method／result 不在清單內就丟掉不記；detail 截到 200 字元
- 只取四個欄位：瀏覽器多帶 username／password 也不會進稽核
"""
from __future__ import annotations

import asyncio
import json

import pytest
from app.services import rustdesk_web

from tests.test_rustdesk_web_console import (
    FakeBrowser,
    FakeRedis,
    _audits,
    _env,
    _run,
    _ticket,
)
from tests.test_rustdesk_web_files import _file_env, _logged_in_file_session

PEER = "123456789"


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


async def _desktop_session(fake_redis, admin_user, ip, srv, *, login: bool = True):
    t = await _ticket(fake_redis, user_id=admin_user.id, ip_id=ip.id, server_id=srv.id)
    b = FakeBrowser()
    task = await _run(ip.id, t, b)
    await b.wait_for(lambda: b.binaries)
    b.send_bin(b"P" * 90)                      # PublicKey
    if login:
        b.send_bin(b"L" * 150)                 # LoginRequest（密文）
        b.send_json({"t": "login_result", "ok": True, "error": ""})
    return b, task


async def _close(b: FakeBrowser, task: asyncio.Task) -> None:
    b.send_json({"t": "close", "reason": "user"})
    await asyncio.wait_for(task, 5)


def _elevations(audits: list[tuple[str, dict]]) -> list[dict]:
    return [d for a, d in audits if a == "rustdesk.elevation_request"]


async def test_elevation_audit_is_written_and_marked_as_browser_reported(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv)
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "requested", "detail": ""})
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "ok", "detail": ""})
        b.send_json({"t": "elevation_audit", "method": "logon", "result": "requested", "detail": ""})
        b.send_json({"t": "elevation_audit", "method": "logon", "result": "error",
                     "detail": "Failed to run portable service process"})
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "timeout", "detail": ""})
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    found = _elevations(audits)
    assert [(d["method"], d["result"]) for d in found] == [
        ("direct", "requested"), ("direct", "ok"), ("logon", "requested"), ("logon", "error"), ("direct", "timeout")]
    d = found[3]
    assert d["detail"] == "Failed to run portable service process"
    assert d["peer_id"] == PEER
    assert d["server_id"] == str(srv.id)
    assert d["source"] == "browser"
    assert "reported by the browser" in d["description"]
    assert found[0]["detail"] == ""
    closed = audits[-1][1]
    assert audits[-1][0] == "rustdesk.web_session_close"
    assert closed["elevation_audits"] == 5
    assert closed["elevation_audits_dropped"] == 0


async def test_elevation_audit_keeps_only_the_four_fields(db_session, admin_user, fake_redis) -> None:
    """K.2：不可以包含帳號或密碼；瀏覽器多帶了其他欄位，後端只取 t、method、result、detail。"""
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv)
        b.send_json({"t": "elevation_audit", "method": "logon", "result": "requested", "detail": "",
                     "username": "CORP\\administrator", "password": "S3cret-Pa55", "extra": {"x": 1}})
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    found = _elevations(audits)
    assert len(found) == 1
    assert set(found[0]) == {"peer_id", "server_id", "method", "result", "detail", "source", "description"}
    dumped = json.dumps(audits, ensure_ascii=False)
    assert "administrator" not in dumped
    assert "S3cret-Pa55" not in dumped


async def test_elevation_audit_drops_unknown_methods_and_results(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv)
        for bad in (
            {"method": "runas", "result": "ok"},                  # 不在清單的 method
            {"method": "DIRECT", "result": "ok"},
            {"method": "direct", "result": "maybe"},              # 不在清單的 result
            {"method": "direct", "result": "cancelled"},
            {"method": 1, "result": "ok"},                        # 不是字串
            {"method": "direct", "result": True},
            {"result": "ok"},                                      # 缺欄位
            {"method": "logon"},
        ):
            b.send_json({"t": "elevation_audit", **bad})
        b.send_json({"t": "elevation_audit", "method": "logon", "result": "ok", "detail": ""})
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    found = _elevations(audits)
    assert [(d["method"], d["result"]) for d in found] == [("logon", "ok")]
    assert audits[-1][1]["elevation_audits_dropped"] == 8


async def test_elevation_audit_caps_the_detail_at_200_characters(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv)
        # （FakeBrowser 送的 JSON 會把非 ASCII 跳脫成 \uXXXX，控制訊息有 4096 字元上限，所以用英文字母）
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "error", "detail": "E" * 900})
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "error", "detail": "a\u0000b\nc"})
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "error", "detail": 42})
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "requested"})
        await _close(b, task)
    found = _elevations(await _audits(db_session, ip.id))
    assert len(found) == 4
    assert found[0]["detail"] == "E" * 200
    assert found[1]["detail"] == "a b c", "控制字元換成空白（JSONB 也存不了 \\u0000）"
    assert found[2]["detail"] == "", "不是字串的 detail 不記內容（事件本身照記）"
    assert found[3]["detail"] == ""


async def test_elevation_audit_is_ignored_on_file_transfer_connections(db_session, admin_user, fake_redis) -> None:
    async with _file_env(db_session) as (ip, srv, _rd):
        b, task = await _logged_in_file_session(db_session, admin_user, fake_redis, ip, srv)
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "requested", "detail": ""})
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    assert _elevations(audits) == []
    assert "elevation_audits" not in audits[-1][1]


async def test_elevation_audit_is_ignored_before_login(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv, login=False)
        b.send_json({"t": "elevation_audit", "method": "direct", "result": "requested", "detail": ""})
        await _close(b, task)
    assert _elevations(await _audits(db_session, ip.id)) == []


async def test_desktop_sessions_without_elevation_keep_the_close_audit_unchanged(db_session, admin_user,
                                                                                fake_redis) -> None:
    """沒有提權的連線（絕大多數，例如 Linux 受控端）：結束的稽核不多出提權的計數欄位。"""
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv)
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    assert audits[-1][0] == "rustdesk.web_session_close"
    assert "elevation_audits" not in audits[-1][1]


async def test_elevation_audit_is_rate_limited_per_connection(db_session, admin_user, fake_redis) -> None:
    async with _env(db_session, admin_user, fake_redis) as (ip, srv, _rd):
        b, task = await _desktop_session(fake_redis, admin_user, ip, srv)
        for _ in range(200):
            b.send_json({"t": "elevation_audit", "method": "direct", "result": "requested", "detail": ""})
        await _close(b, task)
    audits = await _audits(db_session, ip.id)
    found = _elevations(audits)
    assert 0 < len(found) < 200
    closed = audits[-1][1]
    assert closed["elevation_audits"] == len(found)
    assert closed["elevation_audits_dropped"] == 200 - len(found)
