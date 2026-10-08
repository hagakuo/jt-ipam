"""RustDesk 客戶端回報的接收端：代理在 RustDesk 主機上聽 TCP 21114，收客戶端送的心跳／系統資訊／稽核，
與 hbbs 資料庫比對後轉給 jt-ipam。

依據只有 docs/SPEC_RUSTDESK_API_zh-TW.md（乾淨室）。這裡守的界線：
1. 回應絕不含 strategy／disconnect／modified_at（會中斷連線、改客戶端設定）；心跳一律回 {}
2. uuid 只在本機與 hbbs 資料庫比對：轉送內容、日誌都不可以出現
3. 驗證不過不轉送：心跳回 {}、系統資訊回 ID_NOT_FOUND、稽核回 200（計入 unverified）
4. 本文 64 KB、10 秒內讀完、每個來源 IP 每秒 20 個請求；JSON 壞掉或型別不對回 400；其他路徑 404
5. 轉送：session_id 轉字串、驗證通過那一筆補 action=auth、nonce 去重、心跳同 ID 合併、
   佇列上限丟最舊的並計數、送失敗保留佇列
6. 網頁上沒開就完全不聽這個埠
"""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import pathlib
import socket
import sqlite3
import time
import types
import uuid
from datetime import datetime

import pytest

_AGENT = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_rustdesk_agent.py"

DEV = "123456789"
OTHER = "222333444"
UUID_RAW = bytes(range(0xA1, 0xB1))                 # 16 個位元組，hbbs 存的原始值
UUID_B64 = base64.b64encode(UUID_RAW).decode()
OTHER_RAW = b"other-device-uuid-value"
OTHER_B64 = base64.b64encode(OTHER_RAW).decode()
WRONG_B64 = base64.b64encode(b"\x00" * 16).decode()
FORBIDDEN = ("strategy", "disconnect", "modified_at")


def _agent():
    spec = importlib.util.spec_from_file_location(f"jt_agent_rdapi_{uuid.uuid4().hex[:6]}", _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _data_dir(tmp_path: pathlib.Path, peers: dict[str, bytes]) -> pathlib.Path:
    """hbbs 工作目錄：peer 表（guid, id, uuid, pk, created_at, user, status, note, info）。"""
    d = tmp_path / "rustdesk-server"
    d.mkdir()
    con = sqlite3.connect(d / "db_v2.sqlite3")
    con.executescript("""
        create table peer (
            guid blob primary key not null, id varchar(100) not null, uuid blob not null,
            pk blob not null, created_at datetime not null default(current_timestamp),
            user blob, status tinyint, note varchar(300), info text not null
        ) without rowid;
        create unique index index_peer_id on peer (id);
    """)
    for i, (pid, raw) in enumerate(peers.items()):
        con.execute("insert into peer (guid, id, uuid, pk, info) values (?,?,?,?,?)",
                    (f"g{i}".encode(), pid, raw, b"pk-bytes", json.dumps({"ip": "192.0.2.1"})))
    con.commit()
    con.close()
    return d


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except OSError:
        return False


def _send(port: int, path: str, body=None, method: str = "POST", headers: dict | None = None):  # noqa: ANN001
    """送一個請求，回 (狀態碼, 本文, 標頭)。不帶 Content-Type（客戶端不保證會帶）。"""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        data = body if body is None or isinstance(body, bytes) else json.dumps(body).encode()
        c.request(method, path, body=data, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read(), {k.lower(): v for k, v in r.getheaders()}
    finally:
        c.close()


def _raw(port: int, data: bytes, wait: float = 5.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    try:
        s.sendall(data)
        out = b""
        while True:
            try:
                chunk = s.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        return out
    finally:
        s.close()


@pytest.fixture
def rd(tmp_path, monkeypatch):
    a = _agent()
    d = _data_dir(tmp_path, {DEV: UUID_RAW, OTHER: OTHER_RAW})
    monkeypatch.setattr(a, "_rustdesk_dir", lambda: str(d))
    monkeypatch.setattr(a, "RDAPI_RATE_PER_SEC", 1000)    # 限流另外測；其他測試不要被它干擾
    monkeypatch.setattr(a, "RDAPI_POLL_SECONDS", 0.05)
    sent: list = []

    def fake_req(method, path, body=None, extra_headers=None, timeout=30):  # noqa: ANN001
        sent.append({"method": method, "path": path, "body": json.loads(json.dumps(body))})
        return {"status": "ok"}

    monkeypatch.setattr(a, "_req", fake_req)
    port = a._rdapi_start(0, "127.0.0.1")
    a._RDAPI["source_id"] = "src-1"
    h = types.SimpleNamespace(a=a, port=port, sent=sent, dir=d, fake=fake_req)
    yield h
    a._rdapi_stop()


def _flush(h) -> list:  # noqa: ANN001
    assert h.a._rdapi_flush() is True
    return [e for s in h.sent for e in s["body"]["events"]]


def _dropped(h) -> dict:  # noqa: ANN001
    return h.sent[-1]["body"]["dropped"]


def hb(**kw) -> dict:  # noqa: ANN003
    return {"id": DEV, "uuid": UUID_B64, "ver": 1005000, "modified_at": 0, **kw}


def conn(**kw) -> dict:  # noqa: ANN003
    return {"id": DEV, "uuid": UUID_B64, "conn_id": 7, "session_id": 0, "nonce": str(uuid.uuid4()), **kw}


# ── 1. 心跳 ────────────────────────────────────────────────────────────────

def test_heartbeat_reply_is_always_an_empty_object(rd) -> None:
    for body in (hb(conns=[3, 4], modified_at=1700000000),       # 驗證通過、帶連線與策略時間戳
                 hb(uuid=WRONG_B64),                              # uuid 錯
                 hb(id="999999999")):                             # ID 不存在
        st, raw, hdr = _send(rd.port, "/api/heartbeat", body)
        assert st == 200
        assert raw == b"{}", "心跳回應只能是 {}：其他鍵會中斷連線或改客戶端設定"
        assert json.loads(raw) == {}
        assert not any(k in raw.decode() for k in FORBIDDEN)
    ev = _flush(rd)
    assert [e["kind"] for e in ev] == ["heartbeat"], "只有驗證通過的那一筆會轉送"
    e = ev[0]
    assert e["id"] == DEV and e["ver"] == 1005000 and e["conns"] == 2
    assert e["src_ip"] == "127.0.0.1"
    assert datetime.fromisoformat(e["at"]).utcoffset().total_seconds() == 0
    assert "uuid" not in e
    body = rd.sent[-1]
    assert body["method"] == "POST" and body["path"] == "/api/v1/rustdesk/agent/events"
    assert body["body"]["source_id"] == "src-1"
    assert _dropped(rd)["unverified"] == 2


def test_heartbeat_without_conns_counts_zero(rd) -> None:
    body = hb()
    del body["modified_at"]
    assert _send(rd.port, "/api/heartbeat", body)[:2] == (200, b"{}")
    assert _flush(rd)[0]["conns"] == 0


def test_heartbeats_are_coalesced_per_id(rd) -> None:
    for v in (1, 2, 3):
        _send(rd.port, "/api/heartbeat", hb(ver=v))
    _send(rd.port, "/api/heartbeat", {"id": OTHER, "uuid": OTHER_B64, "ver": 9, "modified_at": 0})
    ev = _flush(rd)
    assert sorted((e["id"], e["ver"]) for e in ev) == [(DEV, 3), (OTHER, 9)], "同一個 ID 一個週期只送最後一筆"


# ── 2. 系統資訊 ────────────────────────────────────────────────────────────

def test_sysinfo_verified_is_forwarded_without_uuid_or_presets(rd) -> None:
    db_before = (rd.dir / "db_v2.sqlite3").read_bytes()
    st, raw, hdr = _send(rd.port, "/api/sysinfo", {
        "id": DEV, "uuid": UUID_B64, "version": "1.5.0", "hostname": "pc-01", "username": "alice",
        "os": "Windows 11 Pro", "cpu": "Intel Core i7 8/4 cores", "memory": "16GB",
        "preset-address-book-name": "secret-ab", "preset-strategy-name": "secret-strategy",
    })
    assert st == 200 and raw == b"SYSINFO_UPDATED"
    assert not hdr.get("content-type", "").startswith("application/json"), "系統資訊的回應是純文字"
    ev = _flush(rd)
    assert ev == [{"kind": "sysinfo", "at": ev[0]["at"], "src_ip": "127.0.0.1", "id": DEV,
                   "hostname": "pc-01", "username": "alice", "os": "Windows 11 Pro",
                   "cpu": "Intel Core i7 8/4 cores", "memory": "16GB", "version": "1.5.0"}]
    blob = json.dumps(rd.sent)
    assert "secret-ab" not in blob and "secret-strategy" not in blob and "preset" not in blob
    assert (rd.dir / "db_v2.sqlite3").read_bytes() == db_before, "hbbs 的資料庫只能唯讀"


def test_sysinfo_failed_verification_is_id_not_found(rd) -> None:
    base = {"hostname": "evil", "os": "x"}
    for ident in ({"id": DEV, "uuid": WRONG_B64},                                         # uuid 錯
                  {"id": DEV, "uuid": OTHER_B64},                                         # 別台的 uuid
                  {"id": DEV, "uuid": base64.b64encode(UUID_RAW + b"\x00").decode()},      # 多一個位元組
                  {"id": DEV, "uuid": UUID_B64.rstrip("=") + "!!"},                       # 不是 base64
                  {"id": "999999999", "uuid": UUID_B64}):                                 # ID 不存在
        st, raw, _ = _send(rd.port, "/api/sysinfo", {**ident, **base})
        assert (st, raw) == (200, b"ID_NOT_FOUND"), ident
    ev = _flush(rd)
    assert ev == []
    assert _dropped(rd)["unverified"] == 5


def test_verification_is_cached(rd, monkeypatch) -> None:
    body = {"id": DEV, "uuid": UUID_B64, "hostname": "pc-01"}
    assert _send(rd.port, "/api/sysinfo", body)[1] == b"SYSINFO_UPDATED"
    (rd.dir / "db_v2.sqlite3").unlink()
    assert _send(rd.port, "/api/sysinfo", body)[1] == b"SYSINFO_UPDATED", "快取期間不必每次開資料庫"
    assert _send(rd.port, "/api/sysinfo", {**body, "uuid": WRONG_B64})[1] == b"ID_NOT_FOUND"


def test_verification_cache_expires(rd, monkeypatch) -> None:
    monkeypatch.setattr(rd.a, "RDAPI_VERIFY_TTL", 0)
    body = {"id": DEV, "uuid": UUID_B64, "hostname": "pc-01"}
    assert _send(rd.port, "/api/sysinfo", body)[1] == b"SYSINFO_UPDATED"
    (rd.dir / "db_v2.sqlite3").unlink()
    assert _send(rd.port, "/api/sysinfo", body)[1] == b"ID_NOT_FOUND", "資料庫讀不到就不能當成驗證通過"


# ── 3. 連線稽核 ────────────────────────────────────────────────────────────

def test_conn_new_auth_close_are_forwarded(rd) -> None:
    big = 2**63 + 5
    r1 = _send(rd.port, "/api/audit/conn", conn(action="new", ip="198.51.100.20", conn_audit_ref="ref-1"))
    r2 = _send(rd.port, "/api/audit/conn", conn(session_id=big, peer=["111222333", "bob-laptop"],
                                                type=0, primary_auth=1))
    r3 = _send(rd.port, "/api/audit/conn", conn(session_id=big, action="close"))
    assert [r[:2] for r in (r1, r2, r3)] == [(200, b"")] * 3
    ev = _flush(rd)
    assert [e["action"] for e in ev] == ["new", "auth", "close"]
    new, auth, close = ev
    assert all(e["kind"] == "conn" and e["id"] == DEV and e["conn_id"] == 7 and e["nonce"] for e in ev)
    assert new["ip"] == "198.51.100.20" and new["conn_audit_ref"] == "ref-1" and new["session_id"] == "0"
    assert new["peer_id"] is None and new["type"] is None
    assert auth["peer_id"] == "111222333" and auth["peer_name"] == "bob-laptop"
    assert auth["type"] == 0 and auth["primary_auth"] == 1 and auth["two_factor"] is None
    assert auth["session_id"] == "9223372036854775813", "超過 2^53 也要原樣轉成字串"
    assert close["session_id"] == str(big)
    assert "peer" not in auth
    assert '"session_id": "9223372036854775813"' in json.dumps(rd.sent)


def test_duplicate_nonce_is_forwarded_once(rd) -> None:
    rec = conn(action="new", ip="198.51.100.20")
    for _ in range(3):                                    # 客戶端重送時沿用同一個 nonce
        assert _send(rd.port, "/api/audit/conn", rec)[:2] == (200, b"")
    _send(rd.port, "/api/audit/conn", conn(action="close"))
    ev = _flush(rd)
    assert [e["action"] for e in ev] == ["new", "close"]


def test_unverified_audit_is_accepted_but_not_forwarded(rd) -> None:
    assert _send(rd.port, "/api/audit/conn", conn(uuid=WRONG_B64, action="new", ip="x"))[:2] == (200, b"")
    assert _flush(rd) == []
    assert _dropped(rd)["unverified"] == 1


def test_note_is_accepted_only_for_known_ids(rd) -> None:
    r1 = _send(rd.port, "/api/audit/conn", {"id": OTHER, "session_id": 42, "note": "fixed the printer"})
    r2 = _send(rd.port, "/api/audit/conn", {"id": "999999999", "session_id": 43, "note": "spoofed"})
    assert r1[:2] == (200, b"") and r2[:2] == (200, b"")
    ev = _flush(rd)
    assert ev == [{"kind": "note", "at": ev[0]["at"], "src_ip": "127.0.0.1", "id": OTHER,
                   "session_id": "42", "note": "fixed the printer", "verified": False}]
    assert _dropped(rd)["unverified"] == 1


# ── 4. 檔案傳輸、告警 ──────────────────────────────────────────────────────

def test_file_audit_info_is_parsed_and_flattened(rd) -> None:
    info = json.dumps({"ip": "198.51.100.20", "name": "bob-laptop", "num": 2,
                       "files": [["report.pdf", 2048], ["a.txt", 12]]})
    nonce = str(uuid.uuid4())
    st, raw, _ = _send(rd.port, "/api/audit/file", {
        "id": DEV, "uuid": UUID_B64, "peer_id": "111222333", "conn_id": 7, "type": 0,
        "path": "C:\\Users\\alice\\Desktop", "is_file": False, "info": info, "nonce": nonce})
    assert (st, raw) == (200, b"")
    _send(rd.port, "/api/audit/file", {
        "id": DEV, "uuid": UUID_B64, "peer_id": "111222333", "conn_id": 7, "type": 1,
        "path": "/tmp/x", "is_file": True, "info": "not json", "nonce": str(uuid.uuid4())})
    ev = _flush(rd)
    assert ev[0] == {"kind": "file", "at": ev[0]["at"], "src_ip": "127.0.0.1", "id": DEV, "nonce": nonce,
                     "conn_id": 7, "peer_id": "111222333", "type": 0, "path": "C:\\Users\\alice\\Desktop",
                     "is_file": False, "ip": "198.51.100.20", "peer_name": "bob-laptop", "num": 2,
                     "files": [["report.pdf", 2048], ["a.txt", 12]]}
    bad = ev[1]
    assert bad["type"] == 1 and bad["is_file"] is True
    assert bad["ip"] is None and bad["peer_name"] is None and bad["num"] is None and bad["files"] is None


def test_alarm_audit_is_forwarded_with_parsed_info(rd) -> None:
    info = json.dumps({"ip": "203.0.113.9", "id": "555666777", "name": "attacker", "extra": {"x": 1}})
    _send(rd.port, "/api/audit/alarm", {"id": DEV, "uuid": UUID_B64, "typ": 2, "info": info,
                                        "conn_id": 9, "nonce": str(uuid.uuid4())})
    _send(rd.port, "/api/audit/alarm", {"id": DEV, "uuid": UUID_B64, "typ": 1, "info": "not json",
                                        "conn_id": 9, "nonce": str(uuid.uuid4())})
    ev = _flush(rd)
    assert [e["kind"] for e in ev] == ["alarm", "alarm"]
    assert ev[0]["typ"] == 2 and ev[0]["conn_id"] == 9
    assert ev[0]["info"] == {"ip": "203.0.113.9", "id": "555666777", "name": "attacker"}
    assert ev[1]["typ"] == 1 and ev[1]["info"] == {}


def test_long_strings_are_truncated(rd) -> None:
    _send(rd.port, "/api/sysinfo", {"id": DEV, "uuid": UUID_B64, "hostname": "h" * 999, "os": "o" * 999,
                                    "cpu": "c" * 999, "memory": "m" * 999})
    info = json.dumps({"ip": "i" * 999, "name": "n" * 999, "num": 1, "files": [["f" * 999, 1]]})
    _send(rd.port, "/api/audit/file", {"id": DEV, "uuid": UUID_B64, "peer_id": "p" * 999, "conn_id": 1,
                                       "type": 0, "path": "x" * 5000, "is_file": True, "info": info,
                                       "nonce": str(uuid.uuid4())})
    sysinfo, file = _flush(rd)
    assert len(sysinfo["hostname"]) == 255 and len(sysinfo["os"]) == 255
    assert len(sysinfo["cpu"]) == 255 and len(sysinfo["memory"]) == 255
    assert len(file["peer_id"]) == 100 and len(file["path"]) == 1024
    assert len(file["peer_name"]) == 255 and len(file["files"][0][0]) == 512
    assert len(file["ip"]) == 64, "IP 欄位比照 jt-ipam 端的長度（再長也不會是 IP）"


# ── 5. 協定層的防護 ────────────────────────────────────────────────────────

def test_other_paths_and_methods_are_404(rd) -> None:
    for path in ("/api/login", "/api/ab", "/api/ab/personal", "/api/users", "/api/peers",
                 "/api/switch-grant", "/api/sysinfo_ver", "/", "/api/heartbeat/x"):
        st, raw, _ = _send(rd.port, path, hb())
        assert (st, raw) == (404, b""), path
    for method in ("GET", "PUT", "DELETE", "OPTIONS", "PATCH"):
        st, raw, _ = _send(rd.port, "/api/heartbeat", None, method=method)
        assert (st, raw) == (404, b""), method
    assert _flush(rd) == []


def test_body_over_64k_is_413(rd) -> None:
    resp = _raw(rd.port, b"POST /api/heartbeat HTTP/1.1\r\nHost: x\r\nContent-Length: 65537\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 413"), resp[:40]
    base = json.dumps(hb(pad=""))
    exact = json.dumps(hb(pad="x" * (65536 - len(base)))).encode()
    assert len(exact) == 65536
    assert _send(rd.port, "/api/heartbeat", exact)[:2] == (200, b"{}"), "剛好 64 KB 可以"


def test_invalid_json_and_wrong_types_are_400(rd) -> None:
    for raw in (b"{not json", b"[1, 2]", b'"text"', b"\xff\xfe\x00", b""):
        st, body, _ = _send(rd.port, "/api/heartbeat", raw)
        assert (st, body) == (400, b""), raw
    nonce = str(uuid.uuid4())
    file_ok = {"id": DEV, "uuid": UUID_B64, "peer_id": "1", "conn_id": 1, "type": 0, "path": "/x",
               "is_file": True, "info": "{}", "nonce": nonce}
    alarm_ok = {"id": DEV, "uuid": UUID_B64, "typ": 2, "info": "{}", "conn_id": 1, "nonce": nonce}
    bad = [
        ("/api/heartbeat", hb(id=123456789)),
        ("/api/heartbeat", hb(uuid=None)),
        ("/api/heartbeat", hb(conns="3")),
        ("/api/heartbeat", hb(conns=[1, "2"])),
        ("/api/heartbeat", hb(ver="1.5.0")),
        ("/api/sysinfo", {"id": DEV, "uuid": UUID_B64, "hostname": ["x"]}),
        ("/api/audit/conn", conn(session_id="123", action="close")),
        ("/api/audit/conn", conn(session_id=1.5, action="close")),
        ("/api/audit/conn", conn(conn_id=True, action="close")),
        ("/api/audit/conn", conn(peer=["only-one"])),
        ("/api/audit/conn", conn(peer=["111", 5])),
        ("/api/audit/conn", conn()),                                  # 沒有 action 也沒有 peer
        ("/api/audit/conn", conn(action="reboot")),
        ("/api/audit/conn", {k: v for k, v in conn(action="close").items() if k != "nonce"}),
        ("/api/audit/conn", {"id": OTHER, "session_id": "42", "note": "x"}),
        ("/api/audit/file", {**file_ok, "is_file": 1}),
        ("/api/audit/file", {**file_ok, "info": {"ip": "x"}}),        # info 必須是字串
        ("/api/audit/alarm", {**alarm_ok, "typ": "2"}),
        ("/api/audit/alarm", {**alarm_ok, "typ": None}),
    ]
    for path, body in bad:
        st, raw, _ = _send(rd.port, path, body)
        assert (st, raw) == (400, b""), (path, body)
    assert _flush(rd) == []
    assert _dropped(rd)["bad_request"] == 5 + len(bad)


def test_rate_limit_per_source_ip_is_429(rd, monkeypatch) -> None:
    monkeypatch.setattr(rd.a, "RDAPI_RATE_PER_SEC", 3)
    codes = [_send(rd.port, "/api/heartbeat", hb())[:2] for _ in range(10)]
    assert codes[:3] == [(200, b"{}")] * 3
    assert (429, b"") in codes
    _flush(rd)
    assert _dropped(rd)["rate_limited"] == sum(1 for c in codes if c[0] == 429)


def test_concurrent_connections_per_ip_are_capped(rd, monkeypatch) -> None:
    monkeypatch.setattr(rd.a, "RDAPI_MAX_CONN_PER_IP", 2)
    idle = [socket.create_connection(("127.0.0.1", rd.port), timeout=5) for _ in range(2)]
    try:
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", rd.port), timeout=5)
        try:
            assert extra.recv(1) == b"", "超過上限的連線直接關掉，不佔執行緒"
        except ConnectionResetError:
            pass
        finally:
            extra.close()
    finally:
        for s in idle:
            s.close()
    time.sleep(0.3)
    assert _send(rd.port, "/api/heartbeat", hb())[:2] == (200, b"{}"), "閒置連線關掉之後恢復"
    _flush(rd)
    assert _dropped(rd)["rate_limited"] >= 1


def test_ids_that_jt_ipam_cannot_store_are_never_forwarded(rd) -> None:
    """ID 格式不合（jt-ipam 收不下、hbbs 的裝置清單也不會列）就算 uuid 對也不轉送 —— 一筆收不下的
    資料會讓整批一直被 jt-ipam 拒絕。"""
    con = sqlite3.connect(rd.dir / "db_v2.sqlite3")
    con.execute("insert into peer (guid, id, uuid, pk, info) values (?,?,?,?,?)",
                (b"gx", "bad id <x>", UUID_RAW, b"pk", "{}"))
    con.commit()
    con.close()
    assert _send(rd.port, "/api/heartbeat", hb(id="bad id <x>"))[:2] == (200, b"{}")
    assert _send(rd.port, "/api/audit/conn", {"id": "bad id <x>", "session_id": 1, "note": "x"})[0] == 200
    assert _flush(rd) == []
    assert _dropped(rd)["unverified"] == 2


def test_slow_requests_are_cut_off(tmp_path, monkeypatch) -> None:
    a = _agent()
    monkeypatch.setattr(a, "RDAPI_SOCKET_TIMEOUT", 1.0)
    port = a._rdapi_start(0, "127.0.0.1")
    try:
        # 宣告的長度沒送完
        t0 = time.monotonic()
        _raw(port, b"POST /api/heartbeat HTTP/1.1\r\nContent-Length: 100\r\n\r\n{", wait=8)
        assert time.monotonic() - t0 < 4
        # 標頭一個位元組一個位元組慢慢送（每次都沒超過單次逾時）也要在時限內斷線
        s = socket.create_connection(("127.0.0.1", port), timeout=8)
        s.sendall(b"POST /api/heartbeat HTTP/1.1\r\nX-Slow: ")
        s.settimeout(0.3)
        t0, closed = time.monotonic(), False
        while time.monotonic() - t0 < 6:
            try:
                s.sendall(b"a")
                if s.recv(1) == b"":
                    closed = True
                    break
            except TimeoutError:
                continue
            except OSError:
                closed = True
                break
        s.close()
        assert closed and time.monotonic() - t0 < 4
    finally:
        a._rdapi_stop()


def test_uuid_never_leaves_the_host(rd, capsys) -> None:
    _send(rd.port, "/api/heartbeat", hb(conns=[1]))
    _send(rd.port, "/api/sysinfo", {"id": DEV, "uuid": UUID_B64, "hostname": "pc-01"})
    _send(rd.port, "/api/audit/conn", conn(action="new", ip="198.51.100.20"))
    _send(rd.port, "/api/audit/conn", conn(peer=["111222333", "bob"], type=0))
    _send(rd.port, "/api/audit/file", {"id": DEV, "uuid": UUID_B64, "peer_id": "1", "conn_id": 1, "type": 0,
                                       "path": "/x", "is_file": True, "info": "{}", "nonce": "n-file"})
    _send(rd.port, "/api/audit/alarm", {"id": DEV, "uuid": UUID_B64, "typ": 2, "info": "{}", "conn_id": 1,
                                        "nonce": "n-alarm"})
    _send(rd.port, "/api/sysinfo", {"id": DEV, "uuid": WRONG_B64, "hostname": "evil"})
    _send(rd.port, "/api/heartbeat", hb(conns="bad"))
    ev = _flush(rd)
    assert {e["kind"] for e in ev} == {"heartbeat", "sysinfo", "conn", "file", "alarm"}
    assert all("uuid" not in e for e in ev)
    blob = json.dumps(rd.sent)
    out = capsys.readouterr()
    logs = out.out + out.err
    for needle in (UUID_B64, UUID_B64.rstrip("="), UUID_RAW.hex(), WRONG_B64, repr(UUID_RAW)):
        assert needle not in blob
        assert needle not in logs


# ── 6. 轉送佇列 ────────────────────────────────────────────────────────────

def test_queue_cap_drops_oldest_and_counts(rd, monkeypatch) -> None:
    monkeypatch.setattr(rd.a, "RDAPI_QUEUE_CAP", 5)
    for i in range(8):
        rd.a._rdapi_enqueue({"kind": "conn", "nonce": f"n{i}"})
    ev = _flush(rd)
    assert [e["nonce"] for e in ev] == ["n3", "n4", "n5", "n6", "n7"]
    assert _dropped(rd)["queue_overflow"] == 3
    rd.a._rdapi_enqueue({"kind": "conn", "nonce": "n8"})
    _flush(rd)
    assert _dropped(rd)["queue_overflow"] == 0, "計數只算上次成功送出之後的"


def test_send_failure_keeps_the_queue(rd, monkeypatch) -> None:
    _send(rd.port, "/api/sysinfo", {"id": DEV, "uuid": UUID_B64, "hostname": "pc-01"})
    _send(rd.port, "/api/sysinfo", {"id": DEV, "uuid": WRONG_B64, "hostname": "evil"})

    def down(*a, **k):  # noqa: ANN002, ANN003
        raise OSError("server down")

    monkeypatch.setattr(rd.a, "_req", down)
    assert rd.a._rdapi_flush() is False
    monkeypatch.setattr(rd.a, "_req", rd.fake)
    ev = _flush(rd)
    assert [e["hostname"] for e in ev] == ["pc-01"]
    assert _dropped(rd)["unverified"] == 1
    n = len(rd.sent)
    assert rd.a._rdapi_flush() is True
    assert len(rd.sent) == n, "沒有新資料就不送"


def test_large_backlog_is_sent_in_batches(rd, monkeypatch) -> None:
    monkeypatch.setattr(rd.a, "RDAPI_FLUSH_BATCH", 3)
    for i in range(7):
        rd.a._rdapi_enqueue({"kind": "conn", "nonce": f"n{i}"})
    ev = _flush(rd)
    assert [len(s["body"]["events"]) for s in rd.sent] == [3, 3, 1]
    assert [e["nonce"] for e in ev] == [f"n{i}" for i in range(7)]


# ── 7. 開關：只有網頁上開啟才聽埠 ─────────────────────────────────────────

def test_apply_listens_only_when_enabled(monkeypatch) -> None:
    a = _agent()
    monkeypatch.setattr(a, "RDAPI_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(a, "_req", lambda *x, **k: {})
    p1, p2 = _free_port(), _free_port()
    try:
        a._rdapi_apply({"source_id": "s1", "interval_seconds": 300})
        assert not _listening(p1), "沒在網頁上開啟就不聽"
        a._rdapi_apply({"source_id": "s1", "interval_seconds": 300, "api_listen": True, "api_port": p1})
        assert _listening(p1)
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": p1})
        assert _listening(p1)
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": p2})
        assert _listening(p2) and not _listening(p1), "換埠要關掉舊的"
        a._rdapi_apply({"source_id": "s1", "api_listen": False, "api_port": p2})
        assert not _listening(p2)
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": p2})
        assert _listening(p2)
        a._rdapi_apply(None)
        assert not _listening(p2), "沒有指派就關掉"
        a._rdapi_apply({"api_listen": True, "api_port": p2})
        assert not _listening(p2), "沒有 source_id 不算指派"
    finally:
        a._rdapi_stop()


def test_apply_default_port(monkeypatch) -> None:
    a = _agent()
    port = _free_port()
    monkeypatch.setattr(a, "RDAPI_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(a, "RDAPI_DEFAULT_PORT", port)
    monkeypatch.setattr(a, "_req", lambda *x, **k: {})
    try:
        a._rdapi_apply({"source_id": "s1", "api_listen": True})
        assert _listening(port)
    finally:
        a._rdapi_stop()


def test_bind_failure_is_logged_and_retried(monkeypatch, capsys) -> None:
    a = _agent()
    monkeypatch.setattr(a, "RDAPI_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(a, "_req", lambda *x, **k: {})
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": port})   # 不可以丟例外
        assert str(port) in capsys.readouterr().err
        blocker.close()
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": port})
        assert _listening(port), "下一輪 poll 再試"
    finally:
        blocker.close()
        a._rdapi_stop()


def test_bind_failure_is_reported_to_jt_ipam(monkeypatch) -> None:
    a = _agent()
    monkeypatch.setattr(a, "RDAPI_LISTEN_HOST", "127.0.0.1")
    monkeypatch.setattr(a, "_req", lambda *x, **k: {})
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": port})
        st = a._rdapi_status()
        assert st["listening"] is False and str(port) in (st["error"] or ""), "畫面要看得到綁不上的原因"
        blocker.close()
        a._rdapi_apply({"source_id": "s1", "api_listen": True, "api_port": port})
        assert a._rdapi_status() == {"listening": True, "port": port, "error": None}
    finally:
        blocker.close()
        a._rdapi_stop()
