"""RustDesk Server（開源版）整合的代理端：裝在 RustDesk 主機上的專用 RustDesk 代理讀 hbbs 的資料庫、查線上狀態，
只回報解析後的結果（ID、首次註冊時間、登記 IP、是否在線、公鑰、版本）。

開源版沒有管理 API（那是 Pro 版的功能），能用的只有：
- hbbs 工作目錄（官方 deb：/var/lib/rustdesk-server）的 SQLite `peer` 表 —— `info` 只有 `{"ip": ...}`
- TCP 21115 的 `OnlineRequest`（protobuf＋hbb_common 的長度前綴）—— **從 127.0.0.1 連會被當成文字管理指令**，
  所以要連主機自己的網卡位址

這裡守的界線：
1. 只取 id／created_at／info.ip 三個欄位；pk、uuid、guid 不讀，私鑰檔 `id_ed25519` 絕不讀
2. 讀不到資料庫要明說（ok=False＋原因），不可以變成「0 台裝置」—— 伺服器會據此把裝置全部清掉
3. OnlineRequest 的封包格式要與 hbbs 一致（用假伺服器驗：長度前綴、欄位編號、位元組順序）
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import socket
import sqlite3
import threading
import uuid

_AGENT = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_rustdesk_agent.py"
_SCAN_AGENT = _AGENT.with_name("jt_ipam_agent.py")

PRIV = "PRIVATE-KEY-MUST-NEVER-LEAVE-THIS-HOST-" + "A" * 49
PUB = "E2EfakeRustDeskKeyForTestsOnly0000000000000="


def _agent():
    spec = importlib.util.spec_from_file_location(f"jt_agent_rd_{uuid.uuid4().hex[:6]}", _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _data_dir(tmp_path: pathlib.Path, peers: list[tuple], *, env: str | None = None) -> pathlib.Path:
    """照 rustdesk-server 的 database.rs 建一個 hbbs 工作目錄。"""
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
    for i, (pid, created, info) in enumerate(peers):
        con.execute("insert into peer (guid, id, uuid, pk, created_at, info) values (?,?,?,?,?,?)",
                    (f"g{i}".encode(), pid, b"uuid-secret", b"pk-bytes", created, info))
    con.commit()
    con.close()
    (d / "id_ed25519").write_text(PRIV)
    (d / "id_ed25519.pub").write_text(PUB)
    if env is not None:
        (d / ".env").write_text(env)
    return d


# ── 1. 讀資料庫 ────────────────────────────────────────────────────────────

def test_reads_only_id_created_and_ip(tmp_path) -> None:
    a = _agent()
    d = _data_dir(tmp_path, [
        ("123456789", "2026-01-02 03:04:05", json.dumps({"ip": "192.0.2.10"})),
        ("987654321", "2026-02-03 04:05:06", json.dumps({"ip": "::ffff:198.51.100.7"})),
        ("555666777", "2026-03-04 05:06:07", json.dumps({})),
    ])
    st, peers = a._rustdesk_read_peers(str(d / "db_v2.sqlite3"))
    assert st["ok"] is True
    by_id = {p["id"]: p for p in peers}
    assert by_id["123456789"] == {"id": "123456789", "created_at": "2026-01-02 03:04:05", "ip": "192.0.2.10"}
    assert by_id["987654321"]["ip"] == "198.51.100.7", "雙堆疊的 IPv4 對應位址要還原成 IPv4"
    assert by_id["555666777"]["ip"] is None
    assert all(set(p) == {"id", "created_at", "ip"} for p in peers), "pk／uuid／guid 不可以出現在回報裡"


def test_skips_rows_with_unusable_values(tmp_path) -> None:
    a = _agent()
    d = _data_dir(tmp_path, [
        ("ok_id-1", "2026-01-01 00:00:00", json.dumps({"ip": "192.0.2.1"})),
        ("bad id <script>", "2026-01-01 00:00:00", json.dumps({"ip": "192.0.2.2"})),
        ("123123123", "2026-01-01 00:00:00", "not json"),
        ("456456456", "2026-01-01 00:00:00", json.dumps({"ip": "not-an-ip"})),
    ])
    _st, peers = a._rustdesk_read_peers(str(d / "db_v2.sqlite3"))
    ids = {p["id"]: p["ip"] for p in peers}
    assert "bad id <script>" not in ids, "ID 是外部寫進來的字串，不合格式就丟掉"
    assert ids["ok_id-1"] == "192.0.2.1"
    assert ids["123123123"] is None and ids["456456456"] is None, "info 壞掉只是沒有 IP，裝置照樣列出"


def test_missing_database_is_an_error_not_zero_devices(tmp_path) -> None:
    a = _agent()
    st, peers = a._rustdesk_read_peers(str(tmp_path / "nope" / "db_v2.sqlite3"))
    assert st["ok"] is False
    assert st["error"], "要講出原因"
    assert peers == []


def test_database_is_opened_read_only(tmp_path) -> None:
    a = _agent()
    d = _data_dir(tmp_path, [("123456789", "2026-01-01 00:00:00", json.dumps({"ip": "192.0.2.1"}))])
    before = (d / "db_v2.sqlite3").read_bytes()
    a._rustdesk_read_peers(str(d / "db_v2.sqlite3"))
    assert (d / "db_v2.sqlite3").read_bytes() == before


def test_public_key_is_read_and_private_key_never(tmp_path) -> None:
    a = _agent()
    d = _data_dir(tmp_path, [])
    assert a._rustdesk_public_key(str(d)) == PUB
    (d / "id_ed25519.pub").write_text("garbage that is not a key")
    assert a._rustdesk_public_key(str(d)) is None


def test_collect_never_contains_the_private_key(tmp_path, monkeypatch) -> None:
    a = _agent()
    d = _data_dir(tmp_path, [("123456789", "2026-01-01 00:00:00", json.dumps({"ip": "192.0.2.1"}))])
    monkeypatch.setattr(a, "_rustdesk_online", lambda ids, host, port: ({i: True for i in ids}, None))
    monkeypatch.setattr(a, "_rustdesk_version", lambda: "1.1.16")
    data = a._rustdesk_collect(str(d))
    blob = json.dumps(data)
    assert PRIV not in blob
    assert "uuid-secret" not in blob and "pk-bytes" not in blob
    assert data["public_key"] == PUB
    assert data["version"] == "1.1.16"
    assert data["files"]["db"]["ok"] is True
    assert data["online_ok"] is True
    assert data["peers"] == [{"id": "123456789", "created_at": "2026-01-01 00:00:00",
                              "ip": "192.0.2.1", "online": True}]


def test_online_failure_is_reported_separately(tmp_path, monkeypatch) -> None:
    """查線上狀態失敗（hbbs 沒在跑、埠不通）不影響裝置清單；伺服器據此保留上一次的在線狀態。"""
    a = _agent()
    d = _data_dir(tmp_path, [("123456789", "2026-01-01 00:00:00", json.dumps({"ip": "192.0.2.1"}))])
    monkeypatch.setattr(a, "_rustdesk_online", lambda ids, host, port: ({}, "ConnectionRefusedError: refused"))
    monkeypatch.setattr(a, "_rustdesk_version", lambda: None)
    data = a._rustdesk_collect(str(d))
    assert data["online_ok"] is False
    assert "refused" in data["online_error"]
    assert data["peers"][0]["online"] is None


# ── 2. 連接埠 ──────────────────────────────────────────────────────────────

def test_online_port_follows_hbbs_port_in_env_file(tmp_path) -> None:
    """OnlineRequest 走 hbbs 的「主埠 − 1」（預設 21116 → 21115）；改過 PORT 時跟著改。"""
    a = _agent()
    assert a._rustdesk_online_port(str(_data_dir(tmp_path, []))) == 21115
    other = tmp_path / "x"
    other.mkdir()
    d2 = _data_dir(other, [], env="RELAY_SERVERS=rd.example.net:21117\nPORT=31116\nKEY=_\n")
    assert a._rustdesk_online_port(str(d2)) == 31115


# ── 3. OnlineRequest 封包 ─────────────────────────────────────────────────

def _varint(b: bytes, i: int) -> tuple[int, int]:
    shift = n = 0
    while True:
        c = b[i]
        i += 1
        n |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return n, i


def _fields(b: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(b):
        tag, i = _varint(b, i)
        ln, i = _varint(b, i)
        out.append((tag >> 3, b[i:i + ln]))
        i += ln
    return out


class FakeHbbs:
    """照 hbbs 的 handle_listener2：讀一個 frame、解 RendezvousMessage.online_request(23)、
    回 online_response(24)｛states(1)｝—— 第 i 個 ID 在 states[i/8] 的第 7-i%8 位元。"""

    def __init__(self, online: set[str]) -> None:
        self.online = online
        self.requests: list[list[str]] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                buf = b""
                while len(buf) < 1 or len(buf) < (buf[0] & 3) + 1:
                    buf += c.recv(65536)
                hl = (buf[0] & 3) + 1
                n = int.from_bytes(buf[:hl], "little") >> 2
                while len(buf) < hl + n:
                    buf += c.recv(65536)
                (num, inner), = _fields(buf[hl:hl + n])
                assert num == 23
                peers = [v.decode() for f, v in _fields(inner) if f == 2]
                self.requests.append(peers)
                states = bytearray((len(peers) + 7) // 8)
                for k, p in enumerate(peers):
                    if p in self.online:
                        states[k // 8] |= 1 << (7 - k % 8)
                resp = bytes([1 << 3 | 2, len(states)]) + bytes(states) if len(states) < 128 else (
                    bytes([1 << 3 | 2]) + _enc_varint(len(states)) + bytes(states))
                msg = bytes([0xC2, 0x01]) + _enc_varint(len(resp)) + resp
                ln = len(msg)
                head = bytes([ln << 2]) if ln <= 0x3F else ((ln << 2) | 1).to_bytes(2, "little")
                c.sendall(head + msg)


def _enc_varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def test_online_request_matches_hbbs_wire_format() -> None:
    a = _agent()
    srv = FakeHbbs({"222222222", "444444444"})
    ids = ["111111111", "222222222", "333333333", "444444444"]
    states, err = a._rustdesk_online(ids, "127.0.0.1", srv.port)
    assert err is None
    assert states == {"111111111": False, "222222222": True, "333333333": False, "444444444": True}
    assert srv.requests == [ids]


def test_many_ids_are_queried_in_batches() -> None:
    a = _agent()
    ids = [f"{100000000 + i}" for i in range(2500)]
    srv = FakeHbbs({ids[0], ids[1499], ids[2499]})
    states, err = a._rustdesk_online(ids, "127.0.0.1", srv.port)
    assert err is None
    assert sum(states.values()) == 3
    assert states[ids[1499]] is True
    assert len(srv.requests) == 3 and max(len(r) for r in srv.requests) <= 1000


def test_unreachable_hbbs_returns_an_error() -> None:
    a = _agent()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                   # 沒人在聽
    states, err = a._rustdesk_online(["123456789"], "127.0.0.1", port)
    assert states == {}
    assert err


def test_local_address_is_not_loopback() -> None:
    """hbbs 把來自 loopback 的連線當成文字管理指令 —— 查線上狀態一定要用主機自己的網卡位址。"""
    a = _agent()
    ip = a._rustdesk_local_ip()
    assert ip and not ip.startswith("127.") and ip != "::1"


# ── 4. 只有伺服器指派了才動作；「立即同步」不等間隔 ─────────────────────────────

def test_does_nothing_unless_assigned(monkeypatch) -> None:
    a = _agent()
    started: list[str] = []
    monkeypatch.setattr(a.threading, "Thread",
                        lambda target, args, **kw: type("T", (), {"start": lambda self: started.append(args[0])})())
    a._rustdesk_maybe_report(None, 1000.0)
    a._rustdesk_maybe_report({}, 1000.0)
    assert started == []
    a._rustdesk_maybe_report({"source_id": "abc", "interval_seconds": 300}, 1000.0)
    assert started == ["abc"]
    a._rustdesk_maybe_report({"source_id": "abc", "interval_seconds": 300}, 1100.0)
    assert started == ["abc"], "間隔內不重複讀"
    a._RUSTDESK_STATE["running"] = False
    a._rustdesk_maybe_report({"source_id": "abc", "interval_seconds": 300}, 1110.0, force=True)
    assert started == ["abc", "abc"], "立即同步不等間隔"


# ── 5. 輪詢：設定、立即同步、測試 ────────────────────────────────────────────

def _fake_poll(a, monkeypatch, cfg: dict) -> list:
    calls: list = []

    def fake_req(method, path, body=None, extra_headers=None, timeout=30):  # noqa: ANN001
        calls.append((method, path, body))
        return dict(cfg) if path.endswith("/poll") else {"status": "ok"}

    monkeypatch.setattr(a, "_req", fake_req)
    monkeypatch.setattr(a, "_maybe_self_update", lambda sha: None)
    return calls


def test_poll_applies_the_settings(monkeypatch) -> None:
    a = _agent()
    cfg = {"source_id": "s1", "enabled": True, "interval_seconds": 300, "api_listen": True, "api_port": 21114,
           "report_now": True, "test_id": None, "agent_sha": "x", "poll_seconds": 10}
    calls = _fake_poll(a, monkeypatch, cfg)
    applied, reports = [], []
    monkeypatch.setattr(a, "_rdapi_apply", applied.append)
    monkeypatch.setattr(a, "_rustdesk_maybe_report", lambda c, now, force=False: reports.append(force))
    assert a.poll_once() == 10
    assert calls[0][1] == "/api/v1/rustdesk/agent/poll"
    body = calls[0][2]
    assert body["version"] == a.AGENT_VERSION and "receiver" in body and "data_dir" in body
    assert applied[-1]["api_listen"] is True and reports == [True]
    _fake_poll(a, monkeypatch, {**cfg, "enabled": False})
    a.poll_once()
    assert applied[-1] is None and reports == [True], "停用：不聽、不讀"
    _fake_poll(a, monkeypatch, {**cfg, "poll_seconds": 1})
    assert a.poll_once() == 5, "伺服器給的輪詢間隔有下限"


def test_a_test_request_runs_once_and_reports(monkeypatch) -> None:
    a = _agent()
    cfg = {"source_id": "s1", "enabled": True, "interval_seconds": 300, "api_listen": False, "api_port": 21114,
           "report_now": False, "test_id": "t-1", "agent_sha": "x", "poll_seconds": 10}
    calls = _fake_poll(a, monkeypatch, cfg)
    monkeypatch.setattr(a, "_rdapi_apply", lambda c: None)
    monkeypatch.setattr(a, "_rustdesk_maybe_report", lambda c, now, force=False: None)
    monkeypatch.setattr(a, "_selftest", lambda: [{"key": "database", "ok": True, "detail": "x"}])
    monkeypatch.setattr(a.threading, "Thread",
                        lambda target, args, **kw: type("T", (), {"start": lambda self: target(*args)})())
    a.poll_once()
    a.poll_once()
    sent = [c for c in calls if c[1].endswith("/test-result")]
    assert len(sent) == 1, "同一個測試只跑一次"
    assert sent[0][2] == {"test_id": "t-1", "checks": [{"key": "database", "ok": True, "detail": "x"}]}


def test_selftest_checks_everything_on_this_host(tmp_path, monkeypatch) -> None:
    a = _agent()
    d = _data_dir(tmp_path, [("123456789", "2026-01-02 03:04:05", json.dumps({"ip": "192.0.2.1"}))])
    monkeypatch.setattr(a, "_rustdesk_dir", lambda: str(d))
    monkeypatch.setattr(a, "_rustdesk_version", lambda: "1.1.16")
    monkeypatch.setattr(a, "_rustdesk_online", lambda ids, host, port: ({}, "ConnectionRefusedError: refused"))
    checks = {c["key"]: c for c in a._selftest()}
    assert set(checks) == {"data_dir", "database", "public_key", "hbbs_version", "online_query", "peer_delete", "logs",
                           "receiver"}
    assert checks["database"]["ok"] and "1 IDs" in checks["database"]["detail"]
    assert checks["public_key"]["ok"] and checks["hbbs_version"]["detail"] == "1.1.16"
    assert not checks["online_query"]["ok"] and "refused" in checks["online_query"]["detail"]
    assert checks["receiver"] == {"key": "receiver", "ok": True, "detail": "off"}
    assert PRIV not in json.dumps(checks), "測試結果不可以帶出私鑰"


def test_scan_agent_no_longer_touches_rustdesk() -> None:
    src = _SCAN_AGENT.read_text(encoding="utf-8")
    for needle in ("_rustdesk_", "_rdapi_", "rustdesk-events", "21114"):
        assert needle not in src, f"RustDesk 改由專用代理負責，掃描代理不該再有 {needle}"
