"""代理（接收端）與 jt-ipam（後端）之間的契約：兩邊分開寫（代理端是乾淨室實作），這裡把它們接起來。

假客戶端照 docs/SPEC_RUSTDESK_API_zh-TW.md 對代理的接收器送真的 HTTP 請求 → 拿代理轉送出來的內容
原封不動送進後端 /rustdesk/agent/events → 一筆都不可以被拒收，資料要落在對的地方。
"""
from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import sqlite3
import uuid

from sqlalchemy import select

from app.models.rustdesk import RustDeskAuditEvent, RustDeskPeer, RustDeskServer

_AGENT = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_rustdesk_agent.py"
DEV = "123456789"
UUID_RAW = b"4C4C4544-0039-3010-8048-B7C04F563532"
UUID_B64 = base64.b64encode(UUID_RAW).decode()


def _agent_mod():
    spec = importlib.util.spec_from_file_location(f"jt_agent_contract_{uuid.uuid4().hex[:6]}", _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _hbbs_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "rustdesk-server"
    d.mkdir()
    con = sqlite3.connect(d / "db_v2.sqlite3")
    con.executescript("""
        create table peer (
            guid blob primary key not null, id varchar(100) not null, uuid blob not null,
            pk blob not null, created_at datetime not null default(current_timestamp),
            user blob, status tinyint, note varchar(300), info text not null
        ) without rowid;
    """)
    con.execute("insert into peer (guid, id, uuid, pk, info) values (?,?,?,?,?)",
                (b"g1", DEV, UUID_RAW, b"pk", json.dumps({"ip": "192.0.2.10"})))
    con.commit()
    con.close()
    return d


def _post(port: int, path: str, body: dict) -> tuple[int, bytes]:
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request("POST", path, body=json.dumps(body).encode())
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


async def test_what_the_agent_forwards_is_accepted_by_the_server(client, db_session, tmp_path, monkeypatch) -> None:
    from app.services.rustdesk import agent_key_hash

    raw_key = "c1" * 20
    srv = RustDeskServer(name=f"rd-contract-{uuid.uuid4().hex[:6]}", agent_key_hash=agent_key_hash(raw_key))
    db_session.add(srv)
    await db_session.commit()

    a = _agent_mod()
    d = _hbbs_dir(tmp_path)
    monkeypatch.setattr(a, "_rustdesk_dir", lambda: str(d))
    sent: list[dict] = []
    monkeypatch.setattr(a, "_req", lambda method, path, body=None, extra_headers=None, timeout=30:
                        (path == "/api/v1/rustdesk/agent/events" and sent.append(json.loads(json.dumps(body))))
                        or {"status": "ok"})
    port = a._rdapi_start(0, "127.0.0.1")
    a._RDAPI["source_id"] = str(srv.id)
    try:
        base = {"id": DEV, "uuid": UUID_B64}
        n = lambda: str(uuid.uuid4())      # noqa: E731
        assert _post(port, "/api/heartbeat", {**base, "ver": 1005000, "modified_at": 0, "conns": [3]}) == (200, b"{}")
        assert _post(port, "/api/sysinfo", {**base, "version": "1.5.0", "hostname": "PC-01", "username": "alice",
                                            "os": "Windows 11 Pro", "cpu": "i5, 6/4 cores", "memory": "16GB",
                                            "preset-address-book-name": "x"}) == (200, b"SYSINFO_UPDATED")
        big = 2**63 + 5
        for body in ({**base, "conn_id": 3, "session_id": 0, "nonce": n(), "action": "new", "ip": "198.51.100.7"},
                     {**base, "conn_id": 3, "session_id": big, "nonce": n(), "peer": ["999888777", "helpdesk"],
                      "type": 0, "primary_auth": 1},
                     {**base, "conn_id": 3, "session_id": big, "nonce": n(), "action": "close"}):
            assert _post(port, "/api/audit/conn", body)[0] == 200
        assert _post(port, "/api/audit/file", {
            **base, "peer_id": "999888777", "conn_id": 3, "type": 1, "path": "/home/alice", "is_file": False,
            "info": json.dumps({"ip": "198.51.100.7", "name": "helpdesk", "num": 2,
                                "files": [["a.txt", 10], ["b.txt", 5]]}), "nonce": n()})[0] == 200
        assert _post(port, "/api/audit/alarm", {
            **base, "typ": 2, "conn_id": 3, "nonce": n(),
            "info": json.dumps({"ip": "203.0.113.9", "id": "555", "name": "x"})})[0] == 200
        assert _post(port, "/api/audit/conn", {"id": DEV, "session_id": big, "note": "fixed the printer"})[0] == 200
        assert a._rdapi_flush() is True
    finally:
        a._rdapi_stop()

    assert sent, "代理沒有轉送任何東西"
    assert UUID_B64 not in json.dumps(sent) and UUID_RAW.decode() not in json.dumps(sent)
    for body in sent:
        assert body is not None
        r = await client.post("/api/v1/rustdesk/agent/events", headers={"X-Agent-Key": raw_key}, json=body)
        assert r.status_code == 200, r.text
        assert r.json()["rejected"] == 0, f"後端拒收了代理轉送的事件：{r.json()}"

    p = (await db_session.execute(select(RustDeskPeer).where(RustDeskPeer.server_id == srv.id,
                                                              RustDeskPeer.rustdesk_id == DEV))).scalars().one()
    assert (p.hostname, p.username, p.os_name, p.client_version, p.active_conns) == (
        "PC-01", "alice", "Windows 11 Pro", "1.5.0", 1)
    rows = (await db_session.execute(select(RustDeskAuditEvent).where(RustDeskAuditEvent.server_id == srv.id)
                                     .order_by(RustDeskAuditEvent.occurred_at))).scalars().all()
    kinds = sorted((r.kind, r.action) for r in rows)
    assert kinds == sorted([("conn", "new"), ("conn", "auth"), ("conn", "close"), ("file", None),
                            ("alarm", None), ("note", None)])
    auth = next(r for r in rows if r.action == "auth")
    assert (auth.peer_id, auth.peer_name, auth.conn_type, auth.session_id) == ("999888777", "helpdesk", 0, str(big))
    f = next(r for r in rows if r.kind == "file")
    assert f.detail["files"] == [["a.txt", 10], ["b.txt", 5]] and f.detail["direction"] == 1
    alarm = next(r for r in rows if r.kind == "alarm")
    assert alarm.alarm_type == 2 and str(alarm.ip) == "203.0.113.9"
    note = next(r for r in rows if r.kind == "note")
    assert note.verified is False and note.detail["note"] == "fixed the printer"
