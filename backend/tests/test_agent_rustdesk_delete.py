"""RustDesk 代理的「刪除舊註冊」（代理 1.2.0）。

hbbs 永遠留著每一個註冊過的 ID；兩邊都允許時（jt-ipam 的 allow_peer_delete＋主機端以 --allow-delete 安裝），
代理照 jt-ipam 給的清單刪掉 hbbs 資料庫裡的舊註冊。這裡守的界線：
1. 主機端沒有允許（JT_RD_ALLOW_DELETE）或資料庫／目錄寫不了 → 一筆都不刪，結果是 failed 並說出原因
2. 刪之前再查一次線上狀態：上線中的不刪（skipped_online）；查不到線上狀態就整批不刪
3. 只刪 peer 表裡 id 相符的那一列，同一個交易；其他表、其他列、私鑰檔都不動
4. hbbs 正在寫入（資料庫鎖住）時等一下，等不到就失敗、交易還原
5. 能力（capabilities）隨輪詢回報；「測試」多一項，沒開不算錯誤
6. 結果送不到 jt-ipam 時留著下次再送，不重做（已經刪掉的再刪會變成「找不到」）
"""
from __future__ import annotations

import json
import sqlite3

from tests.test_agent_rustdesk import PRIV, _agent, _data_dir

IDS = [("111111111", "2023-01-02 03:04:05", json.dumps({"ip": "192.0.2.11"})),
       ("222222222", "2023-02-03 04:05:06", json.dumps({"ip": "192.0.2.12"})),
       ("333333333", "2026-03-04 05:06:07", json.dumps({"ip": "192.0.2.13"}))]


def _ids_in(d) -> set[str]:
    con = sqlite3.connect(d / "db_v2.sqlite3")
    try:
        return {r[0] for r in con.execute("select id from peer")}
    finally:
        con.close()


def _setup(tmp_path, monkeypatch, *, allow: bool = True, online: set[str] | None = None, online_err: str | None = None):
    a = _agent()
    d = _data_dir(tmp_path, IDS)
    if allow:
        monkeypatch.setenv("JT_RD_ALLOW_DELETE", "1")
    else:
        monkeypatch.delenv("JT_RD_ALLOW_DELETE", raising=False)
    asked: list[list[str]] = []

    def fake_online(ids, host, port):  # noqa: ANN001, ANN202
        asked.append(list(ids))
        if online_err:
            return {}, online_err
        return {i: i in (online or set()) for i in ids}, None

    monkeypatch.setattr(a, "_rustdesk_online", fake_online)
    monkeypatch.setattr(a, "_rustdesk_local_ip", lambda: "192.0.2.1")
    monkeypatch.setattr(a, "_rustdesk_dir", lambda: str(d))
    return a, d, asked


# ── 1. 能力 ────────────────────────────────────────────────────────────────

def test_capability_needs_the_host_flag(tmp_path, monkeypatch) -> None:
    a, d, _ = _setup(tmp_path, monkeypatch, allow=False)
    ok, why = a._rustdesk_delete_capability(str(d))
    assert ok is False and "--allow-delete" in why, "主機端沒有以 --allow-delete 安裝 → 不寫，並說怎麼開"
    monkeypatch.setenv("JT_RD_ALLOW_DELETE", "1")
    assert a._rustdesk_delete_capability(str(d)) == (True, None)


def test_capability_needs_a_writable_database_and_directory(tmp_path, monkeypatch) -> None:
    """systemd 的 ReadOnlyPaths 讓 access(W_OK) 失敗（EROFS）：檔案與目錄要分開看，原因要講出是哪一個。"""
    a, d, _ = _setup(tmp_path, monkeypatch)
    db = str(d / "db_v2.sqlite3")
    real = a.os.access
    monkeypatch.setattr(a.os, "access", lambda p, m: False if (p == db and m == a.os.W_OK) else real(p, m))
    ok, why = a._rustdesk_delete_capability(str(d))
    assert ok is False and db in why and "read-only" in why
    monkeypatch.setattr(a.os, "access", lambda p, m: False if (p == str(d) and m == a.os.W_OK) else real(p, m))
    ok, why = a._rustdesk_delete_capability(str(d))
    assert ok is False and "directory" in why
    ok, why = a._rustdesk_delete_capability(str(tmp_path / "missing"))
    assert ok is False and "not found" in why


def test_poll_body_reports_the_capability(tmp_path, monkeypatch) -> None:
    a, _d, _ = _setup(tmp_path, monkeypatch, allow=False)
    body = a._poll_body({})
    assert body["capabilities"]["delete"] is False and "--allow-delete" in body["capabilities"]["delete_reason"]
    monkeypatch.setenv("JT_RD_ALLOW_DELETE", "1")
    assert a._poll_body({})["capabilities"] == {"delete": True, "delete_reason": None}


def test_selftest_has_the_delete_check_and_off_is_not_an_error(tmp_path, monkeypatch) -> None:
    a, _d, _ = _setup(tmp_path, monkeypatch, allow=False)
    monkeypatch.setattr(a, "_rustdesk_version", lambda: "1.1.16")
    checks = {c["key"]: c for c in a._selftest()}
    assert checks["peer_delete"] == {"key": "peer_delete", "ok": True, "detail": "read-only (delete not enabled)"}
    monkeypatch.setenv("JT_RD_ALLOW_DELETE", "1")
    checks = {c["key"]: c for c in a._selftest()}
    assert checks["peer_delete"]["ok"] is True and "writable" in checks["peer_delete"]["detail"]
    monkeypatch.setattr(a, "_rustdesk_delete_capability", lambda d: (False, "/x/db_v2.sqlite3: read-only for the agent"))
    checks = {c["key"]: c for c in a._selftest()}
    assert checks["peer_delete"] == {"key": "peer_delete", "ok": False,
                                     "detail": "/x/db_v2.sqlite3: read-only for the agent"}


# ── 2. 刪除 ────────────────────────────────────────────────────────────────

def test_deletes_only_the_requested_rows_of_the_peer_table(tmp_path, monkeypatch) -> None:
    a, d, asked = _setup(tmp_path, monkeypatch)
    con = sqlite3.connect(d / "db_v2.sqlite3")
    con.execute("create table other (id varchar(100), note text)")
    con.execute("insert into other values ('111111111', 'must stay')")
    con.commit()
    con.close()
    res = a._rustdesk_delete_peers(str(d), ["111111111", "999999999"])
    assert res == {"111111111": ("deleted", None), "999999999": ("not_found", None)}
    assert asked == [["111111111", "999999999"]], "刪之前要再查一次線上狀態"
    assert _ids_in(d) == {"222222222", "333333333"}, "只刪要求的那一列"
    con = sqlite3.connect(d / "db_v2.sqlite3")
    assert con.execute("select note from other").fetchall() == [("must stay",)], "其他表不動"
    con.close()
    assert (d / "id_ed25519").read_text() == PRIV and (d / "id_ed25519.pub").exists(), "金鑰檔不動"


def test_online_ids_are_skipped(tmp_path, monkeypatch) -> None:
    """jt-ipam 看到的是上次回報時的狀態；刪之前 hbbs 說它上線了就不刪。"""
    a, d, _ = _setup(tmp_path, monkeypatch, online={"222222222"})
    res = a._rustdesk_delete_peers(str(d), ["111111111", "222222222"])
    assert res == {"111111111": ("deleted", None), "222222222": ("skipped_online", None)}
    assert _ids_in(d) == {"222222222", "333333333"}


def test_failed_online_check_deletes_nothing(tmp_path, monkeypatch) -> None:
    a, d, _ = _setup(tmp_path, monkeypatch, online_err="ConnectionRefusedError: refused")
    res = a._rustdesk_delete_peers(str(d), ["111111111", "222222222"])
    assert {st for st, _ in res.values()} == {"failed"}
    assert "refused" in res["111111111"][1] and "nothing deleted" in res["111111111"][1]
    assert _ids_in(d) == {"111111111", "222222222", "333333333"}, "不確定是否離線就不動"


def test_without_write_capability_nothing_is_touched(tmp_path, monkeypatch) -> None:
    a, d, asked = _setup(tmp_path, monkeypatch, allow=False)
    before = (d / "db_v2.sqlite3").read_bytes()
    res = a._rustdesk_delete_peers(str(d), ["111111111"])
    assert res["111111111"][0] == "failed" and "--allow-delete" in res["111111111"][1]
    assert (d / "db_v2.sqlite3").read_bytes() == before
    assert asked == [], "沒有權限就連線上狀態都不必查"


def test_a_locked_database_fails_and_rolls_back(tmp_path, monkeypatch) -> None:
    """hbbs 正在寫入：等 busy timeout，等不到就整批失敗（原因原文帶回去），一筆都沒刪。"""
    a, d, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(a, "RUSTDESK_DELETE_BUSY_SECONDS", 0.2)
    holder = sqlite3.connect(d / "db_v2.sqlite3", isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        res = a._rustdesk_delete_peers(str(d), ["111111111", "222222222"])
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert {st for st, _ in res.values()} == {"failed"}
    assert "locked" in res["111111111"][1]
    assert _ids_in(d) == {"111111111", "222222222", "333333333"}


def test_reads_stay_read_only_and_the_rw_opener_never_creates_a_file(tmp_path) -> None:
    a = _agent()
    try:
        a._rustdesk_db_open_rw(str(tmp_path / "nope.sqlite3")).execute("select 1")
        created = True
    except sqlite3.OperationalError:
        created = False
    assert created is False and not (tmp_path / "nope.sqlite3").exists(), "mode=rw：不存在就失敗，不建立新檔"
    d = _data_dir(tmp_path, IDS)
    con = a._rustdesk_db_open(str(d / "db_v2.sqlite3"))
    try:
        con.execute("delete from peer")
        wrote = True
    except sqlite3.OperationalError:
        wrote = False
    finally:
        con.close()
    assert wrote is False, "讀取用的開啟函式一律唯讀"


def test_deleted_ids_leave_the_report_verification_cache(tmp_path, monkeypatch) -> None:
    a, d, _ = _setup(tmp_path, monkeypatch)
    a._RDAPI_CACHE["111111111"] = (1e18, True, b"x")
    a._rustdesk_delete_peers(str(d), ["111111111"])
    assert "111111111" not in a._RDAPI_CACHE, "刪掉的 ID 不可以再被快取當成存在"


# ── 3. 輪詢與結果 ──────────────────────────────────────────────────────────

def _sync_threads(a, monkeypatch) -> None:
    monkeypatch.setattr(a.threading, "Thread",
                        lambda target, args, **kw: type("T", (), {"start": lambda self: target(*args)})())


def test_jobs_from_the_server_are_validated(monkeypatch) -> None:
    a = _agent()
    cfg = {"peer_deletes": [{"req_id": "r1", "rustdesk_id": "111111111"},
                            {"req_id": "r2", "rustdesk_id": "bad id; drop table"},
                            {"req_id": 5, "rustdesk_id": "222222222"}, "junk",
                            *({"req_id": f"x{i}", "rustdesk_id": f"{500000000 + i}"} for i in range(300))]}
    jobs = a._rustdesk_delete_jobs(cfg)
    assert jobs[0] == ("r1", "111111111") and len(jobs) == 200
    assert all(a._RUSTDESK_ID.match(pid) for _r, pid in jobs)
    assert a._rustdesk_delete_jobs({}) == [] and a._rustdesk_delete_jobs(None) == []


def test_results_are_sent_and_kept_when_not_delivered(tmp_path, monkeypatch) -> None:
    a, d, _ = _setup(tmp_path, monkeypatch)
    _sync_threads(a, monkeypatch)
    calls: list = []
    runs: list = []
    real = a._rustdesk_delete_peers
    monkeypatch.setattr(a, "_rustdesk_delete_peers", lambda dd, ids: runs.append(list(ids)) or real(dd, ids))
    fail = {"on": True}

    def fake_req(method, path, body=None, extra_headers=None, timeout=30):  # noqa: ANN001, ANN202
        calls.append((path, body))
        if fail["on"]:
            raise OSError("network down")
        return {"status": "ok"}

    monkeypatch.setattr(a, "_req", fake_req)
    cfg = {"source_id": "s1", "peer_deletes": [{"req_id": "r1", "rustdesk_id": "111111111"},
                                               {"req_id": "r2", "rustdesk_id": "999999999"}]}
    a._rustdesk_maybe_delete(cfg)
    assert calls[-1][0] == "/api/v1/rustdesk/agent/delete-result"
    assert calls[-1][1] == {"source_id": "s1", "results": [
        {"req_id": "r1", "status": "deleted", "detail": None},
        {"req_id": "r2", "status": "not_found", "detail": None}]}
    fail["on"] = False
    a._rustdesk_maybe_delete(cfg)                   # 伺服器還沒收到 → 下次輪詢又帶同一批
    assert runs == [["111111111", "999999999"]], "送不到的結果留著再送，不重做"
    assert calls[-1][1]["results"][0] == {"req_id": "r1", "status": "deleted", "detail": None}
    assert a._DELETE_UNSENT == {}


def test_poll_runs_deletes_only_when_active(monkeypatch) -> None:
    a = _agent()
    cfg = {"source_id": "s1", "enabled": True, "interval_seconds": 300, "api_listen": False, "api_port": 21114,
           "report_now": False, "test_id": None, "agent_sha": "x", "poll_seconds": 10,
           "peer_deletes": [{"req_id": "r1", "rustdesk_id": "111111111"}]}
    monkeypatch.setattr(a, "_req", lambda m, p, body=None, extra_headers=None, timeout=30: dict(cfg))
    monkeypatch.setattr(a, "_maybe_self_update", lambda sha: None)
    monkeypatch.setattr(a, "_rdapi_apply", lambda c: None)
    monkeypatch.setattr(a, "_rustdesk_maybe_report", lambda c, now, force=False: None)
    seen: list = []
    monkeypatch.setattr(a, "_rustdesk_maybe_delete", seen.append)
    a.poll_once()
    assert seen and seen[-1]["peer_deletes"]
    cfg["enabled"] = False
    a.poll_once()
    assert len(seen) == 1, "停用的伺服器不刪"
