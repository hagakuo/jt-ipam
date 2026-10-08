"""RustDesk 代理讀 hbbr／hbbs 的日誌，找出「Key 設錯」的客戶端。

起因（2026-10-05 實機）：win11-desk-01 的 RustDesk Key 有兩個字母大小寫顛倒。它照樣向 hbbs 註冊（顯示「就緒」，
註冊不檢查 Key）、照樣回報主機名稱，同一區網的 RustDesk 程式直接連線也正常；只有走中繼時被 hbbr 拒絕，
網頁連線一定走中繼，所以看起來像網頁連線壞了。hbbr 的日誌寫得很清楚，只是沒人看得到。

日誌格式（官方 deb 1.1.16，systemd 把 stdout 附加到 /var/log/rustdesk-server/{hbbr,hbbs}.log）：
  [2026-10-05 07:02:15.843229 +08:00] WARN [src/relay_server.rs:431] Relay authentication failed from [::ffff:192.0.2.54]:56019 - invalid key
  [2026-10-04 18:43:00.727774 +08:00] WARN [src/rendezvous_server.rs:683] Authentication failed from [::ffff:192.0.2.86]:38160 for peer 000000001 - invalid key
  [2026-10-05 01:13:06.764229 +08:00] INFO [src/relay_server.rs:453] New relay request 48523c24-... from [::ffff:192.0.2.8]:19913
  [2026-10-05 01:13:07.068381 +08:00] INFO [src/relay_server.rs:437] Relayrequest 48523c24-... from [::ffff:192.0.2.44]:57212 got paired

界線：只讀、不改日誌；只送「哪個 IP 在什麼時間被拒／通過幾次」，不送日誌原文；
輪替（copytruncate 會讓檔案變小）與半行要處理；送不出去的下一輪再送，不可以掉。
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid

_AGENT = pathlib.Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_rustdesk_agent.py"

FAIL_RELAY = ("[2026-10-05 07:02:15.843229 +08:00] WARN [src/relay_server.rs:431] Relay authentication failed "
              "from [::ffff:192.0.2.54]:56019 - invalid key\n")
FAIL_RELAY2 = ("[2026-10-05 07:02:26.143295 +08:00] WARN [src/relay_server.rs:431] Relay authentication failed "
               "from [::ffff:192.0.2.54]:56022 - invalid key\n")
FAIL_HBBS = ("[2026-10-04 18:43:00.727774 +08:00] WARN [src/rendezvous_server.rs:683] Authentication failed from "
             "[::ffff:192.0.2.86]:38160 for peer 000000001 - invalid key\n")
OK_NEW = ("[2026-10-05 01:13:06.764229 +08:00] INFO [src/relay_server.rs:453] New relay request "
          "48523c24-f67c-4ec1-ae82-34475d02df2a from [::ffff:192.0.2.8]:19913\n")
OK_PAIRED = ("[2026-10-05 01:13:07.068381 +08:00] INFO [src/relay_server.rs:437] Relayrequest "
             "48523c24-f67c-4ec1-ae82-34475d02df2a from [::ffff:192.0.2.44]:57212 got paired\n")
NOISE = "[2026-10-04 16:30:57.745684 +08:00] INFO [src/relay_server.rs:125] LIMIT_SPEED: 32Mb/s\n"


def _agent(monkeypatch, log_dir: pathlib.Path):
    monkeypatch.setenv("JT_RD_LOG_DIR", str(log_dir))
    spec = importlib.util.spec_from_file_location(f"jt_agent_rdk_{uuid.uuid4().hex[:6]}", _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _logs(tmp_path: pathlib.Path, hbbr: str = "", hbbs: str = "") -> pathlib.Path:
    d = tmp_path / "rustdesk-log"
    d.mkdir(exist_ok=True)
    (d / "hbbr.log").write_text(hbbr, encoding="utf-8")
    (d / "hbbs.log").write_text(hbbs, encoding="utf-8")
    return d


def test_parse_the_four_line_kinds(tmp_path, monkeypatch) -> None:
    a = _agent(monkeypatch, _logs(tmp_path))
    assert a._keylog_parse(FAIL_RELAY) == ("relay", "192.0.2.54", None, "2026-10-05T07:02:15+08:00")
    assert a._keylog_parse(FAIL_HBBS) == ("hbbs", "192.0.2.86", "000000001", "2026-10-04T18:43:00+08:00")
    assert a._keylog_parse(OK_NEW) == ("ok", "192.0.2.8", None, "2026-10-05T01:13:06+08:00")
    assert a._keylog_parse(OK_PAIRED) == ("ok", "192.0.2.44", None, "2026-10-05T01:13:07+08:00")
    assert a._keylog_parse(NOISE) is None
    assert a._keylog_parse("garbage") is None
    # IPv4 直接寫（沒有 ::ffff: 也沒有中括號）也要認得
    assert a._keylog_parse(FAIL_RELAY.replace("[::ffff:192.0.2.54]", "192.0.2.54"))[1] == "192.0.2.54"


def test_collect_aggregates_per_ip_and_reports_once(tmp_path, monkeypatch) -> None:
    d = _logs(tmp_path, hbbr=NOISE + FAIL_RELAY + FAIL_RELAY2 + OK_NEW + OK_PAIRED, hbbs=FAIL_HBBS)
    a = _agent(monkeypatch, d)
    a._keylog_collect()
    kc = a._keylog_take()
    fails = {(f["scope"], f["ip"]): f for f in kc["fails"]}
    assert fails[("relay", "192.0.2.54")]["n"] == 2
    assert fails[("relay", "192.0.2.54")]["first"] == "2026-10-05T07:02:15+08:00"
    assert fails[("relay", "192.0.2.54")]["last"] == "2026-10-05T07:02:26+08:00"
    assert fails[("hbbs", "192.0.2.86")]["target"] == "000000001"
    assert {o["ip"] for o in kc["ok"]} == {"192.0.2.8", "192.0.2.44"}
    assert kc["logs"]["hbbr"] is True and kc["logs"]["hbbs"] is True and kc["logs"]["error"] is None
    # 送過的不再送；沒有新的日誌就是空的
    a._keylog_collect()
    kc = a._keylog_take()
    assert kc["fails"] == [] and kc["ok"] == []


def test_only_new_lines_after_the_first_read_and_half_lines_wait(tmp_path, monkeypatch) -> None:
    d = _logs(tmp_path, hbbr=FAIL_RELAY)
    a = _agent(monkeypatch, d)
    a._keylog_collect()
    a._keylog_take()
    with open(d / "hbbr.log", "a", encoding="utf-8") as f:
        f.write(FAIL_RELAY2[:40])           # 寫到一半
    a._keylog_collect()
    assert a._keylog_take()["fails"] == []
    with open(d / "hbbr.log", "a", encoding="utf-8") as f:
        f.write(FAIL_RELAY2[40:])
    a._keylog_collect()
    fails = a._keylog_take()["fails"]
    assert len(fails) == 1 and fails[0]["n"] == 1 and fails[0]["last"] == "2026-10-05T07:02:26+08:00"


def test_copytruncate_rotation_starts_over(tmp_path, monkeypatch) -> None:
    """官方 logrotate 用 copytruncate：同一個檔案被截成 0 再繼續寫，讀到的位置要歸零。"""
    d = _logs(tmp_path, hbbr=NOISE * 50 + FAIL_RELAY)
    a = _agent(monkeypatch, d)
    a._keylog_collect()
    a._keylog_take()
    (d / "hbbr.log").write_text(FAIL_RELAY2, encoding="utf-8")       # 截斷後寫入，比原本短
    a._keylog_collect()
    fails = a._keylog_take()["fails"]
    assert len(fails) == 1 and fails[0]["last"] == "2026-10-05T07:02:26+08:00"


def test_new_file_after_rotation_is_read_from_the_start(tmp_path, monkeypatch) -> None:
    d = _logs(tmp_path, hbbr=FAIL_RELAY)
    a = _agent(monkeypatch, d)
    a._keylog_collect()
    a._keylog_take()
    os.rename(d / "hbbr.log", d / "hbbr.log.1")
    (d / "hbbr.log").write_text(NOISE * 200 + FAIL_RELAY2, encoding="utf-8")   # 新檔比舊檔長也要從頭讀
    a._keylog_collect()
    assert len(a._keylog_take()["fails"]) == 1


def test_first_read_only_looks_back_a_bounded_amount(tmp_path, monkeypatch) -> None:
    """代理剛啟動時只回頭看最後一段（不從幾 GB 的日誌開頭讀起），而且不會把被切掉的半行當成一筆。"""
    d = _logs(tmp_path, hbbr=FAIL_RELAY * 10 + NOISE * 20 + FAIL_RELAY2)
    a = _agent(monkeypatch, d)
    a.KEYLOG_BACKFILL_BYTES = len(NOISE) * 20 + len(FAIL_RELAY2) + 10
    a._keylog_collect()
    fails = a._keylog_take()["fails"]
    assert len(fails) == 1 and fails[0]["n"] == 1 and fails[0]["last"] == "2026-10-05T07:02:26+08:00"


def test_unsent_results_are_kept_for_the_next_poll(tmp_path, monkeypatch) -> None:
    d = _logs(tmp_path, hbbr=FAIL_RELAY)
    a = _agent(monkeypatch, d)
    a._keylog_collect()
    kc = a._keylog_take()
    a._keylog_restore(kc)                   # 輪詢失敗
    with open(d / "hbbr.log", "a", encoding="utf-8") as f:
        f.write(FAIL_RELAY2)
    a._keylog_collect()
    fails = a._keylog_take()["fails"]
    assert len(fails) == 1 and fails[0]["n"] == 2
    assert fails[0]["first"] == "2026-10-05T07:02:15+08:00" and fails[0]["last"] == "2026-10-05T07:02:26+08:00"


def test_missing_logs_are_reported_not_fatal(tmp_path, monkeypatch) -> None:
    """用 docker 或自己寫 unit 的站台日誌可能在別處：說清楚讀不到，其他功能照常。"""
    a = _agent(monkeypatch, tmp_path / "nope")
    a._keylog_collect()
    kc = a._keylog_take()
    assert kc["fails"] == [] and kc["logs"]["hbbr"] is False and kc["logs"]["error"]


def test_entries_are_capped(tmp_path, monkeypatch) -> None:
    lines = "".join(FAIL_RELAY.replace("192.0.2.54", f"198.51.100.{i % 250}").replace(
        "[::ffff:", "[::ffff:").replace("198.51.100.", f"10.{i // 250}.0.") for i in range(30))
    d = _logs(tmp_path, hbbr=lines)
    a = _agent(monkeypatch, d)
    a.KEYLOG_MAX_ENTRIES = 10
    a._keylog_collect()
    kc = a._keylog_take()
    assert len(kc["fails"]) == 10 and kc["dropped"] == 20


def test_poll_body_carries_key_checks_and_selftest_checks_the_logs(tmp_path, monkeypatch) -> None:
    d = _logs(tmp_path, hbbr=FAIL_RELAY)
    a = _agent(monkeypatch, d)
    a._keylog_collect()
    body = a._poll_body()
    assert body["key_checks"]["fails"][0]["ip"] == "192.0.2.54"
    monkeypatch.setattr(a, "_rustdesk_dir", lambda: str(tmp_path / "no-data-dir"))
    checks = {c["key"]: c for c in a._selftest()}
    assert checks["logs"]["ok"] is True and str(d) in checks["logs"]["detail"]


def test_poll_falls_back_when_an_old_server_rejects_key_checks(tmp_path, monkeypatch) -> None:
    """升級空窗：jt-ipam 的檔案先換了（代理據此自我更新），後端還沒重啟 → 舊後端以 422 拒絕不認得的欄位。
    代理不帶 key_checks 重送，輪詢照常，結果留到下一輪。"""
    import io
    import urllib.error
    d = _logs(tmp_path, hbbr=FAIL_RELAY)
    a = _agent(monkeypatch, d)
    sent: list = []

    def fake_req(method, path, body=None, timeout=30):  # noqa: ANN001, ANN202
        sent.append(body)
        if "key_checks" in body:
            raise urllib.error.HTTPError(path, 422, "Unprocessable Entity", {}, io.BytesIO(b""))
        return {"enabled": False, "poll_seconds": 10}

    monkeypatch.setattr(a, "_req", fake_req)
    monkeypatch.setattr(a, "_maybe_self_update", lambda sha: None)
    assert a.poll_once() == 10
    assert "key_checks" in sent[0] and "key_checks" not in sent[1]
    assert a._keylog_take()["fails"][0]["ip"] == "192.0.2.54", "沒送到的留到下一輪"
