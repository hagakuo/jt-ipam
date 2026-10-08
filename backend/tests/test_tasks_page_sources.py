"""作業頁要看得到每一種「資料進來」的方式，而且能篩選、搜尋（使用者 2026-10-06）。

以前只有伺服器自己排程拉的整合會留作業記錄；代理推上來的（RustDesk、ISC DHCP）與資料庫更新
（OUI、Recog、GeoIP）從來沒有，作業頁上看不到它們有沒有在跑。代理每幾分鐘回報一次，所以跟排程同步
一樣每個來源只保留一列（upsert），不會灌爆清單。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.background_task import BackgroundTask
from sqlalchemy import func, select

from tests.test_dhcp_standalone import _agent as _scan_agent
from tests.test_dhcp_standalone import _report as _isc_report
from tests.test_rustdesk import _report as _rd_report
from tests.test_rustdesk import _send as _rd_send
from tests.test_rustdesk import _server as _rd_server


async def _rows(db, kind: str) -> list[BackgroundTask]:
    db.expire_all()
    return list((await db.execute(select(BackgroundTask).where(BackgroundTask.kind == kind))).scalars())


async def test_rustdesk_report_keeps_one_row_per_server(client, db_session) -> None:
    raw = "rd-key-" + uuid.uuid4().hex
    srv = await _rd_server(db_session, raw)
    sid, sname = srv.id, srv.name
    await _rd_send(client, raw, _rd_report(srv.id, [("111222333", "192.0.2.10", True)]))
    await _rd_send(client, raw, _rd_report(srv.id, [("111222333", "192.0.2.10", True),
                                                    ("444555666", "192.0.2.11", False)]))
    rows = await _rows(db_session, "rustdesk.sync")
    assert len(rows) == 1, "每台伺服器只保留一列"
    r = rows[0]
    assert r.trigger == "scheduled" and r.status == "succeeded"
    assert r.target_id == sid and r.target_label == sname
    assert r.summary["peers"] == 2 and r.summary["online"] == 1


async def test_rustdesk_unreadable_database_is_a_failed_row(client, db_session) -> None:
    raw = "rd-key-" + uuid.uuid4().hex
    srv = await _rd_server(db_session, raw)
    await _rd_send(client, raw, _rd_report(srv.id, [], db_ok=False))
    (r,) = await _rows(db_session, "rustdesk.sync")
    assert r.status == "failed" and r.error


async def test_deleting_a_rustdesk_server_removes_its_row(client, auth_headers, db_session) -> None:
    raw = "rd-key-" + uuid.uuid4().hex
    srv = await _rd_server(db_session, raw)
    await _rd_send(client, raw, _rd_report(srv.id, []))
    r = await client.delete(f"/api/v1/rustdesk/servers/{srv.id}", headers=auth_headers)
    assert r.status_code in (200, 204), r.text
    assert await _rows(db_session, "rustdesk.sync") == []


async def test_isc_dhcp_report_keeps_one_row_per_source(client, db_session) -> None:
    from app.models.dhcp_standalone import IscDhcpServer
    raw = "isc-key-" + uuid.uuid4().hex
    agent = await _scan_agent(db_session, raw)
    src = IscDhcpServer(name=f"isc-{uuid.uuid4().hex[:6]}", agent_id=agent.id)
    db_session.add(src)
    await db_session.commit()
    src_id = src.id
    for _ in range(2):
        rep = await client.post("/api/v1/scan-agents/dhcpd-report", headers={"X-Agent-Key": raw},
                                json=_isc_report(src.id))
        assert rep.status_code == 200, rep.text
    rows = await _rows(db_session, "isc_dhcp.sync")
    assert len(rows) == 1
    assert rows[0].target_id == src_id and rows[0].status == "succeeded"


async def test_manual_oui_refresh_leaves_a_row(client, auth_headers, db_session, monkeypatch) -> None:
    from app.services import oui

    async def fake_download() -> str:
        return "00:00:5E\tIANA\tICANN, IANA Department\n"
    monkeypatch.setattr(oui, "_download_manuf", fake_download)
    r = await client.post("/api/v1/oui/refresh", headers=auth_headers)
    assert r.status_code == 200, r.text
    (row,) = await _rows(db_session, "oui.refresh")
    assert row.trigger == "manual" and row.status == "succeeded"
    assert row.actor_user_id is not None
    assert row.summary["parsed"] == 1


async def test_scheduled_refresh_helper_upserts_one_row(db_session) -> None:
    from app.services.background_tasks import record_refresh
    for _ in range(2):
        await record_refresh(db_session, "recog.refresh", ok=True,
                             summary={"status": "up_to_date", "release": "3.2.0"})
    rows = await _rows(db_session, "recog.refresh")
    assert len(rows) == 1 and rows[0].trigger == "scheduled"
    assert rows[0].target_label == "Recog"


async def test_filters_and_search(client, auth_headers, db_session) -> None:
    now = datetime.now(UTC)
    tag = uuid.uuid4().hex[:8]
    db_session.add_all([
        BackgroundTask(kind="opnsense.sync", trigger="scheduled", target_label=f"fw-{tag}",
                       status="succeeded", progress=100, queued_at=now, finished_at=now),
        BackgroundTask(kind="ip.identify", trigger="manual", target_label=f"192.0.2.9 ({tag})",
                       status="failed", progress=100, error="agent offline", queued_at=now, finished_at=now),
    ])
    await db_session.commit()

    async def ask(**params) -> list[str]:
        r = await client.get("/api/v1/tasks", headers=auth_headers, params={"q": tag, **params})
        assert r.status_code == 200, r.text
        return sorted(x["kind"] for x in r.json()["items"])

    assert await ask() == ["ip.identify", "opnsense.sync"]
    assert await ask(trigger="manual") == ["ip.identify"]
    assert await ask(kind="opnsense.sync") == ["opnsense.sync"]
    assert await ask(status_in="failed") == ["ip.identify"]
    # 錯誤訊息也搜得到；% 與 _ 是字面，不是萬用字元
    r = await client.get("/api/v1/tasks", headers=auth_headers, params={"q": "agent offline"})
    assert any(x["target_label"].endswith(f"({tag})") for x in r.json()["items"])
    r = await client.get("/api/v1/tasks", headers=auth_headers, params={"q": "%"})
    assert r.status_code == 200 and all("%" in (x["kind"] + (x["target_label"] or "") + (x["error"] or ""))
                                        for x in r.json()["items"])

    kinds = await client.get("/api/v1/tasks/kinds", headers=auth_headers)
    assert kinds.status_code == 200, kinds.text
    assert {"opnsense.sync", "ip.identify"} <= set(kinds.json())


async def test_agent_and_refresh_rows_do_not_hide_a_stalled_sync_timer(db_session) -> None:
    """系統診斷用「最後一筆背景作業」判斷排程有沒有在跑；代理回報、探測、資料庫更新
    不是 jt-ipam-sync 寫的，不可以把停擺的排程遮掉。"""
    from app.services.self_check import run_checks
    old = datetime.now(UTC) - timedelta(hours=30)
    now = datetime.now(UTC)
    await db_session.execute(BackgroundTask.__table__.delete())
    db_session.add_all([
        BackgroundTask(kind="opnsense.sync", trigger="scheduled", target_label="fw",
                       status="succeeded", progress=100, queued_at=old, finished_at=old),
        BackgroundTask(kind="rustdesk.sync", trigger="scheduled", target_label="rd",
                       status="succeeded", progress=100, queued_at=now, finished_at=now),
        BackgroundTask(kind="oui.refresh", trigger="scheduled", target_label="Wireshark manuf",
                       status="succeeded", progress=100, queued_at=now, finished_at=now),
        BackgroundTask(kind="ip.identify", trigger="manual", target_label="192.0.2.1",
                       status="succeeded", progress=100, queued_at=now, finished_at=now),
    ])
    await db_session.commit()
    rep = (await run_checks(db_session)).as_dict()
    sync = [c for c in rep["checks"] if c["key"] == "sync"]
    assert sync and sync[0]["status"] == "warn", sync
    assert (await db_session.scalar(select(func.count()).select_from(BackgroundTask))) == 4
