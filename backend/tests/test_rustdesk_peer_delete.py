"""RustDesk「刪除舊註冊」的伺服器端（0182）。

hbbs 永遠留著每一個註冊過的 ID。管理員在 jt-ipam 選舊的 ID，代理下次輪詢取走、在 RustDesk 主機上刪。
這裡守的界線：
1. 兩邊都同意才排得進去：網頁上的 allow_peer_delete（預設關）＋代理回報寫得了（主機端以 --allow-delete 安裝）
2. 只收這台伺服器的、jt-ipam 看來離線的 ID；整批檢查，一個不合就整批不收；一次最多 500 個；只有管理員
3. 輪詢只在允許且伺服器啟用時帶工作；關掉開關時等待中的一併取消；超過一天沒取走的算逾時
4. 結果：刪掉的裝置在 jt-ipam 也刪、留稽核、要代理馬上重讀；重送與別台的結果略過
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.models.audit import AuditLog
from app.models.rustdesk import RustDeskPeerDelete, RustDeskServer
from sqlalchemy import select

from tests.test_rustdesk import _peers, _poll, _report, _send, _server

CAN = {"delete": True, "delete_reason": None}


async def _ready(client, db_session, raw: str, peers: list[tuple], **kw) -> RustDeskServer:
    """一台允許刪除、代理回報寫得了、已經有裝置的伺服器。peers: (id, ip, online)"""
    srv = await _server(db_session, raw, allow_peer_delete=True, **kw)
    assert (await _poll(client, raw, capabilities=CAN)).status_code == 200
    if peers:
        await _send(client, raw, _report(srv.id, peers))
    return srv


async def _ask(client, auth_headers, srv, ids):
    return await client.post(f"/api/v1/rustdesk/servers/{srv.id}/peers/delete", headers=auth_headers,
                             json={"rustdesk_ids": ids})


async def _rows(db_session, srv) -> dict[str, RustDeskPeerDelete]:
    rows = (await db_session.execute(select(RustDeskPeerDelete).where(RustDeskPeerDelete.server_id == srv.id)
                                     .execution_options(populate_existing=True))).scalars().all()
    return {r.rustdesk_id: r for r in rows}


async def _actions(db_session, srv) -> list[AuditLog]:
    return list((await db_session.execute(select(AuditLog).where(AuditLog.object_id == srv.id)
                                          .order_by(AuditLog.id))).scalars().all())


async def _result(client, raw, srv, results):
    return await client.post("/api/v1/rustdesk/agent/delete-result", headers={"X-Agent-Key": raw},
                             json={"source_id": str(srv.id), "results": results})


# ── 1. 排入請求 ─────────────────────────────────────────────────────────────

async def test_queue_old_offline_ids_and_audit_who_asked(client, auth_headers, db_session, admin_user) -> None:
    raw = "pd1" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False), ("222222222", None, False),
                                                 ("333333333", "192.0.2.13", True)])
    r = await _ask(client, auth_headers, srv, ["111111111", "222222222", "111111111"])
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["queued"] == 2 and body["already_pending"] == 0 and body["requested_at"] and body["eta_seconds"] > 0
    rows = await _rows(db_session, srv)
    assert set(rows) == {"111111111", "222222222"} and {x.status for x in rows.values()} == {"pending"}
    assert all(x.requested_by == admin_user.id for x in rows.values())
    again = await _ask(client, auth_headers, srv, ["111111111"])
    assert again.json()["queued"] == 0 and again.json()["already_pending"] == 1, "重複按不會變成兩筆"
    req = [a for a in await _actions(db_session, srv) if a.action == "rustdesk.peer_delete_requested"]
    assert req and req[0].diff["ids"] == ["111111111", "222222222"] and req[0].diff["count"] == 2
    assert req[0].actor_user_id == admin_user.id
    lst = (await client.get(f"/api/v1/rustdesk/servers/{srv.id}/peer-deletes", headers=auth_headers)).json()
    assert lst["total"] == 2 and {i["status"] for i in lst["items"]} == {"pending"}
    assert lst["items"][0]["requested_by_name"] == admin_user.username


async def test_needs_the_web_switch_and_the_agent_capability(client, auth_headers, db_session) -> None:
    raw = "pd2" * 14
    srv = await _server(db_session, raw)
    await _send(client, raw, _report(srv.id, [("111111111", "192.0.2.11", False)]))
    r = await _ask(client, auth_headers, srv, ["111111111"])
    assert r.status_code == 409 and r.json()["detail"]["code"] == "rustdesk_peer_delete_off", "網頁上沒開就不收"
    srv.allow_peer_delete = True
    await db_session.commit()
    r = await _ask(client, auth_headers, srv, ["111111111"])
    assert r.status_code == 409 and r.json()["detail"]["code"] == "rustdesk_peer_delete_agent", "舊版代理不回報能力"
    await _poll(client, raw, capabilities={"delete": False,
                                           "delete_reason": "not enabled on this host (re-run the installer with "
                                                            "--allow-delete)"})
    r = await _ask(client, auth_headers, srv, ["111111111"])
    assert r.status_code == 409 and "--allow-delete" in r.json()["detail"]["params"]["reason"], "原因要帶到畫面上"
    await _poll(client, raw, capabilities=CAN)
    assert (await _ask(client, auth_headers, srv, ["111111111"])).status_code == 202
    srv_read = (await client.get("/api/v1/rustdesk/servers", headers=auth_headers)).json()["items"][0]
    assert srv_read["allow_peer_delete"] is True and srv_read["agent_status"]["capabilities"] == CAN


async def test_online_unknown_and_disabled_are_refused_as_a_whole(client, auth_headers, db_session) -> None:
    raw = "pd3" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False), ("333333333", "192.0.2.13", True)])
    r = await _ask(client, auth_headers, srv, ["111111111", "333333333"])
    assert r.status_code == 409 and r.json()["detail"]["code"] == "rustdesk_peer_delete_online"
    assert "333333333" in r.json()["detail"]["params"]["ids"]
    other = await _ready(client, db_session, "pd4" * 14, [("444444444", None, False)])
    r = await _ask(client, auth_headers, srv, ["111111111", "444444444"])
    assert r.status_code == 422 and r.json()["detail"]["code"] == "rustdesk_peer_delete_unknown", "別台伺服器的 ID 不收"
    assert await _rows(db_session, srv) == {} and await _rows(db_session, other) == {}, "整批不收：一筆都沒排"
    srv.enabled = False
    await db_session.commit()
    r = await _ask(client, auth_headers, srv, ["111111111"])
    assert r.status_code == 409 and r.json()["detail"]["code"] == "rustdesk_server_disabled"


async def test_request_shape_and_limit(client, auth_headers, db_session) -> None:
    raw = "pd5" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False)])
    for bad in ([], [f"{100000000 + i}" for i in range(501)], ["bad id"], ["x" * 101]):
        assert (await _ask(client, auth_headers, srv, bad)).status_code == 422, len(bad)


async def test_only_admins(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"viewer-{uuid.uuid4().hex[:8]}", email=f"v-{uuid.uuid4().hex[:8]}@test.local",
             password_hash=hash_password("TestPassword2026!"), auth_provider="local", is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {issue_access_token(u)}"}
    srv = await _ready(client, db_session, "pd6" * 14, [("111111111", "192.0.2.11", False)])
    assert (await _ask(client, hdr, srv, ["111111111"])).status_code == 403
    assert (await client.get(f"/api/v1/rustdesk/servers/{srv.id}/peer-deletes", headers=hdr)).status_code == 403
    assert await _rows(db_session, srv) == {}


async def test_never_seen_online_filter(client, auth_headers, db_session) -> None:
    """「從未上線」＝jt-ipam 從沒看過它上線：刪除舊註冊最常挑的那一群。"""
    raw = "pde" * 14
    srv = await _ready(client, db_session, raw, [("111111111", None, False), ("222222222", None, True),
                                                 ("333333333", None, False)])
    await _send(client, raw, _report(srv.id, [("111111111", None, False), ("222222222", None, False),
                                              ("333333333", None, False)]))
    r = await client.get(f"/api/v1/rustdesk/servers/{srv.id}/peers?never_online=true", headers=auth_headers)
    assert sorted(i["rustdesk_id"] for i in r.json()["items"]) == ["111111111", "333333333"], "上線過一次的不算"


# ── 2. 輪詢帶工作 ───────────────────────────────────────────────────────────

async def test_poll_carries_pending_only_while_allowed(client, auth_headers, db_session) -> None:
    raw = "pd7" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False), ("222222222", None, False)])
    assert (await _poll(client, raw, capabilities=CAN)).json()["peer_deletes"] == []
    await _ask(client, auth_headers, srv, ["111111111", "222222222"])
    jobs = (await _poll(client, raw, capabilities=CAN)).json()["peer_deletes"]
    assert sorted(j["rustdesk_id"] for j in jobs) == ["111111111", "222222222"]
    assert all(uuid.UUID(j["req_id"]) for j in jobs)
    assert len((await _poll(client, raw)).json()["peer_deletes"]) == 2, "結果送到前每次輪詢都帶著"
    srv.enabled = False
    await db_session.commit()
    assert (await _poll(client, raw)).json()["peer_deletes"] == [], "停用的伺服器不帶"
    srv.enabled = True
    await db_session.commit()
    r = await client.patch(f"/api/v1/rustdesk/servers/{srv.id}", headers=auth_headers,
                           json={"allow_peer_delete": False})
    assert r.status_code == 200 and r.json()["allow_peer_delete"] is False
    assert (await _poll(client, raw)).json()["peer_deletes"] == []
    rows = await _rows(db_session, srv)
    assert {x.status for x in rows.values()} == {"cancelled"}, "關掉開關：等待中的取消，不可以等重新打開時才執行"
    upd = [a for a in await _actions(db_session, srv) if a.action == "update"]
    assert upd[-1].diff.get("cancelled_peer_deletes") == 2


async def test_poll_hands_out_at_most_a_batch(client, auth_headers, db_session) -> None:
    raw = "pd8" * 14
    ids = [f"{600000000 + i}" for i in range(250)]
    srv = await _ready(client, db_session, raw, [(i, None, False) for i in ids])
    assert (await _ask(client, auth_headers, srv, ids)).json()["queued"] == 250
    assert len((await _poll(client, raw)).json()["peer_deletes"]) == 200


async def test_pending_requests_expire_after_a_day(client, auth_headers, db_session) -> None:
    raw = "pd9" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False), ("222222222", None, False)])
    await _ask(client, auth_headers, srv, ["111111111", "222222222"])
    rows = await _rows(db_session, srv)
    rows["111111111"].requested_at = datetime.now(UTC) - timedelta(days=2)
    await db_session.commit()
    jobs = (await _poll(client, raw)).json()["peer_deletes"]
    assert [j["rustdesk_id"] for j in jobs] == ["222222222"], "逾時的不再帶給代理"
    rows = await _rows(db_session, srv)
    assert rows["111111111"].status == "failed" and "expired" in rows["111111111"].detail
    assert rows["111111111"].finished_at is not None
    lst = (await client.get(f"/api/v1/rustdesk/servers/{srv.id}/peer-deletes?status=failed",
                            headers=auth_headers)).json()
    assert [i["rustdesk_id"] for i in lst["items"]] == ["111111111"]


async def test_list_expires_too_and_filters_by_time(client, auth_headers, db_session) -> None:
    from app.services.rustdesk import expire_peer_deletes
    raw = "pda" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False)])
    old = RustDeskPeerDelete(server_id=srv.id, rustdesk_id="111111111", status="pending",
                             requested_at=datetime.now(UTC) - timedelta(days=3))
    db_session.add(old)
    await db_session.commit()
    since = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    lst = (await client.get(f"/api/v1/rustdesk/servers/{srv.id}/peer-deletes", headers=auth_headers,
                            params={"since": since})).json()
    assert lst["total"] == 0
    lst = (await client.get(f"/api/v1/rustdesk/servers/{srv.id}/peer-deletes", headers=auth_headers)).json()
    assert lst["items"][0]["status"] == "failed", "畫面打開時就判逾時，不用等代理輪詢"
    assert await expire_peer_deletes(db_session, srv.id) == 0


# ── 3. 結果 ────────────────────────────────────────────────────────────────

async def test_results_delete_peers_audit_and_ask_for_a_fresh_report(client, auth_headers, db_session) -> None:
    raw = "pdb" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False), ("222222222", None, False),
                                                 ("333333333", None, False), ("444444444", None, False)])
    await _ask(client, auth_headers, srv, ["111111111", "222222222", "333333333", "444444444"])
    jobs = {j["rustdesk_id"]: j["req_id"] for j in (await _poll(client, raw)).json()["peer_deletes"]}
    r = await _result(client, raw, srv, [
        {"req_id": jobs["111111111"], "status": "deleted"},
        {"req_id": jobs["222222222"], "status": "skipped_online"},
        {"req_id": jobs["333333333"], "status": "not_found"},
        {"req_id": jobs["444444444"], "status": "failed", "detail": "OperationalError: database is locked"}])
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] == 1 and r.json()["skipped_online"] == 1 and r.json()["stale"] == 0
    assert set(await _peers(db_session, srv)) == {"222222222", "333333333", "444444444"}, "只有刪掉的才從清單拿掉"
    rows = await _rows(db_session, srv)
    assert rows["111111111"].status == "deleted" and rows["222222222"].status == "skipped_online"
    assert rows["444444444"].detail == "OperationalError: database is locked"
    assert all(x.finished_at for x in rows.values())
    done = [a for a in await _actions(db_session, srv) if a.action == "rustdesk.peer_deleted"]
    assert len(done) == 1 and done[0].diff["ids"] == ["111111111"] and done[0].diff["skipped_online"] == 1
    assert done[0].actor_user_id is None and "rustdesk-agent" in (done[0].actor_user_agent or "")
    cfg = (await _poll(client, raw)).json()
    assert cfg["report_now"] is True, "刪掉之後要代理馬上重讀一次（裝置數跟著更新）"
    assert cfg["peer_deletes"] == []
    again = await _result(client, raw, srv, [{"req_id": jobs["111111111"], "status": "not_found"}])
    assert again.json()["stale"] == 1, "重送的結果略過，不蓋掉已經記下的"
    assert (await _rows(db_session, srv))["111111111"].status == "deleted"


async def test_results_from_another_server_are_refused_or_ignored(client, auth_headers, db_session) -> None:
    raw, other_raw = "pdc" * 14, "pdd" * 14
    srv = await _ready(client, db_session, raw, [("111111111", "192.0.2.11", False)])
    other = await _ready(client, db_session, other_raw, [("222222222", None, False)])
    await _ask(client, auth_headers, srv, ["111111111"])
    req_id = (await _poll(client, raw)).json()["peer_deletes"][0]["req_id"]
    r = await _result(client, other_raw, srv, [{"req_id": req_id, "status": "deleted"}])
    assert r.status_code == 409, "別台的金鑰不可以寫這台的結果"
    r = await _result(client, other_raw, other, [{"req_id": req_id, "status": "deleted"}])
    assert r.json()["stale"] == 1 and r.json()["deleted"] == 0, "別台的請求編號一律略過"
    assert set(await _peers(db_session, srv)) == {"111111111"}
    assert (await _rows(db_session, srv))["111111111"].status == "pending"
    bad = await _result(client, raw, srv, [{"req_id": req_id, "status": "pending"}])
    assert bad.status_code == 422, "代理只能回報結果，不能把狀態改回等待中"
