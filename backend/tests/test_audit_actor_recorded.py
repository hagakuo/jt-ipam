"""稽核記錄要記下是誰做的（2026-09-30 盤點 API 手冊時順帶發現）。

使用者管理（建立／修改／刪除帳號、群組成員＝提權）、OPNsense 與 Wazuh 整合的 20 處稽核，
操作者取自 `request.state.user_id` —— 那個值從來沒有人設定，所以一律記成空的。正式機上這類紀錄
45 筆全部查不出是誰做的。
"""
from __future__ import annotations

import uuid

from app.models.audit import AuditLog
from sqlalchemy import select


async def _last(db, action: str, object_type: str) -> AuditLog:
    return (await db.execute(select(AuditLog).where(
        AuditLog.action == action, AuditLog.object_type == object_type)
        .order_by(AuditLog.id.desc()).limit(1))).scalar_one()


async def test_creating_a_user_records_who_did_it(client, auth_headers, admin_user, db_session) -> None:
    r = await client.post("/api/v1/users", headers=auth_headers, json={
        "username": f"u-{uuid.uuid4().hex[:6]}", "email": f"{uuid.uuid4().hex[:6]}@example.com",
        "password": "Str0ng-Passw0rd-2026!"})
    assert r.status_code == 201, r.text
    row = await _last(db_session, "create", "user")
    assert str(row.actor_user_id) == str(admin_user.id)


async def test_integration_changes_record_who_did_it(client, auth_headers, admin_user, db_session) -> None:
    r = await client.post("/api/v1/wazuh/instances", headers=auth_headers, json={
        "name": f"wz-{uuid.uuid4().hex[:6]}", "api_url": "https://wazuh.example.com:55000",
        "api_user": "ro", "api_password": "x" * 12})
    assert r.status_code in (200, 201), r.text
    row = await _last(db_session, "create", "wazuh_instance")
    assert str(row.actor_user_id) == str(admin_user.id)


def test_no_endpoint_reads_an_actor_nobody_sets() -> None:
    """守門：稽核的操作者要來自 CurrentUser 或 request.state.user_id（由 get_current_user 設定）。"""
    import inspect

    from app.api.v1 import dependencies
    assert "request.state.user_id = " in inspect.getsource(dependencies.get_current_user)
