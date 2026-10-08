"""稽核記錄寫入後不可以被任何東西改動 —— 包括資料庫自己。

2026-09-23 prod 實際發生：刪除一個帳號，稽核鏈就斷了。`audit_logs.actor_user_id`
原本有外鍵指向 `users`、而且是 `ON DELETE SET NULL` —— 刪帳號時資料庫會**自動改寫**
這個人所有的稽核記錄（actor 變成 NULL），內容一變，雜湊就重算不回來。
把 actor 換回原本的帳號 ID，雜湊完全吻合，證明記錄沒有被人竄改，是外鍵做的。

一條「正常的刪帳號操作就會弄斷」的稽核鏈，等於告訴稽核人員「斷了也不代表什麼」，
這個機制就沒有用了。所以這裡守三件事：

1. `audit_logs` 不可以有任何外鍵（誰被刪都不能連帶改到稽核記錄）；
2. 資料庫層直接拒絕 UPDATE / DELETE（程式錯誤、串連、誤操作都改不動）；
3. 系統匯入不碰 `audit_logs`（別台機器的歷史接不進這條鏈，也不能被拿來覆寫）。
"""
from __future__ import annotations

import uuid

import pytest
from app.core.audit import append_audit, verify_chain
from app.models.audit import AuditLog
from sqlalchemy import delete, select, text, update


async def _audit(session, actor):  # type: ignore[no-untyped-def]
    await append_audit(
        session, actor_user_id=str(actor) if actor else None, actor_ip="198.51.100.9",
        actor_user_agent="pytest", object_type="auth", object_id=None,
        action="login_success", diff={"username": "tmp"}, request_id=str(uuid.uuid4()),
    )
    await session.flush()


@pytest.mark.anyio
async def test_deleting_a_user_does_not_rewrite_their_audit_records(db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User

    db_session.autoflush = False   # 比照正式環境（見 test_audit_chain_order）
    user = User(username=f"tmp-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@test.local",
                display_name="tmp", password_hash=hash_password("TestPassword2026!"),
                auth_provider="local", is_active=True, is_admin=True)
    db_session.add(user)
    await db_session.flush()
    uid = user.id

    await _audit(db_session, uid)
    await _audit(db_session, uid)
    before = [(r.id, r.actor_user_id, r.this_hash) for r in (await db_session.execute(
        select(AuditLog).where(AuditLog.actor_user_id == uid).order_by(AuditLog.id))).scalars()]
    assert len(before) == 2

    await db_session.delete(user)
    await db_session.flush()
    db_session.expire_all()

    after = [(r.id, r.actor_user_id, r.this_hash) for r in (await db_session.execute(
        select(AuditLog).where(AuditLog.id.in_([b[0] for b in before])).order_by(AuditLog.id))).scalars()]
    assert after == before, "刪除帳號改寫了他的稽核記錄"
    ok, bad = await verify_chain(db_session)
    assert ok is True, f"刪除帳號後稽核鏈在 id={bad} 中斷"


@pytest.mark.anyio
async def test_audit_logs_has_no_foreign_keys(db_session) -> None:
    rows = (await db_session.execute(text(
        "select conname from pg_constraint where contype = 'f' "
        "and conrelid = 'audit_logs'::regclass"))).scalars().all()
    assert rows == [], f"audit_logs 不可以有外鍵（會被串連改寫）：{rows}"


@pytest.mark.anyio
async def test_audit_rows_cannot_be_updated(db_session) -> None:
    await _audit(db_session, None)
    last = (await db_session.execute(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(1))).scalar_one()
    with pytest.raises(Exception, match="append-only"):
        async with db_session.begin_nested():
            await db_session.execute(update(AuditLog).where(AuditLog.id == last).values(action="tampered"))


@pytest.mark.anyio
async def test_audit_rows_cannot_be_deleted(db_session) -> None:
    await _audit(db_session, None)
    last = (await db_session.execute(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(1))).scalar_one()
    with pytest.raises(Exception, match="append-only"):
        async with db_session.begin_nested():
            await db_session.execute(delete(AuditLog).where(AuditLog.id == last))


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["merge", "replace"])
async def test_system_import_never_touches_audit_logs(db_session, mode) -> None:
    from app.services.system_transfer import importer

    db_session.autoflush = False
    await _audit(db_session, None)
    await db_session.commit()
    before = [(r.id, r.this_hash) for r in (await db_session.execute(
        select(AuditLog).order_by(AuditLog.id))).scalars()]
    assert before

    # 一份「別台機器」的匯出包：帶了一筆同 id、內容不同的稽核記錄
    forged = {"id": before[-1][0], "ts": "2026-01-01T00:00:00+00:00", "actor_user_id": None,
              "actor_ip": None, "actor_user_agent": None, "object_type": "auth", "object_id": None,
              "action": "forged", "diff": None, "request_id": None,
              "prev_hash": "00" * 32, "this_hash": "11" * 32}
    report = await importer.apply_import(
        db_session, {"tables": {"audit_logs": [forged]}}, mode=mode, dry_run=False)

    db_session.expire_all()
    after = [(r.id, r.this_hash) for r in (await db_session.execute(
        select(AuditLog).order_by(AuditLog.id))).scalars()]
    assert after == before, f"{mode} 匯入改動了本機的稽核記錄"
    assert "audit_logs" in (report.get("skipped") or {}), "報告要講明稽核記錄沒有匯入"
    ok, bad = await verify_chain(db_session)
    assert ok is True, f"匯入後稽核鏈在 id={bad} 中斷"
