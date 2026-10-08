"""issue #43 的第二半：作業失敗時，最終狀態一定要寫得進去。

作業裡的資料庫錯誤（例如唯一鍵衝突）會讓 session 進入「交易已失敗」狀態；原本在 finally 裡
直接 commit 寫 status=failed，會丟 PendingRollbackError → 作業永遠停在「執行中」。
"""
from __future__ import annotations

import pytest
from app.models.background_task import BackgroundTask
from app.models.librenms import LibreNMSInstance
from app.services import background_tasks as bt
from sqlalchemy import select


@pytest.mark.anyio
async def test_a_task_whose_session_is_broken_still_ends_as_failed(db_session, monkeypatch) -> None:
    task = BackgroundTask(kind="test.broken", status="pending", trigger="manual", progress=0)
    db_session.add(task)
    await db_session.commit()

    async def runner(sess, t):
        # 兩筆同名的整合 → 唯一鍵衝突 → session 進入交易失敗狀態
        for _ in range(2):
            sess.add(LibreNMSInstance(name="dup-task-final-state", api_url="http://192.0.2.62",
                                      api_token_enc=b"x", api_token_nonce=b"x"))
        await sess.flush()
        return {}

    await bt._run(task.id, runner)
    await db_session.refresh(task)
    assert task.status == "failed", "作業卡在 running：失敗後的最終狀態沒寫進去"
    assert task.finished_at is not None
    assert "IntegrityError" in (task.error or "")


@pytest.mark.anyio
async def test_a_task_that_succeeds_still_ends_as_succeeded(db_session) -> None:
    task = BackgroundTask(kind="test.ok", status="pending", trigger="manual", progress=0)
    db_session.add(task)
    await db_session.commit()

    async def runner(sess, t):
        t.progress = 50
        return {"n": 3}

    await bt._run(task.id, runner)
    await db_session.refresh(task)
    assert (task.status, task.progress, task.summary) == ("succeeded", 100, {"n": 3})
    assert task.finished_at is not None
    row = (await db_session.execute(select(BackgroundTask).where(BackgroundTask.id == task.id))).scalar_one()
    assert row.error is None
