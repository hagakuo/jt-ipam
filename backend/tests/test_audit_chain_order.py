"""單一交易內連寫多筆稽核記錄時，鏈必須仍然接得起來。"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.audit import append_audit, verify_chain
from app.models.audit import AuditLog


@pytest.mark.anyio
async def test_multiple_audits_in_one_transaction_chain_correctly(db_session) -> None:
    """批次刪除會在同一交易寫好幾筆 —— 每一筆都要接在前一筆後面。

    先前 `append_audit` 只 add 不 flush，於是同交易內每一筆讀到的「前一筆」都一樣，
    全部指向同一個 prev_hash。prod 上因此累積了 28 個斷點（26 個來自 NAT 批次刪除）。
    """
    # ⚠️ 正式的 session 是 autoflush=False（app/core/db.py），測試 fixture 預設是 True。
    # 差別正好就是這個 bug 能活在 prod 卻沒有測試抓到的原因 —— 要重現就得比照正式設定。
    db_session.autoflush = False
    for i in range(4):
        await append_audit(
            db_session, actor_user_id=None, actor_ip=None, actor_user_agent=None,
            object_type="nat", object_id=None, action="delete",
            diff={"i": i}, request_id=str(uuid.uuid4()),
        )
    await db_session.flush()

    rows = list((await db_session.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(4))).scalars().all())[::-1]
    prevs = [r.prev_hash for r in rows]
    assert len(set(prevs)) == 4, "同交易內多筆稽核記錄接到了同一個前置雜湊"
    for earlier, later in zip(rows, rows[1:], strict=False):
        assert later.prev_hash == earlier.this_hash

    ok, bad = await verify_chain(db_session)
    assert ok is True, f"鏈在 id={bad} 中斷"
