"""清除全部巡檢發現。

為什麼是「刪除」而不是「全部忽略」：忽略會留下指紋，往後每一次巡檢遇到同一件事都會
自動忽略。若「清除」用忽略實作，使用者按下去等於**永久封住**這些發現 —— 跟他想要的
「清掉、下次重新分析一次」正好相反。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.ai_finding import AIFinding
from app.models.audit import AuditLog
from httpx import AsyncClient
from sqlalchemy import func, select


@pytest.fixture
async def mixed_findings(db_session):
    run_id = uuid.uuid4()
    tag = uuid.uuid4().hex[:6]
    for i, st in enumerate(("open", "open", "dismissed")):
        db_session.add(AIFinding(
            run_id=run_id, severity="high", category="exposure",
            title=f"t{i}-{tag}", detail="d", recommendation="r",
            evidence={"ips": [], "note": "n"}, status=st,
            fingerprint=f"fp-{tag}-{i}",
        ))
    await db_session.commit()
    return tag


@pytest.mark.anyio
async def test_clear_removes_everything_including_dismissed(
    client: AsyncClient, auth_headers, mixed_findings, db_session,
):
    """已忽略的也要刪掉 —— 留著的話，下次巡檢會因為指紋相符而自動忽略，等於沒清。"""
    before = await db_session.scalar(select(func.count()).select_from(AIFinding))
    assert before >= 3

    r = await client.delete("/api/v1/ai-audit/findings", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["deleted"] == before

    await db_session.commit()   # 讓這個 session 看得到端點那邊已提交的刪除
    after = await db_session.scalar(select(func.count()).select_from(AIFinding))
    assert after == 0


@pytest.mark.anyio
async def test_clear_is_audited(client: AsyncClient, auth_headers, mixed_findings, db_session):
    """一次刪掉整份清單是不可逆的操作，稽核記錄一定要留。"""
    await client.delete("/api/v1/ai-audit/findings", headers=auth_headers)
    await db_session.commit()
    row = (await db_session.execute(
        select(AuditLog).where(AuditLog.object_type == "ai_audit", AuditLog.action == "clear")
        .order_by(AuditLog.ts.desc()).limit(1)
    )).scalars().first()
    assert row is not None
    assert row.diff and row.diff.get("count", 0) >= 3


@pytest.mark.anyio
async def test_clear_requires_admin(client: AsyncClient, db_session):
    """整份清單是管理資料，非管理員不得清除（比照這一支的其他端點）。"""
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"na-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local",
             display_name="NA", password_hash=hash_password("TestPassword2026!"),
             auth_provider="local", is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.commit()
    tok = issue_access_token(u)
    r = await client.delete("/api/v1/ai-audit/findings",
                            headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403
