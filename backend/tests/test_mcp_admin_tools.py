"""AI 巡檢／異常偵測的 MCP 工具權限層級。

REST 端這兩塊都是 `require_admin`（巡檢結論與異常清單，本質上是一份跨部門的弱點
清單）。MCP 是同一份資料的另一道門 —— 門的鎖不一樣，等於沒鎖。這裡把兩道門釘在一起。
"""
from __future__ import annotations

import uuid

import pytest

from app.mcp.tools import ADMIN_TOOLS, TOOLS, authorize_tool
from app.models.permission import Permission
from app.models.user import User


async def _wildcard_reader(db_session) -> User:
    """唯讀檢視者：非管理員，但有「萬用」讀取授權 → has_global_read 為真。

    這正是會誤放的那種帳號：全域基礎設施工具對他放行，巡檢結論卻不該。
    """
    from app.core.security import hash_password
    u = User(username=f"ro-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local",
             display_name="RO", password_hash=hash_password("TestPassword2026!"),
             auth_provider="local", is_active=True, is_admin=False)
    db_session.add(u)
    await db_session.flush()
    for ot in ("subnet", "device", "section"):
        db_session.add(Permission(object_type=ot, object_id=None,
                                  principal_type="user", principal_id=u.id, level="read"))
    await db_session.commit()
    return u


@pytest.mark.anyio
async def test_wildcard_reader_cannot_read_ai_findings(db_session):
    """有萬用讀取權限但非管理員 → 巡檢發現要擋（REST 已是 admin，MCP 不能鬆）。"""
    u = await _wildcard_reader(db_session)
    from app.mcp.tools import has_global_read
    assert await has_global_read(db_session, u) is True, "前提：這個帳號確實有全域讀取"
    # 全域基礎設施工具對他是放行的 —— 用來證明擋下巡檢不是因為他什麼都不能用
    assert await authorize_tool(db_session, u, "list_vlans") is None
    assert await authorize_tool(db_session, u, "list_ai_findings") is not None


@pytest.mark.anyio
async def test_wildcard_reader_cannot_read_anomalies(db_session):
    """異常偵測同理：REST 是 require_admin，MCP 也必須是。"""
    u = await _wildcard_reader(db_session)
    assert await authorize_tool(db_session, u, "list_anomalies") is not None


@pytest.mark.anyio
async def test_admin_can_read_both(db_session, admin_user):
    """管理員兩支都要通 —— 否則這道鎖是把功能鎖死，不是收斂權限。"""
    for name in ("list_ai_findings", "list_anomalies"):
        assert await authorize_tool(db_session, admin_user, name) is None, name


def test_both_tools_registered_as_admin_only():
    for name in ("list_ai_findings", "list_anomalies"):
        assert name in TOOLS, name
        assert name in ADMIN_TOOLS, name


@pytest.mark.anyio
async def test_anomaly_tool_is_read_only(db_session, admin_user):
    """唯讀查詢不可以順手發通知，也不可以 commit。

    `services.anomaly.run_detection` 兩件事都做（命中時通知全體管理員 + 結尾無條件
    `session.commit()`，會把同一個 session 裡其他未定的異動一起送出去），所以這支工具
    要逐條呼叫偵測函式，不能圖方便直接叫它。這裡驗的是行為，不是原始碼字串。
    """
    from sqlalchemy import func, select as _select

    from app.models.notification import Notification

    before = await db_session.scalar(_select(func.count()).select_from(Notification))

    commits = 0
    real_commit = db_session.commit

    async def counting_commit(*a, **kw):
        nonlocal commits
        commits += 1
        return await real_commit(*a, **kw)

    db_session.commit = counting_commit
    try:
        out = await TOOLS["list_anomalies"]["fn"](db_session, admin_user, limit=5)
    finally:
        db_session.commit = real_commit

    assert "counts" in out and "items" in out
    assert commits == 0, "查詢不該 commit"
    after = await db_session.scalar(_select(func.count()).select_from(Notification))
    assert after == before, "查詢不該發通知"
