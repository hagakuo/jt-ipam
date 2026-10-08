"""MCP 的兩個功能問題（2026-09-30 盤點 API 使用手冊時抓到）。

1. 手冊、設定頁的客戶端設定產生器給的都是 `POST /api/mcp`（不帶斜線），實際回 405：
   MCP 掛在 `/api/mcp/`，不帶斜線的路徑落到前端的靜態檔。照設定頁設定的 MCP 客戶端全部連不上。
2. 在 AI 對話裡，異動工具要使用者按確認、會寫稽核（action=ai_tool_exec）；走 MCP 的 tools/call
   直接執行而且**不留稽核** —— 用 admin 權杖從外部建子網路、改 IP，稽核記錄裡什麼都沒有。
"""
from __future__ import annotations

import uuid

import pytest
from app.mcp.server import process_message
from app.models.audit import AuditLog
from app.models.section import Section
from sqlalchemy import select


@pytest.mark.parametrize("path", ["/api/mcp", "/api/mcp/", "/mcp", "/mcp/"])
async def test_mcp_url_works_with_and_without_trailing_slash(client, path) -> None:
    r = await client.post(path, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    # 對外 MCP 預設關閉 → 403 的 JSON-RPC 錯誤；重點是有進到 MCP，不是前端靜態檔的 405
    assert r.status_code == 403, (path, r.status_code, r.text[:200])
    assert r.json()["error"]["code"] == -32001


async def test_mutating_tool_called_over_mcp_is_audited(admin_user, db_session) -> None:
    sec = Section(name=f"mcp-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.commit()
    r = await process_message(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "create_subnet", "arguments": {"cidr": "198.51.100.0/24", "section_id": str(sec.id)}}},
        admin_user, origin={"channel": "mcp-http", "ip": "192.0.2.50", "user_agent": "claude-desktop"})
    assert r["result"]["isError"] is False, r
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "mcp_tool_exec"))).scalars().all()
    assert len(rows) == 1
    assert rows[0].diff["tool"] == "create_subnet"
    assert rows[0].diff["channel"] == "mcp-http"
    assert "198.51.100.0/24" in rows[0].diff["summary"]
    assert str(rows[0].actor_user_id) == str(admin_user.id)
    assert str(rows[0].actor_ip) == "192.0.2.50"


async def test_read_only_tool_calls_are_not_audited(admin_user, db_session) -> None:
    await process_message({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                           "params": {"name": "stats_overview", "arguments": {}}}, admin_user)
    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "mcp_tool_exec"))).scalars().all()
    assert rows == []
