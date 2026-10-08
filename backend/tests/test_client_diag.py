"""前端頁面載入診斷：只寫日誌、欄位限長、要登入、控制字元不進日誌。"""
from __future__ import annotations

import logging

import pytest


@pytest.mark.anyio
async def test_page_load_is_logged(client, auth_headers, caplog) -> None:
    caplog.set_level(logging.INFO, logger="jt-ipam.client")
    r = await client.post("/api/v1/client/page-load", headers=auth_headers, json={
        "path": "/addresses/x", "nav_type": "reload", "was_discarded": True, "visibility": "visible",
        "reload_reason": "chunk\nfailed", "lifecycle": ["hidden@1", "freeze@2"], "build": "abc"})
    assert r.status_code == 204, r.text
    line = next(rec.getMessage() for rec in caplog.records if "client page load" in rec.getMessage())
    assert "discarded=True" in line and "nav=reload" in line and "hidden@1 | freeze@2" in line
    assert "\n" not in line, "控制字元不可進日誌（會被拿來偽造日誌行）"


@pytest.mark.anyio
async def test_page_load_needs_login_and_rejects_unknown_fields(client, auth_headers) -> None:
    assert (await client.post("/api/v1/client/page-load", json={})).status_code == 401
    r = await client.post("/api/v1/client/page-load", headers=auth_headers, json={"evil": 1})
    assert r.status_code == 422
    r = await client.post("/api/v1/client/page-load", headers=auth_headers, json={"path": "x" * 500})
    assert r.status_code == 422
