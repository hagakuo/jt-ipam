"""Token restrictions must survive the HTTP/stdio shared resolver."""

from datetime import UTC, datetime, timedelta

import pytest
from app.core.security import generate_api_token
from app.mcp.server import process_message, resolve_token
from app.models.user import APIToken


async def _resolve(db_session, admin_user, scopes, filters=None):
    raw, prefix, digest = generate_api_token(env_label="test")
    db_session.add(APIToken(
        user_id=admin_user.id, name="context-regression", token_hash=digest,
        token_prefix=prefix, scopes=scopes, object_filters=filters,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    ))
    await db_session.commit()
    user, readonly = await resolve_token(raw)
    assert user is not None
    assert user._api_token_scopes == scopes
    assert user._api_token_object_filters == filters
    return user, readonly


async def _call(user, readonly, name):
    return await process_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": {}}}, user, readonly=readonly,
    )


@pytest.mark.asyncio
async def test_legacy_tool_scope_survives_resolver(db_session, admin_user):
    user, readonly = await _resolve(db_session, admin_user, ["mcp:tool:calc_ip_info"])
    result = await process_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, user, readonly=readonly,
    )
    assert {tool["name"] for tool in result["result"]["tools"]} == {"calc_ip_info"}
    denied = await _call(user, readonly, "stats_overview")
    assert denied["result"]["isError"] is True
    assert "permission_denied" in denied["result"]["content"][0]["text"]


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [["read"], ["mcp:read"]])
async def test_readonly_context_allows_reads_and_denies_writes(db_session, admin_user, scopes):
    user, readonly = await _resolve(db_session, admin_user, scopes)
    assert readonly is True
    assert (await _call(user, readonly, "stats_overview"))["result"]["isError"] is False
    assert (await _call(user, readonly, "update_ip"))["result"]["isError"] is True


@pytest.mark.asyncio
async def test_object_filters_fail_closed_after_resolution(db_session, admin_user):
    user, readonly = await _resolve(db_session, admin_user, [], {"subnet_ids": ["restricted"]})
    denied = await _call(user, readonly, "stats_overview")
    assert denied["result"]["isError"] is True
    assert "object_filters" in denied["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_unrestricted_context_preserves_compatibility(db_session, admin_user):
    user, readonly = await _resolve(db_session, admin_user, [])
    assert readonly is False
    assert (await _call(user, readonly, "stats_overview"))["result"]["isError"] is False
