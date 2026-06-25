from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.mcp.tools import authorize_tool
from app.services.auth import refresh_token_is_revoked


class _User(SimpleNamespace):
    pass


@pytest.mark.anyio
async def test_mcp_api_token_scope_denies_unlisted_tool():
    user = _User(is_admin=True)
    user._api_token_scopes = ["mcp:tool:search_ip"]
    user._api_token_object_filters = None

    denied = await authorize_tool(None, user, "stats_overview")  # type: ignore[arg-type]

    assert denied == "permission_denied: MCP token scope does not allow this tool"


@pytest.mark.anyio
async def test_mcp_api_token_object_filters_fail_closed_for_data_tools():
    user = _User(is_admin=True)
    user._api_token_scopes = ["mcp:*"]
    user._api_token_object_filters = {"subnet": ["00000000-0000-0000-0000-000000000000"]}

    assert await authorize_tool(None, user, "calc_ip_info") is None  # type: ignore[arg-type]
    denied = await authorize_tool(None, user, "stats_overview")  # type: ignore[arg-type]

    assert denied == "permission_denied: MCP does not support token object_filters yet"


def test_refresh_token_revoked_after_logout_timestamp():
    now = datetime.now(UTC)
    user = _User(refresh_token_revoked_after=now)

    assert refresh_token_is_revoked(user, {"iat": (now - timedelta(seconds=1)).timestamp()})
    assert not refresh_token_is_revoked(user, {"iat": (now + timedelta(seconds=1)).timestamp()})
    assert refresh_token_is_revoked(user, {})


def test_agent_self_update_requires_authenticated_channel(monkeypatch, capsys):
    agent_path = Path(__file__).resolve().parents[2] / "agent" / "jt_ipam_agent.py"
    spec = importlib.util.spec_from_file_location("jt_ipam_agent_test", agent_path)
    assert spec is not None
    assert spec.loader is not None
    jt_ipam_agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(jt_ipam_agent)

    monkeypatch.setattr(jt_ipam_agent, "AUTO_UPDATE", True)
    monkeypatch.setattr(jt_ipam_agent, "INSECURE", True)
    monkeypatch.setattr(jt_ipam_agent, "SERVER", "https://ipam.example")

    called = False

    def fake_get_bytes(path: str) -> bytes:
        nonlocal called
        called = True
        return b"payload"

    monkeypatch.setattr(jt_ipam_agent, "_get_bytes", fake_get_bytes)

    jt_ipam_agent._maybe_self_update("0" * 64)

    assert called is False
    assert "not authenticated" in capsys.readouterr().out
