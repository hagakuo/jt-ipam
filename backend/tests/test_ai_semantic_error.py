"""Semantic search failures retain the caller's error visibility policy."""

from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.ai import semantic_search
from app.services import ai
from fastapi import HTTPException


@pytest.mark.asyncio
@pytest.mark.parametrize("is_admin", [False, True])
async def test_semantic_search_error_uses_current_user(monkeypatch, is_admin):
    async def fail(*args, **kwargs):
        raise ai.AIError("private-upstream-host")

    monkeypatch.setattr(ai, "semantic_search", fail)
    with pytest.raises(HTTPException) as exc:
        await semantic_search(
            user=SimpleNamespace(is_admin=is_admin), session=None, q="test", limit=20,
        )
    assert exc.value.status_code == 502
    if not is_admin:
        assert "private-upstream-host" not in str(exc.value.detail)
