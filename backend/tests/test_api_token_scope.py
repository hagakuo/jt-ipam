"""API Token scope 檢驗。

背景：`api_tokens.scopes` 以前可以填任何值但完全沒有任何程式讀取它 —— token
實際上一律繼承擁有者的完整 RBAC 權限。所以填了 `["read"]` 的 token 照樣能刪
子網路。這批測試釘住修好後的行為。
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.core.api_scope import (
    ALLOWED_SCOPES,
    SAFE_METHODS,
    enforce_method_scope,
    token_is_readonly,
)

# ── 純函式（不需 DB）───────────────────────────────────────────────


def test_only_read_scope_is_supported() -> None:
    assert ALLOWED_SCOPES == {"read"}


def test_empty_scopes_is_unrestricted() -> None:
    """空 scopes＝不限制 —— 這道檢驗上線時既有 token 不能全部失效。"""
    assert token_is_readonly([]) is False
    assert token_is_readonly(None) is False
    for method in ("GET", "POST", "PATCH", "PUT", "DELETE"):
        enforce_method_scope([], method)          # 不得拋錯


def test_read_scope_is_readonly() -> None:
    assert token_is_readonly(["read"]) is True


@pytest.mark.parametrize("method", sorted(SAFE_METHODS))
def test_readonly_token_allows_safe_methods(method: str) -> None:
    enforce_method_scope(["read"], method)        # 不得拋錯


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_readonly_token_blocks_mutating_methods(method: str) -> None:
    with pytest.raises(HTTPException) as exc:
        enforce_method_scope(["read"], method)
    assert exc.value.status_code == 403
    assert "read-only" in str(exc.value.detail)


@pytest.mark.parametrize("method", ["get", "post", "Delete"])
def test_method_check_is_case_insensitive(method: str) -> None:
    """ASGI 一般給大寫，但別讓大小寫成為繞過的縫。"""
    if method.upper() in SAFE_METHODS:
        enforce_method_scope(["read"], method)
    else:
        with pytest.raises(HTTPException):
            enforce_method_scope(["read"], method)


# ── schema 驗證 ────────────────────────────────────────────────────


def test_create_schema_rejects_unenforceable_scopes() -> None:
    """不能再填「看起來有限制、其實沒作用」的 scope。"""
    import pydantic

    from app.schemas.api_token import APITokenCreate

    assert APITokenCreate(name="t").scopes == []
    assert APITokenCreate(name="t", scopes=["read"]).scopes == ["read"]

    for bad in (["write"], ["admin"], ["subnets:read"], ["read", "write"]):
        with pytest.raises(pydantic.ValidationError):
            APITokenCreate(name="t", scopes=bad)


# ── 端到端：唯讀 token 打真的端點 ──────────────────────────────────


@pytest.mark.asyncio
async def test_readonly_token_end_to_end(client, auth_headers) -> None:  # noqa: ANN001
    """建一把唯讀 token，確認 GET 通、寫入被 403 擋。

    用 admin 建 token —— 正是最危險的情境：擁有者是 admin，
    所以「唯讀」必須真的靠 scope 生效，不能靠 RBAC。
    """
    r = await client.post(
        "/api/v1/api-tokens",
        json={"name": "e2e-readonly", "scopes": ["read"]},
        headers=auth_headers,
    )
    assert r.status_code == 201, r.text
    raw = r.json()["token"]
    ro = {"Authorization": f"Bearer {raw}"}

    # 讀取：通
    assert (await client.get("/api/v1/subnets", headers=ro)).status_code == 200

    # 寫入：403（不是 401、也不是 422 —— 要能分辨「認證過但 scope 不足」）
    r = await client.post(
        "/api/v1/sections",
        json={"name": "should-not-be-created"},
        headers=ro,
    )
    assert r.status_code == 403, r.text
    assert "read-only" in r.text

    # 未帶 scope 的 token 仍可寫入（向下相容）
    r = await client.post(
        "/api/v1/api-tokens",
        json={"name": "e2e-unrestricted"},
        headers=auth_headers,
    )
    assert r.status_code == 201, r.text
    full = {"Authorization": f"Bearer {r.json()['token']}"}
    r = await client.post("/api/v1/sections", json={"name": "scope-compat-ok"}, headers=full)
    assert r.status_code in (200, 201), r.text


@pytest.mark.asyncio
async def test_unenforceable_scope_rejected_by_endpoint(client, auth_headers) -> None:  # noqa: ANN001
    r = await client.post(
        "/api/v1/api-tokens",
        json={"name": "bogus", "scopes": ["write"]},
        headers=auth_headers,
    )
    assert r.status_code == 422, r.text
