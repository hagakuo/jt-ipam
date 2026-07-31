"""API Token 的 scope 檢驗。

目前只支援一個 scope 值 `read`（唯讀）：

- `scopes == []`       → 不限制，沿用該 token 擁有者的 RBAC 權限
- `scopes == ["read"]` → 唯讀，任何會改資料的操作一律 403

其餘值在建立 token 時就被擋掉（見 `schemas/api_token.py`），所以這裡只認 `read`。
之所以「空＝不限制」而不是「空＝什麼都不能做」，是為了讓既有 token 不會因為
這道檢驗上線而全部失效。

⚠️ `api_tokens.object_filters`（逐物件限制）**目前不生效**：要限制 token 只能碰
特定物件，請另建一個低權限使用者、用 RBAC 授權指定物件，再以該帳號建立 token。
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import HTTPException, status

READ_SCOPE = "read"

#: 建立 token 時允許填的 scope 值（其餘一律拒絕，避免出現看似有用其實沒作用的欄位）
ALLOWED_SCOPES: frozenset[str] = frozenset({READ_SCOPE})

#: 不會改資料的 HTTP 方法
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

_DENIED = (
    "This API token is read-only (scope 'read'); "
    "it cannot perform operations that change data."
)


def token_is_readonly(scopes: Iterable[str] | None) -> bool:
    """這把 token 是否為唯讀。"""
    return READ_SCOPE in set(scopes or ())


def enforce_method_scope(scopes: Iterable[str] | None, method: str) -> None:
    """唯讀 token 碰到會改資料的 HTTP 方法 → 403。

    給 REST（含 phpIPAM 相容層）用；MCP 走 JSON-RPC（永遠是 POST），
    改由 `token_is_readonly()` 決定 readonly 模式、擋下異動類工具。
    """
    if token_is_readonly(scopes) and method.upper() not in SAFE_METHODS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_DENIED)
