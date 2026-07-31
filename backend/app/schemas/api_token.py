"""API Token schemas。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, field_validator

from app.core.api_scope import ALLOWED_SCOPES
from app.schemas.base import StrictModel


class APITokenCreate(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    # 預設 90 天，最長 1 年（A07）
    expires_in_days: Annotated[int, Field(ge=1, le=365)] = 90
    scopes: list[str] = Field(
        default_factory=list,
        description=(
            "留空＝不限制（沿用擁有者權限）；填 ['read']＝唯讀，"
            "任何會改資料的操作一律 403。目前只支援這兩種。"
        ),
    )
    object_filters: dict[str, Any] | None = Field(
        default=None,
        description=(
            "保留欄位，目前不生效。要限制 token 只能碰特定物件，請另建低權限使用者、"
            "用 RBAC 授權指定物件，再以該帳號建立 token。"
        ),
    )

    @field_validator("scopes")
    @classmethod
    def _check_scopes(cls, v: list[str]) -> list[str]:
        """只接受實際會被強制執行的 scope 值。

        這個欄位以前可以填任何字串但完全沒作用，會讓人誤以為 token 已被限制。
        現在無法強制執行的值一律拒絕，不再留看似有用其實沒作用的旋鈕。
        """
        unknown = sorted(set(v) - ALLOWED_SCOPES)
        if unknown:
            allowed = ", ".join(sorted(ALLOWED_SCOPES))
            raise ValueError(
                f"unsupported scope(s): {', '.join(unknown)}. "
                f"only [{allowed}] is enforced; leave scopes empty for an unrestricted token"
            )
        return v


class APITokenCreateResponse(StrictModel):
    """建立成功一次性回傳明文 token；之後再也無法取得。"""

    id: uuid.UUID
    name: str
    token: str               # 完整 token（jt_<env>_<random>）— 僅此一次
    token_prefix: str
    expires_at: datetime
    scopes: list[str]


class APITokenRead(StrictModel):
    id: uuid.UUID
    name: str
    token_prefix: str
    scopes: list[str]
    object_filters: dict[str, Any] | None
    expires_at: datetime
    last_used_at: datetime | None
    last_used_ip: str | None
    revoked_at: datetime | None
    created_at: datetime

    @field_validator("last_used_ip", mode="before")
    @classmethod
    def _coerce_last_used_ip(cls, v: object) -> str | None:
        # INET 欄位 asyncpg 回 IPv4Address；token 用過後列出會 Pydantic 500
        return None if v is None else str(v)
