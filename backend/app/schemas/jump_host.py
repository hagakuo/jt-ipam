"""跳板主機 schemas（issue #24 階段一）。

機密欄位（私鑰／密碼）**只進不出**：任何 read schema 都不含它們，也不含指紋以外的
任何可回推的資料。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from app.schemas.base import StrictModel


class JumpHostBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    host: Annotated[str, Field(min_length=1, max_length=255)]
    port: Annotated[int, Field(ge=1, le=65535)] = 22
    username: Annotated[str, Field(min_length=1, max_length=128)]
    auth_kind: Literal["key", "password"] = "key"
    enabled: bool = True
    #: 每台跳板同時允許的主控台連線數（多個 session 共用一條 SSH 連線，但轉發本身仍佔資源）
    max_sessions: Annotated[int, Field(ge=1, le=200)] = 10
    description: Annotated[str | None, Field(max_length=2048)] = None


class JumpHostCreate(JumpHostBase):
    #: 二擇一，對應 auth_kind
    private_key: Annotated[str | None, Field(max_length=16384)] = None
    password: Annotated[str | None, Field(max_length=512)] = None


class JumpHostUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    host: Annotated[str | None, Field(min_length=1, max_length=255)] = None
    port: Annotated[int | None, Field(ge=1, le=65535)] = None
    username: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    auth_kind: Literal["key", "password"] | None = None
    private_key: Annotated[str | None, Field(max_length=16384)] = None
    password: Annotated[str | None, Field(max_length=512)] = None
    enabled: bool | None = None
    max_sessions: Annotated[int | None, Field(ge=1, le=200)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    #: 信任（或改信任）這個主機金鑰指紋。由「測試連線」回報的值原樣送回來。
    host_key_fingerprint: Annotated[str | None, Field(max_length=128)] = None


class JumpHostRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    host: str
    port: int
    username: str
    auth_kind: str
    enabled: bool
    max_sessions: int
    description: str | None = None
    host_key_fingerprint: str | None = None
    #: 有沒有設過金鑰／密碼（不回內容 —— 這是「設好了沒」而不是「設了什麼」）
    has_secret: bool = False
    last_ok_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime
