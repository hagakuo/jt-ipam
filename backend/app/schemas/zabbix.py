"""Zabbix 整合 schemas。

認證有兩種：API token（5.4+，建議）或帳號密碼（舊版走 user.login 換 session token）。
兩者都是機密，一律只進不出 —— Read 沒有任何機密欄位。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, HttpUrl

from app.schemas.base import StrictModel


class ZabbixBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    # 填前端網址即可（會自動補 /api_jsonrpc.php），也接受直接填完整端點
    api_url: HttpUrl
    enabled: bool = True
    verify_tls: bool = True
    # 重疊網段安全：留空＝全域比對。有重疊網段時前端會跳 ScopeOverlapWarning。
    scope_subnet_ids: list[uuid.UUID] | None = None
    sync_interval_seconds: Annotated[int, Field(ge=30, le=86400)] = 300
    description: Annotated[str | None, Field(max_length=2048)] = None


class ZabbixCreate(ZabbixBase):
    api_token: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    api_user: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_password: Annotated[str | None, Field(min_length=1, max_length=512)] = None


class ZabbixUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_url: HttpUrl | None = None
    api_token: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    api_user: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_password: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    scope_subnet_ids: list[uuid.UUID] | None = None
    sync_interval_seconds: Annotated[int | None, Field(ge=30, le=86400)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None


class ZabbixRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    api_url: str
    enabled: bool
    verify_tls: bool
    api_user: str | None = None
    # 有沒有設 token／密碼要看得出來（不回內容），否則使用者無從判斷該不該重填
    has_api_token: bool = False
    has_api_password: bool = False
    scope_subnet_ids: list[uuid.UUID] | None = None
    sync_interval_seconds: int
    description: str | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime
