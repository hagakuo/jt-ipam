"""ESXi / vCenter 整合的 schema。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, HttpUrl

from app.schemas.base import StrictModel


class ESXiBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    # 例：https://esxi.example.com（可帶自訂埠）。SOAP 端點固定是 <api_url>/sdk
    api_url: HttpUrl
    # 備援位址（換行或逗號分隔）。vCenter 可能有多個位址，或 vCenter 停機時想改打某台
    # ESXi —— 依序試到通為止。**這個欄位漏掉會讓整個新增表單 422**（StrictModel 是
    # extra=forbid，前端一律會送這個鍵，留空時送 null）。
    extra_api_urls: Annotated[str | None, Field(max_length=2048)] = None
    username: Annotated[str, Field(min_length=1, max_length=128)]
    enabled: bool = True
    verify_tls: bool = True
    sync_interval_seconds: Annotated[int, Field(ge=30, le=86400)] = 300
    scope_subnet_ids: list[str] | None = None
    description: Annotated[str | None, Field(max_length=2048)] = None


class ESXiCreate(ESXiBase):
    password: Annotated[str, Field(min_length=1, max_length=512)]


class ESXiUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_url: HttpUrl | None = None
    extra_api_urls: Annotated[str | None, Field(max_length=2048)] = None
    username: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    password: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    sync_interval_seconds: Annotated[int | None, Field(ge=30, le=86400)] = None
    scope_subnet_ids: list[str] | None = None
    description: Annotated[str | None, Field(max_length=2048)] = None


class ESXiRead(ESXiBase):
    id: uuid.UUID
    cluster_id: uuid.UUID | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
