"""獨立 DHCP 伺服器（Kea／ISC DHCP，issue #45）的 schemas。讀取用的 schema 不帶任何密碼欄位。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, field_validator

from app.schemas.base import StrictModel


def _http_url(v: str | None) -> str | None:
    if v is None:
        return v
    v = v.strip()
    if not v.lower().startswith(("http://", "https://")):
        raise ValueError("api_url must start with http:// or https://")
    return v


# ── Kea ──────────────────────────────────────────────────────────────────────

class KeaDhcpBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    api_url: Annotated[str, Field(min_length=8, max_length=2048)]
    verify_tls: bool = True
    username: Annotated[str | None, Field(max_length=255)] = None
    enabled: bool = True
    sync_scopes: bool = True
    sync_leases: bool = True
    sync_interval_seconds: Annotated[int, Field(ge=30, le=86400)] = 300
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None

    @field_validator("api_url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        return _http_url(v) or v


class KeaDhcpCreate(KeaDhcpBase):
    # 沒開 HTTP 認證的 Kea（只聽本機或內網）可以不給
    password: Annotated[str | None, Field(max_length=512)] = None


class KeaDhcpUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_url: Annotated[str | None, Field(min_length=8, max_length=2048)] = None
    verify_tls: bool | None = None
    username: Annotated[str | None, Field(max_length=255)] = None
    password: Annotated[str | None, Field(max_length=512)] = None     # 留空＝不更改
    enabled: bool | None = None
    sync_scopes: bool | None = None
    sync_leases: bool | None = None
    sync_interval_seconds: Annotated[int | None, Field(ge=30, le=86400)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None

    @field_validator("api_url")
    @classmethod
    def _check_url(cls, v: str | None) -> str | None:
        return _http_url(v)


class KeaDhcpRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    api_url: str
    verify_tls: bool
    username: str | None = None
    has_password: bool = False
    enabled: bool
    sync_scopes: bool
    sync_leases: bool
    sync_interval_seconds: int
    description: str | None = None
    scope_subnet_ids: list[uuid.UUID] | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    last_summary: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


# ── ISC DHCP ─────────────────────────────────────────────────────────────────

class IscDhcpBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    agent_id: uuid.UUID | None = None
    enabled: bool = True
    sync_scopes: bool = True
    sync_leases: bool = True
    report_interval_seconds: Annotated[int, Field(ge=60, le=86400)] = 300
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class IscDhcpCreate(IscDhcpBase):
    pass


class IscDhcpUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    agent_id: uuid.UUID | None = None
    enabled: bool | None = None
    sync_scopes: bool | None = None
    sync_leases: bool | None = None
    report_interval_seconds: Annotated[int | None, Field(ge=60, le=86400)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class IscDhcpRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    agent_id: uuid.UUID | None = None
    agent_name: str | None = None
    agent_version: str | None = None
    agent_last_seen_at: datetime | None = None
    enabled: bool
    sync_scopes: bool
    sync_leases: bool
    report_interval_seconds: int
    description: str | None = None
    scope_subnet_ids: list[uuid.UUID] | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    file_status: dict[str, Any] | None = None
    last_summary: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime
