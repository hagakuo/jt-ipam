"""FortiGate 整合 schemas（Beta）。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, HttpUrl

from app.schemas.base import StrictModel


class FortiGateBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    api_url: HttpUrl
    enabled: bool = True
    verify_tls: bool = True
    # 留空＝自動探索全部 VDOM
    vdoms: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = None
    sync_dhcp: bool = False
    sync_dhcp_ranges: bool = False
    sync_arp: bool = True
    sync_vpn: bool = False
    sync_policies: bool = False
    sync_nat: bool = False
    sync_addresses: bool = False
    sync_interval_seconds: Annotated[int, Field(ge=30, le=86400)] = 300
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class FortiGateCreate(FortiGateBase):
    api_token: Annotated[str, Field(min_length=1, max_length=512)]


class FortiGateUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_url: HttpUrl | None = None
    api_token: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    vdoms: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = None
    sync_dhcp: bool | None = None
    sync_dhcp_ranges: bool | None = None
    sync_arp: bool | None = None
    sync_vpn: bool | None = None
    sync_policies: bool | None = None
    sync_nat: bool | None = None
    sync_addresses: bool | None = None
    sync_interval_seconds: Annotated[int | None, Field(ge=30, le=86400)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class FortiGateRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    api_url: str
    enabled: bool
    verify_tls: bool
    vdoms: list[str] | None = None
    sync_dhcp: bool
    sync_dhcp_ranges: bool
    sync_arp: bool
    sync_vpn: bool
    sync_policies: bool
    sync_nat: bool
    sync_addresses: bool
    sync_interval_seconds: int
    description: str | None = None
    scope_subnet_ids: list[uuid.UUID] | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime
