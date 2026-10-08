"""Palo Alto（PAN-OS）整合 schemas。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, HttpUrl

from app.schemas.base import StrictModel

#: REST URI 裡的版本段。留空＝由 `show system info` 自行推導。
_VERSION_PATTERN = r"^v\d+\.\d+$"


class PaloAltoBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    api_url: HttpUrl
    enabled: bool = True
    verify_tls: bool = True
    #: 留空＝自動偵測（強烈建議留空；填錯會讓所有 REST 端點回 404）
    api_version: Annotated[str | None, Field(pattern=_VERSION_PATTERN)] = None
    #: 留空＝自動探索全部 vsys
    vsys_list: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = None
    sync_dhcp: bool = False
    sync_arp: bool = True
    sync_policies: bool = False
    sync_nat: bool = False
    sync_addresses: bool = False
    sync_vpn: bool = True
    sync_interval_seconds: Annotated[int, Field(ge=30, le=86400)] = 300
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class PaloAltoCreate(PaloAltoBase):
    api_key: Annotated[str, Field(min_length=1, max_length=1024)]


class PaloAltoUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_url: HttpUrl | None = None
    api_key: Annotated[str | None, Field(min_length=1, max_length=1024)] = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    api_version: Annotated[str | None, Field(pattern=_VERSION_PATTERN)] = None
    #: 明確清掉自訂版本、改回自動偵測（`None` 在 PATCH 是「不修改」）
    clear_api_version: bool = False
    vsys_list: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = None
    sync_dhcp: bool | None = None
    sync_arp: bool | None = None
    sync_policies: bool | None = None
    sync_nat: bool | None = None
    sync_addresses: bool | None = None
    sync_vpn: bool | None = None
    sync_interval_seconds: Annotated[int | None, Field(ge=30, le=86400)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class PaloAltoRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    api_url: str
    enabled: bool
    verify_tls: bool
    api_version: str | None = None
    vsys_list: list[str] | None = None
    sync_dhcp: bool
    sync_arp: bool
    sync_policies: bool
    sync_nat: bool
    sync_addresses: bool
    sync_vpn: bool = True
    sync_interval_seconds: int
    description: str | None = None
    scope_subnet_ids: list[uuid.UUID] | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class PaloAltoPolicyRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    vsys: str
    name: str
    position: int | None = None
    action: str | None = None
    disabled: bool | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    source: str | None = None
    destination: str | None = None
    application: str | None = None
    service: str | None = None
    description: str | None = None
    last_sync_at: datetime | None = None


class PaloAltoAddressRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    vsys: str
    name: str
    obj_type: str | None = None
    kind: str
    value: str | None = None
    members: list | None = None
    description: str | None = None
    last_sync_at: datetime | None = None
