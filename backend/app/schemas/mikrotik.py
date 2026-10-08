"""MikroTik RouterOS 整合 schemas。

比其他整合多了一組「安全參數」（cpu_load_limit / section_delay_ms / max_response_mb）——
客戶的 MikroTik 是主力路由器，這些不是效能微調而是設定層級的保護，因此可讀可改。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, HttpUrl

from app.schemas.base import StrictModel


class MikroTikBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    api_url: HttpUrl
    api_username: Annotated[str, Field(min_length=1, max_length=128)]
    enabled: bool = True
    verify_tls: bool = True
    # 主力路由器 → 預設 900 秒（其他整合是 300）
    sync_interval_seconds: Annotated[int, Field(ge=60, le=86400)] = 900

    sync_dhcp: bool = True
    sync_dhcp_ranges: bool = True
    sync_firewall: bool = True
    sync_nat: bool = True
    sync_address_lists: bool = True
    sync_vpn: bool = True
    #: ⚠️ 預設關：全表 ARP 在大型路由器上可能是上萬列。
    #: 先用「測試連線」看它回報幾列、花幾秒，再自己決定要不要開。
    sync_arp: bool = False
    #: 第二階段（0170）：介面、鄰居落到 `device_id` 這台裝置；FDB 預設關（大型 bridge 可能上萬列）
    sync_interfaces: bool = True
    sync_neighbors: bool = True
    sync_fdb: bool = False
    #: 這台路由器＝哪一台 jt-ipam 裝置；留空＝同步時用 API 位址對到的 IP 所屬裝置
    device_id: uuid.UUID | None = None

    cpu_load_limit: Annotated[int, Field(ge=0, le=100)] = 70
    section_delay_ms: Annotated[int, Field(ge=0, le=10000)] = 300
    max_response_mb: Annotated[int, Field(ge=1, le=256)] = 8

    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class MikroTikCreate(MikroTikBase):
    api_password: Annotated[str, Field(min_length=1, max_length=512)]


class MikroTikUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_url: HttpUrl | None = None
    api_username: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    api_password: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    sync_interval_seconds: Annotated[int | None, Field(ge=60, le=86400)] = None
    sync_dhcp: bool | None = None
    sync_dhcp_ranges: bool | None = None
    sync_firewall: bool | None = None
    sync_nat: bool | None = None
    sync_address_lists: bool | None = None
    sync_vpn: bool | None = None
    sync_arp: bool | None = None
    sync_interfaces: bool | None = None
    sync_neighbors: bool | None = None
    sync_fdb: bool | None = None
    device_id: uuid.UUID | None = None
    cpu_load_limit: Annotated[int | None, Field(ge=0, le=100)] = None
    section_delay_ms: Annotated[int | None, Field(ge=0, le=10000)] = None
    max_response_mb: Annotated[int | None, Field(ge=1, le=256)] = None
    description: Annotated[str | None, Field(max_length=2048)] = None
    scope_subnet_ids: list[uuid.UUID] | None = None


class MikroTikRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    api_url: str
    api_username: str
    enabled: bool
    verify_tls: bool
    sync_interval_seconds: int
    sync_dhcp: bool
    sync_dhcp_ranges: bool
    sync_firewall: bool
    sync_nat: bool
    sync_address_lists: bool
    sync_vpn: bool
    sync_arp: bool
    sync_interfaces: bool = True
    sync_neighbors: bool = True
    sync_fdb: bool = False
    device_id: uuid.UUID | None = None
    cpu_load_limit: int
    section_delay_ms: int
    max_response_mb: int
    description: str | None = None
    scope_subnet_ids: list[uuid.UUID] | None = None
    routeros_version: str | None = None
    board_name: str | None = None
    last_sync_at: datetime | None = None
    last_error: str | None = None
    #: 逐區段的耗時／CPU（含「因為 CPU 超標而提早停止」的原因）
    last_cost: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


class MikroTikRuleRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    router_id: uuid.UUID
    table_name: str
    chain: str | None = None
    position: int
    action: str | None = None
    disabled: bool
    src_address: str | None = None
    dst_address: str | None = None
    protocol: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    in_interface: str | None = None
    out_interface: str | None = None
    to_addresses: str | None = None
    to_ports: str | None = None
    comment: str | None = None
    synced_at: datetime


class MikroTikAddressListRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    router_id: uuid.UUID
    list_name: str
    address: str
    dynamic: bool
    timeout: str | None = None
    comment: str | None = None
    synced_at: datetime
