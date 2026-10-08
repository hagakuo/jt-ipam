"""OCS Inventory NG 整合 schemas。

與其他整合最大的不同：**帳密是選用的**（OCS REST 預設無驗證），所以 `api_username` /
`api_password` 都可為 None。Phase 1 只收 REST 來源。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, HttpUrl

from app.schemas.base import StrictModel


class OcsBase(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    base_url: HttpUrl
    enabled: bool = True
    verify_tls: bool = True
    #: 帳密選用 —— OCS REST 預設無驗證
    api_username: Annotated[str | None, Field(max_length=128)] = None
    #: 2.11 增量跑得動每小時；2.10 只能全量，管理員應自己調長
    sync_interval_seconds: Annotated[int, Field(ge=300, le=86400)] = 3600
    stale_after_days: Annotated[int, Field(ge=1, le=3650)] = 30
    sync_networks: bool = True
    sync_bios: bool = True
    #: ⚠️ 預設關：軟體讓每台 ~2 KB → ~80 KB（5000 台 ≈ 400 MB/輪）。第一版尚未落地儲存。
    sync_software: bool = False
    #: 限定子網路範圍（重疊網段時只在這些子網路內比對；未裝 Agent 的 IP 也只列這些）。空＝全域
    scope_subnet_ids: list[str] | None = None


class OcsCreate(OcsBase):
    api_password: Annotated[str | None, Field(max_length=512)] = None


class OcsUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    base_url: HttpUrl | None = None
    enabled: bool | None = None
    verify_tls: bool | None = None
    api_username: Annotated[str | None, Field(max_length=128)] = None
    api_password: Annotated[str | None, Field(max_length=512)] = None
    #: 傳 true 明確清掉已存的帳密（改回無驗證）
    clear_credentials: bool = False
    sync_interval_seconds: Annotated[int | None, Field(ge=300, le=86400)] = None
    stale_after_days: Annotated[int | None, Field(ge=1, le=3650)] = None
    sync_networks: bool | None = None
    sync_bios: bool | None = None
    sync_software: bool | None = None
    scope_subnet_ids: list[str] | None = None


class OcsRead(StrictModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    source_type: str
    base_url: str | None
    enabled: bool
    verify_tls: bool
    api_username: str | None
    #: 有沒有設密碼（不回明文）
    has_password: bool = False
    sync_interval_seconds: int
    stale_after_days: int
    sync_networks: bool
    sync_bios: bool
    sync_software: bool
    scope_subnet_ids: list[str] | None = None
    detected_version: str | None
    last_sync_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    last_cost: dict[str, Any] | None

    @classmethod
    def from_row(cls, row: Any) -> OcsRead:
        obj = cls.model_validate(row)
        obj.has_password = row.api_password_enc is not None
        return obj
