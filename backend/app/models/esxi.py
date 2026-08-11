"""VMware ESXi / vCenter 整合（vSphere SOAP API）。

**同一套設定同時涵蓋單機 ESXi 與 vCenter** —— 兩者都是 `/sdk` 上的 VIM API，差別只在
清單的層次深度，所以不需要分成兩種整合。

與 Proxmox 各自獨立設定、獨立同步（延續本專案「不做跨廠牌抽象」的原則），
但寫進**同一組虛擬化資料表**（`virt_clusters` / `virtual_machines` / `vm_interfaces`），
所以拓樸、AI 對話、MCP 的 `list_vms` 都不必為了新平台改一行。

唯讀：只呼叫 login / 建立檢視 / 取屬性 / logout，不對 ESXi 寫入任何東西。
免費版 ESXi 的 vSphere API 本來就是唯讀的，對這個用途正好。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ESXiInstance(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "esxi_instances"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # 例：https://esxi.example.com（可帶自訂埠）。SOAP 端點固定是 <api_url>/sdk
    api_url: Mapped[str] = mapped_column(Text, nullable=False)
    # 備援位址（換行或逗號分隔）。vCenter 可能有多個位址，或 vCenter 停機時想改打某台
    # ESXi —— 依序試到通為止。與 Proxmox 的 extra_api_urls 同一套作法。
    extra_api_urls: Mapped[str | None] = mapped_column(Text)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    password_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    password_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # 對映到哪個叢集紀錄（第一次同步時建立，之後沿用）
    cluster_id: Mapped[uuid.UUID | None] = mapped_column()

    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    # 限定子網路範圍：重疊網段下用來把 IP 比對縮到正確的子網路
    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(JSONB)

    description: Mapped[str | None] = mapped_column(Text)
