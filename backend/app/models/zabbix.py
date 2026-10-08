"""Zabbix 整合 model。

定位是**監控面補充**，不是 LibreNMS 的替代：Zabbix 給的是存活狀態、監控涵蓋落差、
主機名稱與維護脈絡。ARP／FDB 不在它的內建資料裡（要靠自訂 SNMP 項目），因此不承諾。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import DateTime as SADateTime
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ZabbixInstance(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Zabbix API 連線實例。"""

    __tablename__ = "zabbix_instances"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    api_url: Mapped[str] = mapped_column(Text, nullable=False)

    # API token（Zabbix 5.4+，建議）或帳密登入取 session token；兩者皆 AES-GCM 加密
    api_token_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    api_token_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    api_user: Mapped[str | None] = mapped_column(String(128))
    api_password_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    api_password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # 重疊網段安全：限定比對範圍（空＝全域）。與其他整合同一個機制。
    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(JSONB)
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(SADateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)


class ZabbixHost(Base, UUIDPrimaryKeyMixin):
    """Zabbix 主機鏡像（可重新同步的資料）。"""

    __tablename__ = "zabbix_hosts"
    __table_args__ = (
        UniqueConstraint("instance_id", "hostid", name="uq_zabbix_host_instance_hostid"),
    )

    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("zabbix_instances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    hostid: Mapped[str] = mapped_column(String(32), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str | None] = mapped_column(String(16))
    available: Mapped[str | None] = mapped_column(String(16))
    maintenance: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ip: Mapped[str | None] = mapped_column(INET)
    dns: Mapped[str | None] = mapped_column(String(255))
    groups: Mapped[list[Any] | None] = mapped_column(JSONB)
    tags: Mapped[list[Any] | None] = mapped_column(JSONB)
    inventory: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    jt_ipam_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_addresses.id", ondelete="SET NULL"))
    last_seen_at: Mapped[datetime | None] = mapped_column(SADateTime(timezone=True))
    synced_at: Mapped[datetime] = mapped_column(
        SADateTime(timezone=True), server_default=func.now(), nullable=False)
