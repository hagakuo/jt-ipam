"""獨立的 DHCP 伺服器（issue #45）：沒有架在 OPNsense／pfSense 上的 Kea 與 ISC DHCP。

兩者都寫進共用的 dhcp_pool_ranges／dhcp_reservations／dhcp_lease_sightings（各自只清自己的列），
但資料怎麼來完全不同，所以是兩張表：

- **Kea**（`kea_dhcp_servers`）：jt-ipam 主動拉 Kea 的 JSON 控制 API（控制代理或 Kea 3.0 直連）
- **ISC DHCP**（`isc_dhcp_servers`）：isc-dhcp-server 沒有能列出全部租約的 API，由裝在 DHCP 主機上的
  掃描代理讀本機 dhcpd.conf／dhcpd.leases、解析後回報；jt-ipam 不連過去
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class KeaDhcpServer(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "kea_dhcp_servers"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # 控制代理（http(s)://host:8000/）或 Kea 3.0 DHCP 伺服器自己的 HTTP 控制通道
    api_url: Mapped[str] = mapped_column(Text, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # HTTP Basic 認證（Kea 1.9 起支援；沒設就不帶）。密碼 AES-GCM 雙欄加密
    username: Mapped[str | None] = mapped_column(String(255))
    password_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    sync_scopes: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)   # 範圍＋保留
    sync_leases: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)   # 租約（要 lease_cmds）

    # 限定子網路範圍（留空＝全域比對；重疊網段建議設定）
    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(ARRAY(UUID(as_uuid=True)))

    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    # 上一次同步看到什麼（Kea 版本、連線方式、租約是否可用…），給畫面顯示
    last_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    description: Mapped[str | None] = mapped_column(Text)


class IscDhcpServer(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "isc_dhcp_servers"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # 裝在這台 DHCP 主機上的掃描代理（一台代理只對應一個來源）。代理被刪掉就斷開，來源留著
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_agents.id", ondelete="SET NULL"), unique=True)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # 代理多久讀一次檔、回報一次
    report_interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    sync_scopes: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)   # 範圍＋固定分配
    sync_leases: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)   # 租約

    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(ARRAY(UUID(as_uuid=True)))

    # 最後一次收到代理回報（健康告警與畫面都看這個）
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    # 代理讀檔的狀態：{"conf": {path, ok, error, size, mtime}, "leases": {...}}
    file_status: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    last_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    description: Mapped[str | None] = mapped_column(Text)
