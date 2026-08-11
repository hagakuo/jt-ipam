"""網段上被觀測到會回應 DHCP 的主機。

為什麼要存表：這是「某個時刻在網路上看到的事」，不是可以事後重算的推導結果。
非法 DHCP 伺服器往往只出現一陣子（有人插了台家用路由器、某台 VM 誤開 DHCP），
沒有留下觀測記錄的話，事後完全查不到它曾經存在過。

「合法與否」不存在這裡 —— 那是拿 `ip_addresses.is_dhcp_server` 即時比對出來的。
存成欄位的話，改了標記之後舊記錄就會跟現況不一致。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import INET, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class DHCPSighting(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "dhcp_sightings"

    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnets.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # 回應 DHCPOFFER 的伺服器位址（option 54 server identifier，沒有就用封包來源）
    server_ip: Mapped[str] = mapped_column(INET, nullable=False)
    server_mac: Mapped[str | None] = mapped_column(MACADDR)
    offered_ip: Mapped[str | None] = mapped_column(INET)
    router: Mapped[str | None] = mapped_column(INET)
    # 經由 DHCP relay 轉送的回應：這種情況下 server_ip 不一定在本網段
    via_relay: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_agents.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(16), default="scanner", nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        # 同一個網段的同一台伺服器只留一列，重複觀測更新 last_seen_at
        UniqueConstraint("subnet_id", "server_ip", name="dhcp_sighting_unique"),
        Index("ix_dhcp_sightings_last_seen", "last_seen_at"),
    )
