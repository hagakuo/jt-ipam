"""子網路內的位址範圍（集區）—— GitHub issue #40。

子網路是一個 L3 網路（CIDR，有遮罩、閘道、廣播）；DHCP 集區、保留給印表機的一段位址之類的東西
是子網路**裡面**的一段連續位址，常常不是一個 CIDR 表示得了的（例如 .181～.250）。以前只能把它
拆成一堆 /32、/31 的「子網路」—— phpIPAM 也是逼人這樣做。這張表讓它直接是子網路裡的一段範圍。

用途為 DHCP 集區的範圍，會跟各整合同步回來的 DHCP 範圍（`dhcp_pool_ranges`）一起用：
清單上的「在 DHCP 範圍內」、DHCP 集區使用率、AI 工具都算進去（見 services/ip_ranges.py）。
"""

from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: 用途：DHCP 集區／保留（給特定設備、不要配發）／其他
IP_RANGE_PURPOSES = ("dhcp", "reserved", "other")


class IPRange(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ip_ranges"

    # 子網路刪掉，範圍跟著刪（它只是子網路裡的一段）
    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False)
    start_ip: Mapped[str] = mapped_column(INET, nullable=False)      # 起（含）
    end_ip: Mapped[str] = mapped_column(INET, nullable=False)        # 迄（含）
    purpose: Mapped[str] = mapped_column(String(16), nullable=False, default="dhcp",
                                         server_default="dhcp")
    name: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    # 由整合偵測到的 DHCP 發放範圍自動建立：`<來源>:<實例 id>`（與 dhcp_pool_ranges 的來源相同）；
    # 手動建立的是 NULL。自動的跟著上游走（services/ip_ranges.sync_auto_dhcp_ranges），不能手動改／刪
    source_origin: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_ip_ranges_subnet_id", "subnet_id"),
        Index("ix_ip_ranges_source_origin", "source_origin"),
        CheckConstraint("family(start_ip) = family(end_ip)", name="ip_range_same_family"),
        CheckConstraint("start_ip <= end_ip", name="ip_range_ordered"),
        CheckConstraint("purpose IN ('dhcp','reserved','other')", name="ip_range_purpose_valid"),
    )
