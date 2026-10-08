"""逐日存活觀測（可用性長條圖的資料來源）。

一天一列（每個 IP）。存在的理由：先前每日狀態是由狀態轉換推估的，沒有觀測撐著的
日子照樣會被畫成綠色 —— 實機上讓一台關了幾十天的機器顯示 52 天全綠。
"""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import Boolean, Date, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IPLivenessDay(Base):
    __tablename__ = "ip_liveness_days"

    ip_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_addresses.id", ondelete="CASCADE"),
        primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    #: 當天曾被**會老化**的來源看到（掃描代理／LibreNMS 裝置狀態）
    up: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: 當天曾判定離線
    down: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: 當天唯一的證據是 ARP —— 不足以宣稱可用（ARP 沒有時間概念）
    arp_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
