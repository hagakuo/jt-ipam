"""掃描代理每一輪的耗時記錄（保留 7 天）。

使用者要求（2026-09-28）：「要自動記錄每輪 scan 花多久，太長要通知管理員」。
一輪一列：上線偵測耗時、當時的週期設定、背景重量探測的待辦量。負載面板畫趨勢、
判斷「背景待辦是不是一直消化不完」都靠這張表。逐子網路的細節只留最近一輪（scan_agents.last_cycle）。
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ScanAgentCycle(Base):
    __tablename__ = "scan_agent_cycles"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_agents.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_s: Mapped[float] = mapped_column(Float, nullable=False)
    interval_s: Mapped[int] = mapped_column(Integer, nullable=False)
    heavy_backlog: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts: Mapped[int | None] = mapped_column(Integer)
    alive: Mapped[int | None] = mapped_column(Integer)
