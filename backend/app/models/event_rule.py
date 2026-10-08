"""事件規則：事件 → 條件 → 動作。

條件與動作存成結構化資料（不是可執行的運算式）—— 規則由使用者輸入，
能執行的東西就是一條注入路徑。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy import DateTime as SADateTime
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class EventRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "event_rules"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: 訂閱的事件；["*"] = 全部
    events: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    #: [{field, op, value}]，全部成立才算命中（AND）
    conditions: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    #: [{type: notify_admins|webhook, ...}]
    actions: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_matched_at: Mapped[datetime | None] = mapped_column(SADateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
