"""IP 釋放後的冷卻期。

獨立成表而不是放在 `ip_addresses`：實務上「釋放」最常見的做法就是把那筆 IP 刪掉，
紀錄放在原表會跟著消失。冷卻期要能撐過刪除才有意義。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime as SADateTime
from sqlalchemy import ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin


class IPCooldown(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "ip_cooldowns"
    __table_args__ = (
        UniqueConstraint("subnet_id", "ip", name="uq_ip_cooldown_subnet_ip"),
    )

    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    released_at: Mapped[datetime] = mapped_column(SADateTime(timezone=True), nullable=False)
    until: Mapped[datetime] = mapped_column(SADateTime(timezone=True), nullable=False)
    #: 釋放當下的身分 —— 冷卻期間有人問「這位址剛剛是誰」，要答得出來
    previous_hostname: Mapped[str | None] = mapped_column(Text)
    previous_mac: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    released_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    #: 提前解除：留下誰、何時、為什麼
    cleared_at: Mapped[datetime | None] = mapped_column(SADateTime(timezone=True))
    cleared_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    cleared_reason: Mapped[str | None] = mapped_column(Text)
