"""沒有納管、但看得到在用的位址（2026-10-06 使用者：「就算關閉自動加，也要讓格子看得出來該 IP 被用、但不是我們納管」）。

掃描代理的「自動收錄」關閉時，掃到 IPAM 裡沒有的活位址以前直接丟掉，指示計上跟閒置一模一樣。現在只記「看到過」：
位址、所屬子網路、誰看到的、最早與最近的時間，有的話附 MAC 與主機名稱 —— **不建 IP 記錄**。

- 只記指派給該代理、而且有開掃描的子網路內的位址
- 30 天沒再看到就清掉（jt-ipam-sync 每輪一次）；之後被登錄了，指示計以 IP 記錄為準
- LibreNMS 的 ARP 表本來就留著未登錄的位址（arp_entries），讀的時候一起算，不重複存
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin


class UnmanagedSighting(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "unmanaged_sightings"

    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    # 誰看到的：scanner（掃描代理）；之後別的來源也可以寫進來
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))   # 哪一台掃描代理
    mac: Mapped[str | None] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("subnet_id", "ip", "source", name="uq_unmanaged_sighting"),
        Index("ix_unmanaged_sightings_last_seen", "last_seen_at"),
    )
