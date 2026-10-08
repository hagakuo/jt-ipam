"""工具探測工作（由掃描代理在當地執行的 ping / port / traceroute / rDNS）。

為什麼要有這張表：掃描代理只由內往外連（poll/report），後端沒有辦法主動叫它做事。
把「請求」放進佇列、由代理自己來領，是在不開放任何入站連線的前提下唯一乾淨的作法。

安全邊界（實作時務必維持）：
- `kind` 只接受允許清單探測；代理端也要自己驗一次，不可只信後端給的內容
- 參數一律以陣列傳給子行程，**永遠不經過 shell**
- `expires_at`：代理離線時工作自動作廢，避免它上線後一次補跑一堆過期探測
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime as SADateTime
from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin

# 允許清單：只開放唯讀、無副作用的網路探測。**不開放任意指令**。
# identify：IP 詳細頁的「探測」—— 對單一 IP 做非侵入式識別（服務版本、OS 指紋、banner、
# TLS 憑證、名稱查詢），只有管理員能發起（services/ip_identify）。
PROBE_KINDS = ("ping", "tcp", "traceroute", "rdns", "identify")

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"


class AgentProbeJob(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "agent_probe_jobs"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_agents.id", ondelete="CASCADE"),
        nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_PENDING)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    #: 執行中的進度（目前只有 identify 會回報）：{stage, phase, percent, remaining, open[], elapsed, log[]}
    progress: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        SADateTime(timezone=True), server_default=func.now(), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(SADateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(SADateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(SADateTime(timezone=True), nullable=False)
