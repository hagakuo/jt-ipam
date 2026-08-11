"""AI 巡檢發現（排程對 IPAM 資料做的安全/異常分析結果）。

為什麼要存表而不是每次現算：LLM 分析很慢也耗 token，儀表板每次載入都重跑不切實際。
把結果落地之後，儀表板與清單頁讀的是同一份快照，也才有「何時發現、是否已處理」可言。

⚠️ **這些是 LLM 的推測，不是查核過的事實。** 每一筆都必須帶著 `evidence`（產生它的
實際資料）一起顯示，讓人可以自己判斷；UI 也要標明來源是 AI。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AIFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_findings"

    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    # low / medium / high —— 由 LLM 給，但值域由我們限制（模型會自創等級）
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    category: Mapped[str] = mapped_column(String(48), nullable=False, default="other")
    title: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recommendation: Mapped[str | None] = mapped_column(Text)
    # 產生這條結論的實際資料：沒有它就只是一句無法查證的斷言
    evidence: Mapped[dict | None] = mapped_column(JSONB)
    # 關聯物件（可為空）—— 用來從發現跳到該 IP / 子網路 / 裝置
    object_type: Mapped[str | None] = mapped_column(String(32))
    object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # 「同一件事」的指紋（分類＋依據資料的 IP 清單）。用來讓已忽略的發現在下次巡檢
    # 時不要又跳回未處理 —— 不用標題算，因為標題每次都是模型重寫的。
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)

    # 寫出這條結論的模型。巡檢是推測不是事實，而不同模型的品質差很多 ——
    # 換過模型之後若分不出哪幾條是舊模型寫的，就無從判斷新模型到底有沒有比較好。
    model: Mapped[str | None] = mapped_column(String(128))

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")  # open/dismissed
    dismissed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    # 一定要寫 timezone=True：不寫的話 SQLAlchemy 推出 naive DateTime，
    # 塞 tz-aware 值進去 asyncpg 會 DataError（欄位本身是 timestamptz）
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_ai_findings_status_severity", "status", "severity"),
        Index("ix_ai_findings_created", text("created_at DESC")),
    )
