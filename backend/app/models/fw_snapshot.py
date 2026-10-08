"""防火牆規則快照（0118）。

一列＝一次「規則真的變了」的事件（含與上一份的 diff）；沒變不插列。
不設 FK：防火牆實例刪除後，變更歷史仍是稽核證據，要留著。
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class FwRuleSnapshot(Base):
    __tablename__ = "fw_rule_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)   # opnsense/pfsense/fortigate/paloalto
    instance_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    instance_name: Mapped[str] = mapped_column(String(255), nullable=False)
    taken_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"))
    rules_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    rules: Mapped[list] = mapped_column(JSONB, nullable=False)  # type: ignore[type-arg]
    # none_as_null：Python None 要存成 SQL NULL，不是 JSON null —— 否則
    # 「diff IS NULL＝baseline」在 SQL 層永遠不成立（prod 實資料抓到的）
    diff: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True), nullable=True)  # type: ignore[type-arg]
    # 認可（0119）：誰確認了這筆變更＋說明。沒被認可的異動＝稽核上「無人說明的變更」
    ack_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ack_note: Mapped[str | None] = mapped_column(Text, nullable=True)
