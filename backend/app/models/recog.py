"""Recog 指紋資料庫（rapid7/recog）：一個指紋檔一列。

選用元件，由 services/recog.py 下載與更新（安裝／升級時、之後每週一次）。
`fingerprints` 存的是 Recog 原本的 Ruby 正規式（載入時才轉成 Python），
每筆：{"p": pattern, "f": flags, "d": description, "a": [[pos, name, value], ...], "c": certainty}。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class RecogDatabase(Base):
    __tablename__ = "recog_databases"

    # 指紋檔的 matches 屬性（ssh.banner、http_header.server…）；沒有的用檔名
    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    filename: Mapped[str] = mapped_column(String(128), nullable=False)
    release: Mapped[str] = mapped_column(String(32), nullable=False)
    # 轉換規則的版本：程式改進轉換方式後，同一版要重新匯入
    translator_version: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str | None] = mapped_column(String(32))
    database_type: Mapped[str | None] = mapped_column(String(32))
    preference: Mapped[float | None] = mapped_column(Float)
    fingerprints: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    # 原始指紋數與被剔除的數量（轉換不了、比不中自己的範例、可能回溯爆炸）
    total: Mapped[int] = mapped_column(Integer, nullable=False)
    skipped: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
