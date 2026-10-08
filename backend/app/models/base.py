"""SQLAlchemy 2.0 declarative base + 共用 mixin。"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# 命名慣例：Alembic 自動命名約束（避免 PG 預設名隨機）
_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=_NAMING_CONVENTION)

    type_annotation_map = {
        dict[str, Any]: "JSONB",
    }


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        # 程式端先產生：ORM 事先知道主鍵，同一次 flush 的多筆新增才能整批送出。只有資料庫預設時，
        # 每一筆都要單獨 INSERT … RETURNING 取回主鍵 —— 一次同步寫三萬筆異動記錄就是三萬次來回
        # （2026-09-30 大量資料測試）。資料庫預設留著，給直接寫 SQL 的地方（遷移、灌資料）。
        default=uuid.uuid4,
        insert_sentinel=True,
        server_default=func.gen_random_uuid(),  # 需要 pgcrypto extension
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
