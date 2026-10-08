"""層架的每一層可以有不同高度（IVAR / 鍍鉻層架實際上就是這樣裝）。

原本一台層架只能有一個層高，但層架的層板本來就是一層一層各自可調 —— 常見的裝法是
下面留高一點放主機或 UPS、上面壓矮一點放網通設備。存成一個陣列，由第 1 層起算；
null 或長度對不上就退回原本的 `row_height_mm`，所以既有資料畫出來完全不變。

Revision ID: 0147_rack_level_heights
Revises: 0146_rack_wood_shelf
Create Date: 2026-09-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0147_rack_level_heights"
down_revision: str | None = "0146_rack_wood_shelf"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("racks", sa.Column(
        "level_heights", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("racks", "level_heights")
