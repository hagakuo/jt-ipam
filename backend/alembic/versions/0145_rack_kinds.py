"""機架型態擴充：標準機櫃 / 工業機櫃 / 一般層架 / 鍍鉻層架（issue #30）。

原本只有 rack / shelf 兩種。實務上中小企業還會用工業機櫃與鍍鉻層架（圓管立柱 + 網狀
層板），三者的寬度、層高與外觀都不同 —— 示意圖要畫得出來，型態就得分得出來。

Revision ID: 0145_rack_kinds
Revises: 0144_rack_kind_slots60
Create Date: 2026-09-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0145_rack_kinds"
down_revision: str | None = "0144_rack_kind_slots60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 欄位原本是 varchar(8)：放得下 rack / shelf，放不下 industrial 與 wire_shelf。
    op.alter_column("racks", "kind", type_=sa.String(16),
                    existing_type=sa.String(8), existing_nullable=False,
                    existing_server_default="rack")
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.create_check_constraint(
        "ck_racks_kind_valid", "racks",
        "kind IN ('rack','industrial','shelf','wire_shelf')")


def downgrade() -> None:
    # 回到只有兩種：新型態各自併回最接近的舊值
    op.execute("UPDATE racks SET kind='rack' WHERE kind='industrial'")
    op.execute("UPDATE racks SET kind='shelf' WHERE kind='wire_shelf'")
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.create_check_constraint(
        "ck_racks_kind_valid", "racks", "kind IN ('rack','shelf')")
    op.alter_column("racks", "kind", type_=sa.String(8),
                    existing_type=sa.String(16), existing_nullable=False,
                    existing_server_default="rack")
