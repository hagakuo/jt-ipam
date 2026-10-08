"""層架：層板厚度／離地高度、頂板上方可放、層內可上下疊放。

三件事，都是「把層架當成真的層架」才會有的：

1. **層板厚度 / 離地**：層高填的是淨空高（不含層板），所以整台的總高要另外把板厚與
   最下層板離地的高度算進去，否則畫出來會比實物矮一截。
2. **頂板上方**：層架沒有天花板，最上面那片板的上面本來就放得了東西。資料上是
   「第 u_height + 1 層」。
3. **層內上下疊**：一層的淨空高常常放得下兩三台疊起來，而且不一定放滿。
   用與橫向完全相同的區間模型（起始格 + 跨幾格，共 RACK_SLOTS 格），
   `rack_vslot` 的 0 是**貼著層板的那一側**（東西是放在板上的）。

Revision ID: 0148_shelf_stack_and_top
Revises: 0147_rack_level_heights
Create Date: 2026-09-21
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0148_shelf_stack_and_top"
down_revision: str | None = "0147_rack_level_heights"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("racks", sa.Column("board_mm", sa.Integer(), nullable=True))
    op.add_column("racks", sa.Column("floor_mm", sa.Integer(), nullable=True))
    # 既有資料一律「整層佔滿」，所以預設值就是舊行為，不必回填
    op.add_column("devices", sa.Column(
        "rack_vslot", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("devices", sa.Column(
        "rack_vslot_span", sa.Integer(), nullable=False, server_default="60"))


def downgrade() -> None:
    op.drop_column("devices", "rack_vslot_span")
    op.drop_column("devices", "rack_vslot")
    op.drop_column("racks", "floor_mm")
    op.drop_column("racks", "board_mm")
