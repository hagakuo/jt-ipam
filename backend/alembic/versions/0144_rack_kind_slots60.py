"""層架支援與 60 格網格（GitHub issue #30；#31 的網格改寬）。

兩件事：

1. **網格 12 → 60**。先前取 12 只看了 #31（要 6 等分），但 #30 的層架明講「一層可以並排
   3~5 台」—— 12 除不盡 5。60 是 1~6 的最小公倍數，1/2、1/3、1/4、1/5、1/6 全部表達得出來。
   既有資料等比放大 ×5（12 格的 1 格 = 60 格的 5 格），位置與寬度完全不變。

2. **racks.kind / row_height_mm**。層架沒有 U 的概念，寬度與層高也不是標準值；
   立面圖要照這兩個值畫，否則三層架會被畫成三條細線。

Revision ID: 0144_rack_kind_slots60
Revises: 0143_rack_slots
Create Date: 2026-09-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0144_rack_kind_slots60"
down_revision: str | None = "0143_rack_slots"
branch_labels = None
depends_on = None

SCALE = 5          # 12 → 60


def upgrade() -> None:
    # 1) 網格放大：既有的 slot/span 等比 ×5，畫面上的位置與寬度不變
    op.execute(f"UPDATE devices SET rack_slot = rack_slot * {SCALE}, "
               f"rack_slot_span = rack_slot_span * {SCALE}")
    op.alter_column("devices", "rack_slot_span", server_default="60")

    # 2) 層架
    op.add_column("racks", sa.Column(
        "kind", sa.String(8), nullable=False, server_default="rack"))
    op.add_column("racks", sa.Column("row_height_mm", sa.Integer()))
    op.create_check_constraint(
        "ck_racks_kind_valid", "racks", "kind IN ('rack','shelf')")


def downgrade() -> None:
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.drop_column("racks", "row_height_mm")
    op.drop_column("racks", "kind")
    op.alter_column("devices", "rack_slot_span", server_default="12")
    op.execute(f"UPDATE devices SET rack_slot = rack_slot / {SCALE}, "
               f"rack_slot_span = GREATEST(rack_slot_span / {SCALE}, 1)")
