"""機櫃橫向分格：devices.rack_slot / rack_slot_span 取代 rack_side（GitHub issue #31）。

原本寬度只有 full / left / right，一個 U 最多並排兩台。改成「起始格 + 跨幾格」的區間模型，
網格 12 格（12 被 2/3/4/6 整除，所以 1/2、1/3、1/4、1/6 都表達得出來；issue 提的 6 格
除不盡 1/4）。重疊判定因此變成「U 區間相交 且 格子區間相交」，與 U 位用的是同一種運算。

回填：full→(0,12)、left→(0,6)、right→(6,6)。降級時映射回最接近的 full/left/right
（落在左半視為 left、右半視為 right、跨越中線視為 full）—— 會失真，但那是降級的本質。

Revision ID: 0143_rack_slots
Revises: 0142_ocs_id
Create Date: 2026-09-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0143_rack_slots"
down_revision: str | None = "0142_ocs_id"
branch_labels = None
depends_on = None

SLOTS = 12


def upgrade() -> None:
    op.add_column("devices", sa.Column(
        "rack_slot", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("devices", sa.Column(
        "rack_slot_span", sa.Integer(), nullable=False, server_default=str(SLOTS)))
    op.execute(f"""
        UPDATE devices SET
          rack_slot = CASE WHEN rack_side = 'right' THEN {SLOTS // 2} ELSE 0 END,
          rack_slot_span = CASE WHEN rack_side IN ('left', 'right')
                                THEN {SLOTS // 2} ELSE {SLOTS} END
    """)
    op.drop_column("devices", "rack_side")


def downgrade() -> None:
    op.add_column("devices", sa.Column(
        "rack_side", sa.String(8), nullable=False, server_default="full"))
    op.execute(f"""
        UPDATE devices SET rack_side = CASE
          WHEN rack_slot = 0 AND rack_slot_span >= {SLOTS} THEN 'full'
          WHEN rack_slot + rack_slot_span <= {SLOTS // 2} THEN 'left'
          WHEN rack_slot >= {SLOTS // 2} THEN 'right'
          ELSE 'full'
        END
    """)
    op.drop_column("devices", "rack_slot_span")
    op.drop_column("devices", "rack_slot")
