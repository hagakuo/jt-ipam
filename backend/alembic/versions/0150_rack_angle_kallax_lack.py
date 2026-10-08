"""機架型態新增角鋼層架、IKEA KALLAX、LackRack，並加上表面顏色。

- angle_shelf：台灣最常見的免螺絲角鋼層架（L 型立柱＋鋼橫桿＋夾板）
- kallax：IKEA KALLAX 格子櫃（一格一格，外框比內隔板厚）
- lackrack：IKEA LACK 邊桌當 19 吋機櫃（兩腳淨距 450mm＝導軌開口，以 U 計）

`finish` 是表面顏色（角鋼的黑／白／鍍鋅、KALLAX 的白／黑棕／橡木紋…），外觀會因此
不同才需要記。null＝該型態的預設色。

Revision ID: 0150_rack_angle_kallax_lack
Revises: 0149_audit_logs_append_only
Create Date: 2026-09-24
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0150_rack_angle_kallax_lack"
down_revision: str | None = "0149_audit_logs_append_only"
branch_labels = None
depends_on = None

_KINDS_NEW = ("'rack','industrial','shelf','wire_shelf','wood_shelf',"
              "'angle_shelf','kallax','lackrack'")
_KINDS_OLD = "'rack','industrial','shelf','wire_shelf','wood_shelf'"


def upgrade() -> None:
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.create_check_constraint("ck_racks_kind_valid", "racks", f"kind IN ({_KINDS_NEW})")
    op.add_column("racks", sa.Column("finish", sa.String(16), nullable=True))


def downgrade() -> None:
    op.drop_column("racks", "finish")
    # 併回最接近的舊值：兩種層架回一般層架、LackRack 回標準機櫃（一樣以 U 計）
    op.execute("UPDATE racks SET kind='shelf' WHERE kind IN ('angle_shelf','kallax')")
    op.execute("UPDATE racks SET kind='rack' WHERE kind='lackrack'")
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.create_check_constraint("ck_racks_kind_valid", "racks", f"kind IN ({_KINDS_OLD})")
