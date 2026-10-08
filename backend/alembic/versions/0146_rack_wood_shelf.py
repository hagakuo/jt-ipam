"""機架型態新增木質層架（松木側架 + 層板，如 IKEA IVAR）。

鍍鉻層架之外，另一種中小企業／SOHO 常見的放法是木質層架。它的外觀與前四種都不同
（側架是一片有整排孔位的松木框，不是圓管立柱），型態分得出來，示意圖才畫得出來。

Revision ID: 0146_rack_wood_shelf
Revises: 0145_rack_kinds
Create Date: 2026-09-20
"""
from __future__ import annotations

from alembic import op

revision: str = "0146_rack_wood_shelf"
down_revision: str | None = "0145_rack_kinds"
branch_labels = None
depends_on = None

_KINDS_NEW = "'rack','industrial','shelf','wire_shelf','wood_shelf'"
_KINDS_OLD = "'rack','industrial','shelf','wire_shelf'"


def upgrade() -> None:
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.create_check_constraint("ck_racks_kind_valid", "racks", f"kind IN ({_KINDS_NEW})")


def downgrade() -> None:
    # 木質層架併回最接近的舊值：一樣是以「層」計的層架
    op.execute("UPDATE racks SET kind='shelf' WHERE kind='wood_shelf'")
    op.drop_constraint("ck_racks_kind_valid", "racks", type_="check")
    op.create_check_constraint("ck_racks_kind_valid", "racks", f"kind IN ({_KINDS_OLD})")
