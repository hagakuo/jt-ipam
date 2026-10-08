"""子網路內的位址範圍（集區）—— GitHub issue #40。

DHCP 集區這類「子網路裡的一段連續位址」常常不是一個 CIDR 表示得了的（.181～.250）。
子網路維持 CIDR，範圍是子網路裡的另一種物件；子網路刪掉時跟著刪。

Revision ID: 0151_ip_ranges
Revises: 0150_rack_angle_kallax_lack
Create Date: 2026-09-24
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0151_ip_ranges"
down_revision: str | None = "0150_rack_angle_kallax_lack"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ip_ranges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("subnet_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("start_ip", postgresql.INET(), nullable=False),
        sa.Column("end_ip", postgresql.INET(), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False, server_default="dhcp"),
        sa.Column("name", sa.String(64), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("family(start_ip) = family(end_ip)", name="ip_range_same_family"),
        sa.CheckConstraint("start_ip <= end_ip", name="ip_range_ordered"),
        sa.CheckConstraint("purpose IN ('dhcp','reserved','other')", name="ip_range_purpose_valid"),
    )
    op.create_index("ix_ip_ranges_subnet_id", "ip_ranges", ["subnet_id"])


def downgrade() -> None:
    op.drop_index("ix_ip_ranges_subnet_id", table_name="ip_ranges")
    op.drop_table("ip_ranges")
