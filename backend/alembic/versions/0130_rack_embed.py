"""rack diagram embedding: per-rack opt-in flag

The diagram can be published as an SVG for other dashboards (LibreNMS widgets and
the like) to show with a plain <img>. Publishing is per rack and off by default:
a rack diagram reveals device names and their positions, so exposing every rack
because one of them is useful would be the wrong default.

Revision ID: 0130_rack_embed
Revises: 0129_virt_long_names
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0130_rack_embed"
down_revision = "0129_virt_long_names"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "racks",
        sa.Column("expose_svg", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("racks", "expose_svg")
