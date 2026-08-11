"""esxi_instances.extra_api_urls：備援位址

vCenter 可能有多個位址，或 vCenter 停機時想改打某台 ESXi —— 依序試到通為止。
與 Proxmox 的 extra_api_urls 同一套作法。

Revision ID: 0111_esxi_extra_urls
Revises: 0110_esxi
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0111_esxi_extra_urls"
down_revision = "0110_esxi"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("esxi_instances", sa.Column("extra_api_urls", sa.Text()))


def downgrade() -> None:
    op.drop_column("esxi_instances", "extra_api_urls")
