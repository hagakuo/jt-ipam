"""dhcp_reservations + ip_addresses.dhcp_reserved

DHCP 固定分配（reservation / static mapping）：這個 MAC 固定拿這個 IP。
`ip_addresses.dhcp_reserved` 是給清單頁用的衍生旗標（每次同步重算），
明細要看是哪台 DHCP、綁哪張網卡則查 dhcp_reservations。

Revision ID: 0107_dhcp_reservations
Revises: 0106_subnet_anomaly
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0107_dhcp_reservations"
down_revision = "0106_subnet_anomaly"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dhcp_reservations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_name", sa.String(128)),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("mac", sa.String(32)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("description", sa.String(255)),
        sa.Column("source", sa.String(16), nullable=False, server_default="kea"),
        sa.Column("ip_address_id", postgresql.UUID(as_uuid=True)),
        sa.Column("synced_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_dhcp_reservations_ip", "dhcp_reservations", ["ip"])
    op.create_index("ix_dhcp_reservations_mac", "dhcp_reservations", ["mac"])
    op.create_index("ix_dhcp_reservations_source", "dhcp_reservations",
                    ["source_type", "source_id"])
    op.add_column("ip_addresses", sa.Column(
        "dhcp_reserved", sa.Boolean(), nullable=False, server_default=sa.text("false")))


def downgrade() -> None:
    op.drop_column("ip_addresses", "dhcp_reserved")
    op.drop_index("ix_dhcp_reservations_source", table_name="dhcp_reservations")
    op.drop_index("ix_dhcp_reservations_mac", table_name="dhcp_reservations")
    op.drop_index("ix_dhcp_reservations_ip", table_name="dhcp_reservations")
    op.drop_table("dhcp_reservations")
