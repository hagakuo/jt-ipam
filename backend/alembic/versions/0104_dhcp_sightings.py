"""dhcp_sightings：網段上觀測到的 DHCP 伺服器（用來揪出非法 DHCP）

Revision ID: 0104_dhcp_sightings
Revises: 0103_subnet_ai_audit
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0104_dhcp_sightings"
down_revision = "0103_subnet_ai_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dhcp_sightings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("subnet_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("server_ip", postgresql.INET(), nullable=False),
        sa.Column("server_mac", postgresql.MACADDR(), nullable=True),
        sa.Column("offered_ip", postgresql.INET(), nullable=True),
        sa.Column("router", postgresql.INET(), nullable=True),
        sa.Column("via_relay", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scan_agents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="scanner"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("subnet_id", "server_ip", name="dhcp_sighting_unique"),
    )
    op.create_index("ix_dhcp_sightings_subnet_id", "dhcp_sightings", ["subnet_id"])
    op.create_index("ix_dhcp_sightings_last_seen", "dhcp_sightings", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("ix_dhcp_sightings_last_seen", table_name="dhcp_sightings")
    op.drop_index("ix_dhcp_sightings_subnet_id", table_name="dhcp_sightings")
    op.drop_table("dhcp_sightings")
