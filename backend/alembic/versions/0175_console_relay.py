"""主控台經由掃描代理中繼（issue #24 階段二，2026-10-02）。

- subnets／ip_addresses 加 console_agent_id（FK → scan_agents，SET NULL）；與 jump_host_id 只能擇一（CHECK）。
- scan_agents 加 relay_allowed（預設 false）、relay_max_sessions（預設 4）、relay_caps（代理回報的能力）。

既有站台升級後行為不變：沒有人指派就沒有任何中繼。

Revision ID: 0175_console_relay
Revises: 0174_liveness_flip_source
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0175_console_relay"
down_revision = "0174_liveness_flip_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table, ck in (("subnets", "subnet_console_egress_one"), ("ip_addresses", "ip_console_egress_one")):
        op.add_column(table, sa.Column("console_agent_id", UUID(as_uuid=True),
                                       sa.ForeignKey("scan_agents.id", ondelete="SET NULL"), nullable=True))
        op.create_index(f"ix_{table}_console_agent_id", table, ["console_agent_id"])
        op.create_check_constraint(ck, table, "jump_host_id IS NULL OR console_agent_id IS NULL")
    op.add_column("scan_agents", sa.Column("relay_allowed", sa.Boolean(), nullable=False,
                                           server_default=sa.text("false")))
    op.add_column("scan_agents", sa.Column("relay_max_sessions", sa.Integer(), nullable=False,
                                           server_default=sa.text("4")))
    op.add_column("scan_agents", sa.Column("relay_caps", JSONB(), nullable=True))


def downgrade() -> None:
    for col in ("relay_caps", "relay_max_sessions", "relay_allowed"):
        op.drop_column("scan_agents", col)
    for table, ck in (("ip_addresses", "ip_console_egress_one"), ("subnets", "subnet_console_egress_one")):
        op.drop_constraint(ck, table, type_="check")
        op.drop_index(f"ix_{table}_console_agent_id", table_name=table)
        op.drop_column(table, "console_agent_id")
