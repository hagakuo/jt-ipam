"""kea_dhcp_servers / isc_dhcp_servers：獨立的 Kea 與 ISC DHCP 伺服器（issue #45）

Kea 由 jt-ipam 主動拉 JSON 控制 API；ISC DHCP 由裝在 DHCP 主機上的掃描代理讀檔回報。

Revision ID: 0165_standalone_dhcp
Revises: 0164_scan_agent_cycles
Create Date: 2026-09-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0165_standalone_dhcp"
down_revision: str | None = "0164_scan_agent_cycles"
branch_labels = None
depends_on = None


def _common() -> list[sa.Column]:
    return [
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sync_scopes", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sync_leases", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scope_subnet_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True))),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("last_summary", postgresql.JSONB()),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "kea_dhcp_servers",
        *_common(),
        sa.Column("api_url", sa.Text(), nullable=False),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("username", sa.String(255)),
        sa.Column("password_enc", sa.LargeBinary()),
        sa.Column("password_nonce", sa.LargeBinary()),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False, server_default="300"),
    )
    op.create_table(
        "isc_dhcp_servers",
        *_common(),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scan_agents.id", ondelete="SET NULL"), unique=True),
        sa.Column("report_interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("file_status", postgresql.JSONB()),
    )


def downgrade() -> None:
    for src in ("kea_dhcp", "isc_dhcp"):
        op.execute(f"DELETE FROM dhcp_pool_ranges WHERE source_type = '{src}'")      # noqa: S608
        op.execute(f"DELETE FROM dhcp_reservations WHERE source_type = '{src}'")     # noqa: S608
        op.execute(f"DELETE FROM dhcp_lease_sightings WHERE source_type = '{src}'")  # noqa: S608
    op.drop_table("isc_dhcp_servers")
    op.drop_table("kea_dhcp_servers")
