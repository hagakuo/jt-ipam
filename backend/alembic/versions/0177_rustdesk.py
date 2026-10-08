"""RustDesk Server（開源版）整合（2026-10-04）。

rustdesk_servers：一台 RustDesk 伺服器，由裝在它上面的掃描代理回報（一台代理一台伺服器）。
rustdesk_peers：hbbs 資料庫裡的 ID、登記 IP、線上狀態，以及保守對應到的 IP 記錄。

只新增資料表，既有站台升級後行為不變；要在網頁上新增 RustDesk 伺服器並指派代理才會開始收資料。

Revision ID: 0177_rustdesk
Revises: 0176_relay_ports_web_ui
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0177_rustdesk"
down_revision = "0176_relay_ports_web_ui"
branch_labels = None
depends_on = None


def _ts() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "rustdesk_servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scan_agents.id", ondelete="SET NULL"), unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("report_interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("client_address", sa.String(255)),
        sa.Column("public_key", sa.String(64)),
        sa.Column("server_version", sa.String(32)),
        sa.Column("last_report_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("file_status", postgresql.JSONB()),
        sa.Column("last_summary", postgresql.JSONB()),
        sa.Column("description", sa.Text()),
        *_ts(),
    )
    op.create_table(
        "rustdesk_peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("server_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("rustdesk_servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rustdesk_id", sa.String(100), nullable=False),
        sa.Column("registered_ip", postgresql.INET()),
        sa.Column("first_registered_at", sa.DateTime(timezone=True)),
        sa.Column("online", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_online_at", sa.DateTime(timezone=True)),
        sa.Column("address_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="SET NULL")),
        sa.Column("match_status", sa.String(16), nullable=False, server_default="no_ip"),
        *_ts(),
        sa.UniqueConstraint("server_id", "rustdesk_id", name="uq_rustdesk_peer"),
    )
    op.create_index("ix_rustdesk_peers_server_id", "rustdesk_peers", ["server_id"])
    op.create_index("ix_rustdesk_peers_rustdesk_id", "rustdesk_peers", ["rustdesk_id"])
    op.create_index("ix_rustdesk_peers_address_id", "rustdesk_peers", ["address_id"])


def downgrade() -> None:
    op.drop_table("rustdesk_peers")
    op.drop_table("rustdesk_servers")
