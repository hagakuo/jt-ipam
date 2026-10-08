"""MikroTik RouterOS 整合（Phase 1）：路由器實例／防火牆規則／位址清單三張表。

設計取捨見 `docs/SPEC_MIKROTIK_zh-TW.md`。與其他防火牆整合最大的不同是**安全參數**：
客戶端是主力路由器（CCR2004／CCR1072），所以「不要把路由器拖慢」是欄位層級的需求 ——
逐區段開關、CPU 門檻、區段間隔、回應大小上限都存在實例上，而且**重的區段預設關**。

Revision ID: 0135_mikrotik
Revises: 0134_last_seen_zabbix
Create Date: 2026-09-04
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0135_mikrotik"
down_revision: str | None = "0134_last_seen_zabbix"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mikrotik_routers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("api_url", sa.Text(), nullable=False),
        sa.Column("api_username", sa.String(128), nullable=False),
        sa.Column("api_password_enc", postgresql.BYTEA(), nullable=False),
        sa.Column("api_password_nonce", postgresql.BYTEA(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # 主力路由器 → 預設 15 分鐘，不是其他整合的 5 分鐘
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False,
                  server_default=sa.text("900")),
        # 逐區段開關：重的（ARP 全表、bridge host）預設關，等看過診斷的列數再開
        sa.Column("sync_interfaces", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_dhcp", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_dhcp_ranges", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_firewall", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_nat", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_address_lists", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
        sa.Column("sync_neighbors", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_arp", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sync_fdb", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sync_vpn", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        # 安全參數（門檻待實機校準，見規格 §11）
        sa.Column("cpu_load_limit", sa.Integer(), nullable=False, server_default=sa.text("70")),
        sa.Column("section_delay_ms", sa.Integer(), nullable=False,
                  server_default=sa.text("300")),
        sa.Column("max_response_mb", sa.Integer(), nullable=False, server_default=sa.text("8")),
        sa.Column("scope_subnet_ids", postgresql.JSONB()),
        sa.Column("description", sa.Text()),
        sa.Column("routeros_version", sa.String(32)),
        sa.Column("board_name", sa.String(64)),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        # 逐區段成本：耗時／列數／位元組／cpu 前後 —— 讓管理員看得到哪一段最貴
        sa.Column("last_cost", postgresql.JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )

    op.create_table(
        "mikrotik_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("router_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("mikrotik_routers.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        # filter / nat / mangle —— 同一張表，用 table 欄位分
        sa.Column("table_name", sa.String(16), nullable=False),
        sa.Column("chain", sa.String(64)),
        sa.Column("position", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("action", sa.String(32)),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("src_address", sa.Text()),
        sa.Column("dst_address", sa.Text()),
        sa.Column("protocol", sa.String(32)),
        sa.Column("src_port", sa.String(64)),
        sa.Column("dst_port", sa.String(64)),
        sa.Column("in_interface", sa.String(64)),
        sa.Column("out_interface", sa.String(64)),
        sa.Column("to_addresses", sa.Text()),
        sa.Column("to_ports", sa.String(64)),
        sa.Column("comment", sa.Text()),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )

    op.create_table(
        "mikrotik_address_lists",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("router_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("mikrotik_routers.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("list_name", sa.String(128), nullable=False),
        sa.Column("address", sa.Text(), nullable=False),
        sa.Column("dynamic", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("timeout", sa.String(32)),
        sa.Column("comment", sa.Text()),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_mikrotik_address_lists_list", "mikrotik_address_lists",
                    ["router_id", "list_name"])


def downgrade() -> None:
    op.drop_index("ix_mikrotik_address_lists_list", table_name="mikrotik_address_lists")
    op.drop_table("mikrotik_address_lists")
    op.drop_table("mikrotik_rules")
    op.drop_table("mikrotik_routers")
