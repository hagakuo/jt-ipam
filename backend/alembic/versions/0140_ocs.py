"""OCS Inventory NG 整合（Phase 1）：ocs_servers 實例表 + ip_addresses.last_seen_ocs。

定位與設計取捨見 `docs/SPEC_OCS_zh-TW.md` 與 model 檔頭。要點：REST 帳密選用（OCS 預設無驗證）、
軟體區段預設關（每台 ~2 KB→~80 KB）、增量是版本能力（2.11 有、2.10 無，故留 last_incremental_epoch
游標）、來源類型 rest/db 一開始就是欄位（DB 直讀是第二階段的退路）。

Revision ID: 0140_ocs
Revises: 0139_locale_ja
Create Date: 2026-09-18
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0140_ocs"
down_revision: str | None = "0139_locale_ja"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ocs_servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("source_type", sa.String(8), nullable=False, server_default=sa.text("'rest'")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # REST 來源
        sa.Column("base_url", sa.Text()),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # 帳密選用 —— OCS REST 預設無驗證
        sa.Column("api_username", sa.String(128)),
        sa.Column("api_password_enc", postgresql.BYTEA()),
        sa.Column("api_password_nonce", postgresql.BYTEA()),
        # DB 來源（第二階段，欄位先留）
        sa.Column("db_host", sa.String(255)),
        sa.Column("db_port", sa.Integer()),
        sa.Column("db_name", sa.String(128)),
        sa.Column("db_username", sa.String(128)),
        sa.Column("db_password_enc", postgresql.BYTEA()),
        sa.Column("db_password_nonce", postgresql.BYTEA()),
        # 同步範圍：硬體/OS 是基礎無開關；軟體預設關（膨脹）
        sa.Column("sync_networks", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_bios", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_software", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False,
                  server_default=sa.text("3600")),
        sa.Column("stale_after_days", sa.Integer(), nullable=False, server_default=sa.text("30")),
        # 診斷與同步狀態
        sa.Column("detected_version", sa.String(32)),
        sa.Column("last_incremental_epoch", sa.BigInteger()),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("last_cost", postgresql.JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint("source_type in ('rest','db')", name="ck_ocs_source_type"),
    )
    op.add_column("ip_addresses", sa.Column("last_seen_ocs", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("ip_addresses", "last_seen_ocs")
    op.drop_table("ocs_servers")
