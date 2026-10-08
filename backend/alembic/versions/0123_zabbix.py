"""Zabbix 整合：實例設定與主機鏡像

Revision ID: 0123_zabbix
Revises: 0122_agent_probe_jobs
Create Date: 2026-08-24

Zabbix 在台灣是裝機量最大的開源 NMS。定位是**監控面補充**，不是 LibreNMS 的替代：
它給的是存活狀態、監控涵蓋落差、主機名稱與維護脈絡；ARP／FDB 那一層不在 Zabbix
的內建資料裡（需自訂 SNMP 項目），因此不承諾。

認證用 API token（Zabbix 5.4+）或 user.login 取得的 session token，兩者都以
AES-GCM 加密存放，欄位與其他整合一致。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

revision = "0123_zabbix"
down_revision = "0122_agent_probe_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zabbix_instances",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("api_url", sa.Text(), nullable=False),
        # API token（建議）或帳密登入；兩者擇一，皆加密
        sa.Column("api_token_enc", sa.LargeBinary()),
        sa.Column("api_token_nonce", sa.LargeBinary()),
        sa.Column("api_user", sa.String(128)),
        sa.Column("api_password_enc", sa.LargeBinary()),
        sa.Column("api_password_nonce", sa.LargeBinary()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # 重疊網段安全：限定要比對的子網路（空＝全域）
        sa.Column("scope_subnet_ids", JSONB()),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False,
                  server_default="300"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "zabbix_hosts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("instance_id", UUID(as_uuid=True),
                  sa.ForeignKey("zabbix_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hostid", sa.String(32), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),        # 技術名稱
        sa.Column("name", sa.String(255)),                        # 顯示名稱
        sa.Column("status", sa.String(16)),                       # monitored | unmonitored
        sa.Column("available", sa.String(16)),                    # up | down | unknown
        sa.Column("maintenance", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("ip", INET()),
        sa.Column("dns", sa.String(255)),
        sa.Column("groups", JSONB()),
        sa.Column("tags", JSONB()),
        sa.Column("inventory", JSONB()),
        sa.Column("jt_ipam_address_id", UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="SET NULL")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("synced_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("instance_id", "hostid", name="uq_zabbix_host_instance_hostid"),
    )
    op.create_index("ix_zabbix_hosts_ip", "zabbix_hosts", ["ip"])


def downgrade() -> None:
    op.drop_index("ix_zabbix_hosts_ip", table_name="zabbix_hosts")
    op.drop_table("zabbix_hosts")
    op.drop_table("zabbix_instances")
