"""FortiGate 整合（Beta）：實例 / 政策 / 位址物件三張表 + 放寬 nat_translations.external_id

external_id 原本 String(64)；FortiGate 的 NAT 以 `<vdom>:<物件名>` 當外部識別，
FortiOS 物件名可長達 79 字，加上 VDOM 首碼會超過 64 → 放寬到 200（純放寬，不影響既有值）。

Revision ID: 0100_fortigate
Revises: 0099_windows_dhcp_servers
Create Date: 2026-07-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0100_fortigate"
down_revision: str | None = "0099_windows_dhcp_servers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fortigate_firewalls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("api_url", sa.Text(), nullable=False),
        sa.Column("api_token_enc", sa.LargeBinary(), nullable=False),
        sa.Column("api_token_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("vdoms", postgresql.ARRAY(sa.String(64))),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("sync_dhcp", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sync_dhcp_ranges", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sync_arp", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sync_vpn", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sync_policies", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sync_nat", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sync_addresses", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("scope_subnet_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True))),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "fortigate_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("firewall_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("fortigate_firewalls.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("vdom", sa.String(64), nullable=False, server_default="root"),
        sa.Column("policyid", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255)),
        sa.Column("status", sa.String(16)),
        sa.Column("action", sa.String(16)),
        sa.Column("srcintf", sa.Text()),
        sa.Column("dstintf", sa.Text()),
        sa.Column("srcaddr", sa.Text()),
        sa.Column("dstaddr", sa.Text()),
        sa.Column("service", sa.Text()),
        sa.Column("nat", sa.Boolean()),
        sa.Column("comments", sa.Text()),
        sa.Column("raw", postgresql.JSONB()),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("firewall_id", "vdom", "policyid", name="fortigate_policy_unique"),
    )

    op.create_table(
        "fortigate_address_objects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("firewall_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("fortigate_firewalls.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("vdom", sa.String(64), nullable=False, server_default="root"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("obj_type", sa.String(32)),
        sa.Column("kind", sa.String(16), nullable=False, server_default="address"),
        sa.Column("value", sa.Text()),
        sa.Column("members", postgresql.JSONB()),
        sa.Column("comment", sa.Text()),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("firewall_id", "vdom", "name", "kind", name="fortigate_addr_unique"),
    )

    # FortiGate 的 external_id 是 `<vdom>:<物件名>`，可能超過原本的 64 字
    op.alter_column("nat_translations", "external_id",
                    existing_type=sa.String(64), type_=sa.String(200), existing_nullable=True)


def downgrade() -> None:
    # 先清掉 FortiGate 來源的衍生資料（無外鍵 cascade 可依靠）
    op.execute("DELETE FROM dhcp_pool_ranges WHERE source_type = 'fortigate'")
    op.execute("DELETE FROM nat_translations WHERE source_origin LIKE 'fortigate:%'")
    # 放寬前先截斷，避免縮回 64 時炸掉
    op.execute("UPDATE nat_translations SET external_id = left(external_id, 64) "
               "WHERE external_id IS NOT NULL AND length(external_id) > 64")
    op.alter_column("nat_translations", "external_id",
                    existing_type=sa.String(200), type_=sa.String(64), existing_nullable=True)
    op.drop_table("fortigate_address_objects")
    op.drop_table("fortigate_policies")
    op.drop_table("fortigate_firewalls")
