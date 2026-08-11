"""ESXi / vCenter 整合（vSphere SOAP）

新增 esxi_instances；virtual_machines 加 external_id 供非 Proxmox 平台使用
（Proxmox 用整數 VMID、VMware 用字串 MoRef，不共用同一欄）。

Revision ID: 0110_esxi
Revises: 0109_wazuh_sca
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0110_esxi"
down_revision = "0109_wazuh_sca"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("virtual_machines", sa.Column("external_id", sa.String(64)))
    op.create_index("ix_virtual_machines_external_id", "virtual_machines", ["external_id"])
    op.create_unique_constraint(
        "vm_cluster_external_uq", "virtual_machines", ["cluster_id", "external_id"])
    op.create_table(
        "esxi_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("api_url", sa.Text(), nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password_enc", sa.LargeBinary(), nullable=False),
        sa.Column("password_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True)),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("scope_subnet_ids", postgresql.JSONB()),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("esxi_instances")
    op.drop_constraint("vm_cluster_external_uq", "virtual_machines", type_="unique")
    op.drop_index("ix_virtual_machines_external_id", table_name="virtual_machines")
    op.drop_column("virtual_machines", "external_id")
