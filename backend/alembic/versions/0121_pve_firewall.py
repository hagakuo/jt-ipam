"""Proxmox VE 防火牆：規則、生效狀態、安全群組、IPSet／alias

Revision ID: 0121_pve_firewall
Revises: 0120_users_email_not_unique
Create Date: 2026-08-24

PVE 防火牆是東西向／主機層的分段管制，與外層防火牆分開建模（見
docs/SPEC_PVE_FIREWALL_zh-TW.md）。三個設計重點都反映在欄位上：

1. `scope` 是一等欄位 —— 規則掛在資料中心／節點／guest 哪一層，決定它的意義
2. `pve_firewall_state` 存「是否真的生效」所需的**三個開關與各層預設政策**，
   並把它們收斂成單一 `posture` 欄位；UI 與異常偵測只讀 posture，避免各處自行拼裝條件
3. 政策欄位另存 `*_explicit`：PVE API **不回傳未設定的欄位**，缺席代表沿用內建預設，
   與「明確設成該值」意義不同
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0121_pve_firewall"
down_revision = "0120_users_email_not_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pve_firewall_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("instance_id", UUID(as_uuid=True),
                  sa.ForeignKey("proxmox_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),        # datacenter|node|guest
        sa.Column("node_name", sa.String(128)),
        sa.Column("vmid", sa.Integer()),
        sa.Column("guest_kind", sa.String(8)),                    # qemu|lxc
        sa.Column("pos", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("direction", sa.String(8)),                     # in|out|forward
        sa.Column("action", sa.String(64)),                       # ACCEPT|DROP|REJECT|<group>
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("proto", sa.String(16)),
        sa.Column("dport", sa.String(64)),
        sa.Column("sport", sa.String(64)),
        sa.Column("source", sa.Text()),
        sa.Column("dest", sa.Text()),
        sa.Column("iface", sa.String(64)),
        sa.Column("macro", sa.String(64)),
        sa.Column("macro_expanded", sa.Text()),
        sa.Column("group_ref", sa.String(64)),
        sa.Column("comment", sa.Text()),
        sa.Column("raw", JSONB()),
        sa.Column("synced_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_pve_fw_rules_instance", "pve_firewall_rules", ["instance_id"])
    op.create_index("ix_pve_fw_rules_guest", "pve_firewall_rules", ["instance_id", "vmid"])

    op.create_table(
        "pve_firewall_state",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("instance_id", UUID(as_uuid=True),
                  sa.ForeignKey("proxmox_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vmid", sa.Integer(), nullable=False),
        sa.Column("guest_kind", sa.String(8)),
        sa.Column("node_name", sa.String(128)),
        sa.Column("cluster_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("guest_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("nic_firewall", JSONB()),         # {"net0": true, "net1": false}
        sa.Column("cluster_policy_in", sa.String(8)),
        sa.Column("cluster_policy_out", sa.String(8)),
        sa.Column("guest_policy_in", sa.String(8)),
        sa.Column("guest_policy_out", sa.String(8)),
        # 這幾個值是「明設」還是「沿用 PVE 內建預設」——API 不回傳未設定的欄位
        sa.Column("cluster_policy_in_explicit", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("guest_policy_in_explicit", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("guest_enabled_explicit", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("effective", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("posture", sa.String(16), nullable=False, server_default="unprotected"),
        sa.Column("synced_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("instance_id", "vmid", name="uq_pve_fw_state_instance_vmid"),
    )

    op.create_table(
        "pve_firewall_groups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("instance_id", UUID(as_uuid=True),
                  sa.ForeignKey("proxmox_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("rules", JSONB()),
        sa.Column("synced_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("instance_id", "name", name="uq_pve_fw_group_instance_name"),
    )

    op.create_table(
        "pve_firewall_ipsets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("instance_id", UUID(as_uuid=True),
                  sa.ForeignKey("proxmox_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),        # datacenter|guest
        sa.Column("vmid", sa.Integer()),
        sa.Column("kind", sa.String(8), nullable=False),          # ipset|alias
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("members", JSONB()),
        sa.Column("members_resolved", JSONB()),
        sa.Column("synced_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_pve_fw_ipsets_lookup", "pve_firewall_ipsets",
                    ["instance_id", "scope", "vmid", "name"])

    op.add_column("proxmox_instances",
                  sa.Column("sync_firewall", sa.Boolean(), nullable=False,
                            server_default=sa.text("true")))


def downgrade() -> None:
    op.drop_column("proxmox_instances", "sync_firewall")
    op.drop_index("ix_pve_fw_ipsets_lookup", table_name="pve_firewall_ipsets")
    op.drop_table("pve_firewall_ipsets")
    op.drop_table("pve_firewall_groups")
    op.drop_table("pve_firewall_state")
    op.drop_index("ix_pve_fw_rules_guest", table_name="pve_firewall_rules")
    op.drop_index("ix_pve_fw_rules_instance", table_name="pve_firewall_rules")
    op.drop_table("pve_firewall_rules")
