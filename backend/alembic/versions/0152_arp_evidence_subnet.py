"""ARP 觀測帶子網路：掃描代理與防火牆看到的 IP／MAC 也當 IP 衝突偵測的依據 —— GitHub issue #41。

`arp_entries` 原本只有 LibreNMS 同步會寫（`device_id` 是 LibreNMS 裝置）。掃描代理與防火牆
的觀測沒有 LibreNMS 裝置，改以「子網路」界定範圍：重疊網段（兩個單位各有一個 10.9.0.5）
不能互相判成衝突。這類觀測以 (ip, mac, source, subnet_id) 唯一，再看到一次只更新時間。

既有的 LibreNMS 列不受影響（subnet_id 留空、device_id 有值，原本的唯一條件照舊）。

Revision ID: 0152_arp_evidence_subnet
Revises: 0151_ip_ranges
Create Date: 2026-09-24
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0152_arp_evidence_subnet"
down_revision: str | None = "0151_ip_ranges"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("arp_entries", sa.Column(
        "subnet_id", postgresql.UUID(as_uuid=True),
        sa.ForeignKey("subnets.id", ondelete="CASCADE"), nullable=True))
    op.create_index("ix_arp_entries_subnet_id", "arp_entries", ["subnet_id"])
    op.create_index(
        "arp_entry_observed_unique", "arp_entries", ["ip", "mac", "source", "subnet_id"],
        unique=True,
        postgresql_where=sa.text("device_id IS NULL AND subnet_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("arp_entry_observed_unique", table_name="arp_entries")
    op.drop_index("ix_arp_entries_subnet_id", table_name="arp_entries")
    op.drop_column("arp_entries", "subnet_id")
