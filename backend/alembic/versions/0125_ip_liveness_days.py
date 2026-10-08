"""逐日存活觀測：可用性長條圖不再靠推估

Revision ID: 0125_liveness_days
Revises: 0124_last_seen_arp
Create Date: 2026-08-25

在此之前，長條圖是由 `ip_change_log` 的狀態轉換「重建」出來的：某天的狀態＝上一筆
轉換的值，一路延續到下一筆轉換。沒有轉換的日子沒有任何觀測撐著，卻會被畫成綠色。

實機上就出事了：一台關了幾十天的 VM，因為七月留下一筆轉換，之後每一天都被畫成可用。
更麻煩的是它一旦重新開機、被掃描代理看到，「這個 IP 有存活來源」又會成立，
推估就又把整段歷史填綠 —— 逐 IP 的布林值救不了逐日的問題。

所以改成**每輪同步逐一記下當天實際觀測到什麼**。一天一列（每 IP），只增不改語意：
- up：當天曾被會老化的來源看到（掃描代理探測／LibreNMS 裝置狀態）
- down：當天曾判定離線
- arp_only：當天唯一的證據是 ARP（沒有時間概念，不足以宣稱可用）
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0125_liveness_days"
down_revision = "0124_last_seen_arp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ip_liveness_days",
        sa.Column("ip_id", UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("day", sa.Date(), primary_key=True),
        sa.Column("up", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("down", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("arp_only", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_ip_liveness_days_day", "ip_liveness_days", ["day"])


def downgrade() -> None:
    op.drop_index("ix_ip_liveness_days_day", table_name="ip_liveness_days")
    op.drop_table("ip_liveness_days")
