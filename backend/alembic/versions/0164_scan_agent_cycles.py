"""scan_agent_cycles：掃描代理每一輪的耗時記錄（保留 7 天）。

使用者要求（2026-09-28）：自動記錄每輪掃描花多久，太長要通知管理員。一輪一列，
負載面板畫趨勢、判斷背景待辦是否一直消化不完都靠它。回報時順手清掉 7 天前的列。

Revision ID: 0164_scan_agent_cycles
Revises: 0163_scan_agent_last_cycle
Create Date: 2026-09-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0164_scan_agent_cycles"
down_revision: str | None = "0163_scan_agent_last_cycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_agent_cycles",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("agent_id", UUID(as_uuid=True), sa.ForeignKey("scan_agents.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_s", sa.Float, nullable=False),
        sa.Column("interval_s", sa.Integer, nullable=False),
        sa.Column("heavy_backlog", sa.Integer, nullable=False, server_default="0"),
        sa.Column("hosts", sa.Integer),
        sa.Column("alive", sa.Integer),
    )
    op.create_index("ix_scan_agent_cycles_agent_at", "scan_agent_cycles", ["agent_id", "at"])


def downgrade() -> None:
    op.drop_index("ix_scan_agent_cycles_agent_at", table_name="scan_agent_cycles")
    op.drop_table("scan_agent_cycles")
