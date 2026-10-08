"""scan_agents.last_cycle：代理最近一輪掃描的耗時與待辦量。

使用者要求（2026-09-28）：一台代理能扛多少子網路／位址，要靠量測而不是猜。代理每輪回報
總耗時、逐子網路耗時／位址數／在線數／是否被截斷，以及背景重量探測的待辦量；這一欄存最近一輪，
給掃描代理頁的負載顯示與超載通知用。

Revision ID: 0163_scan_agent_last_cycle
Revises: 0162_probe_job_progress
Create Date: 2026-09-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0163_scan_agent_last_cycle"
down_revision: str | None = "0162_probe_job_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_agents", sa.Column("last_cycle", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("scan_agents", "last_cycle")
