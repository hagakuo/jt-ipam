"""agent_probe_jobs.progress：代理執行中回報的進度（IP「探測」頁顯示現在在做什麼）。

使用者回饋（2026-09-28）：探測要跑好幾分鐘，畫面上只有「探測中」看不出在做什麼。代理跑 nmap 時
每隔幾秒把階段、完成百分比、已發現的埠送回來，存在這一欄；結果回報後就不再更新。
另外 identify 多了 level（standard／deep），存在既有的 params JSONB 裡，不另加欄位。

Revision ID: 0162_probe_job_progress
Revises: 0161_device_port_source
Create Date: 2026-09-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0162_probe_job_progress"
down_revision: str | None = "0161_device_port_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_probe_jobs", sa.Column("progress", JSONB, nullable=True))
    # 探測頁要列出某個 IP 的歷次探測：依種類＋建立時間找
    op.create_index("ix_agent_probe_jobs_kind_created", "agent_probe_jobs", ["kind", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_agent_probe_jobs_kind_created", table_name="agent_probe_jobs")
    op.drop_column("agent_probe_jobs", "progress")
