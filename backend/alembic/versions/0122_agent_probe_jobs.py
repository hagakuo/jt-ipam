"""工具探測工作佇列：讓網路探測可以指定由掃描代理在當地執行

Revision ID: 0122_agent_probe_jobs
Revises: 0121_pve_firewall
Create Date: 2026-08-24

掃描代理是**只由內往外**（poll/report），後端無法主動指使它。因此「從代理執行探測」
走工作佇列：後端建立待辦 → 代理長輪詢領取 → 當地執行 → 回報結果 → 前端取回。
探測是請求／回應、不需要低延遲串流，長輪詢就夠，不必動用 WebSocket。

安全考量寫在欄位上：`kind` 只允許允許清單內的探測種類；`requested_by` 逐筆留痕；
`expires_at` 讓沒人領的工作自動作廢，避免代理離線後累積成一堆遲來的探測。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0122_agent_probe_jobs"
down_revision = "0121_pve_firewall"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_probe_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),          # ping|tcp|traceroute|rdns
        sa.Column("params", JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("result", JSONB()),
        sa.Column("error", sa.Text()),
        sa.Column("requested_by", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_probe_jobs_pending", "agent_probe_jobs",
                    ["agent_id", "status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_agent_probe_jobs_pending", table_name="agent_probe_jobs")
    op.drop_table("agent_probe_jobs")
