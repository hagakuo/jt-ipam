"""ai_findings：AI 巡檢發現

排程分析 IPAM 資料後把發現落地。存表而不是每次現算，是因為 LLM 分析慢且耗 token，
儀表板每次載入都重跑不可行。
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0102_ai_findings"
down_revision = "0101_librenms_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="low"),
        sa.Column("category", sa.String(length=48), nullable=False, server_default="other"),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("recommendation", sa.Text()),
        sa.Column("evidence", postgresql.JSONB()),
        sa.Column("object_type", sa.String(length=32)),
        sa.Column("object_id", postgresql.UUID(as_uuid=True)),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("dismissed_by", postgresql.UUID(as_uuid=True)),
        sa.Column("dismissed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["dismissed_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_ai_findings_run_id", "ai_findings", ["run_id"])
    op.create_index("ix_ai_findings_status_severity", "ai_findings", ["status", "severity"])
    op.create_index("ix_ai_findings_created", "ai_findings", [sa.text("created_at DESC")])


def downgrade() -> None:
    op.drop_index("ix_ai_findings_created", table_name="ai_findings")
    op.drop_index("ix_ai_findings_status_severity", table_name="ai_findings")
    op.drop_index("ix_ai_findings_run_id", table_name="ai_findings")
    op.drop_table("ai_findings")
