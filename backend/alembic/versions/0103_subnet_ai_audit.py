"""subnets.ai_audit_enabled：子網路是否納入 AI 巡檢

預設 true：既有網段維持現況（本來就全部都會被巡檢），新網段也自動納入 —— 預設排除的話，
使用者要記得逐一去開，忘了就是安靜地漏掉，而漏掉的網段不會有任何跡象。

Revision ID: 0103_subnet_ai_audit
Revises: 0102_ai_findings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0103_subnet_ai_audit"
down_revision = "0102_ai_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "subnets",
        sa.Column("ai_audit_enabled", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
    )


def downgrade() -> None:
    op.drop_column("subnets", "ai_audit_enabled")
