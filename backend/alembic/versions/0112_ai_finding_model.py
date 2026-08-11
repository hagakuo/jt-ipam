"""ai_findings.model — 每條發現是哪個模型寫的

Revision ID: 0112_ai_finding_model
Revises: 0111_esxi_extra_urls
Create Date: 2026-08-07

巡檢結論是模型的推測，而不同模型的品質差很多。換過模型之後，畫面上分不出哪幾條是
舊模型寫的、哪幾條是新的 —— 判斷「這個模型到底有沒有比較好」就沒有依據。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0112_ai_finding_model"
down_revision = "0111_esxi_extra_urls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_findings", sa.Column("model", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_findings", "model")
