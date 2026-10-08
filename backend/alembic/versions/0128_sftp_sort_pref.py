"""SFTP 檔案清單的排序偏好

Revision ID: 0128_sftp_sort
Revises: 0127_event_rules
Create Date: 2026-08-27

「資料夾優先」與「檔案資料夾一起排」兩派都有道理（檔案總管是前者，`ls` 是後者），
所以做成偏好而不是替使用者決定。存在 user_preferences 而非瀏覽器本機：
與 page_size 一樣，換一台裝置登入時應該還是同一個習慣。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0128_sftp_sort"
down_revision = "0127_event_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_preferences",
        sa.Column("sftp_sort_dirs_first", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
    )


def downgrade() -> None:
    op.drop_column("user_preferences", "sftp_sort_dirs_first")
