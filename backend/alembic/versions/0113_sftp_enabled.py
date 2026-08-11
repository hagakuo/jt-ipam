"""ip_addresses.sftp_enabled — SFTP 是獨立於 SSH 的開關

Revision ID: 0113_sftp_enabled
Revises: 0112_ai_finding_model
Create Date: 2026-08-09

原本 SFTP 沿用 ssh_enabled，開了 SSH 就等於開了傳檔。實務上這兩件事不一定要綁在一起：
有些主機只想開放送設定檔／取 log，不想讓人開終端機。

**既有資料沿用 ssh_enabled 的值**：升級前「開了 SSH 的 IP」本來就能用 SFTP（那是 0.5.155
的行為），若一律預設 false，升上來會變成功能無聲消失。要收回的人自己關掉即可。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0113_sftp_enabled"
down_revision = "0112_ai_finding_model"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ip_addresses",
        sa.Column("sftp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    # 沿用升級前的實際行為，而不是把既有站台的功能關掉
    op.execute("UPDATE ip_addresses SET sftp_enabled = ssh_enabled WHERE ssh_enabled")


def downgrade() -> None:
    op.drop_column("ip_addresses", "sftp_enabled")
